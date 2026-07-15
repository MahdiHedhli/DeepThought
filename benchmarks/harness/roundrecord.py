"""Benchmark instrumentation for the vuln-rediscovery skill build.

Each skill-build round emits a RoundRecord: what it targeted, what it cost
(wall time, tokens, review rounds, effort), the detector's precision and recall
on the fixture, and pointers to the captured artifacts. After the skill is built,
each bug class gets a HeldOutResult measuring the real thing, whether the detector
finds the same pattern in CVEs it was never tuned on.

The aggregator turns these into the two tables that go in the docs: build cost per
round, and generalization per class. This is the yardstick, not training data, so
the numbers that matter are the held-out ones.
"""

from __future__ import annotations

import math
from fractions import Fraction
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


def _safe_div(n: int, d: int) -> float:
    return round(n / d, 3) if d else 0.0


def _pct(value: float) -> str:
    """Percent for the benchmark yardstick. NEVER round a sub-1.0 rate UP to 100% —
    a single remaining miss must stay visible (199/200 shows 99.5%, not 100%). Only
    an exact >=1.0 renders '100%'; everything else floors to 0.1%."""
    if value >= 1.0:
        return "100%"
    return f"{math.floor(value * 1000) / 10:.1f}%"


def _cell(value: str) -> str:
    """A markdown table cell. The values are our own accounting data, but a stray
    pipe or newline would corrupt the whole table into gibberish, so escape pipes
    and flatten newlines — a row stays exactly one row."""
    return str(value).replace("|", "\\|").replace("\n", " ").replace("\r", " ")


def _md_table(headers: list[str], rows: list[list[str]]) -> str:
    line = "| " + " | ".join(_cell(h) for h in headers) + " |"
    sep = "| " + " | ".join("---" for _ in headers) + " |"
    body = ["| " + " | ".join(_cell(c) for c in r) + " |" for r in rows]
    return "\n".join([line, sep, *body])


class Metrics(BaseModel):
    """Confusion counts on a labeled set, with derived precision and recall."""

    model_config = ConfigDict(extra="forbid")

    tp: int = Field(default=0, ge=0)  # vulnerable sinks correctly flagged
    fp: int = Field(default=0, ge=0)  # safe code wrongly flagged
    fn: int = Field(default=0, ge=0)  # vulnerable sinks missed

    @property
    def precision(self) -> float:
        return _safe_div(self.tp, self.tp + self.fp)

    @property
    def recall(self) -> float:
        return _safe_div(self.tp, self.tp + self.fn)

    @property
    def f1(self) -> float:
        # From RAW counts, not the already-rounded precision/recall — computing F1
        # from rounded inputs compounds the rounding error (e.g. tp=1,fp=0,fn=11
        # gives 0.153 via rounded recall vs the true 0.154). F1 = 2tp/(2tp+fp+fn).
        return _safe_div(2 * self.tp, 2 * self.tp + self.fp + self.fn)


class Tokens(BaseModel):
    model_config = ConfigDict(extra="forbid")

    input: int = Field(default=0, ge=0)
    output: int = Field(default=0, ge=0)

    @property
    def total(self) -> int:
        return self.input + self.output


class RoundRecord(BaseModel):
    """One skill-build round: build one bug-class detector from one seed CVE."""

    model_config = ConfigDict(extra="forbid")

    cve: str
    package: str
    cwe: str
    bug_class: str
    discovery: str  # coverage_fuzz, oss_fuzz, static_ast, taint, config_rule, variant, regex_complexity
    tier: str  # deterministic or sandbox
    language: str

    wall_seconds: int = Field(default=0, ge=0)
    tokens: Tokens = Field(default_factory=Tokens)
    review_rounds: int = Field(default=0, ge=0)
    findings_fixed: int = Field(default=0, ge=0)
    loc_added: int = Field(default=0, ge=0)
    loc_removed: int = Field(default=0, ge=0)

    fixture: Metrics = Field(default_factory=Metrics)  # precision/recall on the seed fixture
    skill_section: str = ""  # the SKILL.md heading this round contributed
    artifacts: dict[str, str] = Field(default_factory=dict)  # name -> stored path
    status: str = "pending"  # pending, rediscovered, verified, blocked

    def cost_row(self) -> list[str]:
        hrs = f"{self.wall_seconds / 3600:.2f}h"
        return [
            self.cve,
            self.bug_class,
            self.discovery,
            self.tier,
            hrs,
            f"{self.tokens.total:,}",
            str(self.review_rounds),
            f"{self.fixture.precision:.2f}",
            f"{self.fixture.recall:.2f}",
            self.status,
        ]


class HeldOutResult(BaseModel):
    """The real test: run the finished detector against CVEs it never saw."""

    model_config = ConfigDict(extra="forbid")

    bug_class: str
    detector: str  # the SKILL.md rule id
    heldout_cves: list[str] = Field(default_factory=list)
    rediscovered: int = Field(default=0, ge=0)
    missed: int = Field(default=0, ge=0)
    missed_cves: list[str] = Field(default_factory=list)  # each missed CVE becomes a new fixture
    metrics: Metrics = Field(default_factory=Metrics)  # precision/recall across held-out packages

    @property
    def generalization(self) -> float:
        total = self.rediscovered + self.missed
        return _safe_div(self.rediscovered, total)

    def row(self) -> list[str]:
        total = self.rediscovered + self.missed
        return [
            self.bug_class,
            self.detector,
            f"{self.rediscovered}/{total}",
            _pct(self.generalization),
            f"{self.metrics.precision:.2f}",
            f"{self.metrics.recall:.2f}",
        ]


class Benchmark(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rounds: list[RoundRecord] = Field(default_factory=list)
    heldout: list[HeldOutResult] = Field(default_factory=list)

    # -- summary -----------------------------------------------------------
    def total_wall_seconds(self) -> int:
        return sum(r.wall_seconds for r in self.rounds)

    def total_tokens(self) -> int:
        return sum(r.tokens.total for r in self.rounds)

    def total_review_rounds(self) -> int:
        return sum(r.review_rounds for r in self.rounds)

    def mean_generalization(self) -> float:
        # The mean over MEASURED classes. summary_line() surfaces how many built
        # classes are unmeasured, so this number can never be read as complete when
        # it is not (a partial held-out set must not masquerade as the full headline).
        if not self.heldout:
            return 0.0
        exact_rates = [
            Fraction(h.rediscovered, h.rediscovered + h.missed)
            if h.rediscovered + h.missed
            else Fraction(0)
            for h in self.heldout
        ]
        return round(float(sum(exact_rates, Fraction(0)) / len(exact_rates)), 3)

    def unmeasured_classes(self) -> list[str]:
        """Built bug classes (from rounds) that have NO held-out result yet — the
        headline must not average as if these were measured. Empty when every built
        class has a held-out row."""
        measured = {h.bug_class for h in self.heldout}
        out: list[str] = []
        for r in self.rounds:
            if r.bug_class not in measured and r.bug_class not in out:
                out.append(r.bug_class)
        return out

    # -- documentation tables ---------------------------------------------
    def cost_table(self) -> str:
        headers = ["CVE", "class", "discovery", "tier", "wall", "tokens", "rounds", "prec", "rec", "status"]
        return _md_table(headers, [r.cost_row() for r in self.rounds])

    def generalization_table(self) -> str:
        headers = ["class", "detector", "held-out found", "generalization", "prec", "rec"]
        return _md_table(headers, [h.row() for h in self.heldout])

    def summary_line(self) -> str:
        hrs = self.total_wall_seconds() / 3600
        measured = len({h.bug_class for h in self.heldout})
        line = (
            f"{len(self.rounds)} classes built in {hrs:.1f}h, "
            f"{self.total_tokens():,} tokens, {self.total_review_rounds()} review rounds; "
            f"mean held-out generalization {_pct(self.mean_generalization())} "
            f"over {measured} measured class(es)"
        )
        # NEVER let the headline imply completeness it does not have: name any built
        # class with no held-out result so a partial mean cannot read as the full score.
        unmeasured = self.unmeasured_classes()
        if unmeasured:
            line += f" — WARNING: {len(unmeasured)} unmeasured: {', '.join(unmeasured)}"
        return line


# --------------------------------------------------------------------------- #
# Versioned generalization log: the curve over the skill's life, plus the
# regression bar. Detectors improve, but no change may lower a class's rate.
# --------------------------------------------------------------------------- #


class ClassRate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    bug_class: str
    detector: str = ""
    rediscovered: int = Field(default=0, ge=0)
    total: int = Field(default=0, ge=0)

    @model_validator(mode="after")
    def _counts_are_possible(self) -> "ClassRate":
        # rediscovered can never exceed total: a >total count would publish a
        # >100% rate and (with nonzero rediscovered on zero total) silently show 0%.
        # These feed the published metric and the merge gate, so reject at the boundary.
        if self.rediscovered > self.total:
            raise ValueError(
                f"rediscovered ({self.rediscovered}) cannot exceed total ({self.total})"
            )
        return self

    @property
    def generalization(self) -> float:
        return _safe_div(self.rediscovered, self.total)

    @property
    def exact(self) -> Fraction:
        # The UNROUNDED rate, for gate comparisons (rounding is display-only).
        return Fraction(self.rediscovered, self.total) if self.total else Fraction(0)


class Snapshot(BaseModel):
    """The whole skill's held-out generalization at one point in time."""

    model_config = ConfigDict(extra="forbid")

    label: str  # a version tag, date, or commit
    rates: list[ClassRate] = Field(default_factory=list)

    @field_validator("rates")
    @classmethod
    def _unique_bug_classes(cls, v: list[ClassRate]) -> list[ClassRate]:
        # A duplicate bug_class would double-count in mean() and hide a drop in
        # regressions() (rate_for returns only the first match), silently defeating
        # the regression bar. Reject duplicates at the model boundary.
        names = [r.bug_class for r in v]
        if len(names) != len(set(names)):
            dupes = sorted({c for c in names if names.count(c) > 1})
            raise ValueError(f"duplicate bug_class in snapshot rates: {dupes}")
        return v

    @property
    def mean(self) -> float:
        if not self.rates:
            return 0.0
        return round(
            float(sum((rate.exact for rate in self.rates), Fraction(0)) / len(self.rates)),
            3,
        )

    def rate_for(self, bug_class: str) -> Optional[float]:
        for r in self.rates:
            if r.bug_class == bug_class:
                return r.generalization
        return None

    def classrate_for(self, bug_class: str) -> Optional["ClassRate"]:
        for r in self.rates:
            if r.bug_class == bug_class:
                return r
        return None

    @classmethod
    def from_heldout(cls, label: str, heldout: list["HeldOutResult"]) -> "Snapshot":
        return cls(
            label=label,
            rates=[
                ClassRate(
                    bug_class=h.bug_class,
                    detector=h.detector,
                    rediscovered=h.rediscovered,
                    total=h.rediscovered + h.missed,
                )
                for h in heldout
            ],
        )


class GeneralizationLog(BaseModel):
    """Ordered history of snapshots, oldest first. This is the living metric."""

    model_config = ConfigDict(extra="forbid")

    snapshots: list[Snapshot] = Field(default_factory=list)

    def append(self, snapshot: Snapshot) -> None:
        self.snapshots.append(snapshot)

    def latest(self) -> Optional[Snapshot]:
        return self.snapshots[-1] if self.snapshots else None

    def regressions(self, candidate: Snapshot) -> list[str]:
        """The regression bar. No class rate may drop versus the latest snapshot.
        Returns a list of violations, empty when the candidate is clean."""
        base = self.latest()
        if base is None:
            return []
        out: list[str] = []
        candidate_classes = {r.bug_class for r in candidate.rates}
        for r in candidate.rates:
            base_r = base.classrate_for(r.bug_class)
            # Compare EXACT fractions, not the 3-decimal rounded rate: at large totals
            # a real drop (e.g. 999/1000 -> 998/999) rounds to the same 0.999 and would
            # slip past a rounded comparison. Round only for the display string.
            if base_r is not None and r.exact < base_r.exact:
                out.append(
                    f"{r.bug_class}: {_pct(base_r.generalization)} -> "
                    f"{_pct(r.generalization)} regressed"
                )
        # A class present in the baseline but MISSING from the candidate is the
        # ultimate rate drop — coverage removed. Flag it, so accepts() cannot be
        # passed by simply omitting a class that would otherwise regress (a partial
        # re-measure must re-assert every prior class, not silently drop one).
        for r in base.rates:
            if r.bug_class not in candidate_classes:
                out.append(f"{r.bug_class}: {_pct(r.generalization)} -> dropped (class missing)")
        return out

    def accepts(self, candidate: Snapshot) -> bool:
        """True only if the candidate regresses no class. Merge gate for any
        detector change."""
        return not self.regressions(candidate)

    def curve_table(self) -> str:
        classes: list[str] = []
        for s in self.snapshots:
            for r in s.rates:
                if r.bug_class not in classes:
                    classes.append(r.bug_class)
        headers = ["class", *[s.label for s in self.snapshots]]
        rows: list[list[str]] = []
        for c in classes:
            row = [c]
            for s in self.snapshots:
                v = s.rate_for(c)
                row.append(_pct(v) if v is not None else "-")
            rows.append(row)
        rows.append(["mean", *[_pct(s.mean) for s in self.snapshots]])
        return _md_table(headers, rows)

    def climb(self) -> str:
        if len(self.snapshots) < 2:
            return "insufficient history"
        first, last = self.snapshots[0], self.snapshots[-1]
        return f"mean generalization {_pct(first.mean)} -> {_pct(last.mean)} over {len(self.snapshots)} versions"
