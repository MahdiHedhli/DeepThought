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

from typing import Optional

from pydantic import BaseModel, ConfigDict, Field


def _safe_div(n: int, d: int) -> float:
    return round(n / d, 3) if d else 0.0


def _md_table(headers: list[str], rows: list[list[str]]) -> str:
    line = "| " + " | ".join(headers) + " |"
    sep = "| " + " | ".join("---" for _ in headers) + " |"
    body = ["| " + " | ".join(r) + " |" for r in rows]
    return "\n".join([line, sep, *body])


class Metrics(BaseModel):
    """Confusion counts on a labeled set, with derived precision and recall."""

    model_config = ConfigDict(extra="forbid")

    tp: int = 0  # vulnerable sinks correctly flagged
    fp: int = 0  # safe code wrongly flagged
    fn: int = 0  # vulnerable sinks missed

    @property
    def precision(self) -> float:
        return _safe_div(self.tp, self.tp + self.fp)

    @property
    def recall(self) -> float:
        return _safe_div(self.tp, self.tp + self.fn)

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return round(2 * p * r / (p + r), 3) if (p + r) else 0.0


class Tokens(BaseModel):
    model_config = ConfigDict(extra="forbid")

    input: int = 0
    output: int = 0

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

    wall_seconds: int = 0
    tokens: Tokens = Field(default_factory=Tokens)
    review_rounds: int = 0
    findings_fixed: int = 0
    loc_added: int = 0
    loc_removed: int = 0

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
    rediscovered: int = 0
    missed: int = 0
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
            f"{self.generalization:.0%}",
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
        if not self.heldout:
            return 0.0
        return round(sum(h.generalization for h in self.heldout) / len(self.heldout), 3)

    # -- documentation tables ---------------------------------------------
    def cost_table(self) -> str:
        headers = ["CVE", "class", "discovery", "tier", "wall", "tokens", "rounds", "prec", "rec", "status"]
        return _md_table(headers, [r.cost_row() for r in self.rounds])

    def generalization_table(self) -> str:
        headers = ["class", "detector", "held-out found", "generalization", "prec", "rec"]
        return _md_table(headers, [h.row() for h in self.heldout])

    def summary_line(self) -> str:
        hrs = self.total_wall_seconds() / 3600
        return (
            f"{len(self.rounds)} classes built in {hrs:.1f}h, "
            f"{self.total_tokens():,} tokens, {self.total_review_rounds()} review rounds; "
            f"mean held-out generalization {self.mean_generalization():.0%}"
        )


# --------------------------------------------------------------------------- #
# Versioned generalization log: the curve over the skill's life, plus the
# regression bar. Detectors improve, but no change may lower a class's rate.
# --------------------------------------------------------------------------- #


class ClassRate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    bug_class: str
    detector: str = ""
    rediscovered: int = 0
    total: int = 0

    @property
    def generalization(self) -> float:
        return _safe_div(self.rediscovered, self.total)


class Snapshot(BaseModel):
    """The whole skill's held-out generalization at one point in time."""

    model_config = ConfigDict(extra="forbid")

    label: str  # a version tag, date, or commit
    rates: list[ClassRate] = Field(default_factory=list)

    @property
    def mean(self) -> float:
        if not self.rates:
            return 0.0
        return round(sum(r.generalization for r in self.rates) / len(self.rates), 3)

    def rate_for(self, bug_class: str) -> Optional[float]:
        for r in self.rates:
            if r.bug_class == bug_class:
                return r.generalization
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
        for r in candidate.rates:
            prev = base.rate_for(r.bug_class)
            if prev is not None and r.generalization < prev:
                out.append(f"{r.bug_class}: {prev:.0%} -> {r.generalization:.0%} regressed")
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
                row.append(f"{v:.0%}" if v is not None else "-")
            rows.append(row)
        rows.append(["mean", *[f"{s.mean:.0%}" for s in self.snapshots]])
        return _md_table(headers, rows)

    def climb(self) -> str:
        if len(self.snapshots) < 2:
            return "insufficient history"
        first, last = self.snapshots[0], self.snapshots[-1]
        return f"mean generalization {first.mean:.0%} -> {last.mean:.0%} over {len(self.snapshots)} versions"
