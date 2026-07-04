import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "harness"))

from roundrecord import Benchmark, HeldOutResult, Metrics, RoundRecord, Tokens


def test_metric_math():
    m = Metrics(tp=8, fp=2, fn=2)
    assert m.precision == 0.8
    assert m.recall == 0.8
    assert m.f1 == 0.8


def test_metric_empty_is_zero_not_crash():
    m = Metrics()
    assert m.precision == 0.0 and m.recall == 0.0 and m.f1 == 0.0


def test_generalization_rate():
    h = HeldOutResult(bug_class="prototype_pollution", detector="DT-PP-MERGE", rediscovered=3, missed=1)
    assert h.generalization == 0.75


def test_benchmark_summary_and_tables():
    b = Benchmark(
        rounds=[
            RoundRecord(
                cve="CVE-2025-64718",
                package="js-yaml",
                cwe="CWE-1321",
                bug_class="prototype_pollution",
                discovery="static_ast",
                tier="deterministic",
                language="js",
                wall_seconds=3600,
                tokens=Tokens(input=120000, output=40000),
                review_rounds=2,
                fixture=Metrics(tp=1, fp=0, fn=0),
                status="rediscovered",
            ),
            RoundRecord(
                cve="CVE-2025-67306",
                package="ffmpeg",
                cwe="CWE-122",
                bug_class="heap_overflow",
                discovery="coverage_fuzz",
                tier="sandbox",
                language="c",
                wall_seconds=7200,
                tokens=Tokens(input=200000, output=60000),
                review_rounds=4,
                fixture=Metrics(tp=1, fp=0, fn=0),
                status="verified",
            ),
        ],
        heldout=[
            HeldOutResult(
                bug_class="prototype_pollution",
                detector="DT-PP-MERGE",
                heldout_cves=["CVE-2025-57820", "CVE-2025-13465"],
                rediscovered=2,
                missed=0,
                metrics=Metrics(tp=2, fp=0, fn=0),
            )
        ],
    )
    assert b.total_wall_seconds() == 10800
    assert b.total_tokens() == 420000
    assert b.mean_generalization() == 1.0
    assert "prototype_pollution" in b.cost_table()
    assert "generalization" in b.generalization_table()
    assert "2 classes built" in b.summary_line()


def test_extra_fields_rejected():
    import pytest
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        Metrics(tp=1, bogus=2)


from roundrecord import ClassRate, GeneralizationLog, HeldOutResult, Snapshot


def _snap(label, pairs):
    return Snapshot(label=label, rates=[ClassRate(bug_class=c, rediscovered=r, total=t) for c, r, t in pairs])


def test_snapshot_mean_and_lookup():
    s = _snap("v1", [("pp", 8, 10), ("redos", 5, 5)])
    assert s.rate_for("pp") == 0.8
    assert s.mean == 0.9  # (0.8 + 1.0)/2


def test_snapshot_from_heldout():
    h = [HeldOutResult(bug_class="pp", detector="DT-PP", rediscovered=3, missed=1)]
    s = Snapshot.from_heldout("v1", h)
    assert s.rates[0].total == 4 and s.rate_for("pp") == 0.75


def test_regression_bar_clean_pass():
    log = GeneralizationLog()
    log.append(_snap("v1", [("pp", 8, 10), ("redos", 5, 5)]))
    candidate = _snap("v2", [("pp", 9, 10), ("redos", 5, 5)])  # pp improved, redos held
    assert log.regressions(candidate) == []
    assert log.accepts(candidate) is True


def test_regression_bar_blocks_a_drop():
    log = GeneralizationLog()
    log.append(_snap("v1", [("pp", 8, 10), ("redos", 5, 5)]))
    # fixing pp but regressing redos must be rejected
    candidate = _snap("v2", [("pp", 10, 10), ("redos", 4, 5)])
    violations = log.regressions(candidate)
    assert violations and "redos" in violations[0]
    assert log.accepts(candidate) is False


def test_first_snapshot_has_no_regressions():
    log = GeneralizationLog()
    assert log.regressions(_snap("v1", [("pp", 1, 10)])) == []


def test_curve_and_climb():
    log = GeneralizationLog()
    log.append(_snap("v1", [("pp", 8, 10), ("redos", 4, 5)]))
    log.append(_snap("v2", [("pp", 9, 10), ("redos", 5, 5)]))
    table = log.curve_table()
    assert "class" in table and "v1" in table and "v2" in table and "mean" in table
    assert "->" in log.climb()


# --- review fixes: metric precision, regression-bar integrity, validation ----


def test_f1_is_computed_from_raw_counts_not_rounded_inputs():
    # Deriving F1 from already-rounded precision/recall compounds rounding error.
    # tp=1,fp=0,fn=11: true F1 = 2/13 = 0.1538 -> 0.154, not 0.153.
    assert Metrics(tp=1, fp=0, fn=11).f1 == 0.154
    assert Metrics(tp=8, fp=2, fn=2).f1 == 0.8  # the existing exact case still holds


def test_regression_bar_blocks_a_dropped_class():
    # Omitting a previously tracked class from the candidate is the ultimate rate
    # drop; accepts() must NOT pass just because the class vanished.
    log = GeneralizationLog()
    log.append(_snap("v1", [("pp", 8, 10), ("redos", 5, 5)]))
    candidate = _snap("v2", [("pp", 9, 10)])  # redos dropped entirely
    violations = log.regressions(candidate)
    assert violations and "redos" in violations[0] and "dropped" in violations[0]
    assert log.accepts(candidate) is False


def test_snapshot_rejects_duplicate_bug_classes():
    import pytest
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        _snap("v1", [("pp", 8, 10), ("pp", 3, 10)])


def test_negative_counts_are_rejected():
    import pytest
    from pydantic import ValidationError

    for kwargs in ({"tp": -1}, {"fn": -3}):
        with pytest.raises(ValidationError):
            Metrics(**kwargs)
    with pytest.raises(ValidationError):
        Tokens(input=-1)


def test_md_table_escapes_pipes_and_newlines():
    # A stray pipe or newline in a cell must not corrupt the table into extra
    # columns/rows.
    b = Benchmark(
        rounds=[
            RoundRecord(
                cve="CVE-2025-0001",
                package="pkg",
                cwe="CWE-1",
                bug_class="proto\npollution",  # newline in a rendered cell
                discovery="static_ast",
                tier="deterministic",
                language="js",
                fixture=Metrics(tp=1),
                status="redisc|overed",        # pipe in a rendered cell
            )
        ]
    )
    table = b.cost_table()
    # header + separator + exactly ONE data row: a leaked newline would split the
    # row into two lines (4 total). Flattening keeps it at 3.
    assert len(table.splitlines()) == 3
    assert "proto pollution" in table  # the newline became a space, one row
    assert "\\|" in table              # the literal pipe was escaped, not structural
