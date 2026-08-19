from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from gatekeeper.core import metrics
from gatekeeper.core.finding import (
    Decision,
    Finding,
    GateResult,
    Reason,
    RunResult,
    Severity,
    Verdict,
)
from gatekeeper.core.store import Store


def make_run(run_id: str, verdict: Verdict, findings: list[Finding] | None = None) -> RunResult:
    findings = findings or []
    gate = GateResult(
        gate="G1.deps",
        status="fail" if findings else "pass",
        duration_s=1.5,
        findings=findings,
        facts={"deps.new_package_count": len(findings), "diff.effective_lines": 42},
    )
    return RunResult(
        run_id=run_id,
        repo="/repo",
        base_sha="a" * 40,
        head_sha="b" * 40,
        gate_results=[gate],
        decision=Decision(
            verdict=verdict,
            reasons=[Reason("blocking", "deps.unknown_package", "szczegół", "G1.deps")]
            if verdict is Verdict.BLOCK
            else [],
        ),
        duration_s=12.0,
    )


def finding(rule_id: str = "deps.unknown_package", title: str = "pakiet nie istnieje") -> Finding:
    return Finding(
        gate="G1.deps",
        rule_id=rule_id,
        severity=Severity.CRITICAL,
        title=title,
        failure_scenario="instalacja się wywali",
        file="pyproject.toml",
        evidence={"snippet": title},
    )


@pytest.fixture
def store(tmp_path) -> Store:
    return Store(tmp_path / "runs.db")


def test_zapis_i_odczyt_przebiegu(store):
    store.record(make_run("r1", Verdict.BLOCK, [finding()]))

    runs = store.runs_since(30)
    assert len(runs) == 1
    assert runs[0]["verdict"] == "BLOCK"
    assert runs[0]["diff_lines"] == 42
    assert len(store.query("SELECT * FROM findings")) == 1
    assert len(store.query("SELECT * FROM reasons")) == 1


def test_ponowny_zapis_tego_samego_przebiegu_nie_duplikuje(store):
    run = make_run("r1", Verdict.PASS)
    store.record(run)
    store.record(run)
    assert len(store.runs_since(30)) == 1


def test_werdykt_czlowieka_wymaga_znanego_znaleziska(store):
    with pytest.raises(KeyError):
        store.record_verdict("nieistniejacy", "false_positive")


def test_precyzja_liczy_sie_tylko_z_ocenionych_znalezisk(store):
    trafne, bledne = finding(title="trafne"), finding(title="bledne")
    store.record(make_run("r1", Verdict.BLOCK, [trafne]))
    store.record(make_run("r2", Verdict.BLOCK, [bledne]))
    store.record(make_run("r3", Verdict.BLOCK, [finding(title="nieocenione")]))

    store.record_verdict(trafne.fingerprint, "true_positive", author="ala")
    store.record_verdict(bledne.fingerprint, "false_positive", author="ala")

    stats = {r.rule_id: r for r in store.rule_precision()}["deps.unknown_package"]
    assert stats.findings == 3
    assert stats.judged == 2
    assert stats.precision == 0.5  # nieocenione znalezisko nie psuje ani nie poprawia wyniku


def test_oznaczenie_incydentu(store):
    store.record(make_run("r1", Verdict.PASS))
    store.mark_incident("r1", note="rollback po 20 minutach")
    assert store.runs_since(30)[0]["caused_incident"] == 1

    with pytest.raises(KeyError):
        store.mark_incident("nie-ma-takiego")


# ------------------------------------------------------------------ metryki


def test_metryki_bez_danych_nie_udaja_pomiaru(store):
    report = metrics.collect(store, days=30)
    assert report.runs == 0
    assert "brak danych" in report.render()


def test_metryki_licza_rozklad_werdyktow(store):
    store.record(make_run("r1", Verdict.PASS))
    store.record(make_run("r2", Verdict.PASS))
    store.record(make_run("r3", Verdict.BLOCK, [finding()]))
    store.record(make_run("r4", Verdict.PASS_WITH_REVIEW))

    rendered = metrics.collect(store, days=30).render()
    assert "4 przebiegów" in rendered
    assert "Zablokowane: 25%" in rendered
    assert "Bez ręcznego review: 50%" in rendered


def test_precyzja_bez_werdyktow_jest_jawnie_nieznana(store):
    """Zero ocenionych znalezisk i precyzja 0% to dwie różne rzeczy."""
    store.record(make_run("r1", Verdict.BLOCK, [finding()]))
    rendered = metrics.collect(store, days=30).render()
    assert "Precyzja bramki: brak danych" in rendered
    assert "gatekeeper verdict" in rendered


def test_escape_rate_bez_oznaczonych_incydentow_jest_nieznany(store):
    store.record(make_run("r1", Verdict.PASS))
    rendered = metrics.collect(store, days=30).render()
    assert "Escape rate: brak danych" in rendered


def test_escape_rate_po_oznaczeniu_incydentu(store):
    store.record(make_run("r1", Verdict.PASS))
    store.record(make_run("r2", Verdict.PASS))
    store.mark_incident("r1")
    rendered = metrics.collect(store, days=30).render()
    assert "Escape rate: 50%" in rendered


def test_stare_przebiegi_wypadaja_z_okna(store):
    store.record(make_run("r1", Verdict.PASS))
    old = (datetime.now(UTC) - timedelta(days=90)).isoformat()
    with store._connect() as conn:
        conn.execute("UPDATE runs SET started_at = ? WHERE run_id = 'r1'", (old,))
        conn.commit()
    assert store.runs_since(30) == []


def test_uzycie_markerow_charakteryzujacych_jest_raportowane(store):
    run = make_run("r1", Verdict.PASS)
    run.gate_results[0].facts["tests.characterization_used"] = 3
    store.record(run)
    assert "Testy zwolnione z cross-verify: 3" in metrics.collect(store, days=30).render()
