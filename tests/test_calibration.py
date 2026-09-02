"""Testy harnessu kalibracyjnego — logika, nie pełny przebieg bramek.

Pełny `gatekeeper calibrate` woła prawdziwe rejestry pakietów i narzędzia
zewnętrzne (patrz `calibration/cases.yaml`), więc tu sprawdzamy parsowanie
przypadków, budowę repo z `base/`/`head/` i porównanie wyniku z oczekiwaniem
— bez zależności od sieci czy zainstalowanych binariów.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from gatekeeper_core.calibration import (
    Case,
    Expectation,
    _build_case_repo,
    _check,
    load_cases,
)
from gatekeeper_core.core.finding import Decision, GateResult, Reason, RunResult, Verdict


def _run(verdict: Verdict, reasons=(), warnings=()) -> RunResult:
    return RunResult(
        run_id="x",
        repo=".",
        base_sha="a" * 40,
        head_sha="b" * 40,
        gate_results=[GateResult(gate="G0.scope", status="pass")],
        decision=Decision(verdict=verdict, reasons=list(reasons), warnings=list(warnings)),
    )


def _case(**expect_kwargs) -> Case:
    return Case(name="t", description="", fixture="t", expect=Expectation(**expect_kwargs))


def test_wczytywanie_prawdziwego_pliku_cases_yaml():
    """Python-pack dziedziczy tylko przypadki wymagające tego pack'a
    zainstalowanego (PythonRulePack, PythonTestToolchain,
    PythonComplexityAnalyzer) — gate'y w pełni core-owe i G1.deps/G3.sca
    (PyPI/npm/NuGet) mają własny zestaw w `llm-code-gatekeeper-core`, patrz
    komentarz na górze pliku."""
    cases = load_cases(Path("calibration/cases.yaml"))
    assert {c.name for c in cases} == {
        "eval-na-wejsciu",
        "test-bez-dowodu",
        "test-bez-asercji",
        "zlozonosc-powyzej-progu",
        "zlozonosc-straznik",
        "zlozonosc-poza-diffem",
        "rozgalezienie-bez-testu",
    }
    eval_case = next(c for c in cases if c.name == "eval-na-wejsciu")
    assert eval_case.requires_tools == ("semgrep", "gitleaks")
    assert eval_case.expect.warning_rules == ("sast.critical_count",)


def test_check_zgodny_werdykt_i_reguly_przechodzi():
    case = _case(verdict=Verdict.BLOCK, blocking_rules=("deps.unknown_package",))
    reason = Reason(source="blocking", rule="deps.unknown_package", detail="x")
    run = _run(Verdict.BLOCK, reasons=[reason])

    result = _check(case, run)

    assert result.passed
    assert result.reason == ""


def test_check_zly_werdykt_daje_czytelny_powod():
    case = _case(verdict=Verdict.PASS)
    run = _run(Verdict.BLOCK)

    result = _check(case, run)

    assert not result.passed
    assert "PASS" in result.reason
    assert "BLOCK" in result.reason


def test_check_brakujaca_regula_blokujaca_failuje():
    case = _case(verdict=Verdict.BLOCK, blocking_rules=("deps.unknown_package",))
    run = _run(Verdict.BLOCK, reasons=[Reason(source="blocking", rule="inna.regula", detail="x")])

    result = _check(case, run)

    assert not result.passed
    assert "deps.unknown_package" in result.reason


def test_check_brakujace_ostrzezenie_failuje():
    case = _case(verdict=Verdict.PASS, warning_rules=("sast.critical_count",))
    run = _run(Verdict.PASS)  # brak ostrzeżeń w ogóle

    result = _check(case, run)

    assert not result.passed
    assert "sast.critical_count" in result.reason


def test_budowa_repo_z_base_head_odzwierciedla_usuniecie_pliku(tmp_path):
    fixture = tmp_path / "fixture"
    (fixture / "base").mkdir(parents=True)
    (fixture / "head").mkdir(parents=True)
    (fixture / "base" / "old.py").write_text("x = 1\n")
    (fixture / "head" / "new.py").write_text("y = 2\n")

    with _build_case_repo(fixture) as (repo_path, base_sha, head_sha):
        assert (repo_path / "new.py").exists()
        assert not (repo_path / "old.py").exists()  # head nie ma już old.py
        assert base_sha != head_sha


def test_brak_fixture_daje_czytelny_blad(tmp_path):
    with pytest.raises(FileNotFoundError), _build_case_repo(tmp_path / "nie-ma-takiego"):
        pass
