from __future__ import annotations

import json
from pathlib import Path

import pytest

from gatekeeper.adapters import gitleaks
from gatekeeper.core.change import ChangeContext
from gatekeeper.core.finding import Decision, RunResult, Verdict
from gatekeeper.core.report import render_markdown
from gatekeeper.gates.g3_secrets import SecretsGate

GOLDEN = Path(__file__).parent / "data" / "gitleaks_report.json"
SECRET = "AKIAIOSFODNN7EXAMPLE"


def test_parsowanie_raportu_gitleaksa_golden_file():
    leaks = gitleaks.parse_report(GOLDEN.read_text(encoding="utf-8"))
    assert [leak.rule_id for leak in leaks] == ["aws-access-token", "generic-api-key"]
    assert leaks[0].file == "tests/fixtures/aws_config.py"
    assert leaks[0].line == 12
    assert leaks[0].entropy == pytest.approx(3.5849625)


def test_pusty_raport_nie_wywraca_adaptera():
    assert gitleaks.parse_report("") == []
    assert gitleaks.parse_report("[]") == []


def test_sekret_nigdy_nie_trafia_do_raportu_w_jawnej_postaci():
    """Komentarz w PR widzi więcej osób niż plik, z którego sekret pochodzi."""
    leaks = gitleaks.parse_report(GOLDEN.read_text(encoding="utf-8"))
    finding = gitleaks.to_finding(leaks[0], "G3.secrets", in_diff=True)

    assert SECRET not in str(finding.to_dict())
    assert finding.evidence["redacted"] == "AKIA…(20 znaków)"

    run = RunResult(
        run_id="x",
        repo=".",
        base_sha="a" * 40,
        head_sha="b" * 40,
        gate_results=[],
        decision=Decision(verdict=Verdict.BLOCK),
    )
    run.gate_results.append(_result_with(finding))
    assert SECRET not in render_markdown(run)


def _result_with(finding):
    from gatekeeper.core.finding import GateResult

    return GateResult(gate="G3.secrets", status="fail", findings=[finding])


def test_sekret_w_zmienionym_pliku_blokuje_zastany_nie(repo, monkeypatch):
    repo.checkout("feature", create=True)
    repo.write("tests/fixtures/aws_config.py", "KEY = 'x'\n")
    repo.commit("test: fixture")
    change = ChangeContext.from_git(repo.path, "main", "HEAD")

    leaks = gitleaks.parse_report(GOLDEN.read_text(encoding="utf-8"))
    monkeypatch.setattr(gitleaks, "is_available", lambda: True)
    monkeypatch.setattr(gitleaks, "version", lambda: "8.18.0")
    monkeypatch.setattr(gitleaks, "scan", lambda **kwargs: leaks)

    result = SecretsGate({}).run(change)

    assert result.facts["secrets.found_in_diff"] is True
    assert result.facts["secrets.count"] == 2
    assert result.facts["secrets.count_in_diff"] == 1
    assert result.status == "fail"

    rules = {f.rule_id for f in result.findings}
    assert rules == {"secrets.found_in_diff", "secrets.preexisting"}
    preexisting = next(f for f in result.findings if f.rule_id == "secrets.preexisting")
    assert preexisting.severity == "medium"  # dług, nie blokada tego PR-a


def test_sciezki_bezwzgledne_sa_sprowadzane_do_sciezek_repozytorium(tmp_path):
    """Regresja: gitleaks zwraca ścieżki w postaci, w jakiej dostał `--source`.

    Przy skanie po ścieżce bezwzględnej porównanie z listą zmienionych plików
    nie trafiało, więc sekret wprowadzony w danym PR wyglądał na zastany
    i nie blokował niczego. Wykryte dopiero na żywym uruchomieniu — golden file
    z relatywnymi ścieżkami tego nie łapał.
    """
    root = tmp_path / "repo"
    (root / "src").mkdir(parents=True)
    payload = json.dumps(
        [
            {
                "RuleID": "github-pat",
                "Description": "GitHub PAT",
                "File": str(root / "src" / "app.py"),
                "StartLine": 2,
                "Secret": "ghp_" + "x" * 36,
            }
        ]
    )
    leaks = gitleaks.parse_report(payload, root=root)
    assert leaks[0].file == "src/app.py"

    # bez podanego korzenia ścieżka zostaje bezwzględna — i tak ma być,
    # zgadywanie prefiksu byłoby gorsze niż jawny brak dopasowania
    assert gitleaks.parse_report(payload)[0].file.startswith("/")


def test_sekret_z_tego_pr_blokuje_przy_prawdziwym_gitleaksie(repo):
    """Test integracyjny na żywym binarium — pomijany, gdy go nie ma."""
    if not gitleaks.is_available():
        pytest.skip("gitleaks niedostępny")

    repo.checkout("feature", create=True)
    repo.write("src/ci.py", 'GITHUB_TOKEN = "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"\n')
    repo.commit("feat: token")
    change = ChangeContext.from_git(repo.path, "main", "HEAD")

    result = SecretsGate({}).run(change)

    assert result.status == "fail"
    assert result.facts["secrets.found_in_diff"] is True
    assert result.facts["secrets.unresolved_paths"] == 0
    assert result.findings[0].file == "src/ci.py"


def test_brak_narzedzia_to_blad_a_nie_zielona_bramka(repo, monkeypatch):
    change = ChangeContext.from_git(repo.path, "HEAD", "HEAD")
    monkeypatch.setattr(gitleaks, "is_available", lambda: False)
    monkeypatch.setattr(gitleaks, "version", lambda: None)

    assert SecretsGate({}).run(change).status == "error"
    assert SecretsGate({"require_tool": False}).run(change).status == "skipped"
