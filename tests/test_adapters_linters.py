"""Testy adapterów ruff/mypy na zapisanych próbkach prawdziwego wyjścia.

Próbki w `tests/data/` pochodzą z realnych uruchomień (`ruff check
--output-format sarif`, `mypy --output=json`) na małych fixture'ach — nie
z pamięci. Ścieżka bezwzględna, jaką ruff wpisuje do `file://`, jest
zneutralizowana do `file:///repo/...`, żeby fixture nie zależał od katalogu,
w którym została nagrana; reszta struktury (poziomy, `ruleId`, `message`)
jest nietknięta.
"""

from __future__ import annotations

from pathlib import Path

from gatekeeper.adapters.linters import parse_mypy, parse_ruff, ruff_severity
from gatekeeper.core.finding import Severity

RUFF_GOLDEN = Path(__file__).parent / "data" / "ruff_sarif.json"
MYPY_GOLDEN = Path(__file__).parent / "data" / "mypy_output.jsonl"
REPO = Path("/repo")


def test_parsowanie_ruff_sarif_golden_file():
    findings = parse_ruff(RUFF_GOLDEN.read_text(encoding="utf-8"), REPO, "G1.static")

    assert len(findings) == 6
    rule_ids = {f.rule_id for f in findings}
    assert rule_ids == {
        "ruff.I001",
        "ruff.F401",
        "ruff.F841",
        "ruff.E722",
        "ruff.S110",
    }
    # Ścieżka `file:///tmp/.../bad.py` sprowadzona do relatywnej wobec repo.
    assert all(f.file == "bad.py" for f in findings)

    unused_import = next(f for f in findings if f.rule_id == "ruff.F401" and f.line == 1)
    assert unused_import.line == 1
    assert "os" in unused_import.title


def test_ruff_klasyfikuje_wage_po_prefiksie_reguly_nie_po_poziomie():
    """Ruff zwraca `level: error` dla WSZYSTKICH reguł w SARIF-ie — poziom
    nic nie mówi o wadze, trzeba patrzeć na prefiks reguły (F/B/S/... vs styl)."""
    findings = parse_ruff(RUFF_GOLDEN.read_text(encoding="utf-8"), REPO, "G1.static")
    by_rule = {f.rule_id: f for f in findings}

    assert by_rule["ruff.F401"].severity >= Severity.MEDIUM  # Pyflakes: realny defekt
    assert by_rule["ruff.S110"].severity >= Severity.MEDIUM  # bandit-style: bezpieczeństwo
    assert by_rule["ruff.I001"].severity == Severity.LOW  # import order: styl


def test_ruff_severity_bezposrednio():
    assert ruff_severity("F401", "error") == Severity.HIGH
    assert ruff_severity("F401", "warning") == Severity.MEDIUM
    assert ruff_severity("E501", "error") == Severity.LOW  # styl, nie ma w RUFF_HIGH_PREFIXES


def test_pusty_raport_ruff_nie_wywraca_adaptera():
    assert parse_ruff("", REPO, "G1.static") == []
    assert parse_ruff('{"runs": []}', REPO, "G1.static") == []


def test_parsowanie_mypy_golden_file():
    findings = parse_mypy(MYPY_GOLDEN.read_text(encoding="utf-8"), REPO, "G1.static")

    assert len(findings) == 3
    assert {f.rule_id for f in findings} == {"mypy.arg-type", "mypy.assignment"}
    assert all(f.file == "typed.py" for f in findings)
    assert all(f.severity == Severity.HIGH for f in findings)
    assert findings[0].line == 5


def test_mypy_pomija_notatki():
    payload = (
        '{"file": "x.py", "line": 1, "message": "coś", "code": "note", "severity": "note"}\n'
        '{"file": "x.py", "line": 2, "message": "błąd", "code": "arg-type", "severity": "error"}\n'
    )
    findings = parse_mypy(payload, REPO, "G1.static")
    assert len(findings) == 1
    assert findings[0].rule_id == "mypy.arg-type"


def test_mypy_ignoruje_smieci_przed_json_lines():
    """mypy potrafi wypisać ostrzeżenie na stdout przed właściwym JSON Lines."""
    payload = "Success: no issues found\n" + MYPY_GOLDEN.read_text(encoding="utf-8")
    findings = parse_mypy(payload, REPO, "G1.static")
    assert len(findings) == 3
