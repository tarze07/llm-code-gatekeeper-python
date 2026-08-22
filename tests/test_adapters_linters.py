"""Testy adapterów ruff/mypy/tsc/eslint na zapisanych próbkach prawdziwego wyjścia.

Próbki w `tests/data/` pochodzą z realnych uruchomień (`ruff check
--output-format sarif`, `mypy --output=json`, `tsc --noEmit --pretty false`,
`eslint --format json`) na małych fixture'ach — nie z pamięci. Ścieżki
bezwzględne są zneutralizowane do `/repo/...`, żeby fixture nie zależał od
katalogu, w którym została nagrana; reszta struktury (poziomy, kody błędów,
`message`) jest nietknięta.
"""

from __future__ import annotations

from pathlib import Path

from gatekeeper.adapters.linters import (
    ESLINT_HIGH_RULES,
    eslint_severity,
    parse_eslint,
    parse_mypy,
    parse_ruff,
    parse_tsc,
    resolve_bin,
    ruff_severity,
)
from gatekeeper.core.finding import Severity

RUFF_GOLDEN = Path(__file__).parent / "data" / "ruff_sarif.json"
MYPY_GOLDEN = Path(__file__).parent / "data" / "mypy_output.jsonl"
TSC_GOLDEN = Path(__file__).parent / "data" / "tsc_output.txt"
ESLINT_GOLDEN = Path(__file__).parent / "data" / "eslint_output.json"
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


# --------------------------------------------------------------------- tsc


def test_parsowanie_tsc_golden_file():
    findings = parse_tsc(TSC_GOLDEN.read_text(encoding="utf-8"), REPO, "G1.static")

    assert len(findings) == 2
    assert {f.rule_id for f in findings} == {"tsc.TS2345", "tsc.TS2551"}
    assert all(f.severity == Severity.HIGH for f in findings)
    by_rule = {f.rule_id: f for f in findings}
    assert by_rule["tsc.TS2345"].file == "math.ts"
    assert by_rule["tsc.TS2345"].line == 5
    assert "not assignable" in by_rule["tsc.TS2345"].title
    assert by_rule["tsc.TS2551"].file == "user.ts"


def test_pusty_raport_tsc_nie_wywraca_adaptera():
    assert parse_tsc("", REPO, "G1.static") == []
    assert parse_tsc("Found 0 errors.\n", REPO, "G1.static") == []


def test_resolve_bin_preferuje_lokalna_binarke(tmp_path):
    local = tmp_path / "node_modules" / ".bin" / "tsc"
    local.parent.mkdir(parents=True)
    local.write_text("#!/bin/sh\n")

    assert resolve_bin(tmp_path, "tsc") == str(local)
    assert resolve_bin(tmp_path, "eslint") == "eslint"  # brak lokalnej -> globalna nazwa


# ------------------------------------------------------------------ eslint


def test_parsowanie_eslint_golden_file():
    findings = parse_eslint(ESLINT_GOLDEN.read_text(encoding="utf-8"), REPO, "G1.static")

    assert len(findings) == 5
    rule_ids = {f.rule_id for f in findings}
    assert rule_ids == {"eslint.no-undef", "eslint.no-unused-vars", "eslint.no-eval"}
    assert all(f.file in ("other.js", "risky.js") for f in findings)


def test_eslint_klasyfikuje_wage_po_regule_nie_tylko_po_poziomie():
    """eslint zwraca `severity: 2` dla WSZYSTKICH reguł skonfigurowanych jako
    `error` — wiele configów ma wśród nich czysto stylistyczne reguły, więc
    trzeba patrzeć na `ruleId`, tak samo jak ruff patrzy na prefiks."""
    findings = parse_eslint(ESLINT_GOLDEN.read_text(encoding="utf-8"), REPO, "G1.static")
    by_rule = {f.rule_id: f for f in findings}

    assert by_rule["eslint.no-eval"].severity == Severity.HIGH  # w ESLINT_HIGH_RULES
    assert by_rule["eslint.no-undef"].severity == Severity.HIGH  # w ESLINT_HIGH_RULES
    assert by_rule["eslint.no-unused-vars"].severity == Severity.LOW  # `warn`, nie `error`


def test_eslint_severity_bezposrednio():
    assert "no-eval" in ESLINT_HIGH_RULES
    assert eslint_severity("no-eval", 2) == Severity.HIGH
    assert eslint_severity("semi", 2) == Severity.MEDIUM  # `error`, ale nie reguła „problem”
    assert eslint_severity("no-unused-vars", 1) == Severity.LOW


def test_eslint_blad_parsera_ma_rule_id_none():
    """eslint zgłasza błąd parsowania pliku z `ruleId: null` — adapter nie ma
    prawa się na tym wywrócić."""
    payload = (
        '[{"filePath": "/repo/broken.js", "messages": '
        '[{"ruleId": null, "severity": 2, "message": "Parsing error: ...", "line": 1}]}]'
    )
    findings = parse_eslint(payload, REPO, "G1.static")
    assert len(findings) == 1
    assert findings[0].rule_id == "eslint.parse-error"


def test_pusty_raport_eslint_nie_wywraca_adaptera():
    assert parse_eslint("", REPO, "G1.static") == []
    assert parse_eslint("[]", REPO, "G1.static") == []
