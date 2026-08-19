"""Testy adaptera semgrepa na zapisanej próbce prawdziwego wyjścia.

Próbka pochodzi z realnego `semgrep --config rules/semgrep --json` na
`rules/semgrep/tests/never.py` — tym samym pliku, który `semgrep --test`
używa do walidacji reguł. Ścieżki są już relatywne wobec repo (semgrep
dostał cel relatywny), więc fixture nie wymaga neutralizacji.
"""

from __future__ import annotations

from pathlib import Path

from gatekeeper.adapters.semgrep import parse_semgrep
from gatekeeper.core.finding import Severity

GOLDEN = Path(__file__).parent / "data" / "semgrep_never_output.json"
REPO = Path(__file__).parent.parent


def test_parsowanie_semgrep_golden_file():
    findings = parse_semgrep(GOLDEN.read_text(encoding="utf-8"), REPO, "G3.sast")

    assert len(findings) == 10
    rule_ids = {f.rule_id for f in findings}
    assert rule_ids == {
        "sast.no-tls-verify-disabled",
        "sast.no-eval-on-input",
        "sast.no-sql-string-concat",
        "sast.no-shell-true",
        "sast.no-unsafe-deserialization",
        "sast.no-hardcoded-bind-all-interfaces",
    }
    assert all(f.file == "rules/semgrep/tests/never.py" for f in findings)


def test_semgrep_niesie_cwe_i_failure_scenario_z_metadanych_reguly():
    findings = parse_semgrep(GOLDEN.read_text(encoding="utf-8"), REPO, "G3.sast")
    tls = next(f for f in findings if f.rule_id == "sast.no-tls-verify-disabled")

    assert tls.severity == Severity.CRITICAL  # semgrep ERROR → CRITICAL
    assert tls.evidence["cwe"].startswith("CWE-295")
    # `failure_scenario` bramki wymaga treści (Finding.__post_init__) — musi
    # przyjść z `metadata.failure_scenario`, nie z samego `message`.
    assert "certyfikat" in tls.failure_scenario


def test_semgrep_error_zamiast_warning_jest_krytyczny():
    findings = parse_semgrep(GOLDEN.read_text(encoding="utf-8"), REPO, "G3.sast")
    bind_all = next(f for f in findings if f.rule_id == "sast.no-hardcoded-bind-all-interfaces")
    assert bind_all.severity == Severity.HIGH  # WARNING w never.yaml


def test_pusty_raport_semgrep_nie_wywraca_adaptera():
    assert parse_semgrep("", REPO, "G3.sast") == []
    assert parse_semgrep('{"results": []}', REPO, "G3.sast") == []
