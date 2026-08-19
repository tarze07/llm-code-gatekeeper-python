from __future__ import annotations

from datetime import date, timedelta

import pytest

from gatekeeper.core.finding import Finding, GateResult, Severity, Verdict
from gatekeeper.core.policy import Exemption, Expression, Policy, PolicyError

POLICY = {
    "version": 1,
    "blocking": ["secrets.found_in_diff", "deps.unknown_package", "sast.severity >= high"],
    "thresholds": {
        "diff.effective_lines": {"max": 400},
        "diff_coverage": {"min": 0.8, "on_violation": "warn"},
    },
    "human_review_required_when": ["deps.new_external_package"],
}


def policy(**overrides) -> Policy:
    data = {**POLICY, **overrides}
    return Policy.from_dict(data)


def decide(facts, gate_results=None):
    return policy().decide(facts, gate_results or [])


# ---------------------------------------------------------------- wyrażenia


@pytest.mark.parametrize(
    "expr,facts,expected",
    [
        ("secrets.found_in_diff", {"secrets.found_in_diff": True}, True),
        ("secrets.found_in_diff", {"secrets.found_in_diff": False}, False),
        ("secrets.found_in_diff", {}, False),  # brakujący fakt nigdy nie wyzwala reguły
        ("deps.new_packages", {"deps.new_packages": []}, False),
        ("deps.new_packages", {"deps.new_packages": ["foo"]}, True),
        ("sast.severity >= high", {"sast.severity": "critical"}, True),
        ("sast.severity >= high", {"sast.severity": "medium"}, False),
        ("sast.severity >= high", {"sast.severity": Severity.HIGH}, True),
        ("mutation.score < 0.6", {"mutation.score": 0.55}, True),
        ("mutation.score < 0.6", {"mutation.score": 0.6}, False),
        ("diff.files == 3", {"diff.files": 3}, True),
        ("model.name != codex", {"model.name": "claude"}, True),
    ],
)
def test_ewaluacja_wyrazen(expr, facts, expected):
    assert Expression.parse(expr).evaluate(facts) is expected


def test_wyrazenie_bez_prawej_strony_jest_bledem():
    with pytest.raises(PolicyError):
        Expression.parse("sast.severity >=")


# ----------------------------------------------------------------- decyzja


def test_blokujacy_fakt_daje_block():
    decision = decide({"secrets.found_in_diff": True})
    assert decision.verdict is Verdict.BLOCK
    assert decision.reasons[0].rule == "secrets.found_in_diff"


def test_prog_przekroczony_daje_block_z_czytelnym_powodem():
    decision = decide({"diff.effective_lines": 812})
    assert decision.verdict is Verdict.BLOCK
    assert "812" in decision.reasons[0].detail


def test_prog_z_on_violation_warn_nie_blokuje():
    decision = decide({"diff_coverage": 0.4})
    assert decision.verdict is Verdict.PASS
    assert decision.warnings and "diff_coverage" in decision.warnings[0].rule


def test_human_review_daje_pass_with_review():
    decision = decide({"deps.new_external_package": True})
    assert decision.verdict is Verdict.PASS_WITH_REVIEW


def test_block_wygrywa_z_review():
    decision = decide({"deps.new_external_package": True, "deps.unknown_package": True})
    assert decision.verdict is Verdict.BLOCK


def test_czysty_przebieg_daje_pass():
    assert decide({"diff.effective_lines": 12}).verdict is Verdict.PASS


def test_paths_match_kieruje_do_czlowieka(repo):
    from gatekeeper.core.change import ChangeContext

    repo.checkout("feature", create=True)
    repo.write("src/auth/login.py", "def login():\n    return True\n")
    repo.commit("feat: logowanie")
    change = ChangeContext.from_git(repo.path, "main", "HEAD")

    p = Policy.from_dict(
        {"version": 1, "human_review_required_when": [{"paths_match": ["**/auth/**"]}]}
    )
    decision = p.decide({}, [], change=change)
    assert decision.verdict is Verdict.PASS_WITH_REVIEW
    assert "src/auth/login.py" in decision.reasons[0].detail


def test_bledna_bramka_nie_przechodzi_cicho():
    results = [GateResult(gate="G3.secrets", status="error", message="brak gitleaksa")]
    decision = policy().decide({}, results)
    assert decision.verdict is Verdict.PASS_WITH_REVIEW

    strict = policy(on_gate_error="block").decide({}, results)
    assert strict.verdict is Verdict.BLOCK


def test_warn_only_degraduje_bramke_do_ostrzezenia():
    results = [GateResult(gate="G3.secrets", status="fail", facts={"secrets.found_in_diff": True})]
    p = policy(warn_only=["G3.secrets"])
    decision = p.decide({"secrets.found_in_diff": True}, results)
    assert decision.verdict is Verdict.PASS
    assert decision.warnings


# ---------------------------------------------------------------- wyjątki


def test_aktywny_wyjatek_wycisza_regule():
    p = policy()
    p.exemptions = [
        Exemption(
            rule="deps.unknown_package",
            owner="@zespol",
            reason="pakiet z prywatnego rejestru",
            expires=date.today() + timedelta(days=10),
        )
    ]
    decision = p.decide({"deps.unknown_package": True}, [])
    assert decision.verdict is Verdict.PASS
    assert decision.suppressed


def test_wygasly_wyjatek_nie_wycisza_i_jest_bledem_walidacji():
    p = policy()
    p.exemptions = [
        Exemption(
            rule="deps.unknown_package",
            owner="@zespol",
            reason="stary powód",
            expires=date.today() - timedelta(days=1),
        )
    ]
    assert p.decide({"deps.unknown_package": True}, []).verdict is Verdict.BLOCK
    assert any("wygasł" in e for e in p.lint())


# ------------------------------------------------------------------- lint


def test_lint_wykrywa_literowke_w_nazwie_faktu():
    p = Policy.from_dict({"version": 1, "blocking": ["secrets.found_in_dif"]})
    errors = p.lint(known_facts={"secrets.found_in_diff"})
    assert errors and "secrets.found_in_dif" in errors[0]


def test_lint_wykrywa_nieznana_bramke_w_warn_only():
    p = Policy.from_dict({"version": 1, "warn_only": ["G9.cos"]})
    assert p.lint(known_gates={"G0.scope"})


def test_prog_bez_min_i_max_jest_odrzucany():
    with pytest.raises(PolicyError):
        Policy.from_dict({"version": 1, "thresholds": {"x": {}}})


def test_powod_decyzji_wskazuje_znaleziska():
    finding = Finding(
        gate="G3.secrets",
        rule_id="secrets.found_in_diff",
        severity=Severity.CRITICAL,
        title="klucz AWS",
        failure_scenario="sekret trafia do historii gita",
        file="tests/fixtures/config.py",
    )
    results = [
        GateResult(
            gate="G3.secrets",
            status="fail",
            findings=[finding],
            facts={"secrets.found_in_diff": True},
        )
    ]
    decision = policy().decide({"secrets.found_in_diff": True}, results)
    assert decision.reasons[0].fingerprints == (finding.fingerprint,)
    assert decision.reasons[0].gate == "G3.secrets"
