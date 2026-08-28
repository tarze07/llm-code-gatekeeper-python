"""Testy integracyjne `G2.test_sanity` — przez prawdziwe repo git (fixture `repo`
z `conftest.py`), tak jak `test_gate_crossverify.py`: bramka czyta pliki
przez `ChangeContext.file_at`, więc warto to ćwiczyć na realnym diffie,
nie na atrapie.
"""

from __future__ import annotations

from gatekeeper.core.change import ChangeContext
from gatekeeper.gates.g2_test_sanity import TestSanity

APP_CODE = "def dodaj(a, b):\n    return a + b\n"


def _change_with_test(repo, test_body: str) -> ChangeContext:
    repo.write("src/calc.py", APP_CODE)
    repo.commit("baza")
    repo.checkout("feature", create=True)
    repo.write("tests/test_calc.py", test_body)
    repo.commit("feat: nowy test")
    return ChangeContext.from_git(repo.path, "main", "HEAD")


def test_brak_asercji_blokuje(repo):
    change = _change_with_test(
        repo, "from src.calc import dodaj\n\n\ndef test_dodaj():\n    dodaj(2, 3)\n"
    )
    result = TestSanity({}).run(change)

    assert result.status == "fail"
    assert result.facts["sanity.blocking_count"] == 1
    assert {f.rule_id for f in result.findings} == {"test.no_assertion"}


def test_stala_asercja_blokuje(repo):
    change = _change_with_test(repo, "def test_cos():\n    assert True\n")
    result = TestSanity({}).run(change)

    assert result.status == "fail"
    assert "test.constant_assertion" in result.facts["sanity.rule_ids"]


def test_echo_mocka_flaguje_ale_nie_blokuje(repo):
    change = _change_with_test(
        repo,
        "from unittest.mock import Mock\n\n\n"
        "def test_cos():\n"
        "    klient = Mock(return_value=42)\n"
        "    assert klient() == 42\n",
    )
    result = TestSanity({}).run(change)

    assert result.status == "pass"
    assert result.facts["sanity.blocking_count"] == 0
    assert {f.rule_id for f in result.findings} == {"test.mock_echo"}


def test_dobry_test_przechodzi_bez_znalezisk(repo):
    change = _change_with_test(
        repo, "from src.calc import dodaj\n\n\ndef test_dodaj():\n    assert dodaj(2, 3) == 5\n"
    )
    result = TestSanity({}).run(change)

    assert result.status == "pass"
    assert result.findings == []
    assert result.facts["sanity.checked_count"] == 1


def test_asercja_w_helperze_jeden_poziom_ratuje_test(repo):
    change = _change_with_test(
        repo,
        "def _assert_dodaje(a, b, oczekiwane):\n"
        "    assert a + b == oczekiwane\n\n\n"
        "def test_dodaj():\n"
        "    _assert_dodaje(2, 3, 5)\n",
    )
    result = TestSanity({}).run(change)

    assert result.status == "pass"
    assert result.findings == []


def test_brak_nowych_testow_jest_pomijany(repo):
    repo.write("src/calc.py", APP_CODE)
    repo.commit("baza")
    repo.checkout("feature", create=True)
    repo.write("src/calc.py", APP_CODE + "\n\ndef odejmij(a, b):\n    return a - b\n")
    repo.commit("feat: bez testów")
    change = ChangeContext.from_git(repo.path, "main", "HEAD")

    result = TestSanity({}).run(change)

    assert result.status == "skipped"
    assert result.facts["sanity.checked_count"] == 0
