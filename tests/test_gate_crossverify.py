"""Testy weryfikacji krzyżowej — uruchamiają prawdziwego pytesta w worktree.

Celowo bez atrap: cała wartość tej bramki polega na tym, że *naprawdę* wykonuje
nowe testy przeciw staremu kodowi. Test z zamockowanym uruchomieniem
sprawdzałby wyłącznie własne wyobrażenie o tym, jak zachowuje się pytest.
"""

from __future__ import annotations

import pytest

from gatekeeper.core.change import ChangeContext
from gatekeeper.core.runner import network_isolation_available
from gatekeeper.gates.g2_crossverify import CrossVerify
from gatekeeper.testing.toolchain import PythonTestToolchain

BASE_CODE = """
def cena(x):
    return x * 1.23
"""

HEAD_CODE = """
def cena(x, rabat=0.0):
    return x * 1.23 * (1 - rabat)
"""


def prepare(repo, head_code: str, head_tests: str, base_tests: str = "") -> ChangeContext:
    repo.write("calc.py", BASE_CODE)
    if base_tests:
        repo.write("tests/test_calc.py", base_tests)
    repo.commit("baza")
    repo.checkout("feature", create=True)
    repo.write("calc.py", head_code)
    repo.write("tests/test_calc.py", head_tests)
    repo.commit("feat: rabaty")
    return ChangeContext.from_git(repo.path, "main", "HEAD")


def test_dobry_test_pada_na_starym_kodzie_i_bramka_przechodzi(repo):
    """Test nowej funkcjonalności *musi* polec na kodzie sprzed zmiany."""
    change = prepare(
        repo,
        HEAD_CODE,
        "from calc import cena\n\n\ndef test_rabat():\n    assert cena(100, rabat=0.5) == 61.5\n",
    )
    result = CrossVerify({}).run(change)

    assert result.status == "pass"
    assert result.facts["tests.pass_on_pre_change_code"] is False
    assert result.facts["tests.proved"] == 1
    assert result.findings == []


def test_bezwartosciowy_test_jest_wykrywany(repo):
    """Test asertujący zachowanie, które istniało wcześniej, niczego nie dowodzi."""
    change = prepare(
        repo,
        HEAD_CODE,
        "from calc import cena\n\n\ndef test_cena_bazowa():\n    assert cena(100) == 123.0\n",
    )
    result = CrossVerify({}).run(change)

    assert result.status == "fail"
    assert result.facts["tests.pass_on_pre_change_code"] is True
    assert result.facts["tests.passing_on_old_code"] == ["tests/test_calc.py::test_cena_bazowa"]

    finding = result.findings[0]
    assert finding.rule_id == "tests.pass_on_pre_change_code"
    assert finding.severity == "high"
    assert "characterization" in finding.failure_scenario


def test_marker_charakteryzujacy_zwalnia_z_dowodu(repo):
    """Trzy legalne przypadki (refaktor, backfill, regresja) deklaruje autor."""
    change = prepare(
        repo,
        HEAD_CODE,
        "import pytest\nfrom calc import cena\n\n\n"
        "@pytest.mark.characterization\n"
        "def test_cena_bazowa():\n    assert cena(100) == 123.0\n",
    )
    result = CrossVerify({}).run(change)

    assert result.status == "pass"
    assert result.facts["tests.characterization_used"] == 1
    assert result.facts["tests.checked"] == 0
    # deklaracja jest widoczna w raporcie — nadużywanie ma być policzalne
    assert result.findings[0].rule_id == "tests.characterization_declared"


def test_mieszanka_dobrego_i_zlego_testu(repo):
    change = prepare(
        repo,
        HEAD_CODE,
        "from calc import cena\n\n\n"
        "def test_rabat():\n    assert cena(100, rabat=0.5) == 61.5\n\n\n"
        "def test_cena_bazowa():\n    assert cena(100) == 123.0\n",
    )
    result = CrossVerify({}).run(change)

    assert result.status == "fail"
    assert result.facts["tests.proved"] == 1
    assert result.facts["tests.passing_on_old_code"] == ["tests/test_calc.py::test_cena_bazowa"]


def test_blad_importu_nowego_modulu_to_slaby_dowod(repo):
    """Nowy moduł nie istnieje w bazie — test się nie zaimportuje.

    To dowód, ale słaby: nie mówi nic o zachowaniu, tylko o tym, że plik
    jeszcze nie istniał. Liczony osobno, nie blokuje.
    """
    repo.write("calc.py", BASE_CODE)
    repo.commit("baza")
    repo.checkout("feature", create=True)
    repo.write("calc.py", HEAD_CODE)
    repo.write("rabaty.py", "def polityka():\n    return 0.1\n")
    repo.write(
        "tests/test_rabaty.py",
        "from rabaty import polityka\n\n\ndef test_polityka():\n    assert polityka() == 0.1\n",
    )
    repo.commit("feat: moduł rabatów")
    change = ChangeContext.from_git(repo.path, "main", "HEAD")

    result = CrossVerify({}).run(change)

    assert result.status == "pass"
    assert result.facts["tests.weak_evidence"] == 1
    assert result.facts["tests.proved"] == 0


def test_zmiana_bez_kodu_produkcyjnego_jest_pomijana(repo):
    """Sam dodany test nie ma czego dowodzić — stary kod jest identyczny.

    Bez tego wyjątku każdy PR dokładający testy byłby blokowany.
    """
    repo.write("calc.py", BASE_CODE)
    repo.commit("baza")
    repo.checkout("feature", create=True)
    repo.write(
        "tests/test_calc.py",
        "from calc import cena\n\n\ndef test_cena():\n    assert cena(100) == 123.0\n",
    )
    repo.commit("test: dopisz brakujące testy")
    change = ChangeContext.from_git(repo.path, "main", "HEAD")

    result = CrossVerify({}).run(change)

    assert result.status == "skipped"
    assert "nie dotyka kodu produkcyjnego" in result.message


def test_zmiana_kodu_bez_nowych_testow_jest_pomijana(repo):
    repo.write("calc.py", BASE_CODE)
    repo.commit("baza")
    repo.checkout("feature", create=True)
    repo.write("calc.py", HEAD_CODE)
    repo.commit("feat: bez testów")
    change = ChangeContext.from_git(repo.path, "main", "HEAD")

    result = CrossVerify({}).run(change)

    assert result.status == "skipped"
    assert result.facts["tests.new_count"] == 0
    # brak testów w ogóle to problem, ale nie tej bramki — to diff coverage (kamień 4)


def test_kod_produkcyjny_nie_jest_przenoszony_do_kopii_bazowej(repo):
    """Gdyby overlay skopiował kod produkcyjny, bramka mierzyłaby nowy kod nowym."""
    change = prepare(
        repo,
        HEAD_CODE,
        "from calc import cena\n\n\ndef test_rabat():\n    assert cena(100, rabat=0.5) == 61.5\n",
    )
    toolchain = PythonTestToolchain()

    with change.worktree_at(change.base_sha) as worktree:
        toolchain._overlay_tests(change, worktree)
        assert (worktree / "calc.py").read_text() == BASE_CODE  # kod bazowy nietknięty
        assert "rabat" in (worktree / "tests" / "test_calc.py").read_text()  # test z head


@pytest.mark.skipif(
    not network_isolation_available(), reason="brak przestrzeni nazw użytkownika"
)
def test_test_z_pr_nie_ma_dostepu_do_sieci(repo):
    """Uruchamiamy kod napisany przez agenta — nie ma powodu, żeby wychodził na zewnątrz."""
    change = prepare(
        repo,
        HEAD_CODE,
        "import socket\n\n\n"
        "def test_exfiltracja():\n"
        "    socket.create_connection(('1.1.1.1', 443), timeout=3)\n",
    )
    result = CrossVerify({}).run(change)

    # test padł na braku sieci, a nie na asercji — dla bramki to porażka na
    # starym kodzie, czyli „dowód"; dla nas dowód, że izolacja działa
    assert result.facts["tests.passing_on_old_code"] == []
    assert result.status == "pass"
