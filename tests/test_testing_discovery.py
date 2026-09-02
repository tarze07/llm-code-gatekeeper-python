from __future__ import annotations

from gatekeeper_python.testing import discovery
from gatekeeper_python.testing.pytest_runner import build_env, parse_junit, scrub_environment

BASE = '''
def test_stary():
    assert cena(10) == 12.3
'''

HEAD = '''
import pytest


def test_stary():
    assert cena(10) == 12.3


def test_nowy_rabat():
    assert cena(10, rabat=0.5) == 6.15


@pytest.mark.characterization
def test_charakteryzujacy():
    assert cena(10) == 12.3


class TestKoszyk:
    def test_suma(self):
        assert suma([1, 2]) == 3
'''


def test_znajduje_testy_modulowe_i_w_klasach():
    items = discovery.collect_tests(HEAD, "tests/test_cena.py")
    assert set(items) == {
        "tests/test_cena.py::test_stary",
        "tests/test_cena.py::test_nowy_rabat",
        "tests/test_cena.py::test_charakteryzujacy",
        "tests/test_cena.py::TestKoszyk::test_suma",
    }


def test_wykrywa_tylko_nowe_i_zmienione():
    changed = discovery.changed_tests(BASE, HEAD, "tests/test_cena.py")
    names = {i.name for i in changed}
    assert names == {"test_nowy_rabat", "test_charakteryzujacy", "test_suma"}
    assert "test_stary" not in names  # niezmieniony test nie jest dowodem niczego


def test_przeformatowanie_nie_czyni_z_testu_nowego():
    a = "def test_x():\n    assert  1 ==  1\n"
    b = "def test_x():\n    # komentarz\n    assert 1 == 1\n"
    assert discovery.changed_tests(a, b, "t.py") == []


def test_zmiana_asercji_jest_zmiana_testu():
    a = "def test_x():\n    assert cena(1) == 1\n"
    b = "def test_x():\n    assert cena(1) == 2\n"
    assert [i.name for i in discovery.changed_tests(a, b, "t.py")] == ["test_x"]


def test_markery_zwalniajace_sa_rozpoznawane():
    items = discovery.collect_tests(HEAD, "t.py")
    assert items["t.py::test_charakteryzujacy"].declared_escape == "characterization"
    assert items["t.py::test_nowy_rabat"].declared_escape is None


def test_marker_na_klasie_dziedziczy_sie_na_metody():
    source = (
        "import pytest\n\n"
        "@pytest.mark.test_backfill\n"
        "class TestStare:\n"
        "    def test_a(self):\n"
        "        assert True\n"
    )
    items = discovery.collect_tests(source, "t.py")
    assert items["t.py::TestStare::test_a"].declared_escape == "test_backfill"


def test_niepoprawna_skladnia_nie_wywraca_zbierania():
    assert discovery.collect_tests("def test_(:\n", "t.py") == {}


# ------------------------------------------------------------------ JUnit

JUNIT = """<?xml version="1.0" encoding="utf-8"?>
<testsuites><testsuite name="pytest" errors="1" failures="1" skipped="1" tests="4">
  <testcase classname="tests.test_a" name="test_pada" file="tests/test_a.py" line="3">
    <failure message="assert 1 == 2">E assert 1 == 2</failure>
  </testcase>
  <testcase classname="tests.test_a" name="test_przechodzi" file="tests/test_a.py" line="9"/>
  <testcase classname="tests.test_a" name="test_blad_importu" file="tests/test_a.py" line="15">
    <error message="ModuleNotFoundError">brak modułu</error>
  </testcase>
  <testcase classname="tests.test_a.TestKlasa" name="test_metoda" file="tests/test_a.py" line="20">
    <skipped message="pominięty"/>
  </testcase>
</testsuite></testsuites>
"""


def test_parsowanie_junit_rozroznia_porazke_od_bledu():
    outcomes = parse_junit(JUNIT)
    assert outcomes["tests/test_a.py::test_pada"].outcome == "failed"
    assert outcomes["tests/test_a.py::test_przechodzi"].outcome == "passed"
    assert outcomes["tests/test_a.py::test_blad_importu"].outcome == "error"
    assert outcomes["tests/test_a.py::TestKlasa::test_metoda"].outcome == "skipped"


def test_tylko_porazka_asercji_dowodzi_roznicy():
    outcomes = parse_junit(JUNIT)
    assert outcomes["tests/test_a.py::test_pada"].proves_difference
    assert not outcomes["tests/test_a.py::test_blad_importu"].proves_difference
    assert not outcomes["tests/test_a.py::test_przechodzi"].proves_difference


#: Prawdziwe wyjście pytesta 8 (`junit_family=xunit2`, domyślny). Zwróć uwagę:
#: **brak atrybutu `file`** — jest tylko kropkowany `classname`. Parser oparty
#: wyłącznie na `file` po cichu nie znajdował żadnego wyniku, przez co każdy
#: test wyglądał na „bez rozstrzygnięcia" i bramka nigdy nic nie blokowała.
JUNIT_XUNIT2 = """<?xml version="1.0" encoding="utf-8"?><testsuites name="pytest tests">
<testsuite name="pytest" errors="0" failures="1" skipped="0" tests="1" time="0.014">
<testcase classname="tests.test_calc" name="test_rabat" time="0.000">
<failure message="TypeError: unexpected keyword argument">E TypeError</failure>
</testcase></testsuite></testsuites>"""


def test_parsowanie_wspolczesnego_formatu_bez_atrybutu_file():
    outcomes = parse_junit(JUNIT_XUNIT2, expected=["tests/test_calc.py::test_rabat"])
    assert outcomes["tests/test_calc.py::test_rabat"].outcome == "failed"


def test_bez_listy_oczekiwanych_format_xunit2_nie_da_sie_zmapowac():
    # świadome ograniczenie: kropkowana nazwa modułu jest wieloznaczna
    assert parse_junit(JUNIT_XUNIT2) == {}


def test_parametryzacja_sprowadza_sie_do_jednego_testu():
    payload = """<testsuites><testsuite name="pytest">
      <testcase classname="tests.test_b" name="test_p[1]" file="tests/test_b.py"/>
      <testcase classname="tests.test_b" name="test_p[2]" file="tests/test_b.py">
        <failure message="boom">boom</failure>
      </testcase>
    </testsuite></testsuites>"""
    outcomes = parse_junit(payload)
    # jeden przypadek parametru, który poległ, wystarczy za dowód
    assert outcomes["tests/test_b.py::test_p"].outcome == "failed"


# ------------------------------------------------- środowisko uruchomienia


def test_sekrety_nie_trafiaja_do_procesu_uruchamiajacego_testy_z_pr():
    """Uruchomienie testów z PR-a to wykonanie kodu napisanego przez agenta.

    W CI obok stoi token z prawem zapisu do repozytorium — nie ma powodu,
    żeby ten proces go widział.
    """
    env = {
        "PATH": "/usr/bin",
        "GITHUB_TOKEN": "ghp_tajne",
        "AWS_SECRET_ACCESS_KEY": "tajne",
        "AWS_ACCESS_KEY_ID": "AKIA...",
        "NPM_TOKEN": "npm_tajne",
        "DB_PASSWORD": "tajne",
        "HOME": "/home/ja",
    }
    scrubbed = scrub_environment(env)

    assert set(scrubbed) == {"PATH", "HOME"}


def test_keep_env_przywraca_wskazana_zmienna():
    env = {"PATH": "/usr/bin", "TEST_API_TOKEN": "potrzebny", "GITHUB_TOKEN": "nie"}
    scrubbed = scrub_environment(env, keep=("TEST_API_TOKEN",))

    assert scrubbed["TEST_API_TOKEN"] == "potrzebny"
    assert "GITHUB_TOKEN" not in scrubbed


def test_build_env_wskazuje_na_kopie_kodu_bazowego(tmp_path, monkeypatch):
    worktree = tmp_path / "wt"
    (worktree / "src").mkdir(parents=True)
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_tajne")

    env = build_env(worktree, ["src"])

    assert env["PYTHONPATH"].split(":")[:2] == [str(worktree), str(worktree / "src")]
    assert "GITHUB_TOKEN" not in env
