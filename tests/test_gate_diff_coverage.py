"""Testy integracyjne `G2.diff_coverage` — prawdziwe `coverage run` + `coverage xml`
+ `diff-cover` na fixture repo z `conftest.py` (jak `test_gate_crossverify.py` dla
pytesta samego w sobie). To jedyny sposób, żeby faktycznie sprawdzić, że
`--branch-coverage` łapie częściowo pokrytą gałąź, nie tylko wykonaną linię.
"""

from __future__ import annotations

from gatekeeper.core.change import ChangeContext
from gatekeeper.gates.g2_diff_coverage import DiffCoverage

APP_WITH_BRANCH = """
def add(a, b):
    return a + b


def classify(n):
    if n >= 0:
        return "non-negative"
    return "negative"
"""


def _change(repo, app_code: str, test_code: str) -> ChangeContext:
    repo.write("src/app.py", "def add(a, b):\n    return a + b\n")
    repo.commit("baza")
    repo.checkout("feature", create=True)
    repo.write("src/app.py", app_code)
    repo.write("tests/test_app.py", test_code)
    repo.commit("feat: nowa funkcja")
    return ChangeContext.from_git(repo.path, "main", "HEAD")


def test_czesciowe_pokrycie_galezi_daje_ratio_ponizej_jednosci(repo):
    """Test pokrywa tylko gałąź `if`, nigdy `return "negative"` — dokładnie
    przypadek z TOOLS.md §4.5: `--branch-coverage` ma to złapać."""
    change = _change(
        repo,
        APP_WITH_BRANCH,
        "from app import classify\n\n\ndef test_classify_non_negative():\n"
        '    assert classify(5) == "non-negative"\n',
    )
    result = DiffCoverage({}).run(change)

    assert result.status == "pass"
    assert result.facts["coverage.diff_ratio"] == 0.5
    assert result.facts["coverage.covered_lines"] == 2
    assert result.facts["coverage.total_lines"] == 4


def test_pelne_pokrycie_obu_galezi_daje_ratio_rowne_jeden(repo):
    change = _change(
        repo,
        APP_WITH_BRANCH,
        "from app import classify\n\n\n"
        "def test_classify_non_negative():\n"
        '    assert classify(5) == "non-negative"\n\n\n'
        "def test_classify_negative():\n"
        '    assert classify(-5) == "negative"\n',
    )
    result = DiffCoverage({}).run(change)

    assert result.status == "pass"
    assert result.facts["coverage.diff_ratio"] == 1.0


def test_brak_zmian_produkcyjnych_jest_pomijany(repo):
    repo.write("src/app.py", "def add(a, b):\n    return a + b\n")
    repo.commit("baza")
    repo.checkout("feature", create=True)
    repo.write(
        "tests/test_app.py", "from app import add\n\n\ndef test_add():\n    assert add(2, 3) == 5\n"
    )
    repo.commit("test: dopisz test do istniejącego kodu")
    change = ChangeContext.from_git(repo.path, "main", "HEAD")

    result = DiffCoverage({}).run(change)

    assert result.status == "skipped"
    assert result.facts["coverage.diff_ratio"] is None
