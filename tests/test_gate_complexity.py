"""Testy G1.complexity (dispatcher core-owy, `gatekeeper_core.gates.g1_complexity`)
z `PythonComplexityAnalyzer` dogfoodowanym przez entry points
`gatekeeper.complexity_analyzers` — ten sam wzorzec co `test_gate_static.py`.
"""

from __future__ import annotations

from gatekeeper_core.core.change import ChangeContext
from gatekeeper_core.gates.g1_complexity import ComplexityGuard


def test_funkcja_powyzej_progu_blokuje(repo):
    repo.checkout("feature", create=True)
    repo.write(
        "src/skomplikowana.py",
        "def f(a, b, c, d):\n"
        "    if a:\n"
        "        if b:\n"
        "            if c:\n"
        "                if d:\n"
        "                    if a and b:\n"
        "                        if c and d:\n"
        "                            if a or b or c or d:\n"
        "                                return 1\n"
        "    return 0\n",
    )
    repo.commit("feat: zbyt zlozona funkcja")
    change = ChangeContext.from_git(repo.path, "main", "HEAD")

    result = ComplexityGuard({}).run(change)

    assert result.status == "fail"
    assert result.facts["complexity.over_threshold_count"] == 1
    assert result.facts["complexity.max"] > 10
    finding = result.findings[0]
    assert finding.rule_id == "complexity.too_high"
    assert finding.file == "src/skomplikowana.py"


def test_prosta_funkcja_przechodzi(repo):
    repo.checkout("feature", create=True)
    repo.write("src/prosta.py", "def f(x):\n    return x + 1\n")
    repo.commit("feat: prosta funkcja")
    change = ChangeContext.from_git(repo.path, "main", "HEAD")

    result = ComplexityGuard({}).run(change)

    assert result.status == "pass"
    assert result.facts["complexity.over_threshold_count"] == 0
    assert result.findings == []


def test_nietknieta_funkcja_w_tym_samym_pliku_nie_jest_liczona(repo):
    """Stara, złożona funkcja w pliku, który diff dotyka gdzie indziej, nie
    ma prawa trafić do raportu — inaczej pierwszy przebieg na starym repo
    umiera (PLAN-G1-complexity.md §4, test kalibracyjny `zlozonosc-poza-diffem`)."""
    zlozona = (
        "def stara(a, b, c, d):\n"
        "    if a:\n"
        "        if b:\n"
        "            if c:\n"
        "                if d:\n"
        "                    if a and b:\n"
        "                        if c and d:\n"
        "                            if a or b or c or d:\n"
        "                                return 1\n"
        "    return 0\n"
    )
    repo.write("src/mieszany.py", zlozona)
    repo.commit("baza ze stara, zlozona funkcja")
    repo.checkout("feature", create=True)
    repo.write("src/mieszany.py", zlozona + "\n\ndef nowa(x):\n    return x\n")
    repo.commit("feat: dokladamy prosta funkcje")
    change = ChangeContext.from_git(repo.path, "main", "HEAD")

    result = ComplexityGuard({}).run(change)

    assert result.status == "pass"
    assert result.facts["complexity.methods_measured"] == 1
    assert result.facts["complexity.max"] == 1


def test_plik_testowy_pomijany_domyslnie(repo):
    repo.checkout("feature", create=True)
    repo.write(
        "tests/test_cos.py",
        "def test_a(x):\n"
        "    if x == 1:\n"
        "        if x == 2:\n"
        "            if x == 3:\n"
        "                if x == 4:\n"
        "                    if x == 5:\n"
        "                        if x == 6:\n"
        "                            if x == 7:\n"
        "                                if x == 8:\n"
        "                                    if x == 9:\n"
        "                                        if x == 10:\n"
        "                                            if x == 11:\n"
        "                                                pass\n",
    )
    repo.commit("feat: bardzo zlozony test")
    change = ChangeContext.from_git(repo.path, "main", "HEAD")

    result = ComplexityGuard({}).run(change)

    assert result.status == "pass"
    assert result.facts["complexity.methods_measured"] == 0
