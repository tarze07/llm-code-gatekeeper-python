"""Testy `adapters/complexity.py::measure` — czysta funkcja, bez gita.

Semantyka McCabe zgodna z `radon cc_visit`/`flake8-mccabe`
(PLAN-G1-complexity.md w core-repo, §3), nie z uproszczonym przykładem na
slajdzie 10b w `uncle-bob-gauntlet.md` (ten ignoruje krótkie spięcie
`and`/`or`). Fixture ze slajdu 10b jest tu przepisana i asertuje **5**, nie
4 jak wynikałoby z liczenia „na palcach" na slajdzie — dokument sam to
rozstrzyga na korzyść wzoru (`M = E − N + 2P`), nie przykładu.

Dwa dalsze przypadki (`if` z `or`-chainem, `match` z dwoma case'ami +
wildcard) różnią się od liczb podanych w PLAN-G1-complexity.md §7.1 — dla
`if a or b or c` dokument podaje 3, ale to wartość samego łańcucha `or`
(1 start + 2 z `BoolOp` o 3 wartościach) **bez** samego `if`; z `if`
dochodzi kolejne +1 z reguły `If` → 4. Analogicznie dla `match`: 1 (start)
+ 1 (`Match`) + 2 (dwa nie-wildcardowe case) = 4, nie 3 — arytmetyka w
dokumencie się nie spina, formuła (przytoczona w tym samym dokumencie) tak.
Ta sama zasada co przy slajdzie 10b: ufamy wzorowi, nie przykładowi.
"""

from __future__ import annotations

from gatekeeper_python.adapters.complexity import measure


def test_slajd_10b_zagniezdzone_if_i_and_daje_m_5():
    source = (
        "def raty(kwota, lata, dochod):\n"
        "    if kwota > 0:\n"
        "        if lata >= 5 and lata <= 30:\n"
        "            if dochod > kwota * 3:\n"
        "                return kwota / (lata * 12)\n"
        "    return None\n"
    )
    result = measure(source)
    assert len(result) == 1
    assert result[0].complexity == 5


def test_slajd_10b_straznik_daje_m_2():
    source = (
        "def raty(kwota, lata, dochod):\n"
        "    if not poprawne_wejscie(kwota, lata, dochod):\n"
        "        return None\n"
        "    return kwota / (lata * 12)\n"
    )
    assert measure(source)[0].complexity == 2


def test_sam_return_daje_m_1():
    assert measure("def f():\n    return 1\n")[0].complexity == 1


def test_or_chain_trzech_wartosci_daje_m_3():
    """`a or b or c` to jeden węzeł `BoolOp` o 3 wartościach (Python spłaszcza
    ten sam operator w łańcuchu) → +(3−1) = +2, plus start funkcji = 3."""
    source = "def f(a, b, c):\n    return a or b or c\n"
    assert measure(source)[0].complexity == 3


def test_if_z_or_chainem_daje_m_4():
    """Reguła `If` (+1) i reguła `BoolOp` (+2 dla 3 wartości) się sumują —
    to inny przypadek niż `test_or_chain...` powyżej (tu jest też `if`)."""
    source = "def f(a, b, c):\n    if a or b or c:\n        return True\n    return False\n"
    assert measure(source)[0].complexity == 4


def test_match_dwa_case_plus_wildcard_daje_m_4():
    """1 (start) + 1 (Match) + 2 (dwa nie-wildcardowe case, `_` nie liczy się)."""
    source = (
        "def f(x):\n"
        "    match x:\n"
        "        case 1:\n"
        "            return 'a'\n"
        "        case 2:\n"
        "            return 'b'\n"
        "        case _:\n"
        "            return 'c'\n"
    )
    assert measure(source)[0].complexity == 4


def test_zagniezdzona_funkcja_liczy_sie_osobno():
    source = (
        "def outer():\n"
        "    def inner():\n"
        "        if True:\n"
        "            pass\n"
        "    if False:\n"
        "        pass\n"
    )
    result = {m.name: m.complexity for m in measure(source)}
    assert result == {"outer": 2, "inner": 2}
    # `inner` nie dokłada się do `outer` — to jest sedno testu.


def test_lambda_dodaje_zlozonosc_do_otaczajacej_funkcji():
    source = "def f(items):\n    return sorted(items, key=lambda x: x if x > 0 else -x)\n"
    result = measure(source)
    assert len(result) == 1  # lambda NIE jest osobną metodą
    assert result[0].name == "f"
    assert result[0].complexity == 2  # 1 (start) + 1 (IfExp w ciele lambdy)


def test_metoda_w_klasie_ma_kwalifikowana_nazwe():
    source = "class Klasa:\n    def metoda(self):\n        return 1\n"
    result = measure(source)
    assert result[0].name == "Klasa.metoda"


def test_comprehension_z_dwoma_filtrami_ifs():
    source = "def f(xs):\n    return [x for x in xs if x > 0 if x < 10]\n"
    result = measure(source)
    # 1 (start) + 1 (sama comprehension) + 2 (dwa filtry `if`)
    assert result[0].complexity == 4


def test_with_nie_dodaje_zlozonosci():
    source = "def f():\n    with open('x') as fh:\n        return fh.read()\n"
    assert measure(source)[0].complexity == 1


def test_pusta_lista_metod_dla_pliku_bez_funkcji():
    assert measure("x = 1\n") == []
