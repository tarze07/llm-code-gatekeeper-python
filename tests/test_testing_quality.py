"""Testy linter jakości testów (`gatekeeper.testing.quality`) — gołe AST,
bez gita i bez pytesta: to jest logika czysto syntaktyczna.
"""

from __future__ import annotations

import ast

import pytest

from gatekeeper.testing.quality import check_test, module_helpers_of


def _test_node(source: str) -> tuple[ast.FunctionDef, dict[str, ast.FunctionDef]]:
    tree = ast.parse(source)
    helpers = module_helpers_of(tree)
    test_node = next(
        n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name.startswith("test")
    )
    return test_node, helpers


def _rule_ids(source: str) -> set[str]:
    node, helpers = _test_node(source)
    return {issue.rule_id for issue in check_test(node, helpers)}


# --------------------------------------------------------------------------
# test.no_assertion
# --------------------------------------------------------------------------


def test_brak_asercji_jest_wykrywany():
    src = """
def test_cos():
    obliczone = 1 + 1
"""
    assert "test.no_assertion" in _rule_ids(src)


def test_zwykla_asercja_nie_jest_flagowana():
    src = """
def test_cos():
    assert 1 + 1 == 2
"""
    assert "test.no_assertion" not in _rule_ids(src)


def test_pytest_raises_liczy_sie_jako_dowod():
    src = """
def test_cos():
    with pytest.raises(ValueError):
        int("x")
"""
    assert "test.no_assertion" not in _rule_ids(src)


def test_mock_assert_called_liczy_sie_jako_dowod():
    src = """
def test_cos():
    mock_obj.assert_called_once_with(42)
"""
    assert "test.no_assertion" not in _rule_ids(src)


def test_asercja_w_helperze_jeden_poziom_w_glab_sie_liczy():
    src = """
def _assert_valid(x):
    assert x > 0

def test_cos():
    _assert_valid(compute())
"""
    assert "test.no_assertion" not in _rule_ids(src)


def test_asercja_dwa_poziomy_w_glab_juz_sie_nie_liczy():
    src = """
def _inner():
    assert True

def _outer():
    _inner()

def test_cos():
    _outer()
"""
    # `_outer` samo w sobie nie zawiera bezpośredniego dowodu — sprawdzamy
    # tylko jeden poziom, więc to wciąż `no_assertion`.
    assert "test.no_assertion" in _rule_ids(src)


# --------------------------------------------------------------------------
# test.constant_assertion
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "body",
    [
        "assert True",
        "assert 1 == 1",
        "x = 5\n    assert x == x",
    ],
)
def test_stala_asercja_jest_wykrywana(body: str):
    src = f"""
def test_cos():
    {body}
"""
    assert "test.constant_assertion" in _rule_ids(src)


def test_asercja_na_wyniku_funkcji_nie_jest_stala():
    src = """
def test_cos():
    assert oblicz() == 6
"""
    assert "test.constant_assertion" not in _rule_ids(src)


# --------------------------------------------------------------------------
# test.mock_echo
# --------------------------------------------------------------------------


def test_echo_mocka_jest_wykrywane():
    src = """
def test_cos():
    klient = Mock(return_value=42)
    assert klient() == 42
"""
    assert "test.mock_echo" in _rule_ids(src)


def test_mock_porownany_z_inna_wartoscia_nie_jest_echem():
    src = """
def test_cos():
    klient = Mock(return_value=42)
    assert klient() == oblicz_oczekiwana_wartosc()
"""
    assert "test.mock_echo" not in _rule_ids(src)


# --------------------------------------------------------------------------
# test.only_smoke
# --------------------------------------------------------------------------


def test_tylko_is_not_none_jest_flagowane():
    src = """
def test_cos():
    wynik = przetworz(dane)
    assert wynik is not None
"""
    assert "test.only_smoke" in _rule_ids(src)


def test_asercja_na_wartosc_nie_jest_smoke():
    src = """
def test_cos():
    wynik = przetworz(dane)
    assert wynik is not None
    assert wynik.status == "ok"
"""
    assert "test.only_smoke" not in _rule_ids(src)


# --------------------------------------------------------------------------
# test.exception_swallowed
# --------------------------------------------------------------------------


def test_polkniety_wyjatek_jest_wykrywany():
    src = """
def test_cos():
    try:
        ryzykowna_operacja()
    except Exception:
        pass
"""
    assert "test.exception_swallowed" in _rule_ids(src)


def test_wyjatek_z_asercja_w_except_nie_jest_polkniety():
    src = """
def test_cos():
    try:
        ryzykowna_operacja()
    except Exception as exc:
        assert "błąd" in str(exc)
"""
    assert "test.exception_swallowed" not in _rule_ids(src)


def test_dobry_test_nie_ma_zadnych_znaleziska():
    src = """
def test_dodawanie():
    assert dodaj(2, 3) == 5
"""
    assert _rule_ids(src) == set()
