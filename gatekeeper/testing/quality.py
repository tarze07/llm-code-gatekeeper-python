"""Linter jakości testów: testy-atrapy wykrywane przez AST, nie przez uruchomienie.

Dopełnienie `cross-verify` (TOOLS.md §4.2): tamta bramka łapie test, który
przechodzi na starym kodzie. Ta łapie test, który nie ma szans niczego
dowieść niezależnie od tego, jaki kod sprawdza — bo w ogóle nie asertuje,
asertuje stałą, albo asertuje echo własnego mocka.

Pułapka, o której mówi TOOLS.md §4.2: asercja bywa w helperze
(`_assert_valid(x)`), nie bezpośrednio w ciele testu. Rozwiązanie —
`module_helpers` — pozwala zajrzeć **jeden poziom w głąb**: test wołający
helper, który asertuje, liczy się jako mający dowód; helper wołający kolejny
helper już nie (żeby nie robić z tego pełnej analizy wywołań).
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Any

from ..core.finding import Severity

#: Fabryki mocków, których `return_value=` śledzimy dla `test.mock_echo`.
_MOCK_FACTORY_NAMES = frozenset({"Mock", "MagicMock", "AsyncMock"})


@dataclass(frozen=True)
class QualityIssue:
    rule_id: str
    severity: Severity
    title: str
    failure_scenario: str
    evidence: dict[str, Any] = field(default_factory=dict)


def check_test(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    module_helpers: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
) -> list[QualityIssue]:
    """Wszystkie reguły jakości dla jednego testu, w kolejności z TOOLS.md §4.2."""
    rules = (
        _rule_no_assertion,
        _rule_constant_assertion,
        _rule_mock_echo,
        _rule_only_smoke,
        _rule_exception_swallowed,
    )
    issues = []
    for rule in rules:
        issue = rule(node, module_helpers)
        if issue is not None:
            issues.append(issue)
    return issues


def module_helpers_of(
    tree: ast.Module, test_prefix: str = "test"
) -> dict[str, ast.FunctionDef | ast.AsyncFunctionDef]:
    """Funkcje top-level pliku, które same nie są testami — kandydaci na helpery."""
    return {
        n.name: n
        for n in tree.body
        if isinstance(n, ast.FunctionDef) and not n.name.startswith(test_prefix)
    }


# --------------------------------------------------------------------------
# test.no_assertion
# --------------------------------------------------------------------------


def _has_assert_stmt(node: ast.AST) -> bool:
    return any(isinstance(n, ast.Assert) for n in ast.walk(node))


def _has_raises_context(node: ast.AST) -> bool:
    return any(
        isinstance(n, ast.Call)
        and isinstance(n.func, ast.Attribute)
        and n.func.attr in ("raises", "warns")
        for n in ast.walk(node)
    )


def _has_mock_assert_call(node: ast.AST) -> bool:
    return any(
        isinstance(n, ast.Call)
        and isinstance(n.func, ast.Attribute)
        and n.func.attr.startswith("assert_")
        for n in ast.walk(node)
    )


def _has_direct_evidence(node: ast.AST) -> bool:
    return _has_assert_stmt(node) or _has_raises_context(node) or _has_mock_assert_call(node)


def _has_evidence(
    node: ast.AST, module_helpers: dict[str, ast.FunctionDef | ast.AsyncFunctionDef]
) -> bool:
    if _has_direct_evidence(node):
        return True
    called = {
        n.func.id
        for n in ast.walk(node)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
    }
    return any(
        _has_direct_evidence(module_helpers[name]) for name in called if name in module_helpers
    )


def _rule_no_assertion(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    module_helpers: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
) -> QualityIssue | None:
    if _has_evidence(node, module_helpers):
        return None
    return QualityIssue(
        rule_id="test.no_assertion",
        severity=Severity.HIGH,
        title=f"Test `{node.name}` nie zawiera żadnej asercji",
        failure_scenario=(
            f"Test `{node.name}` przejdzie niezależnie od tego, co zwróci testowany kod — "
            "nie ma w nim ani `assert`, ani `pytest.raises`/`pytest.warns`, ani wywołania "
            "`*.assert_*` na mocku (bezpośrednio ani w wołanym helperze). Zielony wynik "
            "niczego nie potwierdza."
        ),
    )


# --------------------------------------------------------------------------
# test.constant_assertion
# --------------------------------------------------------------------------


def _is_constant_truthy(expr: ast.expr) -> bool:
    return isinstance(expr, ast.Constant) and bool(expr.value)


def _is_self_compare(expr: ast.expr) -> bool:
    if not isinstance(expr, ast.Compare) or len(expr.ops) != 1:
        return False
    if not isinstance(expr.ops[0], ast.Eq):
        return False
    return ast.dump(expr.left) == ast.dump(expr.comparators[0])


def _is_trivial(expr: ast.expr) -> bool:
    return _is_constant_truthy(expr) or _is_self_compare(expr)


def _rule_constant_assertion(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    module_helpers: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
) -> QualityIssue | None:
    for n in ast.walk(node):
        if isinstance(n, ast.Assert) and _is_trivial(n.test):
            return QualityIssue(
                rule_id="test.constant_assertion",
                severity=Severity.HIGH,
                title=f"Test `{node.name}` asertuje stałą, nie zachowanie",
                failure_scenario=(
                    f"Linia {n.lineno} w `{node.name}` to `assert` na wyrażeniu, które jest "
                    "zawsze prawdziwe niezależnie od testowanego kodu (stała albo `x == x`) — "
                    "test przejdzie nawet po całkowitym usunięciu implementacji."
                ),
                evidence={"snippet": ast.unparse(n), "line": n.lineno},
            )
    return None


# --------------------------------------------------------------------------
# test.mock_echo
# --------------------------------------------------------------------------


def _mock_factory_name(call: ast.Call) -> str | None:
    func = call.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def _find_mock_return_values(node: ast.AST) -> dict[str, ast.expr]:
    """Zmienna → wyrażenie `return_value=` z `Mock(return_value=...)`."""
    out: dict[str, ast.expr] = {}
    for n in ast.walk(node):
        if not isinstance(n, ast.Assign) or not isinstance(n.value, ast.Call):
            continue
        if _mock_factory_name(n.value) not in _MOCK_FACTORY_NAMES:
            continue
        return_value = next((kw.value for kw in n.value.keywords if kw.arg == "return_value"), None)
        if return_value is None:
            continue
        for target in n.targets:
            if isinstance(target, ast.Name):
                out[target.id] = return_value
    return out


def _rule_mock_echo(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    module_helpers: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
) -> QualityIssue | None:
    mocks = _find_mock_return_values(node)
    if not mocks:
        return None
    for n in ast.walk(node):
        if not isinstance(n, ast.Assert):
            continue
        test = n.test
        if not isinstance(test, ast.Compare) or len(test.ops) != 1:
            continue
        if not isinstance(test.ops[0], ast.Eq):
            continue
        sides = ((test.left, test.comparators[0]), (test.comparators[0], test.left))
        for call_side, other_side in sides:
            if not isinstance(call_side, ast.Call) or not isinstance(call_side.func, ast.Name):
                continue
            expected = mocks.get(call_side.func.id)
            if expected is not None and ast.dump(expected) == ast.dump(other_side):
                return QualityIssue(
                    rule_id="test.mock_echo",
                    severity=Severity.MEDIUM,
                    title=f"Test `{node.name}` porównuje mocka z jego własnym `return_value`",
                    failure_scenario=(
                        f"W `{node.name}` asercja w linii {n.lineno} sprawdza, że "
                        f"`{call_side.func.id}(...)` zwraca dokładnie to, co wpisano jako "
                        "`return_value` tego samego mocka — to potwierdza konfigurację mocka, "
                        "nie zachowanie testowanego kodu."
                    ),
                    evidence={"snippet": ast.unparse(n), "line": n.lineno},
                )
    return None


# --------------------------------------------------------------------------
# test.only_smoke
# --------------------------------------------------------------------------


def _is_not_none_check(expr: ast.expr) -> bool:
    return (
        isinstance(expr, ast.Compare)
        and len(expr.ops) == 1
        and isinstance(expr.ops[0], ast.IsNot)
        and len(expr.comparators) == 1
        and isinstance(expr.comparators[0], ast.Constant)
        and expr.comparators[0].value is None
    )


def _rule_only_smoke(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    module_helpers: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
) -> QualityIssue | None:
    asserts = [n for n in ast.walk(node) if isinstance(n, ast.Assert)]
    if not asserts or not all(_is_not_none_check(a.test) for a in asserts):
        return None
    return QualityIssue(
        rule_id="test.only_smoke",
        severity=Severity.LOW,
        title=f"Test `{node.name}` sprawdza tylko `is not None`",
        failure_scenario=(
            f"`{node.name}` wywołuje testowany kod, ale każda asercja ogranicza się do "
            "`is not None` — funkcja zwracająca zupełnie błędną wartość (byle nie `None`) "
            "nadal przejdzie ten test."
        ),
    )


# --------------------------------------------------------------------------
# test.exception_swallowed
# --------------------------------------------------------------------------


def _handler_body_is_noop(handler: ast.ExceptHandler) -> bool:
    if len(handler.body) != 1:
        return False
    stmt = handler.body[0]
    if isinstance(stmt, ast.Pass):
        return True
    return (
        isinstance(stmt, ast.Expr)
        and isinstance(stmt.value, ast.Constant)
        and stmt.value.value is Ellipsis
    )


def _rule_exception_swallowed(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    module_helpers: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
) -> QualityIssue | None:
    for n in ast.walk(node):
        if not isinstance(n, ast.Try):
            continue
        for handler in n.handlers:
            if _handler_body_is_noop(handler):
                return QualityIssue(
                    rule_id="test.exception_swallowed",
                    severity=Severity.MEDIUM,
                    title=f"Test `{node.name}` połyka wyjątek bez asercji",
                    failure_scenario=(
                        f"W `{node.name}` blok `except` w linii {handler.lineno} tylko "
                        "`pass`/`...` — jeżeli testowany kod rzuci nieoczekiwany wyjątek "
                        "zamiast tego, którego test się spodziewa, test i tak przejdzie."
                    ),
                    evidence={"line": handler.lineno},
                )
    return None
