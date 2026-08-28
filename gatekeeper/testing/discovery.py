"""Wyszukiwanie testów w kodzie — przez AST, nie przez uruchamianie pytesta.

Potrzebujemy dokładnie jednej rzeczy: listy testów, które w tej zmianie są
**nowe albo zmodyfikowane**. Uruchamianie starego kodu przeciw wszystkim
testom projektu nie dowodzi niczego (stare testy oczywiście przechodzą)
i kosztuje kilkanaście minut.

Porównanie po `ast.dump` zamiast po tekście jest celowe: przeformatowanie
testu albo zmiana komentarza nie czyni z niego nowego testu.
"""

from __future__ import annotations

import ast
import hashlib
from dataclasses import dataclass, field

TEST_FUNC_PREFIX = "test"
TEST_CLASS_PREFIX = "Test"

#: Markery, którymi autor jawnie deklaruje, że test *ma prawo* przejść na
#: kodzie sprzed zmiany. Trzy legalne przypadki: czysty refaktor, dopisanie
#: testów do istniejącego kodu, test regresyjny do buga naprawionego wcześniej.
ESCAPE_MARKERS = frozenset({"characterization", "test_backfill", "refactor_only"})


@dataclass(frozen=True)
class TestItem:
    file: str
    name: str
    class_name: str | None
    markers: frozenset[str]
    body_hash: str
    lineno: int
    #: Węzeł AST testu — potrzebny `G2.test_sanity` do analizy treści.
    #: Poza porównaniem (`compare=False`): `changed_tests()` porównuje po
    #: `body_hash`, a węzły AST i tak nie mają sensownej równości.
    node: ast.FunctionDef | ast.AsyncFunctionDef | None = field(
        default=None, compare=False, repr=False
    )

    @property
    def nodeid(self) -> str:
        if self.class_name:
            return f"{self.file}::{self.class_name}::{self.name}"
        return f"{self.file}::{self.name}"

    @property
    def declared_escape(self) -> str | None:
        hit = sorted(self.markers & ESCAPE_MARKERS)
        return hit[0] if hit else None


def collect_tests(source: str, path: str) -> dict[str, TestItem]:
    """Mapa nodeid → test. Pusty słownik, gdy pliku nie da się sparsować."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return {}

    items: dict[str, TestItem] = {}

    def add(node: ast.FunctionDef | ast.AsyncFunctionDef, class_name: str | None) -> None:
        if not node.name.startswith(TEST_FUNC_PREFIX):
            return
        item = TestItem(
            file=path,
            name=node.name,
            class_name=class_name,
            markers=_markers(node),
            body_hash=_body_hash(node),
            lineno=node.lineno,
            node=node,
        )
        items[item.nodeid] = item

    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            add(node, None)
        elif isinstance(node, ast.ClassDef) and node.name.startswith(TEST_CLASS_PREFIX):
            class_markers = _markers(node)
            for child in node.body:
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    before = set(items)
                    add(child, node.name)
                    # markery z klasy dziedziczą się na metody
                    for nodeid in set(items) - before:
                        item = items[nodeid]
                        items[nodeid] = TestItem(
                            file=item.file,
                            name=item.name,
                            class_name=item.class_name,
                            markers=item.markers | class_markers,
                            body_hash=item.body_hash,
                            lineno=item.lineno,
                            node=item.node,
                        )
    return items


def changed_tests(base_source: str, head_source: str, path: str) -> list[TestItem]:
    """Testy nowe albo zmienione względem wersji bazowej."""
    base = collect_tests(base_source, path)
    head = collect_tests(head_source, path)
    out = [
        item
        for nodeid, item in head.items()
        if nodeid not in base or base[nodeid].body_hash != item.body_hash
    ]
    out.sort(key=lambda i: (i.file, i.lineno))
    return out


def _markers(node: ast.AST) -> frozenset[str]:
    found: set[str] = set()
    for decorator in getattr(node, "decorator_list", []):
        target = decorator.func if isinstance(decorator, ast.Call) else decorator
        name = _mark_name(target)
        if name:
            found.add(name)
    return frozenset(found)


def _mark_name(node: ast.AST) -> str | None:
    """`@pytest.mark.slow` / `@mark.slow` → `slow`."""
    if not isinstance(node, ast.Attribute):
        return None
    parent = node.value
    if isinstance(parent, ast.Attribute) and parent.attr == "mark":
        return node.attr
    if isinstance(parent, ast.Name) and parent.id == "mark":
        return node.attr
    return None


def _body_hash(node: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
    body = ast.dump(
        ast.Module(body=list(node.body), type_ignores=[]),
        annotate_fields=True,
        include_attributes=False,  # bez numerów linii: przesunięcie ≠ zmiana
    )
    args = ast.dump(node.args, include_attributes=False)
    return hashlib.sha256(
        (body + args + repr(sorted(_markers(node)))).encode("utf-8")
    ).hexdigest()[:16]
