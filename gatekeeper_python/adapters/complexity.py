"""Złożoność cyklomatyczna (McCabe) przez `ast` — zero nowego narzędzia
(PLAN-G1-complexity.md §6, core repo). Semantyka zgodna z `radon cc_visit`/
`flake8-mccabe`, nie z uproszczeniem slajdu w `uncle-bob-gauntlet.md`
(ten liczy krótkie spięcie `and`/`or` jako dodatkowe krawędzie, slajd 10b
tego nie robi — plan idzie za wzorem `M = E − N + 2P`, nie za przykładem).

Bez `radon` na `[gates]`: zależność tylko po jedną liczbę jest gorsza niż
~80-liniowy visitor i golden test (PLAN-G1-complexity.md §6).
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Any

from gatekeeper_core.core.change import ChangeContext
from gatekeeper_core.core.plugins import ComplexityOutcome, MethodComplexity

#: Węzły, których obecność w ciele funkcji dodaje jedną decyzję — punkt
#: rozgałęzienia ścieżki wykonania (PLAN-G1-complexity.md §3).
_DECISION_NODES = (
    ast.If,
    ast.IfExp,
    ast.For,
    ast.AsyncFor,
    ast.While,
    ast.Assert,
    ast.ExceptHandler,
)


@dataclass(frozen=True)
class _PyMethod:
    name: str
    lineno: int
    end_lineno: int
    complexity: int
    nloc: int


class _ComplexityVisitor(ast.NodeVisitor):
    """Licznik na stosie: każda `FunctionDef`/`AsyncFunctionDef` (zagnieżdżona
    też) dostaje własną ramkę i własny wpis w `results` — zagnieżdżona funkcja
    liczy się osobno, `lambda` dodaje swoją złożoność do otaczającej ramki
    (PLAN-G1-complexity.md §3, „Zagnieżdżone FunctionDef liczymy osobno")."""

    def __init__(self, source_lines: list[str]) -> None:
        self._source_lines = source_lines
        self._class_stack: list[str] = []
        self._frames: list[dict[str, Any]] = []
        self.results: list[_PyMethod] = []

    def _bump(self, delta: int = 1) -> None:
        if self._frames:
            self._frames[-1]["complexity"] += delta

    def _qualified_name(self, name: str) -> str:
        if self._class_stack:
            return f"{self._class_stack[-1]}.{name}"
        return name

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._class_stack.append(node.name)
        self.generic_visit(node)
        self._class_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function(node)

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        self._frames.append({"complexity": 1})
        for stmt in node.body:
            self.visit(stmt)
        frame = self._frames.pop()
        end_lineno = node.end_lineno or node.lineno
        self.results.append(
            _PyMethod(
                name=self._qualified_name(node.name),
                lineno=node.lineno,
                end_lineno=end_lineno,
                complexity=frame["complexity"],
                nloc=self._nloc(node.lineno, end_lineno),
            )
        )

    def _nloc(self, lineno: int, end_lineno: int) -> int:
        body = self._source_lines[lineno - 1 : end_lineno]
        return sum(1 for line in body if line.strip())

    def visit_BoolOp(self, node: ast.BoolOp) -> None:
        self._bump(len(node.values) - 1)
        self.generic_visit(node)

    def visit_ListComp(self, node: ast.ListComp) -> None:
        self._comprehension(node)

    def visit_SetComp(self, node: ast.SetComp) -> None:
        self._comprehension(node)

    def visit_DictComp(self, node: ast.DictComp) -> None:
        self._comprehension(node)

    def visit_GeneratorExp(self, node: ast.GeneratorExp) -> None:
        self._comprehension(node)

    def _comprehension(self, node: ast.expr) -> None:
        self._bump()
        for generator in node.generators:  # type: ignore[attr-defined]
            self._bump(len(generator.ifs))
        self.generic_visit(node)

    def visit_Match(self, node: ast.Match) -> None:
        self._bump()
        for case in node.cases:
            if not self._is_wildcard(case.pattern):
                self._bump()
        self.generic_visit(node)

    @staticmethod
    def _is_wildcard(pattern: ast.pattern) -> bool:
        return isinstance(pattern, ast.MatchAs) and pattern.pattern is None

    def generic_visit(self, node: ast.AST) -> None:
        if isinstance(node, _DECISION_NODES):
            self._bump()
        super().generic_visit(node)


def measure(source: str) -> list[_PyMethod]:
    """Czysta funkcja — testowana bez gita, na zapisanych fragmentach źródła."""
    tree = ast.parse(source)
    visitor = _ComplexityVisitor(source.splitlines())
    visitor.visit(tree)
    return visitor.results


class PythonComplexityAnalyzer:
    """`ComplexityAnalyzer` (`gatekeeper_core.core.plugins`) dla Pythona."""

    analyzer_id = "python"
    languages = ("python",)

    def empty_facts(self) -> dict[str, Any]:
        return {"complexity.python_files_checked": 0}

    def analyze(
        self, change: ChangeContext, config: dict[str, Any], gate_id: str, budget_s: float
    ) -> ComplexityOutcome:
        include_tests = bool(config.get("include_tests", False))
        files = [
            f.path
            for f in change.effective_files
            if f.language == "python"
            and f.status != "D"
            and f.path.endswith(".py")
            and not f.path.endswith(".pyi")
            and (include_tests or not change.is_test_file(f.path))
        ]
        facts = self.empty_facts()
        facts["complexity.python_files_checked"] = len(files)

        methods: list[MethodComplexity] = []
        for path in files:
            source = change.file_at(change.head_sha, path)
            if source is None:
                continue
            try:
                for m in measure(source):
                    methods.append(
                        MethodComplexity(
                            file=path,
                            name=m.name,
                            lineno=m.lineno,
                            end_lineno=m.end_lineno,
                            complexity=m.complexity,
                            nloc=m.nloc,
                        )
                    )
            except SyntaxError:
                # G1.static i tak zablokuje składnię (nie jest w warn_only w
                # wersji per-projektowej), więc tu nie ma sensu przerywać
                # całej analizy — jeden plik bez wyniku, nie awaria bramki.
                continue
        return ComplexityOutcome(methods=methods, facts=facts)
