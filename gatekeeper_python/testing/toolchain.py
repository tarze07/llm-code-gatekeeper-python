"""`TestToolchain` (`core/plugins.py`) dla Pythona.

1:1 przeniesienie logiki, która wcześniej żyła rozproszona po trzech bramkach
(`gates/g2_crossverify.py`, `g2_test_sanity.py`, `g2_diff_coverage.py`) pod
wspólnym `CODE_LANGUAGES = {"python"}` — teraz jest to jeden zarejestrowany
dostawca (`gatekeeper.test_toolchains`), a bramki go tylko wywołują. TS/JS
i C# nie mają dziś odpowiednika (README/PLAN.md to jawnie deklarują) —
brak zarejestrowanego toolchaina dla danego języka to `skipped`, nie błąd.

Uwaga o zakresie: `produce_coverage_report` zwraca dziś gotowy
`DiffCoverageResult` z `adapters/coverage.py` (cały pipeline coverage+diff-cover
w jednym wywołaniu), nie surowy raport Cobertura/LCOV — bo dopóki istnieje
tylko ten jeden toolchain, nie ma jeszcze komu dzielić się wspólnym
`core.diffcover.run_diff_cover_on_report()`. Ta ekstrakcja jest częścią
budowy toolchainów dla TS/C# (Faza 2/3), nie tego kroku.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

from gatekeeper_core.adapters.base import ToolFailed, ToolMissing
from gatekeeper_core.core.change import ChangeContext, ChangedFile
from gatekeeper_core.core.plugins import ToolchainIsolationBroken
from gatekeeper_core.core.runner import Sandbox, SandboxPolicy

from ..adapters.coverage import DiffCoverageResult, run_diff_coverage
from . import discovery, quality
from .pytest_runner import PytestUnavailable, RunOutput, build_env, module_origin, run_pytest

CODE_LANGUAGES = {"python"}


class IsolationBroken(ToolchainIsolationBroken):
    pass


class PythonTestToolchain:
    language = "python"

    # ------------------------------------------------------------ discovery

    def discover_tests(self, change: ChangeContext) -> list[discovery.TestItem]:
        out: list[discovery.TestItem] = []
        for file in change.files:
            if not file.test or file.status == "D" or not file.path.endswith(".py"):
                continue
            head = change.file_at(change.head_sha, file.path) or ""
            base = change.file_at(change.base_sha, file.path) or ""
            out.extend(discovery.changed_tests(base, head, file.path))
        return out

    # -------------------------------------------------------------- quality

    def lint_quality(
        self, change: ChangeContext, tests: list[discovery.TestItem]
    ) -> list[tuple[discovery.TestItem, quality.QualityIssue]]:
        by_file: dict[str, list[discovery.TestItem]] = {}
        for item in tests:
            by_file.setdefault(item.file, []).append(item)

        out: list[tuple[discovery.TestItem, quality.QualityIssue]] = []
        for file, items in by_file.items():
            # `discover_tests` już sparsowało `head_source` bez błędu (inaczej
            # `changed_tests` zwróciłoby dla niego pustą listę) — tu parsujemy
            # drugi raz tylko po to, żeby wyłowić funkcje pomocnicze
            # zdefiniowane obok testów.
            head_source = change.file_at(change.head_sha, file)
            if head_source is None:
                continue
            helpers = quality.module_helpers_of(ast.parse(head_source))
            for item in items:
                if item.node is None:  # pragma: no cover - zawsze ustawione przez collect_tests
                    continue
                for issue in quality.check_test(item.node, helpers):
                    out.append((item, issue))
        return out

    # ---------------------------------------------------------- cross-verify

    def run_cross_verify(
        self,
        change: ChangeContext,
        tests: list[discovery.TestItem],
        config: dict[str, Any],
    ) -> tuple[dict[str, Any], str]:
        """Zwraca `(outcomes, message)` — `outcomes` to `dict[nodeid, TestOutcome]`
        z `testing.pytest_runner`. Rzuca `IsolationBroken`/`PytestUnavailable`,
        tak jak dawniej `CrossVerify._run_against_base` — gate łapie je i
        zamienia na `status="error"`."""
        extra_paths = list(config.get("python_path", ["src"]))
        keep_env = tuple(config.get("keep_env", []))
        with change.worktree_at(change.base_sha) as worktree:
            overlaid = self._overlay_tests(change, worktree)
            env = build_env(worktree, extra_paths, keep_env)
            self._assert_isolation(change, worktree, env, config)
            result: RunOutput = run_pytest(
                worktree=worktree,
                nodeids=[i.nodeid for i in tests],
                env=env,
                timeout_s=float(config.get("timeout_s", 600.0)),
                extra_args=list(config.get("pytest_args", [])),
            )
        return result.outcomes, f"nałożono {overlaid} plików testowych"

    def _overlay_tests(self, change: ChangeContext, worktree: Path) -> int:
        """Do worktree na starym kodzie wnosimy *wyłącznie* pliki testowe.

        Skopiowanie czegokolwiek z kodu produkcyjnego unieważnia cały test.
        """
        count = 0
        for file in change.files:
            if not file.test or file.status == "D":
                continue
            content = change.file_at(change.head_sha, file.path)
            if content is None:
                continue
            target = worktree / file.path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
            count += 1
        return count

    def _assert_isolation(
        self, change: ChangeContext, worktree: Path, env: dict[str, str], config: dict[str, Any]
    ) -> None:
        if config.get("skip_isolation_check"):
            return
        for module in sorted(_top_level_modules(_production_files(change))):
            origin = module_origin(module, worktree, env)
            if origin is None:
                continue
            if not Path(origin).resolve().is_relative_to(worktree.resolve()):
                raise IsolationBroken(
                    f"moduł `{module}` importuje się z {origin}, spoza kopii kodu bazowego "
                    "— testy porównywałyby nowy kod z nowym. Najczęstsza przyczyna: pakiet "
                    "zainstalowany w trybie edytowalnym (`pip install -e .`). Uruchom bramkę "
                    "w środowisku bez takiej instalacji albo ustaw `python_path` w polityce."
                )

    # ------------------------------------------------------------- coverage

    def produce_coverage_report(
        self, change: ChangeContext, config: dict[str, Any]
    ) -> DiffCoverageResult:
        sandbox = Sandbox(
            SandboxPolicy(
                network=False,
                timeout_s=float(config.get("timeout_s", 600.0)),
                keep_env=tuple(config.get("keep_env", ())),
            )
        )
        env = build_env(
            change.repo,
            extra_paths=list(config.get("python_path", ["src"])),
            keep_env=tuple(config.get("keep_env", ())),
        )
        return run_diff_coverage(
            change.repo,
            sandbox,
            change.base_sha,
            timeout_s=float(config.get("timeout_s", 600.0)),
            env=env,
            pytest_args=list(config.get("pytest_args", [])),
        )


def _production_files(change: ChangeContext) -> list[ChangedFile]:
    return [
        f
        for f in change.files
        if not f.test
        and not f.generated
        and f.status != "D"
        and f.language in CODE_LANGUAGES
    ]


def _top_level_modules(files: list[ChangedFile]) -> set[str]:
    modules: set[str] = set()
    for file in files:
        parts = Path(file.path).parts
        if parts and parts[0] == "src":
            parts = parts[1:]
        if not parts:
            continue
        head = parts[0]
        modules.add(head.removesuffix(".py") if head.endswith(".py") else head)
    return {m for m in modules if m.isidentifier()}


__all__ = [
    "PythonTestToolchain",
    "IsolationBroken",
    "PytestUnavailable",
    "ToolFailed",
    "ToolMissing",
]
