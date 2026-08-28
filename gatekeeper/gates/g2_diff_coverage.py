"""G2 — pokrycie różnicowe, branch-aware (TOOLS.md §4.5).

Fakt `coverage.diff_ratio`: jaki procent nowych/zmienionych linii **produkcyjnych**
w diffie wykonuje **cały** zestaw testów repo — nie tylko nowe testy, to różni tę
bramkę od `G2.cross_verify`. `if` z pustą gałęzią błędu nie liczy się jako pokryty
(`--branch-coverage` w `diff-cover`, patrz `adapters/coverage.py`).

Bramka jest wyłącznie faktograficzna, jak `G0.scope`/`G0.provenance`: nigdy nie
ustawia `status="fail"`. Próg (`coverage.diff_ratio < 0.80`) to sprawa polityki
(`policy/gates.yaml`), nie osądu bramki — ten sam podział odpowiedzialności co
wszędzie indziej w tym repo (facts osobno od decyzji, TOOLS.md §1.1).
"""

from __future__ import annotations

import time
from typing import Any

from ..adapters.base import ToolFailed, ToolMissing
from ..adapters.coverage import DiffCoverageResult, run_diff_coverage
from ..core.change import ChangeContext, ChangedFile
from ..core.finding import GateResult
from ..core.runner import Sandbox, SandboxPolicy
from ..testing.pytest_runner import build_env
from . import Gate, register

CODE_LANGUAGES = {"python"}


@register
class DiffCoverage(Gate):
    id = "G2.diff_coverage"
    name = "Pokrycie różnicowe (branch-aware)"
    budget_s = 600.0
    facts = (
        "coverage.diff_ratio",
        "coverage.total_lines",
        "coverage.covered_lines",
        "coverage.tool_available",
    )

    def run(self, change: ChangeContext) -> GateResult:
        started = time.monotonic()
        facts = _empty_facts()

        production = _production_files(change)
        if not production:
            return self.result(
                status="skipped",
                duration_s=time.monotonic() - started,
                facts=facts,
                message="zmiana nie dotyka kodu produkcyjnego w Pythonie — nie ma czego mierzyć",
            )

        sandbox = Sandbox(
            SandboxPolicy(
                network=False,
                timeout_s=self.budget_s,
                keep_env=tuple(self.config.get("keep_env", ())),
            )
        )
        require_tool = bool(self.config.get("require_tool", True))
        env = build_env(
            change.repo,
            extra_paths=list(self.config.get("python_path", ["src"])),
            keep_env=tuple(self.config.get("keep_env", ())),
        )
        try:
            result = run_diff_coverage(
                change.repo,
                sandbox,
                change.base_sha,
                timeout_s=self.budget_s,
                env=env,
                pytest_args=list(self.config.get("pytest_args", [])),
            )
        except (ToolMissing, ToolFailed) as exc:
            facts["coverage.tool_available"] = False
            if not require_tool:
                return self.result(
                    status="skipped",
                    duration_s=time.monotonic() - started,
                    facts=facts,
                    message=f"narzędzie niedostępne, `require_tool: false`: {exc}",
                )
            return self.result(
                status="error",
                duration_s=time.monotonic() - started,
                facts=facts,
                message=str(exc),
            )

        return self._to_result(result, change, facts, started)

    def _to_result(
        self,
        result: DiffCoverageResult,
        change: ChangeContext,
        facts: dict[str, Any],
        started: float,
    ) -> GateResult:
        production_files = {
            path: cov for path, cov in result.files.items() if not change.is_test_file(path)
        }
        covered = sum(cov.covered for cov in production_files.values())
        total = sum(cov.total for cov in production_files.values())

        facts["coverage.covered_lines"] = covered
        facts["coverage.total_lines"] = total
        facts["coverage.diff_ratio"] = covered / total if total else None

        if total == 0:
            message = (
                "brak zmierzonych linii produkcyjnych w diffie — plik nowy/zmieniony "
                "nie pojawił się w raporcie coverage (prawdopodobnie nieużyty przez "
                "żaden test; patrz uwaga w adapters/coverage.py)"
            )
        else:
            message = (
                f"{covered}/{total} nowych linii produkcyjnych pokrytych testami "
                f"({100 * covered / total:.0f}%)"
            )

        return self.result(
            status="pass",
            duration_s=time.monotonic() - started,
            facts=facts,
            message=message,
        )


def _empty_facts() -> dict[str, Any]:
    return {
        "coverage.diff_ratio": None,
        "coverage.total_lines": 0,
        "coverage.covered_lines": 0,
        "coverage.tool_available": True,
    }


def _production_files(change: ChangeContext) -> list[ChangedFile]:
    return [
        f
        for f in change.files
        if not f.test and not f.generated and f.status != "D" and f.language in CODE_LANGUAGES
    ]
