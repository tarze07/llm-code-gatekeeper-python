"""G2 — pokrycie różnicowe, branch-aware (TOOLS.md §4.5).

Fakt `coverage.diff_ratio`: jaki procent nowych/zmienionych linii **produkcyjnych**
w diffie wykonuje **cały** zestaw testów repo — nie tylko nowe testy, to różni tę
bramkę od `G2.cross_verify`. `if` z pustą gałęzią błędu nie liczy się jako pokryty
(`--branch-coverage` w `diff-cover`, patrz `adapters/coverage.py`).

Bramka jest wyłącznie faktograficzna, jak `G0.scope`/`G0.provenance`: nigdy nie
ustawia `status="fail"`. Próg (`coverage.diff_ratio < 0.80`) to sprawa polityki
(`policy/gates.yaml`), nie osądu bramki — ten sam podział odpowiedzialności co
wszędzie indziej w tym repo (facts osobno od decyzji, TOOLS.md §1.1).

Ta bramka sama nie ma logiki językowej — jak `G2.cross_verify`/`G2.test_sanity`,
jest agregatorem poziomu 1 (`core/plugins.py`) po zainstalowanych
`TestToolchain` (`gatekeeper.test_toolchains`); `produce_coverage_report()`
każdego toolchaina robi całą robotę (uruchamia testy repo pod narzędziem
pokrycia i przecina wynik z diffem — dla Pythona: `coverage.py` + `diff-cover`,
patrz `testing/toolchain.py`).
"""

from __future__ import annotations

import time
from importlib.metadata import entry_points
from typing import Any

from ..adapters.base import ToolFailed, ToolMissing
from ..core.change import ChangeContext
from ..core.finding import GateResult
from ..core.plugins import TestToolchain
from . import Gate, register

TOOLCHAIN_GROUP = "gatekeeper.test_toolchains"


def _installed_toolchains() -> list[TestToolchain]:
    return [ep.load()() for ep in entry_points(group=TOOLCHAIN_GROUP)]


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
        require_tool = bool(self.config.get("require_tool", True))

        toolchains = _installed_toolchains()
        touched_production = False
        covered_total = 0
        lines_total = 0
        notes: list[str] = []

        for toolchain in toolchains:
            language = getattr(toolchain, "language", None)
            production = [
                f
                for f in change.files
                if not f.test and not f.generated and f.status != "D" and f.language == language
            ]
            if not production:
                continue
            touched_production = True

            try:
                result = toolchain.produce_coverage_report(change, self.config)
            except (ToolMissing, ToolFailed) as exc:
                facts["coverage.tool_available"] = False
                if not require_tool:
                    notes.append(f"narzędzie niedostępne, `require_tool: false`: {exc}")
                    continue
                return self.result(
                    status="error",
                    duration_s=time.monotonic() - started,
                    facts=facts,
                    message=str(exc),
                )

            production_files = {
                path: cov for path, cov in result.files.items() if not change.is_test_file(path)
            }
            covered_total += sum(cov.covered for cov in production_files.values())
            lines_total += sum(cov.total for cov in production_files.values())

        if not touched_production:
            return self.result(
                status="skipped",
                duration_s=time.monotonic() - started,
                facts=facts,
                message="zmiana nie dotyka kodu produkcyjnego w żadnym zainstalowanym "
                "języku — nie ma czego mierzyć",
            )

        facts["coverage.covered_lines"] = covered_total
        facts["coverage.total_lines"] = lines_total
        facts["coverage.diff_ratio"] = covered_total / lines_total if lines_total else None

        if lines_total == 0:
            message = (
                "brak zmierzonych linii produkcyjnych w diffie — plik nowy/zmieniony "
                "nie pojawił się w raporcie coverage (prawdopodobnie nieużyty przez "
                "żaden test; patrz uwaga w adapters/coverage.py)"
            )
        else:
            message = (
                f"{covered_total}/{lines_total} nowych linii produkcyjnych pokrytych testami "
                f"({100 * covered_total / lines_total:.0f}%)"
            )
        if notes:
            message += " · " + " · ".join(notes)

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
