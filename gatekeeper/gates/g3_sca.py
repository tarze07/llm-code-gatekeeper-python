"""G3 — SCA: podatności w nowo dodanych zależnościach (pip-audit, npm audit,
`dotnet list package --vulnerable`).

Blokujemy wyłącznie na podatnościach w pakietach, które ten PR **wprowadza**
— dług w już zastanych zależnościach to osobny raport tygodniowy, nie
blokada tej zmiany (TOOLS.md §5.1).

Ta bramka sama nie ma logiki per-ekosystem — jest agregatorem poziomu 1
(`core/plugins.py`): grupuje nowe zależności po `dep.ecosystem`, dla każdej
grupy woła `EcosystemProvider.scan_sca()` zainstalowanego dostawcy
(`gatekeeper.dep_ecosystems`, te same providery co `G1.deps`,
`deps/ecosystems.py`) i sumuje wynik. Nowy ekosystem to nowy provider, nie
zmiana w tym pliku. `sca.checked_ecosystems` w faktach mówi, które
z zainstalowanych ekosystemów faktycznie miały nowe zależności w tym PR-ze.

pip-audit i npm audit muszą dostać sieć — pytają o znane podatności w
PyPI/OSV i w bazie doradczej npm. NuGet tak samo (`dotnet list package
--vulnerable` pyta usługę NuGet-a). To jedyna bramka z dostępem do sieci —
sandboxy z odpowiednią polityką buduje sam provider (`scan_sca`), nie ta
bramka.
"""

from __future__ import annotations

import time
from importlib.metadata import entry_points
from typing import Any

from ..adapters.base import ToolMissing
from ..core.change import ChangeContext
from ..core.finding import Finding, GateResult
from ..core.plugins import EcosystemProvider
from ..deps import manifests
from . import Gate, register

DEP_ECOSYSTEM_GROUP = "gatekeeper.dep_ecosystems"


def _installed_ecosystems() -> dict[str, EcosystemProvider]:
    return {ep.name: ep.load()() for ep in entry_points(group=DEP_ECOSYSTEM_GROUP)}


@register
class ScaGuard(Gate):
    id = "G3.sca"
    name = "Podatności w nowych zależnościach (pip-audit, npm audit, dotnet list package)"
    budget_s = 180.0
    facts = (
        "sca.checked_package_count",
        "sca.checked_ecosystems",
        "sca.vulnerable_package_count",
        "sca.unresolved_package_count",
        "sca.finding_count",
        "sca.tool_available",
    )

    def run(self, change: ChangeContext) -> GateResult:
        started = time.monotonic()
        facts = _empty_facts()

        providers = _installed_ecosystems()
        by_ecosystem = self._new_deps_by_ecosystem(change, list(providers.values()))
        total_new = sum(len(deps) for deps in by_ecosystem.values())
        if not total_new:
            return self.result(
                status="pass",
                duration_s=time.monotonic() - started,
                facts=facts,
                message="brak nowych zależności do sprawdzenia",
            )
        facts["sca.checked_package_count"] = total_new
        facts["sca.checked_ecosystems"] = sorted(by_ecosystem)

        require_tool = bool(self.config.get("require_tool", True))
        keep_env = tuple(self.config.get("keep_env", ()))
        findings: list[Finding] = []
        unresolved: list[str] = []

        for ecosystem, deps in by_ecosystem.items():
            provider = next((p for p in providers.values() if p.ecosystem == ecosystem), None)
            if provider is None:  # pragma: no cover - by_ecosystem już filtruje po providers
                continue
            try:
                outcome = provider.scan_sca(
                    change.repo, self.id, deps, timeout_s=self.budget_s, keep_env=keep_env
                )
            except ToolMissing as exc:
                facts["sca.tool_available"] = False
                return self.result(
                    status="error" if require_tool else "skipped",
                    duration_s=time.monotonic() - started,
                    facts=facts,
                    message=str(exc),
                )
            findings.extend(outcome.findings)
            unresolved.extend(outcome.unresolved)

        vulnerable_packages = {f.evidence.get("package") for f in findings}
        facts["sca.finding_count"] = len(findings)
        facts["sca.vulnerable_package_count"] = len(vulnerable_packages)
        facts["sca.unresolved_package_count"] = len(unresolved)

        checked = total_new - len(unresolved)
        message = (
            f"sprawdzono {checked}/{total_new} nowych pakietów "
            f"({', '.join(sorted(by_ecosystem))}), {len(vulnerable_packages)} z podatnościami"
        )
        if unresolved:
            message += f" · nierozwiązane: {', '.join(sorted(unresolved))}"

        return self.result(
            status="fail" if findings else "pass",
            duration_s=time.monotonic() - started,
            facts=facts,
            findings=findings,
            message=message,
        )

    # ------------------------------------------------------------------

    def _new_deps_by_ecosystem(
        self, change: ChangeContext, providers: list[EcosystemProvider]
    ) -> dict[str, list[manifests.Dependency]]:
        changed_manifests = [
            f
            for f in change.files
            if f.status != "D" and any(p.is_manifest(f.path) for p in providers)
        ]
        by_ecosystem: dict[str, list[manifests.Dependency]] = {}
        for changed in changed_manifests:
            head = change.file_at(change.head_sha, changed.path) or ""
            base = change.file_at(change.base_sha, changed.path) or ""
            after: set[manifests.Dependency] = set()
            before: set[manifests.Dependency] = set()
            for provider in providers:
                if provider.is_manifest(changed.path):
                    after |= provider.parse_manifest(changed.path, head)
                    before |= provider.parse_manifest(changed.path, base)
            for dep in manifests.diff_dependencies(before, after):
                by_ecosystem.setdefault(dep.ecosystem, []).append(dep)
        return by_ecosystem


def _empty_facts() -> dict[str, Any]:
    return {
        "sca.checked_package_count": 0,
        "sca.checked_ecosystems": [],
        "sca.vulnerable_package_count": 0,
        "sca.unresolved_package_count": 0,
        "sca.finding_count": 0,
        "sca.tool_available": True,
    }
