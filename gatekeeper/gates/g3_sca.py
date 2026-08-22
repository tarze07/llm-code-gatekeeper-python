"""G3 — SCA: podatności w nowo dodanych zależnościach (pip-audit, npm audit,
`dotnet list package --vulnerable`).

Blokujemy wyłącznie na podatnościach w pakietach, które ten PR **wprowadza**
— dług w już zastanych zależnościach to osobny raport tygodniowy, nie
blokada tej zmiany (TOOLS.md §5.1).

Trzy ekosystemy, jedna bramka, jedna decyzja — polityka nie musi znać
podziału na PyPI/npm/NuGet. `sca.checked_ecosystems` w faktach mówi, które
z nich faktycznie miały nowe zależności w tym PR-ze.

pip-audit i npm audit muszą dostać sieć — pytają o znane podatności w
PyPI/OSV i w bazie doradczej npm. NuGet tak samo (`dotnet list package
--vulnerable` pyta usługę NuGet-a). To jedyna bramka z dostępem do sieci;
`network=True` jest tu jawne, nie domyślne (`core.runner`).
"""

from __future__ import annotations

import tempfile
import time
from pathlib import Path
from typing import Any

from ..adapters import dotnet, sca
from ..adapters.base import ToolFailed, ToolMissing
from ..core.change import ChangeContext
from ..core.finding import Finding, GateResult
from ..core.runner import Sandbox, SandboxPolicy
from ..deps import manifests
from . import Gate, register


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

        by_ecosystem = self._new_deps_by_ecosystem(change)
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
        findings: list[Finding] = []
        unresolved: list[str] = []

        if manifests.PYPI in by_ecosystem:
            outcome = self._check_pypi(change, by_ecosystem[manifests.PYPI], findings, unresolved)
            if outcome is not None:
                facts["sca.tool_available"] = False
                return self.result(
                    status="error" if require_tool else "skipped",
                    duration_s=time.monotonic() - started,
                    facts=facts,
                    message=outcome,
                )

        if manifests.NPM in by_ecosystem:
            outcome = self._check_npm(change, by_ecosystem[manifests.NPM], findings, unresolved)
            if outcome is not None:
                facts["sca.tool_available"] = False
                return self.result(
                    status="error" if require_tool else "skipped",
                    duration_s=time.monotonic() - started,
                    facts=facts,
                    message=outcome,
                )

        if manifests.NUGET in by_ecosystem:
            outcome = self._check_nuget(change, by_ecosystem[manifests.NUGET], findings, unresolved)
            if outcome is not None:
                facts["sca.tool_available"] = False
                return self.result(
                    status="error" if require_tool else "skipped",
                    duration_s=time.monotonic() - started,
                    facts=facts,
                    message=outcome,
                )

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

    # ------------------------------------------------------------------ pypi

    def _check_pypi(
        self,
        change: ChangeContext,
        deps: list[manifests.Dependency],
        findings: list[Finding],
        unresolved: list[str],
    ) -> str | None:
        sandbox = Sandbox(
            SandboxPolicy(network=True, timeout_s=self.budget_s, keep_env=self._keep_env())
        )
        # Jeden pakiet na wywołanie, NIE jeden requirements.txt na wszystkie
        # nowe zależności naraz: `pip-audit -r` rozwiązuje cały plik jako
        # jedną całość, więc pojedynczy nieistniejący/halucynowany pakiet
        # (który i tak osobno łapie G1.deps) wywala rozwiązywanie dla
        # WSZYSTKICH nowych zależności naraz i gasi dowód na resztę.
        for dep in deps:
            name = manifests.normalize(manifests.PYPI, dep.name)
            with tempfile.TemporaryDirectory(prefix="gatekeeper-sca-") as tmp:
                requirements = Path(tmp) / "requirements.txt"
                requirements.write_text((dep.raw or dep.name) + "\n", encoding="utf-8")
                try:
                    findings.extend(
                        sca.run_pip_audit(
                            change.repo,
                            sandbox,
                            self.id,
                            requirements=requirements,
                            new_packages={name},
                            manifest=dep.manifest,
                            timeout_s=self.budget_s,
                        )
                    )
                except ToolMissing as exc:
                    return str(exc)
                except ToolFailed:
                    # Ten jeden pakiet się nie rozwiązał — zwykle dlatego, że
                    # nie istnieje, co G1.deps już zgłasza osobno. Brak dowodu
                    # dla NIEGO nie ma prawa zgasić dowodu dla reszty.
                    unresolved.append(name)
        return None

    # ------------------------------------------------------------------- npm

    def _check_npm(
        self,
        change: ChangeContext,
        deps: list[manifests.Dependency],
        findings: list[Finding],
        unresolved: list[str],
    ) -> str | None:
        sandbox = Sandbox(
            SandboxPolicy(network=True, timeout_s=self.budget_s, keep_env=self._keep_env())
        )
        names = {manifests.normalize(manifests.NPM, d.name) for d in deps}
        try:
            findings.extend(sca.run_npm_audit(change.repo, sandbox, self.id, names))
        except ToolMissing as exc:
            return str(exc)
        except ToolFailed:
            # Cały ekosystem naraz (brak `package-lock.json`, npm padł) —
            # ta partia nowych pakietów zostaje bez dowodu, reszta bramki nie.
            unresolved.extend(sorted(names))
        return None

    # ----------------------------------------------------------------- nuget

    def _check_nuget(
        self,
        change: ChangeContext,
        deps: list[manifests.Dependency],
        findings: list[Finding],
        unresolved: list[str],
    ) -> str | None:
        # CoreCLR rezerwuje kilka GB przestrzeni adresowej na starcie
        # niezależnie od realnego zużycia (jak semgrep, gates/g3_sast.py) —
        # RLIMIT_AS z domyślnej polityki zabija `dotnet` kodem 137.
        sandbox = Sandbox(
            SandboxPolicy(
                network=True, timeout_s=self.budget_s, memory_mb=None, keep_env=self._keep_env()
            )
        )
        by_project: dict[str, set[str]] = {}
        for dep in deps:
            name = manifests.normalize(manifests.NUGET, dep.name)
            project = dotnet.project_for_manifest(change.repo, dep.manifest)
            if project is None:
                unresolved.append(name)
                continue
            by_project.setdefault(project, set()).add(name)

        for project, names in by_project.items():
            try:
                findings.extend(
                    dotnet.run_dotnet_list_vulnerable(
                        change.repo, sandbox, self.id, project, names, timeout_s=self.budget_s
                    )
                )
            except ToolMissing as exc:
                return str(exc)
            except ToolFailed:
                unresolved.extend(sorted(names))
        return None

    # ------------------------------------------------------------------

    def _keep_env(self) -> tuple[str, ...]:
        return tuple(self.config.get("keep_env", ()))

    def _new_deps_by_ecosystem(
        self, change: ChangeContext
    ) -> dict[str, list[manifests.Dependency]]:
        changed_manifests = [
            f for f in change.files if manifests.is_manifest(f.path) and f.status != "D"
        ]
        by_ecosystem: dict[str, list[manifests.Dependency]] = {}
        for changed in changed_manifests:
            head = change.file_at(change.head_sha, changed.path) or ""
            base = change.file_at(change.base_sha, changed.path) or ""
            after = manifests.parse_manifest(changed.path, head)
            before = manifests.parse_manifest(changed.path, base)
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
