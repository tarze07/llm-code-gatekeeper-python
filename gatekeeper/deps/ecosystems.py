"""Konkretne `EcosystemProvider` (`core/plugins.py`) — PyPI, npm, NuGet.

Żyje w core, nie w pack'ach per język: `G1.deps`/`G3.sca` są bramkami-agregatorami
core-owymi (patrz `gates/g1_deps.py`, `gates/g3_sca.py`), a manifest+rejestr+
+typosquat+SCA każdego ekosystemu (`deps.manifests`, `deps.registries`,
`deps.typosquat`, `adapters.sca`, `adapters.dotnet_projects`) to infrastruktura
tych bramek, analogicznie do `adapters/base.py` czy `adapters/gitleaks.py`.
Pack językowy (python/ts/csharp) niczego tu nie rejestruje własnego — po
prostu instaluje core, które już samo zna PyPI/npm/NuGet przez entry points
`gatekeeper.dep_ecosystems`.

Same klasy niczego nowego nie liczą — są cienką warstwą nad już istniejącymi,
sprawdzonymi funkcjami. Jedyna nowa logika to `scan_sca()`: przeniesienie 1:1
dawnych `g3_sca.py::ScaGuard._check_pypi/_check_npm/_check_nuget`.
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any

from ..adapters import sca as sca_adapter
from ..adapters.base import ToolFailed
from ..core.plugins import EcosystemScaResult
from ..core.runner import Sandbox, SandboxPolicy
from . import manifests, typosquat
from .registries import DiskCache, NpmRegistry, NuGetRegistry, PyPIRegistry, Registry


class PyPIEcosystem:
    ecosystem = manifests.PYPI
    _KINDS = ("pyproject", "requirements", "setup.py")

    def is_manifest(self, path: str) -> str | None:
        kind = manifests.manifest_kind(path)
        return kind if kind in self._KINDS else None

    def parse_manifest(self, path: str, content: str) -> set[manifests.Dependency]:
        kind = manifests.manifest_kind(path)
        if kind == "pyproject":
            return manifests.parse_pyproject(content, path)
        if kind == "requirements":
            return manifests.parse_requirements(content, path)
        return set()  # "setup.py": rozpoznane jako manifest, ale bez parsera (dług sprzed podziału)

    def normalize(self, name: str) -> str:
        return manifests.normalize(self.ecosystem, name)

    def build_registry(self, cache_dir: Path) -> Registry:
        return PyPIRegistry(DiskCache(cache_dir))

    def popular_packages(self) -> frozenset[str]:
        return typosquat.popular_packages(self.ecosystem)

    def scan_sca(
        self,
        repo: Path,
        gate_id: str,
        deps: list[manifests.Dependency],
        timeout_s: float,
        keep_env: tuple[str, ...],
    ) -> EcosystemScaResult:
        sandbox = Sandbox(SandboxPolicy(network=True, timeout_s=timeout_s, keep_env=keep_env))
        findings: list[Any] = []
        unresolved: list[str] = []
        # Jeden pakiet na wywołanie, NIE jeden requirements.txt na wszystkie
        # nowe zależności naraz: `pip-audit -r` rozwiązuje cały plik jako
        # jedną całość, więc pojedynczy nieistniejący/halucynowany pakiet
        # (który i tak osobno łapie G1.deps) wywala rozwiązywanie dla
        # WSZYSTKICH nowych zależności naraz i gasi dowód na resztę.
        for dep in deps:
            name = manifests.normalize(self.ecosystem, dep.name)
            with tempfile.TemporaryDirectory(prefix="gatekeeper-sca-") as tmp:
                requirements = Path(tmp) / "requirements.txt"
                requirements.write_text((dep.raw or dep.name) + "\n", encoding="utf-8")
                try:
                    findings.extend(
                        sca_adapter.run_pip_audit(
                            repo,
                            sandbox,
                            gate_id,
                            requirements=requirements,
                            new_packages={name},
                            manifest=dep.manifest,
                            timeout_s=timeout_s,
                        )
                    )
                except ToolFailed:
                    # Ten jeden pakiet się nie rozwiązał — zwykle dlatego, że
                    # nie istnieje, co G1.deps już zgłasza osobno. Brak dowodu
                    # dla NIEGO nie ma prawa zgasić dowodu dla reszty.
                    unresolved.append(name)
        return EcosystemScaResult(findings=findings, unresolved=unresolved)


class NpmEcosystem:
    ecosystem = manifests.NPM

    def is_manifest(self, path: str) -> str | None:
        kind = manifests.manifest_kind(path)
        return kind if kind == "package.json" else None

    def parse_manifest(self, path: str, content: str) -> set[manifests.Dependency]:
        if manifests.manifest_kind(path) == "package.json":
            return manifests.parse_package_json(content, path)
        return set()

    def normalize(self, name: str) -> str:
        return manifests.normalize(self.ecosystem, name)

    def build_registry(self, cache_dir: Path) -> Registry:
        return NpmRegistry(DiskCache(cache_dir))

    def popular_packages(self) -> frozenset[str]:
        return typosquat.popular_packages(self.ecosystem)

    def scan_sca(
        self,
        repo: Path,
        gate_id: str,
        deps: list[manifests.Dependency],
        timeout_s: float,
        keep_env: tuple[str, ...],
    ) -> EcosystemScaResult:
        sandbox = Sandbox(SandboxPolicy(network=True, timeout_s=timeout_s, keep_env=keep_env))
        names = {manifests.normalize(self.ecosystem, d.name) for d in deps}
        try:
            findings = sca_adapter.run_npm_audit(repo, sandbox, gate_id, names)
        except ToolFailed:
            # Cały ekosystem naraz (brak `package-lock.json`, npm padł) —
            # ta partia nowych pakietów zostaje bez dowodu, reszta bramki nie.
            return EcosystemScaResult(findings=[], unresolved=sorted(names))
        return EcosystemScaResult(findings=findings, unresolved=[])


class NuGetEcosystem:
    ecosystem = manifests.NUGET
    _KINDS = ("csproj", "directory.packages.props", "packages.config")

    def is_manifest(self, path: str) -> str | None:
        kind = manifests.manifest_kind(path)
        return kind if kind in self._KINDS else None

    def parse_manifest(self, path: str, content: str) -> set[manifests.Dependency]:
        if manifests.manifest_kind(path) in self._KINDS:
            return manifests.parse_csproj_like(content, path)
        return set()

    def normalize(self, name: str) -> str:
        return manifests.normalize(self.ecosystem, name)

    def build_registry(self, cache_dir: Path) -> Registry:
        return NuGetRegistry(DiskCache(cache_dir))

    def popular_packages(self) -> frozenset[str]:
        return typosquat.popular_packages(self.ecosystem)

    def scan_sca(
        self,
        repo: Path,
        gate_id: str,
        deps: list[manifests.Dependency],
        timeout_s: float,
        keep_env: tuple[str, ...],
    ) -> EcosystemScaResult:
        from ..adapters import dotnet_projects as dotnet_adapter

        # CoreCLR rezerwuje kilka GB przestrzeni adresowej na starcie
        # niezależnie od realnego zużycia (jak semgrep, gates/g3_sast.py) —
        # RLIMIT_AS z domyślnej polityki zabija `dotnet` kodem 137.
        sandbox = Sandbox(
            SandboxPolicy(network=True, timeout_s=timeout_s, memory_mb=None, keep_env=keep_env)
        )
        findings: list[Any] = []
        unresolved: list[str] = []
        by_project: dict[str, set[str]] = {}
        for dep in deps:
            name = manifests.normalize(self.ecosystem, dep.name)
            project = dotnet_adapter.project_for_manifest(repo, dep.manifest)
            if project is None:
                unresolved.append(name)
                continue
            by_project.setdefault(project, set()).add(name)

        for project, names in by_project.items():
            try:
                findings.extend(
                    dotnet_adapter.run_dotnet_list_vulnerable(
                        repo, sandbox, gate_id, project, names, timeout_s=timeout_s
                    )
                )
            except ToolFailed:
                unresolved.extend(sorted(names))
        return EcosystemScaResult(findings=findings, unresolved=unresolved)
