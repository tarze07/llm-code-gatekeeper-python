"""G3 — SCA: podatności w nowo dodanych zależnościach Pythona (pip-audit).

Blokujemy wyłącznie na podatnościach w pakietach, które ten PR **wprowadza**
— dług w już zastanych zależnościach to osobny raport tygodniowy, nie
blokada tej zmiany (TOOLS.md §5.1).

Zakres kamienia 3: tylko PyPI. npm audit / Trivy dla innych ekosystemów
zostają w `NOT_CHECKED`, dopóki nie powstanie osobny adapter — to świadome
zawężenie, nie przeoczenie.

Jedyna bramka, która musi dostać sieć: pip-audit pyta o znane podatności
w PyPI/OSV. `network=True` jest tu jawne, nie domyślne (`core.runner`).
"""

from __future__ import annotations

import tempfile
import time
from pathlib import Path

from ..adapters import sca
from ..adapters.base import ToolFailed, ToolMissing
from ..core.change import ChangeContext
from ..core.finding import GateResult
from ..core.runner import Sandbox, SandboxPolicy
from ..deps import manifests
from . import Gate, register


@register
class ScaGuard(Gate):
    id = "G3.sca"
    name = "Podatności w nowych zależnościach (pip-audit)"
    budget_s = 180.0
    facts = (
        "sca.checked_package_count",
        "sca.vulnerable_package_count",
        "sca.unresolved_package_count",
        "sca.finding_count",
        "sca.tool_available",
    )

    def run(self, change: ChangeContext) -> GateResult:
        started = time.monotonic()
        facts = {
            "sca.checked_package_count": 0,
            "sca.vulnerable_package_count": 0,
            "sca.unresolved_package_count": 0,
            "sca.finding_count": 0,
            "sca.tool_available": True,
        }

        new_deps = self._new_pypi_deps(change)
        if not new_deps:
            return self.result(
                status="pass",
                duration_s=time.monotonic() - started,
                facts=facts,
                message="brak nowych zależności PyPI do sprawdzenia",
            )
        facts["sca.checked_package_count"] = len(new_deps)

        require_tool = bool(self.config.get("require_tool", True))
        sandbox = Sandbox(
            SandboxPolicy(
                network=True,
                timeout_s=self.budget_s,
                keep_env=tuple(self.config.get("keep_env", ())),
            )
        )

        # Jeden pakiet na wywołanie, NIE jeden requirements.txt na wszystkie
        # nowe zależności naraz: `pip-audit -r` rozwiązuje cały plik jako
        # jedną całość, więc pojedynczy nieistniejący/halucynowany pakiet
        # (który i tak osobno łapie G1.deps) wywala rozwiązywanie dla
        # WSZYSTKICH nowych zależności naraz i gasi dowód na resztę —
        # znalezione dopiero na żywym uruchomieniu na PR-ze z dwoma nowymi
        # pakietami naraz, nie z dokumentacji pip-audit.
        findings = []
        unresolved: list[str] = []
        for dep in new_deps:
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
                    facts["sca.tool_available"] = False
                    return self.result(
                        status="error" if require_tool else "skipped",
                        duration_s=time.monotonic() - started,
                        facts=facts,
                        message=str(exc),
                    )
                except ToolFailed:
                    # Ten jeden pakiet się nie rozwiązał — zwykle dlatego, że
                    # nie istnieje, co G1.deps już zgłasza osobno. Brak
                    # dowodu dla NIEGO nie ma prawa zgasić dowodu dla reszty
                    # nowych zależności w tym samym PR-ze.
                    unresolved.append(name)

        vulnerable_packages = {f.evidence.get("package") for f in findings}
        facts["sca.finding_count"] = len(findings)
        facts["sca.vulnerable_package_count"] = len(vulnerable_packages)
        facts["sca.unresolved_package_count"] = len(unresolved)

        checked = len(new_deps) - len(unresolved)
        message = (
            f"sprawdzono {checked}/{len(new_deps)} nowych pakietów, "
            f"{len(vulnerable_packages)} z podatnościami"
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

    def _new_pypi_deps(self, change: ChangeContext) -> list[manifests.Dependency]:
        changed_manifests = [
            f for f in change.files if manifests.is_manifest(f.path) and f.status != "D"
        ]
        new_deps: list[manifests.Dependency] = []
        for changed in changed_manifests:
            head = change.file_at(change.head_sha, changed.path) or ""
            base = change.file_at(change.base_sha, changed.path) or ""
            after = manifests.parse_manifest(changed.path, head)
            before = manifests.parse_manifest(changed.path, base)
            new_deps.extend(manifests.diff_dependencies(before, after))
        return [d for d in new_deps if d.ecosystem == manifests.PYPI]
