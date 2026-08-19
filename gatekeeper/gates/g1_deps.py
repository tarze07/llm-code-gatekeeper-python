"""G1 — `dep-guard`: weryfikacja nowych zależności.

Klasa defektu, której nie łapie żaden standardowy skaner, bo wszystkie
zakładają, że pakiet wpisany do manifestu istnieje. Agent potrafi wymyślić
nazwę pakietu, a lockfile powstaje razem z kodem — więc CI instaluje dokładnie
to, co agent zmyślił (PLAN.md §1).

Wersja z kamienia 1: **istnienie, wiek, typosquat**. Pobrania, repo źródłowe
i importy niezadeklarowane w manifeście dochodzą w kamieniu 3.
"""

from __future__ import annotations

import time
from typing import Any

from ..core.change import ChangeContext
from ..core.finding import Finding, GateResult, Severity
from ..deps import manifests, typosquat
from ..deps.registries import Registry, RegistryUnavailable, default_registries
from . import Gate, register

DEFAULT_MIN_AGE_DAYS = 90
#: Poniżej tego wieku „podobna nazwa" jest podejrzana. Powyżej — to po prostu
#: ustabilizowany pakiet, który przypadkiem nazywa się podobnie.
TYPOSQUAT_AGE_DAYS = 365


@register
class DepGuard(Gate):
    id = "G1.deps"
    name = "Weryfikacja nowych zależności"
    budget_s = 60.0
    facts = (
        "deps.new_packages",
        "deps.new_package_count",
        "deps.new_external_package",
        "deps.unknown_package",
        "deps.typosquat_suspect",
        "deps.too_young",
        "deps.no_source_repo",
        "deps.manifests_changed",
    )

    def __init__(
        self,
        config: dict[str, Any] | None = None,
        registries: dict[str, Registry] | None = None,
    ) -> None:
        super().__init__(config)
        self._registries = registries
        self.min_age_days = float(self.config.get("min_age_days", DEFAULT_MIN_AGE_DAYS))
        self.internal_prefixes: list[str] = list(self.config.get("internal_prefixes", []))
        self.allowlist = {
            manifests.normalize(manifests.PYPI, n) for n in self.config.get("allow_packages", [])
        }

    @property
    def registries(self) -> dict[str, Registry]:
        if self._registries is None:
            self._registries = default_registries()
        return self._registries

    def run(self, change: ChangeContext) -> GateResult:
        started = time.monotonic()
        changed_manifests = [
            f for f in change.files if manifests.is_manifest(f.path) and f.status != "D"
        ]
        if not changed_manifests:
            return self.result(
                status="pass",
                duration_s=time.monotonic() - started,
                facts=_empty_facts(),
                message="żaden manifest zależności nie został zmieniony",
            )

        new_deps: list[manifests.Dependency] = []
        for changed in changed_manifests:
            head = change.file_at(change.head_sha, changed.path) or ""
            base = change.file_at(change.base_sha, changed.path) or ""
            after = manifests.parse_manifest(changed.path, head)
            before = manifests.parse_manifest(changed.path, base)
            new_deps.extend(manifests.diff_dependencies(before, after))

        new_deps = [d for d in new_deps if not self._is_internal(d)]
        findings: list[Finding] = []
        facts = _empty_facts()
        facts["deps.manifests_changed"] = len(changed_manifests)
        facts["deps.new_packages"] = [d.name for d in new_deps]
        facts["deps.new_package_count"] = len(new_deps)
        facts["deps.new_external_package"] = bool(new_deps)

        if not new_deps:
            return self.result(
                status="pass",
                duration_s=time.monotonic() - started,
                facts=facts,
                message="manifest zmieniony, ale bez nowych pakietów",
            )

        try:
            for dep in new_deps:
                findings.extend(self._check(dep, facts))
        except RegistryUnavailable as exc:
            # Świadomie `error`, nie `pass`: brak odpowiedzi rejestru oznacza,
            # że nie sprawdziliśmy niczego, a nie że jest dobrze.
            return self.result(
                status="error",
                duration_s=time.monotonic() - started,
                facts=facts,
                findings=findings,
                message=f"rejestr pakietów nieosiągalny: {exc}",
            )

        return self.result(
            status="fail" if findings else "pass",
            duration_s=time.monotonic() - started,
            facts=facts,
            findings=findings,
            message=f"sprawdzono {len(new_deps)} nowych pakietów",
        )

    # ------------------------------------------------------------------

    def _is_internal(self, dep: manifests.Dependency) -> bool:
        name = manifests.normalize(dep.ecosystem, dep.name)
        if name in self.allowlist:
            return True
        return any(name.startswith(p.lower()) for p in self.internal_prefixes)

    def _check(self, dep: manifests.Dependency, facts: dict[str, Any]) -> list[Finding]:
        registry = self.registries.get(dep.ecosystem)
        if registry is None:
            return []
        info = registry.fetch(dep.name)
        if not info.exists:
            facts["deps.unknown_package"] = True
            return [
                Finding(
                    gate=self.id,
                    rule_id="deps.unknown_package",
                    severity=Severity.CRITICAL,
                    title=f"Pakiet `{dep.name}` nie istnieje w rejestrze {dep.ecosystem}",
                    failure_scenario=(
                        f"Instalacja zależności na dowolnym środowisku przerwie się błędem "
                        f"„No matching distribution found for {dep.name}”. Jeżeli ktoś "
                        f"opublikuje pakiet o tej nazwie wcześniej niż my zauważymy, "
                        f"zainstalujemy jego kod z uprawnieniami naszego procesu budowania."
                    ),
                    file=dep.manifest,
                    evidence={"snippet": dep.raw, "ecosystem": dep.ecosystem},
                )
            ]

        findings: list[Finding] = []
        neighbours = typosquat.nearest_popular(dep.ecosystem, dep.name)
        age = info.age_days
        young = age is not None and age < self.min_age_days

        if neighbours:
            similar = ", ".join(f"`{n.candidate}`" for n in neighbours)
            suspect = age is None or age < TYPOSQUAT_AGE_DAYS
            if suspect:
                facts["deps.typosquat_suspect"] = True
                findings.append(
                    Finding(
                        gate=self.id,
                        rule_id="deps.typosquat_suspect",
                        severity=Severity.CRITICAL,
                        title=f"Nazwa `{dep.name}` myląco podobna do: {similar}",
                        failure_scenario=(
                            f"Jeżeli `{dep.name}` jest podszyciem pod {similar}, jego kod "
                            f"wykona się przy instalacji i w każdym imporcie — z dostępem do "
                            f"zmiennych środowiskowych procesu budowania, czyli do sekretów CI. "
                            f"Pakiet ma {_age_str(age)}, co nie daje mu żadnej historii."
                        ),
                        file=dep.manifest,
                        evidence={
                            "snippet": dep.raw or dep.name,
                            "similar_to": [n.candidate for n in neighbours],
                            "age_days": age,
                        },
                    )
                )
            else:
                findings.append(
                    Finding(
                        gate=self.id,
                        rule_id="deps.similar_name",
                        severity=Severity.LOW,
                        title=f"Nazwa `{dep.name}` przypomina: {similar}",
                        failure_scenario=(
                            f"Pakiet istnieje od {_age_str(age)}, więc raczej nie jest "
                            f"podszyciem — ale jeżeli agent chciał użyć {similar}, "
                            f"zainstalowaliśmy bibliotekę robiącą coś innego."
                        ),
                        file=dep.manifest,
                        evidence={"snippet": dep.raw or dep.name, "age_days": age},
                    )
                )

        if young:
            facts["deps.too_young"] = True
            findings.append(
                Finding(
                    gate=self.id,
                    rule_id="deps.too_young",
                    severity=Severity.HIGH,
                    title=(
                        f"Pakiet `{dep.name}` ma {_age_str(age)} "
                        f"(próg: {self.min_age_days:g} dni)"
                    ),
                    failure_scenario=(
                        "Pakiet bez historii nie ma za sobą ani przeglądu społeczności, ani "
                        "czasu na wykrycie złośliwego wydania. Jeżeli okaże się porzucony lub "
                        "przejęty, wycofanie go z produkcji wymaga zmiany kodu, nie tylko wersji."
                    ),
                    file=dep.manifest,
                    evidence={"snippet": dep.raw or dep.name, "age_days": age},
                )
            )

        if not info.repo_url:
            facts["deps.no_source_repo"] = True
            findings.append(
                Finding(
                    gate=self.id,
                    rule_id="deps.no_source_repo",
                    severity=Severity.MEDIUM,
                    title=f"Pakiet `{dep.name}` nie podaje repozytorium źródłowego",
                    failure_scenario=(
                        "Przy incydencie bezpieczeństwa nie da się przejrzeć kodu ani historii "
                        "zmian pakietu — jedynym źródłem prawdy jest artefakt z rejestru."
                    ),
                    file=dep.manifest,
                    evidence={"snippet": dep.raw or dep.name},
                )
            )
        return findings


def _empty_facts() -> dict[str, Any]:
    return {
        "deps.new_packages": [],
        "deps.new_package_count": 0,
        "deps.new_external_package": False,
        "deps.unknown_package": False,
        "deps.typosquat_suspect": False,
        "deps.too_young": False,
        "deps.no_source_repo": False,
        "deps.manifests_changed": 0,
    }


def _age_str(age_days: float | None) -> str:
    if age_days is None:
        return "nieznany wiek"
    if age_days < 1:
        return "mniej niż dobę"
    if age_days < 60:
        return f"{age_days:.0f} dni"
    return f"{age_days / 30.4:.0f} mies."
