"""G2 — weryfikacja krzyżowa: nowe testy przeciw kodowi **sprzed** zmiany.

Najlepszy stosunek wartości do kosztu w całym systemie. Zasada jest banalna:

    test dla nowej funkcjonalności *musi* polec na starym kodzie.

Jeżeli przechodzi, to nie testuje tego, co deklaruje — a to najczęstszy defekt
kodu z agenta: zielony zestaw testów, który niczego nie dowodzi.

Trzy rzeczy decydują o tym, czy ta bramka przeżyje w zespole:

1. **Obsługa legalnych wyjątków.** Czysty refaktor, dopisanie testów do
   istniejącego kodu i test regresyjny do buga naprawionego wcześniej to
   przypadki, w których test *powinien* przejść na starym kodzie. Autor
   deklaruje je markerem, a bramka liczy te deklaracje i raportuje ich użycie
   — nadużywanie staje się widoczne w liczbach zamiast po cichu drążyć system.
2. **Kontrola izolacji.** Jeżeli pakiet jest zainstalowany w trybie
   edytowalnym, `import` sięgnie po kod z katalogu roboczego zamiast z worktree
   i cała bramka mierzyłaby nowy kod przeciw nowemu. Sprawdzamy to jawnie
   i przy wykryciu przerywamy z błędem zamiast produkować bezwartościowy wynik.
3. **Rozróżnienie porażki od błędu importu.** Test, który poległ na asercji,
   dowodzi czegoś o zachowaniu. Test, który nie zaimportował nieistniejącego
   jeszcze modułu, dowodzi znacznie mniej — i jest liczony osobno.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from ..core.change import ChangeContext, ChangedFile
from ..core.finding import Finding, GateResult, Severity
from ..testing import discovery
from ..testing.pytest_runner import PytestUnavailable, build_env, module_origin, run_pytest
from . import Gate, register

CODE_LANGUAGES = {"python"}


@register
class CrossVerify(Gate):
    id = "G2.cross_verify"
    name = "Nowe testy przeciw kodowi sprzed zmiany"
    budget_s = 600.0
    facts = (
        "tests.new_count",
        "tests.checked",
        "tests.pass_on_pre_change_code",
        "tests.passing_on_old_code",
        "tests.weak_evidence",
        "tests.proved",
        "tests.characterization_used",
        "tests.isolation_broken",
    )

    def run(self, change: ChangeContext) -> GateResult:
        started = time.monotonic()
        facts = _empty_facts()

        production = _production_files(change)
        if not production:
            # Zmiana bez kodu produkcyjnego: stary i nowy kod są identyczne,
            # więc każdy test przeszedłby na „starym" — blokowanie tutaj
            # oznaczałoby blokowanie każdego PR-a dokładającego testy.
            return self.result(
                status="skipped",
                duration_s=time.monotonic() - started,
                facts=facts,
                message="zmiana nie dotyka kodu produkcyjnego — nie ma czego dowodzić",
            )

        candidates = self._collect(change)
        facts["tests.new_count"] = len(candidates)
        if not candidates:
            return self.result(
                status="skipped",
                duration_s=time.monotonic() - started,
                facts=facts,
                message="zmiana w kodzie produkcyjnym bez nowych testów",
            )

        checked = [t for t in candidates if not t.declared_escape]
        declared = [t for t in candidates if t.declared_escape]
        facts["tests.characterization_used"] = len(declared)
        facts["tests.checked"] = len(checked)
        if not checked:
            return self.result(
                status="pass",
                duration_s=time.monotonic() - started,
                facts=facts,
                findings=[_declaration_notice(self.id, declared)] if declared else [],
                message=(
                    f"wszystkie {len(declared)} nowych testów "
                    "zadeklarowano jako charakteryzujące"
                ),
            )

        try:
            outcomes, message = self._run_against_base(change, checked)
        except _IsolationBroken as exc:
            facts["tests.isolation_broken"] = True
            return self.result(
                status="error",
                duration_s=time.monotonic() - started,
                facts=facts,
                message=str(exc),
            )
        except PytestUnavailable as exc:
            return self.result(
                status="error",
                duration_s=time.monotonic() - started,
                facts=facts,
                message=str(exc),
            )

        findings: list[Finding] = []
        passing: list[str] = []
        weak = 0
        proved = 0
        for item in checked:
            outcome = outcomes.get(item.nodeid)
            if outcome is None or outcome.outcome in ("missing", "error", "skipped"):
                weak += 1
                continue
            if outcome.outcome == "failed":
                proved += 1
                continue
            passing.append(item.nodeid)
            findings.append(_useless_test_finding(self.id, item))

        facts.update(
            {
                "tests.pass_on_pre_change_code": bool(passing),
                "tests.passing_on_old_code": passing,
                "tests.weak_evidence": weak,
                "tests.proved": proved,
            }
        )
        if declared:
            findings.append(_declaration_notice(self.id, declared))

        return self.result(
            status="fail" if passing else "pass",
            duration_s=time.monotonic() - started,
            facts=facts,
            findings=findings,
            message=(
                f"{proved} testów dowodzi zmiany, {len(passing)} przechodzi na starym kodzie, "
                f"{weak} bez rozstrzygnięcia · {message}"
            ),
        )

    # ------------------------------------------------------------------

    def _collect(self, change: ChangeContext) -> list[discovery.TestItem]:
        out: list[discovery.TestItem] = []
        for file in change.files:
            if not file.test or file.status == "D" or not file.path.endswith(".py"):
                continue
            head = change.file_at(change.head_sha, file.path) or ""
            base = change.file_at(change.base_sha, file.path) or ""
            out.extend(discovery.changed_tests(base, head, file.path))
        return out

    def _run_against_base(
        self, change: ChangeContext, items: list[discovery.TestItem]
    ) -> tuple[dict[str, Any], str]:
        extra_paths = list(self.config.get("python_path", ["src"]))
        keep_env = tuple(self.config.get("keep_env", []))
        with change.worktree_at(change.base_sha) as worktree:
            overlaid = self._overlay_tests(change, worktree)
            env = build_env(worktree, extra_paths, keep_env)
            self._assert_isolation(change, worktree, env)
            result = run_pytest(
                worktree=worktree,
                nodeids=[i.nodeid for i in items],
                env=env,
                timeout_s=float(self.config.get("timeout_s", self.budget_s)),
                extra_args=list(self.config.get("pytest_args", [])),
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
        self, change: ChangeContext, worktree: Path, env: dict[str, str]
    ) -> None:
        if self.config.get("skip_isolation_check"):
            return
        for module in sorted(_top_level_modules(_production_files(change))):
            origin = module_origin(module, worktree, env)
            if origin is None:
                continue
            if not Path(origin).resolve().is_relative_to(worktree.resolve()):
                raise _IsolationBroken(
                    f"moduł `{module}` importuje się z {origin}, spoza kopii kodu bazowego "
                    "— testy porównywałyby nowy kod z nowym. Najczęstsza przyczyna: pakiet "
                    "zainstalowany w trybie edytowalnym (`pip install -e .`). Uruchom bramkę "
                    "w środowisku bez takiej instalacji albo ustaw `python_path` w polityce."
                )


class _IsolationBroken(RuntimeError):
    pass


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


def _useless_test_finding(gate_id: str, item: discovery.TestItem) -> Finding:
    return Finding(
        gate=gate_id,
        rule_id="tests.pass_on_pre_change_code",
        severity=Severity.HIGH,
        title=f"Test `{item.name}` przechodzi na kodzie sprzed zmiany",
        failure_scenario=(
            f"Test `{item.nodeid}` daje wynik zielony również bez tej zmiany, więc nie "
            f"odróżnia kodu przed od kodu po. Gdyby implementacja została jutro cofnięta "
            f"albo napisana błędnie, ten test nadal by przechodził — czyli nie chroni "
            f"niczego. Jeżeli to celowo test charakteryzujący istniejące zachowanie, "
            f"oznacz go `@pytest.mark.characterization`."
        ),
        file=item.file,
        line=item.lineno,
        evidence={"snippet": item.nodeid, "body_hash": item.body_hash},
    )


def _declaration_notice(gate_id: str, declared: list[discovery.TestItem]) -> Finding:
    names = ", ".join(f"`{i.name}`" for i in declared[:5])
    return Finding(
        gate=gate_id,
        rule_id="tests.characterization_declared",
        severity=Severity.INFO,
        title=f"{len(declared)} testów wyłączono z weryfikacji krzyżowej deklaracją autora",
        failure_scenario=(
            f"Testy {names} są oznaczone markerem zwalniającym z dowodu "
            f"({', '.join(sorted(discovery.ESCAPE_MARKERS))}). "
            "To dopuszczalne przy refaktorze i dopisywaniu testów do istniejącego kodu, ale "
            "rosnąca liczba takich deklaracji oznacza, że bramka przestaje cokolwiek sprawdzać "
            "— liczba jest raportowana w metrykach miesięcznych."
        ),
        file=declared[0].file,
        line=declared[0].lineno,
        confidence=1.0,
        evidence={"snippet": ",".join(i.nodeid for i in declared)},
    )


def _empty_facts() -> dict[str, Any]:
    return {
        "tests.new_count": 0,
        "tests.checked": 0,
        "tests.pass_on_pre_change_code": False,
        "tests.passing_on_old_code": [],
        "tests.weak_evidence": 0,
        "tests.proved": 0,
        "tests.characterization_used": 0,
        "tests.isolation_broken": False,
    }
