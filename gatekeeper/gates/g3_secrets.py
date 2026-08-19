"""G3 — sekrety (gitleaks).

Jedyna bramka, która **nie** zawęża się do diffa: skanuje całe drzewo, ale
rozdziela znaleziska na te w zmienionych plikach (blokujące) i zastane
(raportowane jako dług). Bez tego rozdziału pierwsze uruchomienie na starszym
repozytorium blokuje wszystko i bramka ląduje w koszu.

Skanujemy też pliki testowe i fixture'y — to typowe miejsce wycieków
w kodzie od agentów (PLAN.md §G3).
"""

from __future__ import annotations

import time
from pathlib import Path

from ..adapters import gitleaks
from ..core.change import ChangeContext
from ..core.finding import GateResult
from . import Gate, register


@register
class SecretsGate(Gate):
    id = "G3.secrets"
    name = "Sekrety w kodzie i fixture'ach"
    budget_s = 300.0
    facts = (
        "secrets.found",
        "secrets.found_in_diff",
        "secrets.count",
        "secrets.count_in_diff",
        "secrets.unresolved_paths",
        "secrets.tool_version",
    )

    def run(self, change: ChangeContext) -> GateResult:
        started = time.monotonic()
        require_tool = bool(self.config.get("require_tool", True))
        facts = {
            "secrets.found": False,
            "secrets.found_in_diff": False,
            "secrets.count": 0,
            "secrets.count_in_diff": 0,
            "secrets.unresolved_paths": 0,
            "secrets.tool_version": gitleaks.version(),
        }

        if not gitleaks.is_available():
            # Brak narzędzia nie jest zieloną bramką — to brak dowodu.
            return self.result(
                status="error" if require_tool else "skipped",
                duration_s=time.monotonic() - started,
                facts=facts,
                message=f"gitleaks niedostępny: {gitleaks.INSTALL_HINT}",
            )

        source = Path(self.config.get("source") or change.repo)
        config_path = self.config.get("config_path")
        try:
            leaks = gitleaks.scan(
                source=source,
                config_path=Path(config_path) if config_path else None,
                extra_args=list(self.config.get("extra_args", [])),
                timeout_s=float(self.config.get("timeout_s", self.budget_s)),
            )
        except (gitleaks.ToolMissing, gitleaks.ToolFailed) as exc:
            return self.result(
                status="error",
                duration_s=time.monotonic() - started,
                facts=facts,
                message=str(exc),
            )

        changed = set(change.paths())
        findings = []
        unresolved = 0
        for leak in leaks:
            # Ścieżka bezwzględna oznacza, że nie udało się jej sprowadzić do
            # ścieżki repozytorium — wtedy porównanie z diffem jest bezwartościowe
            # i sekret z tego PR-a wyglądałby na zastany. Liczymy takie przypadki
            # jawnie, zamiast po cichu klasyfikować je jako „nie w diffie".
            if leak.file.startswith("/"):
                unresolved += 1
            in_diff = leak.file in changed
            findings.append(gitleaks.to_finding(leak, self.id, in_diff))

        in_diff_count = sum(1 for f in findings if f.rule_id == "secrets.found_in_diff")
        facts.update(
            {
                "secrets.found": bool(findings),
                "secrets.found_in_diff": in_diff_count > 0,
                "secrets.count": len(findings),
                "secrets.count_in_diff": in_diff_count,
                "secrets.unresolved_paths": unresolved,
            }
        )
        message = (
            f"{in_diff_count} sekretów w zmienionych plikach, "
            f"{len(findings) - in_diff_count} zastanych"
        )
        if unresolved:
            message += f" · {unresolved} znalezisk o ścieżce spoza repozytorium"
        return self.result(
            status="fail" if in_diff_count else "pass",
            duration_s=time.monotonic() - started,
            facts=facts,
            findings=findings,
            message=message,
        )
