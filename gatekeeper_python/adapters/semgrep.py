"""`SemgrepRulePackProvider` (`gatekeeper_core.core.plugins`) tego pack'a.

Parser wyniku semgrepa i uruchamianie samego narzędzia są core-owe
(`gatekeeper_core.adapters.semgrep`, wołane przez `G3.sast`) — ten moduł niesie
wyłącznie reguły „nigdy" specyficzne dla Pythona. `rules_dir()` przez
`importlib.resources`, nie przez wspinanie się po `__file__.parent` —
przeżywa instalację z wheela.
"""

from __future__ import annotations

from importlib.resources import files
from pathlib import Path


class PythonRulePack:
    """`ts`/`csharp`-pack rejestrują analogiczne providery ze swoim własnym
    `rules/semgrep/{ts,csharp}.yaml`; reguła uniwersalna
    (`no-wildcard-iam-policy`, json/yaml) żyje w core (`pack_id="core"`)."""

    pack_id = "python"

    def rules_dir(self) -> Path:
        return Path(str(files("gatekeeper_python") / "rules" / "semgrep" / "python.yaml"))
