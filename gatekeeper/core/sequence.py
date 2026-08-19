"""Zgodność wsteczna: `run_gates` mieszka teraz w `core.orchestrator`.

Sekwencyjna pętla z kamienia 1 została zastąpiona grafem zależności z budżetami
czasowymi. Ten moduł zostaje, żeby nie łamać importów, i zniknie, gdy przestaną
być używane.
"""

from __future__ import annotations

from .orchestrator import FAST_PATH_GATES, run_gates  # noqa: F401
from .orchestrator import NOT_CHECKED as NOT_CHECKED_MILESTONE_1  # noqa: F401

__all__ = ["run_gates", "FAST_PATH_GATES", "NOT_CHECKED_MILESTONE_1"]
