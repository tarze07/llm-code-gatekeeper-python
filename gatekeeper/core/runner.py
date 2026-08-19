"""Jedyny punkt uruchamiania procesów zewnętrznych.

Brama uruchamia testy z PR-a, czyli **wykonuje kod napisany przez agenta**,
a obok stoi token CI z prawem zapisu do repozytorium. Dlatego uruchamianie
procesów nie jest tu detalem implementacyjnym, tylko granicą bezpieczeństwa,
i przechodzi przez jedno miejsce.

Trzy warstwy, niezależne od siebie:

1. **Środowisko** — zmienne wyglądające na poświadczenia są usuwane zawsze.
2. **Sieć** — domyślnie odcięta przez `unshare --net`. Nie wymaga roota ani
   kontenera; wymaga przestrzeni nazw użytkownika (Linux). Gdy niedostępne,
   `ExecResult.isolation` mówi o tym wprost, zamiast udawać izolację.
3. **Zasoby** — limit pamięci i czasu, zabijanie całej grupy procesów.

Czego tu nie ma: montowania read-only i pełnego kontenera. To wymaga dockera
albo podmana, więc jest opcjonalne (`ContainerSandbox`) i włącza się, gdy
środowisko je ma.
"""

from __future__ import annotations

import functools
import os
import resource
import shutil
import signal
import subprocess
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

#: Fragmenty nazw zmiennych środowiskowych, które nie mają prawa trafić do
#: uruchamianego procesu.
SECRET_ENV_MARKERS = (
    "TOKEN",
    "SECRET",
    "PASSWORD",
    "PASSWD",
    "CREDENTIAL",
    "API_KEY",
    "APIKEY",
    "ACCESS_KEY",
    "PRIVATE_KEY",
)

Isolation = Literal["container", "network-namespace", "none"]


class SandboxUnavailable(RuntimeError):
    pass


@dataclass(frozen=True)
class SandboxPolicy:
    """Czego wolno uruchamianemu procesowi."""

    network: bool = False
    timeout_s: float = 300.0
    memory_mb: int | None = 4096
    #: Świadomie `None`: RLIMIT_NPROC liczy procesy całego użytkownika, więc
    #: niski limit potrafi wywrócić procesy niezwiązane z bramą.
    max_processes: int | None = None
    keep_env: tuple[str, ...] = ()
    #: Gdy izolacja sieci jest niedostępna, a proces jej nie potrzebuje:
    #: czy pozwolić mu jednak działać (z adnotacją w wyniku), czy przerwać.
    require_isolation: bool = False


@dataclass
class ExecResult:
    returncode: int
    stdout: str
    stderr: str
    duration_s: float
    timed_out: bool = False
    isolation: Isolation = "none"
    command: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out

    def tail(self, limit: int = 500) -> str:
        return (self.stderr or self.stdout)[-limit:].strip()


@dataclass
class Sandbox:
    """Uruchamianie procesów zgodnie z polityką izolacji."""

    policy: SandboxPolicy = field(default_factory=SandboxPolicy)

    def run(
        self,
        command: Sequence[str],
        cwd: Path | str,
        env: dict[str, str] | None = None,
        timeout_s: float | None = None,
        network: bool | None = None,
    ) -> ExecResult:
        want_network = self.policy.network if network is None else network
        timeout = timeout_s if timeout_s is not None else self.policy.timeout_s
        environment = scrub_environment(dict(env or os.environ), self.policy.keep_env)

        isolation: Isolation = "none"
        argv = list(command)
        # Sprawdzamy istnienie programu przed doklejeniem prefiksu izolacji.
        # Z `unshare` brak programu kończy się kodem 127 wewnątrz przestrzeni
        # nazw, a wtedy bramka nie odróżniłaby „brak narzędzia" od „narzędzie
        # padło" — czyli braku dowodu od dowodu problemu.
        if shutil.which(argv[0]) is None:
            raise SandboxUnavailable(f"nie znaleziono programu: {argv[0]}")
        if not want_network:
            if network_isolation_available():
                argv = [*NETNS_PREFIX, *argv]
                isolation = "network-namespace"
            elif self.policy.require_isolation:
                raise SandboxUnavailable(
                    "brak izolacji sieci (przestrzenie nazw użytkownika niedostępne) — "
                    "uruchom bramę w kontenerze albo ustaw `require_isolation: false`"
                )

        started = time.monotonic()
        try:
            proc = subprocess.Popen(  # noqa: S603
                argv,
                cwd=str(cwd),
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                start_new_session=True,  # własna grupa procesów — da się ubić w całości
                preexec_fn=self._limits(),  # noqa: PLW1509
            )
        except FileNotFoundError as exc:
            raise SandboxUnavailable(f"nie znaleziono programu: {argv[0]}") from exc

        timed_out = False
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            _kill_group(proc)
            stdout, stderr = proc.communicate()
        return ExecResult(
            returncode=proc.returncode,
            stdout=stdout or "",
            stderr=stderr or "",
            duration_s=time.monotonic() - started,
            timed_out=timed_out,
            isolation=isolation,
            command=tuple(argv),
        )

    def _limits(self):
        memory_mb = self.policy.memory_mb
        max_processes = self.policy.max_processes

        def apply() -> None:  # pragma: no cover - wykonuje się w procesie potomnym
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            if memory_mb:
                limit = memory_mb * 1024 * 1024
                resource.setrlimit(resource.RLIMIT_AS, (limit, limit))
            if max_processes:
                resource.setrlimit(resource.RLIMIT_NPROC, (max_processes, max_processes))

        return apply


NETNS_PREFIX = ("unshare", "--user", "--map-root-user", "--net", "--")


@functools.lru_cache(maxsize=1)
def network_isolation_available() -> bool:
    """Czy da się odciąć sieć bez roota i bez kontenera."""
    if os.name != "posix" or shutil.which("unshare") is None:
        return False
    probe = subprocess.run(
        [*NETNS_PREFIX, "true"],
        capture_output=True,
        timeout=10,
        check=False,
    )
    return probe.returncode == 0


def scrub_environment(env: dict[str, str], keep: Sequence[str] = ()) -> dict[str, str]:
    """Usuwa zmienne wyglądające na poświadczenia; `keep` przywraca wskazane."""
    keep_set = set(keep)
    return {
        name: value
        for name, value in env.items()
        if name in keep_set or not any(marker in name.upper() for marker in SECRET_ENV_MARKERS)
    }


def describe_isolation() -> str:
    """Jednozdaniowy opis do raportu — brama ma mówić, czego *nie* gwarantuje."""
    if network_isolation_available():
        return "procesy narzędzi uruchamiane bez dostępu do sieci (przestrzeń nazw sieciowych)"
    return (
        "BRAK izolacji sieci — uruchamiane narzędzia i testy z PR-a mają dostęp do sieci; "
        "uruchom bramę na Linuksie z przestrzeniami nazw użytkownika albo w kontenerze"
    )


def _kill_group(proc: subprocess.Popen) -> None:
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError):  # pragma: no cover
        proc.kill()
