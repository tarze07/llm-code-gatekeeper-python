"""`ChangeContext` — jedyne miejsce w systemie, które zna gita.

Bramki dostają ten obiekt i nie wołają `git` samodzielnie. Dzięki temu da się
je testować bez repozytorium i uruchamiać na diffie z pliku.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

# Pliki generowane maszynowo. Wyłączone z limitu rozmiaru diffa — bez tego
# każdy PR odświeżający lockfile przekracza próg i zespół w tydzień wyłącza
# bramkę (TOOLS.md §2.2).
DEFAULT_GENERATED_GLOBS: tuple[str, ...] = (
    "**/*.lock",
    "**/package-lock.json",
    "**/yarn.lock",
    "**/pnpm-lock.yaml",
    "**/poetry.lock",
    "**/Pipfile.lock",
    "**/go.sum",
    "**/Cargo.lock",
    "**/*.min.js",
    "**/*.min.css",
    "**/*_pb2.py",
    "**/*_pb2_grpc.py",
    "**/*.pb.go",
    "**/migrations/**",
    "**/__snapshots__/**",
    "**/vendor/**",
    "**/*.snap",
    # .NET: katalogi budowania i kod generowany przez MSBuild/projektant —
    # trafiają do diffa, gdy `.gitignore` repozytorium jest niepełny.
    "**/bin/**",
    "**/obj/**",
    "**/*.designer.cs",
    "**/*.AssemblyInfo.cs",
    "**/*.g.cs",
    "**/*.g.i.cs",
)

DEFAULT_TEST_GLOBS: tuple[str, ...] = (
    "**/test_*.py",
    "**/*_test.py",
    "**/tests/**",
    "**/test/**",
    "**/conftest.py",
    "**/*.test.[jt]s",
    "**/*.test.[jt]sx",
    "**/*.spec.[jt]s",
    "**/*.spec.[jt]sx",
    "**/*_test.go",
    # .NET: konwencja nazewnicza xUnit/NUnit/MSTest (obok katalogowej
    # `**/tests/**`/`**/test/**`, która już działa niezależnie od języka).
    "**/*Tests.cs",
    "**/*Test.cs",
)

_LANGUAGES = {
    ".py": "python",
    ".pyi": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".cs": "csharp",
    ".go": "go",
    ".rs": "rust",
    ".java": "java",
    ".rb": "ruby",
    ".php": "php",
    ".tf": "terraform",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".json": "json",
    ".toml": "toml",
    ".md": "markdown",
    ".sql": "sql",
    ".sh": "shell",
}

_DOC_LANGUAGES = {"markdown", None}

TICKET_RE = re.compile(r"\b([A-Z][A-Z0-9]{1,9}-\d+)\b")


class GitError(RuntimeError):
    pass


def glob_to_regex(pattern: str) -> re.Pattern[str]:
    """Tłumaczy glob ze wsparciem `**` na wyrażenie regularne.

    `fnmatch` nie odróżnia `*` od `**`, przez co `**/auth/**` nie działa tak,
    jak każdy oczekuje po lekturze polityki.
    """
    i, out = 0, ["^"]
    while i < len(pattern):
        ch = pattern[i]
        if pattern.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif pattern.startswith("/**", i):
            out.append("(?:/.*)?")
            i += 3
        elif pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif ch == "*":
            out.append("[^/]*")
            i += 1
        elif ch == "?":
            out.append("[^/]")
            i += 1
        elif ch == "[":
            end = pattern.find("]", i)
            if end == -1:
                out.append(re.escape(ch))
                i += 1
            else:
                out.append(pattern[i : end + 1])
                i = end + 1
        else:
            out.append(re.escape(ch))
            i += 1
    out.append("$")
    return re.compile("".join(out))


def matches_any(path: str, patterns: tuple[str, ...] | list[str]) -> bool:
    return any(glob_to_regex(p).match(path) for p in patterns)


@dataclass
class ChangedFile:
    path: str
    status: str  # A / M / D / R / T
    added: int = 0
    removed: int = 0
    added_lines: set[int] = field(default_factory=set)
    old_path: str | None = None
    binary: bool = False
    generated: bool = False
    test: bool = False

    @property
    def language(self) -> str | None:
        return _LANGUAGES.get(Path(self.path).suffix.lower())

    @property
    def is_docs(self) -> bool:
        return self.language == "markdown" or self.path.startswith("docs/")

    @property
    def churn(self) -> int:
        return self.added + self.removed


@dataclass
class Ticket:
    id: str
    source: str  # branch | commit | explicit
    text: str = ""


@dataclass
class Commit:
    """Commit z zakresu zmiany wraz z trailerami.

    Trailery są jedynym trwałym miejscem, w którym da się zapisać, *co*
    wyprodukowało tę zmianę. Bez nich statystyka „defekty per model"
    z PLAN.md §6 jest niepoliczalna.
    """

    sha: str
    author: str
    author_email: str
    subject: str
    trailers: dict[str, str] = field(default_factory=dict)

    def trailer(self, name: str) -> str | None:
        return self.trailers.get(name.lower())


@dataclass
class DiffConfig:
    generated_globs: tuple[str, ...] = DEFAULT_GENERATED_GLOBS
    test_globs: tuple[str, ...] = DEFAULT_TEST_GLOBS


@dataclass
class ChangeContext:
    repo: Path
    base_sha: str
    head_sha: str
    files: list[ChangedFile]
    ticket: Ticket | None = None
    branch: str | None = None
    commits: list[Commit] = field(default_factory=list)
    config: DiffConfig = field(default_factory=DiffConfig)

    # ---------- widoki na diff ----------

    @property
    def effective_files(self) -> list[ChangedFile]:
        """Pliki, które człowiek faktycznie musiałby przeczytać."""
        return [f for f in self.files if not f.generated]

    @property
    def total_lines(self) -> int:
        return sum(f.churn for f in self.files)

    @property
    def effective_lines(self) -> int:
        return sum(f.churn for f in self.effective_files)

    @property
    def is_docs_only(self) -> bool:
        return bool(self.files) and all(f.is_docs for f in self.files)

    def paths(self) -> list[str]:
        return [f.path for f in self.files]

    def added_lines(self, path: str) -> set[int]:
        for f in self.files:
            if f.path == path:
                return f.added_lines
        return set()

    def is_test_file(self, path: str) -> bool:
        return matches_any(path, self.config.test_globs)

    def match_paths(self, patterns: list[str]) -> list[str]:
        return [f.path for f in self.files if matches_any(f.path, patterns)]

    # ---------- dostęp do treści ----------

    def file_at(self, sha: str, path: str) -> str | None:
        """Treść pliku w danym commicie; `None`, gdy plik nie istniał."""
        try:
            return _git(self.repo, "show", f"{sha}:{path}")
        except GitError:
            return None

    @contextmanager
    def worktree_at(self, sha: str) -> Iterator[Path]:
        """Osobny worktree na wskazanym commicie (potrzebny cross-verify).

        Sprząta po sobie także przy wyjątku — zaległe worktree potrafią
        zapchać runnera w kilka dni.
        """
        tmp = Path(tempfile.mkdtemp(prefix="gatekeeper-wt-"))
        target = tmp / "wt"
        try:
            _git(self.repo, "worktree", "add", "--detach", str(target), sha)
            yield target
        finally:
            subprocess.run(
                ["git", "-C", str(self.repo), "worktree", "remove", "--force", str(target)],
                capture_output=True,
                check=False,
            )
            shutil.rmtree(tmp, ignore_errors=True)

    # ---------- konstrukcja ----------

    @classmethod
    def from_git(
        cls,
        repo: Path | str,
        base_ref: str,
        head_ref: str = "HEAD",
        config: DiffConfig | None = None,
        ticket_id: str | None = None,
    ) -> ChangeContext:
        repo = Path(repo).resolve()
        config = config or DiffConfig()
        head_sha = _git(repo, "rev-parse", head_ref).strip()
        # Merge-base, nie czubek gałęzi bazowej. Inaczej diff zawiera cudze
        # commity i scope-guard wybucha fałszywymi alarmami (TOOLS.md §1.2).
        try:
            base_sha = _git(repo, "merge-base", base_ref, head_sha).strip()
        except GitError:
            base_sha = _git(repo, "rev-parse", base_ref).strip()

        statuses = _parse_name_status(
            _git(repo, "diff", "--name-status", "-M", base_sha, head_sha)
        )
        numstat = _parse_numstat(_git(repo, "diff", "--numstat", "-M", base_sha, head_sha))
        added_lines = parse_unified_diff(
            _git(repo, "diff", "--unified=0", "--no-color", "-M", base_sha, head_sha)
        )

        files: list[ChangedFile] = []
        for path, (status, old_path) in statuses.items():
            added, removed, binary = numstat.get(path, (0, 0, False))
            files.append(
                ChangedFile(
                    path=path,
                    status=status,
                    old_path=old_path,
                    added=added,
                    removed=removed,
                    binary=binary,
                    added_lines=added_lines.get(path, set()),
                    generated=matches_any(path, config.generated_globs),
                    test=matches_any(path, config.test_globs),
                )
            )
        files.sort(key=lambda f: f.path)

        branch = _try_git(repo, "rev-parse", "--abbrev-ref", "HEAD")
        ticket = _detect_ticket(repo, base_sha, head_sha, branch, ticket_id)
        commits = parse_commits(
            _try_git(repo, "log", f"--format={_LOG_FORMAT}", f"{base_sha}..{head_sha}") or ""
        )
        return cls(
            repo=repo,
            base_sha=base_sha,
            head_sha=head_sha,
            files=files,
            ticket=ticket,
            branch=branch,
            commits=commits,
            config=config,
        )


# ---------- parsery (czyste funkcje, testowalne bez gita) ----------

#: Rozdzielamy commity znacznikiem, bo treść commita bywa wielolinijkowa.
_COMMIT_SEP = "\x1e"
_FIELD_SEP = "\x1f"
_LOG_FORMAT = f"{_COMMIT_SEP}%H{_FIELD_SEP}%an{_FIELD_SEP}%ae{_FIELD_SEP}%s{_FIELD_SEP}%b"

_TRAILER_RE = re.compile(r"^([A-Za-z][A-Za-z0-9-]*)\s*:\s*(.+?)\s*$")


def parse_commits(log: str) -> list[Commit]:
    commits: list[Commit] = []
    for chunk in log.split(_COMMIT_SEP):
        if not chunk.strip():
            continue
        parts = chunk.split(_FIELD_SEP)
        if len(parts) < 4:
            continue
        sha, author, email, subject = parts[0].strip(), parts[1], parts[2], parts[3]
        body = parts[4] if len(parts) > 4 else ""
        commits.append(
            Commit(
                sha=sha,
                author=author,
                author_email=email,
                subject=subject,
                trailers=parse_trailers(body),
            )
        )
    return commits


def parse_trailers(body: str) -> dict[str, str]:
    """Trailery z końca treści commita, w postaci `Klucz: wartość`.

    Czytamy od dołu i przerywamy na pierwszej linii, która trailerem nie jest —
    inaczej dwukropek w zwykłym zdaniu opisu zacząłby udawać metadane.
    """
    trailers: dict[str, str] = {}
    for line in reversed(body.strip().splitlines()):
        line = line.strip()
        if not line:
            continue
        match = _TRAILER_RE.match(line)
        if not match:
            break
        trailers[match.group(1).lower()] = match.group(2)
    return trailers

_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


def parse_unified_diff(diff: str) -> dict[str, set[int]]:
    """Mapa: ścieżka → numery dodanych linii po stronie `head`."""
    result: dict[str, set[int]] = {}
    current: str | None = None
    new_lineno = 0
    for line in diff.splitlines():
        if line.startswith("diff --git "):
            current = None
            continue
        if line.startswith("+++ "):
            target = line[4:].strip()
            current = None if target == "/dev/null" else _strip_prefix(target)
            if current is not None:
                result.setdefault(current, set())
            continue
        if line.startswith("--- "):
            continue
        m = _HUNK_RE.match(line)
        if m:
            new_lineno = int(m.group(1))
            continue
        if current is None:
            continue
        if line.startswith("+"):
            result[current].add(new_lineno)
            new_lineno += 1
        elif line.startswith(" "):
            new_lineno += 1
        # linie '-' nie przesuwają licznika po stronie head
    return result


def _parse_name_status(out: str) -> dict[str, tuple[str, str | None]]:
    files: dict[str, tuple[str, str | None]] = {}
    for line in out.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        code = parts[0]
        if code.startswith("R") and len(parts) >= 3:
            files[parts[2]] = ("R", parts[1])
        elif len(parts) >= 2:
            files[parts[1]] = (code[0], None)
    return files


def _parse_numstat(out: str) -> dict[str, tuple[int, int, bool]]:
    stats: dict[str, tuple[int, int, bool]] = {}
    for line in out.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        added_s, removed_s, path = parts[0], parts[1], parts[-1]
        binary = added_s == "-" or removed_s == "-"
        added = 0 if binary else int(added_s)
        removed = 0 if binary else int(removed_s)
        # Zapis zmiany nazwy: "old => new" albo "dir/{a => b}/f".
        if " => " in path:
            path = _resolve_rename(path)
        stats[path] = (added, removed, binary)
    return stats


def _resolve_rename(path: str) -> str:
    m = re.match(r"^(.*)\{(.*) => (.*)\}(.*)$", path)
    if m:
        return f"{m.group(1)}{m.group(3)}{m.group(4)}".replace("//", "/")
    return path.split(" => ")[-1]


def _strip_prefix(path: str) -> str:
    for prefix in ("a/", "b/", "i/", "w/", "c/", "o/"):
        if path.startswith(prefix):
            return path[len(prefix) :]
    return path


def _detect_ticket(
    repo: Path,
    base_sha: str,
    head_sha: str,
    branch: str | None,
    explicit: str | None,
) -> Ticket | None:
    if explicit:
        return Ticket(id=explicit, source="explicit")
    if branch:
        m = TICKET_RE.search(branch.upper())
        if m:
            return Ticket(id=m.group(1), source="branch")
    subjects = _try_git(repo, "log", "--format=%s%n%b", f"{base_sha}..{head_sha}") or ""
    m = TICKET_RE.search(subjects)
    if m:
        return Ticket(id=m.group(1), source="commit", text=subjects[:2000])
    return None


def _git(repo: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise GitError(f"git {' '.join(args)}: {proc.stderr.strip()}")
    return proc.stdout


def _try_git(repo: Path, *args: str) -> str | None:
    try:
        return _git(repo, *args).strip()
    except GitError:
        return None
