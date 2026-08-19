from __future__ import annotations

import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from gatekeeper.deps.registries import PackageInfo


class Repo:
    """Minimalne repozytorium git do testów bramek."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.git("init", "-q", "-b", "main")
        self.git("config", "user.email", "test@example.com")
        self.git("config", "user.name", "Test")
        self.git("config", "commit.gpgsign", "false")

    def git(self, *args: str) -> str:
        proc = subprocess.run(
            ["git", "-C", str(self.path), *args],
            capture_output=True,
            text=True,
            check=True,
        )
        return proc.stdout

    def write(self, rel: str, content: str) -> None:
        target = self.path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")

    def commit(self, message: str) -> str:
        self.git("add", "-A")
        self.git("commit", "-q", "-m", message)
        return self.git("rev-parse", "HEAD").strip()

    def checkout(self, branch: str, create: bool = False) -> None:
        self.git("checkout", "-q", *(["-b"] if create else []), branch)


@pytest.fixture
def repo(tmp_path: Path) -> Repo:
    path = tmp_path / "repo"
    path.mkdir(parents=True, exist_ok=True)
    r = Repo(path)
    r.write("README.md", "# projekt\n")
    r.write("src/app.py", "def hello():\n    return 'hi'\n")
    r.commit("initial")
    return r


class FakeRegistry:
    """Rejestr sterowany słownikiem — testy nie dotykają sieci."""

    def __init__(self, ecosystem: str, packages: dict[str, dict]) -> None:
        self.ecosystem = ecosystem
        self.packages = packages
        self.calls: list[str] = []

    def fetch(self, name: str) -> PackageInfo:
        self.calls.append(name)
        spec = self.packages.get(name.lower())
        if spec is None:
            return PackageInfo(self.ecosystem, name, exists=False)
        age_days = spec.get("age_days", 1000)
        return PackageInfo(
            ecosystem=self.ecosystem,
            name=name,
            exists=True,
            first_release=datetime.now(UTC) - timedelta(days=age_days),
            latest_release=datetime.now(UTC),
            repo_url=spec.get("repo_url", "https://github.com/example/example"),
        )
