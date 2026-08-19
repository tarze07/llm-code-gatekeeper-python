"""Klienci rejestrów pakietów (PyPI, npm) z cache na dysku.

Zasada, od której zależy wiarygodność bramki: **brak odpowiedzi rejestru to
błąd bramki, nigdy ciche „przeszło"**. `RegistryUnavailable` propaguje się do
`GateResult(status="error")`, a polityka decyduje, czy to blokuje.
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from .manifests import NPM, PYPI

DEFAULT_CACHE_DIR = Path.home() / ".cache" / "gatekeeper" / "registry"
POSITIVE_TTL = 24 * 3600
NEGATIVE_TTL = 3600  # pakiet mógł zostać opublikowany minutę temu
TIMEOUT = 10.0


class RegistryUnavailable(RuntimeError):
    pass


@dataclass
class PackageInfo:
    ecosystem: str
    name: str
    exists: bool
    first_release: datetime | None = None
    latest_release: datetime | None = None
    repo_url: str | None = None
    summary: str = ""

    @property
    def age_days(self) -> float | None:
        if self.first_release is None:
            return None
        return (datetime.now(UTC) - self.first_release).total_seconds() / 86400

    def to_cache(self) -> dict[str, Any]:
        data = asdict(self)
        for key in ("first_release", "latest_release"):
            value = getattr(self, key)
            data[key] = value.isoformat() if value else None
        return data

    @classmethod
    def from_cache(cls, data: dict[str, Any]) -> PackageInfo:
        for key in ("first_release", "latest_release"):
            if data.get(key):
                data[key] = datetime.fromisoformat(data[key])
        return cls(**data)


class Registry(Protocol):
    ecosystem: str

    def fetch(self, name: str) -> PackageInfo: ...


class DiskCache:
    def __init__(self, directory: Path | None = None) -> None:
        self.directory = Path(directory or DEFAULT_CACHE_DIR)

    def _path(self, ecosystem: str, name: str) -> Path:
        safe = name.replace("/", "__").replace("@", "_at_")
        return self.directory / ecosystem / f"{safe}.json"

    def get(self, ecosystem: str, name: str) -> PackageInfo | None:
        path = self._path(ecosystem, name)
        if not path.exists():
            return None
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return None
        ttl = POSITIVE_TTL if payload.get("data", {}).get("exists") else NEGATIVE_TTL
        if time.time() - payload.get("fetched_at", 0) > ttl:
            return None
        try:
            return PackageInfo.from_cache(payload["data"])
        except (TypeError, KeyError):
            return None

    def put(self, info: PackageInfo) -> None:
        path = self._path(info.ecosystem, info.name)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps({"fetched_at": time.time(), "data": info.to_cache()}),
            encoding="utf-8",
        )


class HttpRegistry:
    ecosystem = ""

    def __init__(self, cache: DiskCache | None = None, session: Any = None) -> None:
        self.cache = cache if cache is not None else DiskCache()
        self._session = session

    @property
    def session(self) -> Any:
        if self._session is None:
            import requests  # import leniwy: testy nie potrzebują sieci

            self._session = requests.Session()
            self._session.headers["User-Agent"] = "llm-code-gatekeeper/0.1"
        return self._session

    def fetch(self, name: str) -> PackageInfo:
        cached = self.cache.get(self.ecosystem, name)
        if cached is not None:
            return cached
        info = self._fetch_remote(name)
        self.cache.put(info)
        return info

    def _fetch_remote(self, name: str) -> PackageInfo:  # pragma: no cover - interfejs
        raise NotImplementedError

    def _get_json(self, url: str) -> dict[str, Any] | None:
        import requests

        last_error: Exception | None = None
        for attempt in range(3):
            try:
                response = self.session.get(url, timeout=TIMEOUT)
            except requests.RequestException as exc:
                last_error = exc
                time.sleep(0.5 * (attempt + 1))
                continue
            if response.status_code == 404:
                return None
            if response.status_code == 429 or response.status_code >= 500:
                last_error = RuntimeError(f"HTTP {response.status_code}")
                time.sleep(1.0 * (attempt + 1))
                continue
            if response.status_code != 200:
                raise RegistryUnavailable(f"{url}: HTTP {response.status_code}")
            try:
                return response.json()
            except ValueError as exc:
                raise RegistryUnavailable(f"{url}: nieparsowalna odpowiedź") from exc
        raise RegistryUnavailable(f"{url}: {last_error}")


class PyPIRegistry(HttpRegistry):
    ecosystem = PYPI
    base_url = "https://pypi.org/pypi"

    def _fetch_remote(self, name: str) -> PackageInfo:
        data = self._get_json(f"{self.base_url}/{name}/json")
        if data is None:
            return PackageInfo(self.ecosystem, name, exists=False)
        info = data.get("info") or {}
        uploads: list[datetime] = []
        for files in (data.get("releases") or {}).values():
            for f in files or []:
                stamp = f.get("upload_time_iso_8601") or f.get("upload_time")
                parsed = _parse_time(stamp)
                if parsed:
                    uploads.append(parsed)
        urls = info.get("project_urls") or {}
        repo = (
            urls.get("Source")
            or urls.get("Source Code")
            or urls.get("Repository")
            or urls.get("Homepage")
            or info.get("home_page")
        )
        return PackageInfo(
            ecosystem=self.ecosystem,
            name=info.get("name") or name,
            exists=True,
            first_release=min(uploads) if uploads else None,
            latest_release=max(uploads) if uploads else None,
            repo_url=repo,
            summary=(info.get("summary") or "")[:200],
        )


class NpmRegistry(HttpRegistry):
    ecosystem = NPM
    base_url = "https://registry.npmjs.org"

    def _fetch_remote(self, name: str) -> PackageInfo:
        data = self._get_json(f"{self.base_url}/{name.replace('/', '%2f')}")
        if data is None:
            return PackageInfo(self.ecosystem, name, exists=False)
        times = data.get("time") or {}
        repository = data.get("repository")
        repo = repository.get("url") if isinstance(repository, dict) else None
        return PackageInfo(
            ecosystem=self.ecosystem,
            name=data.get("name") or name,
            exists=True,
            first_release=_parse_time(times.get("created")),
            latest_release=_parse_time(times.get("modified")),
            repo_url=repo or data.get("homepage"),
            summary=(data.get("description") or "")[:200],
        )


def default_registries(cache_dir: Path | None = None) -> dict[str, Registry]:
    cache = DiskCache(cache_dir)
    return {PYPI: PyPIRegistry(cache), NPM: NpmRegistry(cache)}


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
