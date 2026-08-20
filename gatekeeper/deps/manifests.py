"""Parsowanie manifestów zależności — czyste funkcje, bez sieci i bez gita.

Wykrywamy *nowe* pakiety, więc każdy manifest trzeba sparsować dwa razy:
w wersji z `base` i z `head`. Różnica zbiorów to lista do weryfikacji.
"""

from __future__ import annotations

import json
import re
import tomllib
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path

PYPI = "pypi"
NPM = "npm"
NUGET = "nuget"

_PEP508_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")
_REQ_OPTION = re.compile(r"^\s*-")
_URL_LIKE = re.compile(r"^(https?|git\+|file:|\.{1,2}/)")


@dataclass(frozen=True)
class Dependency:
    ecosystem: str
    name: str
    manifest: str
    raw: str = ""

    @property
    def key(self) -> str:
        return f"{self.ecosystem}:{normalize(self.ecosystem, self.name)}"


def normalize(ecosystem: str, name: str) -> str:
    if ecosystem == PYPI:
        # PEP 503: `-`, `_` i `.` są równoważne.
        return re.sub(r"[-_.]+", "-", name).lower()
    return name.lower()


def is_manifest(path: str) -> bool:
    return manifest_kind(path) is not None


def manifest_kind(path: str) -> str | None:
    name = Path(path).name
    if name == "pyproject.toml":
        return "pyproject"
    if name == "package.json":
        return "package.json"
    if re.fullmatch(r"requirements(-[\w.]+)?\.(txt|in)", name):
        return "requirements"
    if name == "setup.py":
        return "setup.py"
    if name.endswith((".csproj", ".fsproj")):
        return "csproj"
    if name == "Directory.Packages.props":
        return "directory.packages.props"
    if name == "packages.config":
        return "packages.config"
    return None


def parse_manifest(path: str, content: str) -> set[Dependency]:
    kind = manifest_kind(path)
    if kind == "pyproject":
        return parse_pyproject(content, path)
    if kind == "requirements":
        return parse_requirements(content, path)
    if kind == "package.json":
        return parse_package_json(content, path)
    if kind in ("csproj", "directory.packages.props", "packages.config"):
        return parse_csproj_like(content, path)
    return set()


def parse_pyproject(content: str, manifest: str = "pyproject.toml") -> set[Dependency]:
    try:
        data = tomllib.loads(content)
    except tomllib.TOMLDecodeError:
        return set()
    out: set[Dependency] = set()

    project = data.get("project") or {}
    for spec in project.get("dependencies") or []:
        _add_pep508(out, spec, manifest)
    for specs in (project.get("optional-dependencies") or {}).values():
        for spec in specs or []:
            _add_pep508(out, spec, manifest)

    # PEP 735
    for specs in (data.get("dependency-groups") or {}).values():
        for spec in specs or []:
            if isinstance(spec, str):
                _add_pep508(out, spec, manifest)

    poetry = (data.get("tool") or {}).get("poetry") or {}
    for name in (poetry.get("dependencies") or {}):
        if name.lower() != "python":
            out.add(Dependency(PYPI, name, manifest, name))
    for group in (poetry.get("group") or {}).values():
        for name in (group.get("dependencies") or {}):
            if name.lower() != "python":
                out.add(Dependency(PYPI, name, manifest, name))
    return out


def parse_requirements(content: str, manifest: str = "requirements.txt") -> set[Dependency]:
    out: set[Dependency] = set()
    for line in content.splitlines():
        line = line.split(" #", 1)[0].strip()
        if not line or line.startswith("#") or _REQ_OPTION.match(line):
            continue
        if _URL_LIKE.match(line):
            continue
        _add_pep508(out, line, manifest)
    return out


def parse_package_json(content: str, manifest: str = "package.json") -> set[Dependency]:
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return set()
    out: set[Dependency] = set()
    for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        for name, spec in (data.get(section) or {}).items():
            if isinstance(spec, str) and _URL_LIKE.match(spec):
                continue
            out.add(Dependency(NPM, name, manifest, f"{name}@{spec}"))
    return out


def parse_csproj_like(content: str, manifest: str = "app.csproj") -> set[Dependency]:
    """`.csproj`/`.fsproj` (SDK-style), `Directory.Packages.props` (CPM),
    `packages.config` (legacy) — trzy formaty, jedna gramatyka XML.

    Wszystkie trzy używają atrybutu `Include`/`id` na nazwę i `Version`/
    `version` na wersję, więc jeden przebieg po drzewie XML wystarcza —
    nie trzeba rozróżniać formatu przed parsowaniem, tylko przy odczycie
    atrybutów (camelCase w SDK-style vs. lowercase w `packages.config`).
    """
    try:
        root = ET.fromstring(content)
    except ET.ParseError:
        return set()
    out: set[Dependency] = set()
    for el in root.iter():
        tag = _local_tag(el.tag)
        if tag in ("PackageReference", "PackageVersion"):
            name = el.get("Include") or el.get("Update")
            if not name:
                continue
            version = el.get("Version") or (el.findtext(_ns(el.tag, "Version")) or "")
            out.add(Dependency(NUGET, name, manifest, f"{name}@{version}" if version else name))
        elif tag == "package":
            # packages.config: <package id="Newtonsoft.Json" version="13.0.3" .../>
            name = el.get("id")
            if not name:
                continue
            version = el.get("version") or ""
            out.add(Dependency(NUGET, name, manifest, f"{name}@{version}" if version else name))
    return out


def _local_tag(tag: str) -> str:
    """Nazwa elementu bez namespace'u — `.csproj` zwykle go nie ma, ale
    projekty wygenerowane przez niektóre narzędzia go dodają."""
    return tag.rsplit("}", 1)[-1]


def _ns(tag: str, local: str) -> str:
    """Odtwarza namespace z tagu elementu nadrzędnego, dla `findtext` na dziecku."""
    if "}" in tag:
        return f"{tag.split('}')[0]}}}{local}"
    return local


def _add_pep508(out: set[Dependency], spec: str, manifest: str) -> None:
    spec = spec.strip()
    if not spec:
        return
    m = _PEP508_NAME.match(spec)
    if m:
        out.add(Dependency(PYPI, m.group(1), manifest, spec))


def diff_dependencies(
    before: set[Dependency], after: set[Dependency]
) -> list[Dependency]:
    """Pakiety obecne w `after`, a nieobecne w `before` (po normalizacji nazw)."""
    known = {d.key for d in before}
    seen: set[str] = set()
    new: list[Dependency] = []
    for dep in sorted(after, key=lambda d: d.key):
        if dep.key in known or dep.key in seen:
            continue
        seen.add(dep.key)
        new.append(dep)
    return new
