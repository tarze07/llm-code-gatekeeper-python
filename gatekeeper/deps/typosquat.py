"""Wykrywanie typosquatów i slopsquatów.

Trzy decyzje, które decydują o użyteczności tego modułu:

1. **Lista popularnych pakietów jest zwendorowana w repo**, nie pobierana
   w locie. Pobieranie robiłoby z bramki źródło niedeterminizmu i dodatkowy
   punkt awarii (TOOLS.md §3.2).
2. **Maksymalny dystans zależy od długości nazwy.** Dystans 2 na czteroliterowej
   nazwie oznacza „prawie wszystko" — same fałszywe alarmy.
3. **Zwijanie homoglifów przed liczeniem dystansu**: `rn`→`m`, `l`/`1`→`1`,
   cyrylickie `а`/`е`/`о` → łacińskie. `paramiko` vs `paramlko` to dystans 1,
   ale `rnatplotlib` vs `matplotlib` to bez zwijania dystans 2 przy jednym
   znaku różnicy dla oka.
"""

from __future__ import annotations

import functools
from dataclasses import dataclass
from pathlib import Path

from .manifests import NPM, NUGET, PYPI, normalize

DATA_DIR = Path(__file__).resolve().parent.parent / "data"

_HOMOGLYPHS = {
    "а": "a",  # cyrylica
    "е": "e",
    "о": "o",
    "р": "p",
    "с": "c",
    "х": "x",
    "ѕ": "s",
    "і": "i",
    "0": "o",
    "1": "l",
    "5": "s",
    "3": "e",
    "4": "a",
}


@dataclass(frozen=True)
class Neighbour:
    candidate: str
    distance: int


def canonical(ecosystem: str, name: str) -> str:
    name = normalize(ecosystem, name)
    name = "".join(_HOMOGLYPHS.get(ch, ch) for ch in name)
    name = name.replace("rn", "m").replace("vv", "w")
    return name


def max_distance_for(name: str) -> int:
    return 1 if len(name) <= 6 else 2


def damerau_levenshtein(a: str, b: str, cutoff: int = 2) -> int:
    """Dystans Damerau-Levenshteina z wczesnym przerwaniem.

    Zwraca `cutoff + 1`, gdy dystans przekracza próg — reszta i tak nas nie
    interesuje, a przerwanie skraca przebieg po liście 5000 nazw.
    """
    if abs(len(a) - len(b)) > cutoff:
        return cutoff + 1
    prev2: list[int] = []
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        cur = [i] + [0] * len(b)
        best = cur[0]
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            val = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if i > 1 and j > 1 and ca == b[j - 2] and a[i - 2] == cb:
                val = min(val, prev2[j - 2] + 1)
            cur[j] = val
            best = min(best, val)
        if best > cutoff:
            return cutoff + 1
        prev2, prev = prev, cur
    return prev[len(b)] if prev[len(b)] <= cutoff else cutoff + 1


@functools.lru_cache(maxsize=4)
def popular_packages(ecosystem: str) -> frozenset[str]:
    filename = {PYPI: "top_pypi.txt", NPM: "top_npm.txt", NUGET: "top_nuget.txt"}.get(ecosystem)
    if not filename:
        return frozenset()
    path = DATA_DIR / filename
    if not path.exists():
        return frozenset()
    names = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            names.append(normalize(ecosystem, line))
    return frozenset(names)


def is_popular(ecosystem: str, name: str) -> bool:
    return normalize(ecosystem, name) in popular_packages(ecosystem)


def nearest_popular(ecosystem: str, name: str, limit: int = 3) -> list[Neighbour]:
    """Popularne pakiety o nazwie mylnie podobnej do podanej.

    Pusta lista, gdy sam pakiet jest popularny — pakiet z listy nie jest
    podszywaniem się pod samego siebie.
    """
    if is_popular(ecosystem, name):
        return []
    target = canonical(ecosystem, name)
    if len(target) < 3:
        return []
    cutoff = max_distance_for(target)
    hits: list[Neighbour] = []
    for candidate in popular_packages(ecosystem):
        cand = canonical(ecosystem, candidate)
        if cand == target:
            # Ta sama nazwa po zwinięciu homoglifów: `rnatplotlib` vs `matplotlib`.
            hits.append(Neighbour(candidate, 0))
            continue
        distance = damerau_levenshtein(target, cand, cutoff)
        if distance <= cutoff:
            hits.append(Neighbour(candidate, distance))
    hits.sort(key=lambda h: (h.distance, h.candidate))
    return hits[:limit]
