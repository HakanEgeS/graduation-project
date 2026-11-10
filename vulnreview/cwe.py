"""CWE helpers: normalisation and hierarchy-based agreement.

Relations are taken from the MITRE CWE list v4.9 (packaged in cwe2 3.0.0),
using ChildOf links in the Research Concepts view (CWE-1000) only.

agreement(truth, candidates) returns:
  "exact"     - the ground-truth CWE is among the candidates
  "related"   - a candidate is an ancestor/descendant of the truth within
                MAX_HOPS ChildOf links, or shares a direct parent with it
  "incorrect" - otherwise
"""
from __future__ import annotations

import re
from functools import lru_cache

MAX_HOPS = 2
_CWE_RE = re.compile(r"CWE[-_ ]?0*(\d+)", re.IGNORECASE)


def norm(value) -> str | None:
    """'CWE-089: SQL injection' / 'external/cwe/cwe-089' / 89 -> 'CWE-89'."""
    if value is None:
        return None
    if isinstance(value, int):
        return f"CWE-{value}"
    m = _CWE_RE.search(str(value))
    return f"CWE-{int(m.group(1))}" if m else None


@lru_cache(maxsize=1)
def _db():
    from cwe2.database import Database
    return Database()


@lru_cache(maxsize=None)
def parents(cwe_id: int) -> frozenset[int]:
    try:
        w = _db().get(cwe_id)
    except Exception:
        return frozenset()
    text = getattr(w, "related_weaknesses", "") or ""
    out = set()
    for entry in text.split("::"):
        m = re.search(r"NATURE:ChildOf:CWE ID:(\d+):VIEW ID:1000\b", entry)
        if m:
            out.add(int(m.group(1)))
    return frozenset(out)


def _ancestors(cwe_id: int, hops: int) -> set[int]:
    seen, frontier = set(), {cwe_id}
    for _ in range(hops):
        frontier = {p for c in frontier for p in parents(c)} - seen
        seen |= frontier
    return seen


def related(a: str, b: str) -> bool:
    ia, ib = int(a.split("-")[1]), int(b.split("-")[1])
    if ia == ib:
        return True
    if ib in _ancestors(ia, MAX_HOPS) or ia in _ancestors(ib, MAX_HOPS):
        return True
    return bool(parents(ia) & parents(ib))


def agreement(truth: str, candidates) -> str:
    cands = [c for c in candidates if c]
    if truth in cands:
        return "exact"
    if any(related(truth, c) for c in cands):
        return "related"
    return "incorrect"
