"""Findings, masking, and the score.

A Finding is one thing a stealer would walk away with. It carries the category
(what it unlocks), a severity, where it was found, a masked piece of evidence, and
a one-line fix. The secret itself is never stored: `mask()` runs before a Finding
is created.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

SEVERITIES = ["critical", "high", "medium", "low", "info"]
WEIGHTS = {"critical": 25, "high": 10, "medium": 5, "low": 1, "info": 0}
# Each category can cost at most this much, so forty .env secrets do not hide the
# one long-lived cloud key that matters more.
CATEGORY_CAP = 40

CATEGORIES = [
    "Cloud",
    "SSH",
    "Git and GitHub",
    "Package registries",
    "Containers and clusters",
    "Shell history",
    "Project .env files",
    "Environment variables",
    "Browser and wallets",
    "Other tokens",
]


def mask(secret: str) -> str:
    """AKIAIOSFODNN7EXAMPLE -> AKIA…MPLE. Short values become dots. Never returns the input."""
    s = (secret or "").strip()
    if len(s) <= 8:
        return "••••••"
    if len(s) <= 14:
        return s[:2] + "…" + s[-2:]
    return s[:4] + "…" + s[-4:]


def looks_like_placeholder(value: str) -> bool:
    v = value.strip().strip("'\"").lower()
    if not v or len(v) < 6:
        return True
    hints = ("changeme", "change_me", "your-", "your_", "<", ">", "xxx", "example", "placeholder", "todo", "replace", "dummy", "sample", "test", "null", "none")
    return any(h in v for h in hints) or v in {"true", "false", "0", "1"}


@dataclass
class Finding:
    id: str
    category: str
    severity: str
    title: str
    unlocks: str
    fix: str
    path: Path | None = None
    display_path: str = ""
    line: int | None = None
    evidence: str = ""  # already masked
    notes: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(f"bad severity {self.severity}")
        if self.category not in CATEGORIES:
            raise ValueError(f"bad category {self.category}")

    @property
    def weight(self) -> int:
        return WEIGHTS[self.severity]

    @property
    def where(self) -> str:
        return self.display_path + (f":{self.line}" if self.line else "")

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "category": self.category,
            "severity": self.severity,
            "title": self.title,
            "where": self.where,
            "evidence": self.evidence,
            "unlocks": self.unlocks,
            "fix": self.fix,
            "notes": list(self.notes),
        }


def score(findings: Iterable[Finding]) -> tuple[int, str]:
    """100 minus the damage, floored at 0, with a letter grade."""
    by_cat: dict[str, int] = {}
    for f in findings:
        by_cat[f.category] = by_cat.get(f.category, 0) + f.weight
    damage = sum(min(v, CATEGORY_CAP) for v in by_cat.values())
    points = max(0, 100 - damage)
    grade = "A" if points >= 90 else "B" if points >= 75 else "C" if points >= 60 else "D" if points >= 40 else "F"
    return points, grade


def sort_key(f: Finding) -> tuple[int, int, str]:
    return (SEVERITIES.index(f.severity), CATEGORIES.index(f.category), f.title)


def counts(findings: Iterable[Finding]) -> dict[str, int]:
    out = {s: 0 for s in SEVERITIES}
    for f in findings:
        out[f.severity] += 1
    return out
