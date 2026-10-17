"""Where things live on this machine.

Every scanner asks a Machine for paths instead of touching Path.home() directly, so
tests and demos can point loot at a fake home folder and get identical behaviour.
"""

from __future__ import annotations

import os
import platform
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping

# Folders where developers keep projects. Searched (shallowly) for .env files.
DEV_ROOT_NAMES = [
    "Projects", "projects", "Code", "code", "dev", "Dev", "src", "repos", "git", "github",
    "work", "Work", "Desktop", "Documents", "www", "sites",
]


@dataclass
class Machine:
    home: Path
    system: str  # "windows" | "darwin" | "linux"
    env: Mapping[str, str] = field(default_factory=dict)
    appdata: Path | None = None  # Windows %APPDATA%
    localappdata: Path | None = None  # Windows %LOCALAPPDATA%
    user: str = "you"

    # -- constructors ---------------------------------------------------------------

    @classmethod
    def current(cls) -> "Machine":
        system = platform.system().lower()
        if system.startswith("win"):
            system = "windows"
        home = Path.home()
        env = dict(os.environ)
        appdata = Path(env["APPDATA"]) if env.get("APPDATA") else home / "AppData" / "Roaming"
        localappdata = Path(env["LOCALAPPDATA"]) if env.get("LOCALAPPDATA") else home / "AppData" / "Local"
        user = env.get("USER") or env.get("USERNAME") or "you"
        return cls(home=home, system=system, env=env, appdata=appdata, localappdata=localappdata, user=user)

    @classmethod
    def fake(cls, home: Path, system: str = "linux", env: Mapping[str, str] | None = None) -> "Machine":
        """A machine rooted at `home`, for tests and demos. Windows-only folders live under home/AppData."""
        return cls(
            home=Path(home),
            system=system,
            env=dict(env or {}),
            appdata=Path(home) / "AppData" / "Roaming",
            localappdata=Path(home) / "AppData" / "Local",
            user="demo",
        )

    # -- helpers --------------------------------------------------------------------

    @property
    def is_windows(self) -> bool:
        return self.system == "windows"

    @property
    def is_mac(self) -> bool:
        return self.system == "darwin"

    def h(self, *parts: str) -> Path:
        return self.home.joinpath(*parts)

    def dev_roots(self) -> list[Path]:
        """Folders worth looking in for project .env files. Only ones that exist."""
        roots = [self.home] + [self.home / name for name in DEV_ROOT_NAMES]
        seen: set[Path] = set()
        out: list[Path] = []
        for r in roots:
            try:
                if r.is_dir() and r.resolve() not in seen:
                    seen.add(r.resolve())
                    out.append(r)
            except OSError:
                continue
        return out

    def display(self, path: Path) -> str:
        """Shorten a path for display: ~/.aws/credentials instead of the full thing."""
        try:
            rel = path.relative_to(self.home)
            return "~/" + rel.as_posix()
        except ValueError:
            return path.as_posix()
