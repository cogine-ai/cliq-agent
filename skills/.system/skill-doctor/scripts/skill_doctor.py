#!/usr/bin/env python3
"""Read-only diagnostics for Cliq skills."""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
import json
import os
from pathlib import Path
import re
import sys

LOADER_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
PORTABLE_NAME_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
KNOWN_FIELDS = {
    "name",
    "description",
    "license",
    "compatibility",
    "metadata",
    "allowed-tools",
}


@dataclass
class Root:
    scope: str
    source_kind: str
    source_root: str
    rank: int
    owner_root: str | None = None


@dataclass
class Diagnostic:
    level: str
    code: str
    message: str
    source: str | None = None


@dataclass
class Entry:
    name: str
    scope: str
    source_kind: str
    source_root: str
    skill_dir: str
    skill_file: str
    status: str
    diagnostics: list[Diagnostic]
    rank: int
    shadowed_by: str | None = None


def diag(level: str, code: str, message: str, source: str | None = None) -> Diagnostic:
    return Diagnostic(level=level, code=code, message=message, source=source)


def strip_quotes(value: str) -> str:
    value = value.strip()
    if (value.startswith('"') and value.endswith('"')) or (
        value.startswith("'") and value.endswith("'")
    ):
        return value[1:-1]
    return value


def parse_frontmatter(raw: str, source: str) -> tuple[dict[str, str], str, list[Diagnostic]]:
    match = re.match(r"^\ufeff?---[ \t]*\r?\n(.*?)\r?\n---[ \t]*(?:\r?\n|$)(.*)$", raw, re.DOTALL)
    if not match:
        return {}, "", [diag("error", "missing-frontmatter", "Skill file must begin with frontmatter", source)]

    manifest: dict[str, str] = {}
    diagnostics: list[Diagnostic] = []
    frontmatter = match.group(1)
    for raw_line in frontmatter.splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if raw_line[:1].isspace():
            continue
        if ":" not in stripped:
            diagnostics.append(diag("error", "invalid-frontmatter-line", f"Invalid frontmatter line: {stripped}", source))
            continue
        key, value = stripped.split(":", 1)
        key = key.strip()
        value = value.strip()
        if key not in KNOWN_FIELDS:
            diagnostics.append(diag("warning", "unknown-frontmatter-field", f"Ignoring unknown skill field: {key}", source))
            continue
        if key in ("metadata", "allowed-tools") and not value:
            manifest[key] = ""
            continue
        manifest[key] = strip_quotes(value)

    body = (match.group(2) or "").strip()
    return manifest, body, diagnostics


def is_inside(root: Path, target: Path) -> bool:
    try:
        target.relative_to(root)
        return True
    except ValueError:
        return False


def exists(target: Path) -> bool:
    try:
        return target.exists()
    except OSError:
        return False


def find_git_root(cwd: Path) -> Path:
    current = cwd.resolve()
    while True:
        if exists(current / ".git"):
            return current
        if current.parent == current:
            return cwd.resolve()
        current = current.parent


def cliq_home(home: Path) -> Path:
    return Path(os.environ.get("CLIQ_HOME", str(home / ".cliq"))).expanduser().resolve()


def builtin_root() -> Path:
    return Path(__file__).resolve().parents[2]


def discovery_roots(cwd: Path, home: Path) -> list[Root]:
    start = cwd.resolve()
    git_root = find_git_root(start)
    roots: list[Root] = []
    current = start
    depth = 0
    while True:
        base_rank = 10_000 - depth * 10
        roots.append(Root("project", "project-cliq", str(current / ".cliq" / "skills"), base_rank + 2, str(current)))
        roots.append(Root("project", "project-agents", str(current / ".agents" / "skills"), base_rank + 1, str(current)))
        if current == git_root or current.parent == current:
            break
        current = current.parent
        depth += 1

    roots.extend(
        [
            Root("user", "user-cliq", str(cliq_home(home) / "skills"), 2),
            Root("user", "user-agents", str(home / ".agents" / "skills"), 1),
            Root("builtin", "builtin", str(builtin_root()), 0),
        ]
    )
    return roots


def read_entry(root: Root, skill_dir: Path) -> Entry | None:
    skill_file = skill_dir / "SKILL.md"
    diagnostics: list[Diagnostic] = []
    try:
        skill_file_real = skill_file.resolve(strict=True)
    except OSError:
        return None

    if root.owner_root:
        try:
            owner_real = Path(root.owner_root).resolve(strict=True)
            skill_dir_real = skill_dir.resolve(strict=True)
        except OSError:
            owner_real = None
            skill_dir_real = None
        if (
            owner_real is None
            or skill_dir_real is None
            or not is_inside(owner_real, skill_dir_real)
            or not is_inside(owner_real, skill_file_real)
        ):
            diagnostics.append(
                diag(
                    "error",
                    "project-skill-escape",
                    f"Project skill {skill_dir.name} must stay inside its trusted project root",
                    str(skill_file),
                )
            )

    raw = ""
    if not any(item.level == "error" and item.code == "project-skill-escape" for item in diagnostics):
        try:
            raw = skill_file_real.read_text(encoding="utf-8")
        except OSError as exc:
            diagnostics.append(diag("error", "read-failed", f"Failed to read skill file: {exc}", str(skill_file)))
        except UnicodeDecodeError as exc:
            diagnostics.append(diag("error", "read-failed", f"Failed to read skill file: {exc}", str(skill_file)))

    manifest, body, parse_diags = parse_frontmatter(raw, str(skill_file))
    diagnostics.extend(parse_diags)
    declared_name = manifest.get("name", "")
    description = manifest.get("description", "")

    if not declared_name:
        diagnostics.append(diag("error", "missing-name", "Skill file must declare a name", str(skill_file)))
    elif not LOADER_NAME_RE.match(declared_name):
        diagnostics.append(diag("error", "invalid-name", f"Invalid skill name: {declared_name}", str(skill_file)))
    elif not PORTABLE_NAME_RE.match(declared_name):
        diagnostics.append(
            diag(
                "warning",
                "non-portable-name",
                f"Skill name {declared_name} is loadable by Cliq but not lowercase hyphen-case",
                str(skill_file),
            )
        )

    if not description:
        diagnostics.append(diag("error", "missing-description", "Skill file must declare a description", str(skill_file)))
    elif len(description) > 1024:
        diagnostics.append(diag("warning", "long-description", "Skill description exceeds 1024 characters", str(skill_file)))

    if declared_name and declared_name != skill_dir.name:
        diagnostics.append(
            diag("error", "name-mismatch", f"Skill {skill_dir.name} must declare matching frontmatter name", str(skill_file))
        )

    if not body:
        diagnostics.append(diag("warning", "empty-body", "Skill prompt body is empty", str(skill_file)))

    status = "invalid" if any(item.level == "error" for item in diagnostics) else "available"
    return Entry(
        name=skill_dir.name,
        scope=root.scope,
        source_kind=root.source_kind,
        source_root=root.source_root,
        skill_dir=str(skill_dir),
        skill_file=str(skill_file_real),
        status=status,
        diagnostics=diagnostics,
        rank=root.rank,
    )


def read_root(root: Root) -> list[Entry]:
    source_root = Path(root.source_root).expanduser()
    if not exists(source_root):
        return []
    entries: list[Entry] = []
    try:
        children = sorted(source_root.iterdir(), key=lambda item: item.name)
    except OSError as exc:
        return [
            Entry(
                name=source_root.name,
                scope=root.scope,
                source_kind=root.source_kind,
                source_root=str(source_root),
                skill_dir=str(source_root),
                skill_file="",
                status="invalid",
                diagnostics=[diag("error", "root-read-failed", f"Failed to read skill root: {exc}", str(source_root))],
                rank=root.rank,
            )
        ]
    for child in children:
        if not child.is_dir():
            continue
        entry = read_entry(root, child)
        if entry:
            entries.append(entry)
    return entries


def apply_shadowing(entries: list[Entry]) -> None:
    groups: dict[str, list[Entry]] = {}
    for entry in entries:
        groups.setdefault(entry.name, []).append(entry)
    for group in groups.values():
        ranked = sorted(group, key=lambda item: (-item.rank, item.skill_file))
        winner = ranked[0]
        for entry in ranked[1:]:
            entry.status = "shadowed"
            entry.shadowed_by = winner.skill_file
            entry.diagnostics.append(
                diag(
                    "info",
                    "shadowed",
                    f"Skill {entry.name} is shadowed by {winner.source_kind} {winner.skill_file}",
                    entry.skill_file,
                )
            )


def run(cwd: Path, home: Path) -> tuple[list[Root], list[Entry]]:
    roots = discovery_roots(cwd, home)
    entries: list[Entry] = []
    for root in roots:
        entries.extend(read_root(root))
    apply_shadowing(entries)
    entries.sort(key=lambda item: (-item.rank, item.name, item.skill_file))
    return roots, entries


def render_text(roots: list[Root], entries: list[Entry]) -> None:
    print("Cliq skill doctor")
    print()
    print("Discovery roots:")
    for root in roots:
        marker = "present" if exists(Path(root.source_root).expanduser()) else "missing"
        print(f"- {root.scope}/{root.source_kind}: {root.source_root} ({marker})")
    print()
    if not entries:
        print("No skills found.")
        return

    for entry in entries:
        status = "FAIL" if entry.status == "invalid" else "WARN" if entry.status == "shadowed" else "PASS"
        print(f"{status} {entry.name} [{entry.scope}/{entry.source_kind}] {entry.skill_file}")
        for item in entry.diagnostics:
            print(f"  {item.level.upper()} {item.code}: {item.message}")
    all_diags = [item for entry in entries for item in entry.diagnostics]
    errors = sum(1 for item in all_diags if item.level == "error")
    warnings = sum(1 for item in all_diags if item.level == "warning")
    print()
    print(f"Summary: {len(entries)} skills, {errors} errors, {warnings} warnings")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Diagnose Cliq skill health.")
    parser.add_argument("--cwd", default=os.getcwd(), help="Workspace directory to inspect")
    parser.add_argument("--home", default=str(Path.home()), help="Home directory for user skill roots")
    parser.add_argument("--json", action="store_true", help="Print JSON diagnostics")
    args = parser.parse_args(argv)

    roots, entries = run(Path(args.cwd), Path(args.home))
    if args.json:
        print(json.dumps({"roots": [asdict(root) for root in roots], "skills": [asdict(entry) for entry in entries]}, indent=2))
    else:
        render_text(roots, entries)

    has_errors = any(item.level == "error" for entry in entries for item in entry.diagnostics)
    return 1 if has_errors else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
