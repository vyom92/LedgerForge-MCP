from __future__ import annotations

import difflib
import fnmatch
import hashlib
import os
import re
import subprocess
from pathlib import Path
from typing import Any

try:
    from mcp.server import MCPServer
except ImportError:
    # Compatibility with earlier v2 alpha layouts.
    from mcp.server.mcpserver import MCPServer

from mcp.server.transport_security import TransportSecuritySettings


# ===========================================================================
# LedgerForge bridge configuration
# ===========================================================================

# Deliberately hard-coded. This MCP server serves ONE repository only.
REPO = Path("/Users/vyom/Applications/LedgerForge").resolve()

MCP_PATH_ENV = "LEDGERFORGE_MCP_PATH"
PUBLIC_HOST_ENV = "LEDGERFORGE_MCP_HOST"

MAX_SOURCE_FILE_BYTES = 2 * 1024 * 1024
MAX_TOOL_OUTPUT_BYTES = 120_000
MAX_SEARCH_RESULTS = 200
MAX_LIST_RESULTS = 2_000
MAX_SEARCH_LINE_CHARS = 600


# Directory components that must never be exposed through file-content tools.
DENIED_COMPONENTS = {
    ".git",
    ".ssh",
    ".secrets",
    "secrets",
    "credentials",
    "deriveddata",
    "originals",
    "private-originals",
    "private_originals",
    "private-fixtures",
    "private_fixtures",
    "privatefixtures",
}

DENIED_EXACT_FILENAMES = {
    ".env",
    ".netrc",
    ".npmrc",
    "id_rsa",
    "id_ed25519",
}

DENIED_SUFFIXES = {
    ".pem",
    ".key",
    ".p12",
    ".pfx",
    ".sqlite",
    ".sqlite3",
    ".db",
    ".sqlite-wal",
    ".sqlite-shm",
    ".sqlite3-wal",
    ".sqlite3-shm",
    ".db-wal",
    ".db-shm",
}


# ===========================================================================
# Fixed Git execution
# ===========================================================================

def _git_env() -> dict[str, str]:
    env = os.environ.copy()

    # Read-only inspection commands should not take optional Git locks.
    env["GIT_OPTIONAL_LOCKS"] = "0"

    # Never stop waiting for credentials or another interactive prompt.
    env["GIT_TERMINAL_PROMPT"] = "0"

    return env


def run_git(
    *args: str,
    allowed_returncodes: tuple[int, ...] = (0,),
    strip: bool = True,
    timeout: int = 20,
) -> str:
    """
    Run a fixed Git inspection command inside LedgerForge.

    No MCP tool accepts an arbitrary Git command.
    """

    result = subprocess.run(
        ["git", "-C", str(REPO), *args],
        capture_output=True,
        text=True,
        env=_git_env(),
        check=False,
        timeout=timeout,
    )

    if result.returncode not in allowed_returncodes:
        detail = (
            result.stderr.strip()
            or result.stdout.strip()
            or f"exit status {result.returncode}"
        )
        raise RuntimeError(
            f"git {' '.join(args)} failed: {detail}"
        )

    return result.stdout.strip() if strip else result.stdout


def resolve_ref(name: str) -> str | None:
    result = subprocess.run(
        ["git", "-C", str(REPO), "rev-parse", "--verify", name],
        capture_output=True,
        text=True,
        env=_git_env(),
        check=False,
        timeout=10,
    )

    if result.returncode != 0:
        return None

    value = result.stdout.strip()
    return value or None


# ===========================================================================
# Repository-root verification
# ===========================================================================

if not REPO.is_dir():
    raise RuntimeError(
        f"LedgerForge repository does not exist: {REPO}"
    )

actual_root = Path(
    run_git("rev-parse", "--show-toplevel")
).resolve()

if actual_root != REPO:
    raise RuntimeError(
        "Configured LedgerForge path is not the Git worktree root. "
        f"Configured={REPO}, Git={actual_root}"
    )


# ===========================================================================
# Path security
# ===========================================================================

def is_denied_relative_path(relative_path: str) -> bool:
    parts = [
        part.casefold()
        for part in Path(relative_path).parts
    ]

    if any(part in DENIED_COMPONENTS for part in parts):
        return True

    if not parts:
        return True

    filename = parts[-1]

    if filename in DENIED_EXACT_FILENAMES:
        return True

    if filename.startswith(".env."):
        return True

    if any(filename.endswith(suffix) for suffix in DENIED_SUFFIXES):
        return True

    return False


def normalize_repo_path(path: str) -> tuple[str, Path]:
    """
    Resolve a project-relative path and prove it remains inside LedgerForge.

    Absolute paths and symlink escapes are rejected.
    """

    if not path:
        raise ValueError("Path must not be empty.")

    if "\x00" in path:
        raise ValueError("NUL bytes are not permitted in paths.")

    supplied = Path(path)

    if supplied.is_absolute():
        raise PermissionError(
            "Absolute paths are not accepted by LedgerForge Local Bridge."
        )

    candidate = (REPO / supplied).resolve(strict=False)

    try:
        relative = candidate.relative_to(REPO)
    except ValueError as exc:
        raise PermissionError(
            "Path escapes the LedgerForge repository."
        ) from exc

    relative_text = relative.as_posix()

    if relative_text in {"", "."}:
        raise PermissionError(
            "Repository root cannot be used as a file target."
        )

    if is_denied_relative_path(relative_text):
        raise PermissionError(
            "Path is blocked by LedgerForge Local Bridge policy."
        )

    return relative_text, candidate


# ===========================================================================
# Git-visible file sets
#
# `git ls-files --cached --others --exclude-standard` is deliberate:
# ignored files are NOT exposed. This means private/ignored local artifacts
# do not become readable merely because they happen to sit under the repo.
# ===========================================================================

def _path_set_from_git(*args: str) -> set[str]:
    raw = run_git(*args, "-z", strip=False)

    result: set[str] = set()

    for original in raw.split("\0"):
        if not original:
            continue

        try:
            relative, _ = normalize_repo_path(original)
        except (ValueError, PermissionError):
            continue

        result.add(relative)

    return result


def tracked_paths() -> set[str]:
    return _path_set_from_git(
        "ls-files",
        "--cached",
    )


def untracked_paths() -> set[str]:
    return _path_set_from_git(
        "ls-files",
        "--others",
        "--exclude-standard",
    )


def visible_paths() -> set[str]:
    return tracked_paths() | untracked_paths()


def changed_tracked_paths() -> list[str]:
    raw = run_git(
        "diff",
        "--name-only",
        "--no-renames",
        "-z",
        "HEAD",
        "--",
        strip=False,
    )

    paths: list[str] = []

    for original in raw.split("\0"):
        if not original:
            continue

        try:
            relative, _ = normalize_repo_path(original)
        except (ValueError, PermissionError):
            continue

        paths.append(relative)

    return sorted(set(paths))


# ===========================================================================
# Text safety helpers
# ===========================================================================

def read_utf8_file(candidate: Path) -> tuple[bytes, str]:
    if not candidate.exists():
        raise FileNotFoundError(
            f"File does not exist in the working tree: {candidate.name}"
        )

    if not candidate.is_file():
        raise ValueError("Requested path is not a regular file.")

    size = candidate.stat().st_size

    if size > MAX_SOURCE_FILE_BYTES:
        raise ValueError(
            f"File is too large for the bridge ({size} bytes)."
        )

    data = candidate.read_bytes()

    if b"\x00" in data:
        raise ValueError(
            "Binary files are not readable through this MCP tool."
        )

    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(
            "File is not valid UTF-8 text."
        ) from exc

    return data, text


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def truncate_text(
    text: str,
    max_bytes: int,
) -> tuple[str, bool]:
    encoded = text.encode("utf-8")

    if len(encoded) <= max_bytes:
        return text, False

    clipped = encoded[:max_bytes].decode(
        "utf-8",
        errors="ignore",
    )

    return (
        clipped
        + "\n\n...[output truncated by LedgerForge Local Bridge]...",
        True,
    )


def validate_output_limit(max_bytes: int) -> int:
    if max_bytes < 1_000:
        raise ValueError("max_bytes must be at least 1000.")

    if max_bytes > MAX_TOOL_OUTPUT_BYTES:
        raise ValueError(
            f"max_bytes cannot exceed {MAX_TOOL_OUTPUT_BYTES}."
        )

    return max_bytes


# ===========================================================================
# MCP server
# ===========================================================================

mcp = MCPServer(
    "LedgerForge Local Bridge",
    instructions=(
        "Read-only local inspection of the LedgerForge repository. "
        "Only tracked and non-ignored untracked repository files are exposed. "
        "Sensitive paths, ignored files, repository mutation, arbitrary shell, "
        "Git mutation, network access, commit, push, reset, restore, clean, "
        "checkout, switch, stash mutation, and branch mutation are unavailable."
    ),
)


# ===========================================================================
# Tool 1: repository_state
# ===========================================================================

@mcp.tool()
def repository_state() -> dict[str, Any]:
    """
    Return LedgerForge local Git safety state.

    Read-only. Does not fetch or mutate any Git or filesystem state.
    """

    head = resolve_ref("HEAD")
    main = resolve_ref("main")
    origin_main = resolve_ref("origin/main")

    ahead: int | None = None
    behind: int | None = None

    if main and origin_main:
        counts = run_git(
            "rev-list",
            "--left-right",
            "--count",
            "main...origin/main",
        ).split()

        if len(counts) == 2:
            ahead = int(counts[0])
            behind = int(counts[1])

    current_branch = run_git(
        "branch",
        "--show-current",
        allowed_returncodes=(0,),
    )

    status = run_git(
        "status",
        "--porcelain=v2",
        "--branch",
        "--untracked-files=all",
    )

    worktrees = run_git(
        "worktree",
        "list",
        "--porcelain",
    )

    local_branches = run_git(
        "branch",
        "--format=%(refname:short)\t%(objectname)",
    )

    remote_branches = run_git(
        "branch",
        "-r",
        "--format=%(refname:short)\t%(objectname)",
    )

    stashes = run_git(
        "stash",
        "list",
        "--format=%gd\t%H\t%gs",
    )

    tracked_changed = changed_tracked_paths()
    visible_untracked = sorted(untracked_paths())

    return {
        "repository": REPO.name,
        "repository_root": str(REPO),
        "current_branch": current_branch or None,
        "detached_head": not bool(current_branch),
        "head": head,
        "main": main,
        "origin_main": origin_main,
        "main_ahead_of_origin_main": ahead,
        "main_behind_origin_main": behind,
        "tracked_changed_count": len(tracked_changed),
        "visible_untracked_count": len(visible_untracked),
        "tracked_changed_files": tracked_changed,
        "visible_untracked_files": visible_untracked,
        "status_porcelain_v2": status,
        "worktrees": worktrees,
        "local_branches": local_branches,
        "remote_branches": remote_branches,
        "stashes": stashes,
        "notes": [
            "origin/main is the locally recorded remote-tracking ref.",
            "repository_state does not run git fetch.",
            "ignored files are excluded from content tools.",
            "no repository mutation tool is exposed.",
        ],
    }


# ===========================================================================
# Tool 2: list_repo_files
# ===========================================================================

@mcp.tool()
def list_repo_files(
    glob: str | None = None,
    max_results: int = 500,
) -> dict[str, Any]:
    """
    List tracked and non-ignored untracked LedgerForge files.

    Sensitive and ignored paths are excluded.
    """

    if max_results < 1 or max_results > MAX_LIST_RESULTS:
        raise ValueError(
            f"max_results must be between 1 and {MAX_LIST_RESULTS}."
        )

    files = sorted(visible_paths())

    if glob:
        files = [
            path
            for path in files
            if fnmatch.fnmatch(path, glob)
        ]

    total_matches = len(files)
    selected = files[:max_results]

    entries: list[dict[str, Any]] = []

    for relative in selected:
        _, candidate = normalize_repo_path(relative)

        entries.append(
            {
                "path": relative,
                "exists": candidate.is_file(),
                "size_bytes": (
                    candidate.stat().st_size
                    if candidate.is_file()
                    else None
                ),
                "tracked": relative in tracked_paths(),
            }
        )

    return {
        "files": entries,
        "returned": len(entries),
        "total_matches": total_matches,
        "truncated": total_matches > len(entries),
    }


# ===========================================================================
# Tool 3: read_file
# ===========================================================================

@mcp.tool()
def read_file(
    path: str,
    start_line: int = 1,
    end_line: int | None = None,
    include_line_numbers: bool = True,
    max_bytes: int = 80_000,
) -> dict[str, Any]:
    """
    Read bounded UTF-8 text from one LedgerForge file.

    Only tracked or non-ignored untracked files are readable.
    """

    validate_output_limit(max_bytes)

    relative, candidate = normalize_repo_path(path)

    if relative not in visible_paths():
        raise PermissionError(
            "File is ignored, outside Git-visible repository state, "
            "or blocked by policy."
        )

    if start_line < 1:
        raise ValueError("start_line must be at least 1.")

    if end_line is not None and end_line < start_line:
        raise ValueError(
            "end_line must be greater than or equal to start_line."
        )

    data, text = read_utf8_file(candidate)
    lines = text.splitlines()

    if end_line is None:
        resolved_end = len(lines)
    else:
        resolved_end = min(end_line, len(lines))

    selected = lines[start_line - 1 : resolved_end]

    if include_line_numbers:
        rendered = "\n".join(
            f"{number:6d}: {line}"
            for number, line in enumerate(
                selected,
                start=start_line,
            )
        )
    else:
        rendered = "\n".join(selected)

    rendered, truncated = truncate_text(
        rendered,
        max_bytes=max_bytes,
    )

    return {
        "path": relative,
        "sha256": sha256_bytes(data),
        "size_bytes": len(data),
        "total_lines": len(lines),
        "start_line": start_line,
        "end_line": resolved_end,
        "truncated": truncated,
        "content": rendered,
    }


# ===========================================================================
# Tool 4: search_repo
# ===========================================================================

@mcp.tool()
def search_repo(
    query: str,
    regex: bool = False,
    case_sensitive: bool = False,
    path_glob: str | None = None,
    max_results: int = 100,
) -> dict[str, Any]:
    """
    Search tracked and non-ignored untracked LedgerForge UTF-8 text files.

    Search is implemented directly in Python. No shell command is exposed.
    """

    if not query:
        raise ValueError("query must not be empty.")

    if len(query) > 500:
        raise ValueError("query is too long.")

    if max_results < 1 or max_results > MAX_SEARCH_RESULTS:
        raise ValueError(
            f"max_results must be between 1 and {MAX_SEARCH_RESULTS}."
        )

    flags = 0 if case_sensitive else re.IGNORECASE

    compiled: re.Pattern[str] | None = None

    if regex:
        try:
            compiled = re.compile(query, flags)
        except re.error as exc:
            raise ValueError(
                f"Invalid regular expression: {exc}"
            ) from exc

    literal_query = (
        query
        if case_sensitive
        else query.casefold()
    )

    matches: list[dict[str, Any]] = []
    files_scanned = 0
    files_skipped = 0

    for relative in sorted(visible_paths()):
        if path_glob and not fnmatch.fnmatch(
            relative,
            path_glob,
        ):
            continue

        _, candidate = normalize_repo_path(relative)

        if not candidate.is_file():
            continue

        if candidate.stat().st_size > MAX_SOURCE_FILE_BYTES:
            files_skipped += 1
            continue

        try:
            _, text = read_utf8_file(candidate)
        except (ValueError, OSError):
            files_skipped += 1
            continue

        files_scanned += 1

        for line_number, line in enumerate(
            text.splitlines(),
            start=1,
        ):
            if compiled is not None:
                matched = compiled.search(line) is not None
            else:
                haystack = (
                    line
                    if case_sensitive
                    else line.casefold()
                )
                matched = literal_query in haystack

            if not matched:
                continue

            line_text = line

            if len(line_text) > MAX_SEARCH_LINE_CHARS:
                line_text = (
                    line_text[:MAX_SEARCH_LINE_CHARS]
                    + "...[line truncated]"
                )

            matches.append(
                {
                    "path": relative,
                    "line": line_number,
                    "text": line_text,
                }
            )

            if len(matches) >= max_results:
                return {
                    "query": query,
                    "regex": regex,
                    "case_sensitive": case_sensitive,
                    "path_glob": path_glob,
                    "matches": matches,
                    "returned": len(matches),
                    "truncated": True,
                    "files_scanned": files_scanned,
                    "files_skipped": files_skipped,
                }

    return {
        "query": query,
        "regex": regex,
        "case_sensitive": case_sensitive,
        "path_glob": path_glob,
        "matches": matches,
        "returned": len(matches),
        "truncated": False,
        "files_scanned": files_scanned,
        "files_skipped": files_skipped,
    }


# ===========================================================================
# Tool 5: git_diff
# ===========================================================================

@mcp.tool()
def git_diff(
    max_bytes: int = 100_000,
) -> dict[str, Any]:
    """
    Return the tracked working-tree diff against HEAD plus untracked filenames.

    Untracked file CONTENT is intentionally not included here. Use
    get_file_diff(path) for a specific untracked file.
    """

    validate_output_limit(max_bytes)

    changed = changed_tracked_paths()

    if changed:
        diff_text = run_git(
            "diff",
            "--no-color",
            "--no-ext-diff",
            "--no-renames",
            "HEAD",
            "--",
            *changed,
            timeout=30,
        )
    else:
        diff_text = ""

    diff_text, truncated = truncate_text(
        diff_text,
        max_bytes=max_bytes,
    )

    visible_untracked = sorted(untracked_paths())

    return {
        "base": "HEAD",
        "tracked_changed_files": changed,
        "tracked_diff": diff_text,
        "tracked_diff_truncated": truncated,
        "untracked_files": visible_untracked,
        "notes": [
            "Tracked diff includes staged and unstaged changes against HEAD.",
            "Untracked file content is omitted from this aggregate tool.",
            "Use get_file_diff(path) to inspect one untracked file.",
        ],
    }


# ===========================================================================
# Tool 6: get_file_diff
# ===========================================================================

@mcp.tool()
def get_file_diff(
    path: str,
    max_bytes: int = 80_000,
) -> dict[str, Any]:
    """
    Return HEAD-to-working-tree diff for one LedgerForge file.

    For an untracked text file, returns a synthetic /dev/null -> file diff.
    """

    validate_output_limit(max_bytes)

    relative, candidate = normalize_repo_path(path)

    tracked = tracked_paths()
    untracked = untracked_paths()

    if relative in tracked:
        diff_text = run_git(
            "diff",
            "--no-color",
            "--no-ext-diff",
            "--no-renames",
            "HEAD",
            "--",
            relative,
        )

        current_sha: str | None = None

        if candidate.is_file():
            data = candidate.read_bytes()
            current_sha = sha256_bytes(data)

        kind = "tracked"

    elif relative in untracked:
        data, text = read_utf8_file(candidate)

        original_lines: list[str] = []
        current_lines = text.splitlines()

        diff_text = "\n".join(
            difflib.unified_diff(
                original_lines,
                current_lines,
                fromfile="/dev/null",
                tofile=f"b/{relative}",
                lineterm="",
            )
        )

        current_sha = sha256_bytes(data)
        kind = "untracked"

    else:
        raise PermissionError(
            "Path is not a tracked or non-ignored untracked LedgerForge file."
        )

    diff_text, truncated = truncate_text(
        diff_text,
        max_bytes=max_bytes,
    )

    return {
        "path": relative,
        "kind": kind,
        "base": "HEAD" if kind == "tracked" else "/dev/null",
        "current_sha256": current_sha,
        "truncated": truncated,
        "diff": diff_text,
    }


# ===========================================================================
# HTTP transport
# ===========================================================================

MCP_PATH = os.environ.get(MCP_PATH_ENV, "").strip()

if not MCP_PATH:
    raise RuntimeError(
        f"{MCP_PATH_ENV} is not set."
    )

if not MCP_PATH.startswith("/mcp_"):
    raise RuntimeError(
        f"{MCP_PATH_ENV} must begin with /mcp_."
    )

if "/" in MCP_PATH[1:]:
    raise RuntimeError(
        f"{MCP_PATH_ENV} must be one path component."
    )

PUBLIC_HOST = os.environ.get(
    PUBLIC_HOST_ENV,
    "",
).strip()

allowed_hosts = [
    "127.0.0.1:*",
    "localhost:*",
    "[::1]:*",
]

allowed_origins = [
    "http://127.0.0.1:*",
    "http://localhost:*",
    "http://[::1]:*",
]

if PUBLIC_HOST:
    allowed_hosts.extend(
        [
            PUBLIC_HOST,
            f"{PUBLIC_HOST}:*",
        ]
    )

    allowed_origins.extend(
        [
            f"https://{PUBLIC_HOST}",
            f"https://{PUBLIC_HOST}:*",
        ]
    )

transport_security = TransportSecuritySettings(
    enable_dns_rebinding_protection=True,
    allowed_hosts=allowed_hosts,
    allowed_origins=allowed_origins,
)


# ===========================================================================
# Entry point
# ===========================================================================

if __name__ == "__main__":
    mcp.run(
        transport="streamable-http",
        host="127.0.0.1",
        port=8765,
        streamable_http_path=MCP_PATH,
        stateless_http=True,
        json_response=True,
        max_request_body_size=1_000_000,
        transport_security=transport_security,
    )
