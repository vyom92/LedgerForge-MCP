from __future__ import annotations

import difflib
import base64
import secrets
import fnmatch
import hashlib
import hmac
import inspect
import json
import os
import plistlib
import re
import shutil
import signal
import sqlite3
import stat
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Annotated, Literal, Union
from urllib.parse import urlsplit, urlunsplit
from urllib.request import urlopen

from pydantic import AnyHttpUrl, BaseModel, ConfigDict, Field, TypeAdapter, ValidationError
from mcp.server.auth.provider import AccessToken, TokenVerifier
from mcp.server.auth.settings import AuthSettings
from mcp.server.auth.middleware.auth_context import get_access_token

try:
    from mcp.server import MCPServer
except ImportError:
    from mcp.server.mcpserver import MCPServer

from mcp.server.transport_security import TransportSecuritySettings

try:
    from mcp.types import ToolAnnotations
except Exception:  # compatibility with older MCP SDKs
    ToolAnnotations = None  # type: ignore[assignment]


# ==========================================================================
# Configuration
# ==========================================================================

EXECUTOR_VERSION = "2.6.2"
TOOLSET_REVISION = 9
SCHEMA_CONTRACT_REVISION = "2.6.2"
DEFAULT_REPO = Path("/Users/vyom/Applications/LedgerForge").resolve()
REPO_ROOT_ENV = "LEDGERFORGE_EXECUTOR_REPO_ROOT"
EXPECTED_REMOTE_URL_ENV = "LEDGERFORGE_EXECUTOR_EXPECTED_REMOTE_URL"
BRIDGE_ROOT_ENV = "LEDGERFORGE_EXECUTOR_BRIDGE_ROOT"
MAINTENANCE_DESKTOP_ENV = "LEDGERFORGE_EXECUTOR_MAINTENANCE_DESKTOP"
MAINTENANCE_TUNNEL_CONFIG_ENV = "LEDGERFORGE_EXECUTOR_MAINTENANCE_TUNNEL_CONFIG"
REPO = Path(os.environ.get(REPO_ROOT_ENV, str(DEFAULT_REPO))).expanduser().resolve()
BRIDGE_ROOT = Path(os.environ.get(BRIDGE_ROOT_ENV, str(Path.home() / "ledgerforge-mcp-prototype"))).expanduser().resolve()
MAINTENANCE_DESKTOP = Path(os.environ.get(MAINTENANCE_DESKTOP_ENV, str(Path.home() / "Desktop"))).expanduser().resolve()
MAINTENANCE_TUNNEL_CONFIG = Path(os.environ.get(MAINTENANCE_TUNNEL_CONFIG_ENV, str(Path.home() / ".config" / "tunnel-client"))).expanduser().resolve()
DEFAULT_STATE_ROOT = (BRIDGE_ROOT / ".executor-runs-v2_1").resolve()
_state_root_raw = os.environ.get("LEDGERFORGE_EXECUTOR_STATE_ROOT", str(DEFAULT_STATE_ROOT)).strip()
RUNS = Path(_state_root_raw).expanduser().resolve()
try:
    RUNS.relative_to(BRIDGE_ROOT)
except ValueError as exc:
    raise RuntimeError("LEDGERFORGE_EXECUTOR_STATE_ROOT must remain under the executor bridge root.") from exc
if not RUNS.name.startswith(".executor-runs-v2_1"):
    raise RuntimeError("LEDGERFORGE_EXECUTOR_STATE_ROOT must use the .executor-runs-v2_1* namespace.")
OPERATIONS = RUNS / "operations"
LEASES = RUNS / "leases"
JOURNALS = RUNS / "journals"
PROCESS_RECORDS = RUNS / "processes"
EVIDENCE = RUNS / "evidence"
FEATURE_FILE = BRIDGE_ROOT / ".executor-v2.1-features.json"
LEASE_FILE = LEASES / "active.json"
BOOT_FILE = RUNS / "boot.json"

MCP_PATH_ENV = "LEDGERFORGE_EXECUTOR_MCP_PATH"
PUBLIC_HOST_ENV = "LEDGERFORGE_EXECUTOR_MCP_HOST"
BEARER_TOKEN_ENV = "LEDGERFORGE_EXECUTOR_BEARER_TOKEN"
ADMIN_BEARER_TOKEN_ENV = "LEDGERFORGE_EXECUTOR_ADMIN_BEARER_TOKEN"
PUBLIC_URL_ENV = "LEDGERFORGE_EXECUTOR_PUBLIC_URL"
PORT_ENV = "LEDGERFORGE_EXECUTOR_PORT"

VALIDATE_SCRIPT = REPO / "script" / "validate.sh"
BUILD_RUN_SCRIPT = REPO / "script" / "build_and_run.sh"
XCODEBUILD = Path("/usr/bin/xcodebuild")
XCRUN = Path("/usr/bin/xcrun")
SECURITY = Path("/usr/bin/security")
CODESIGN = Path("/usr/bin/codesign")
DEVELOPMENT_TEAM_ENV = "LEDGERFORGE_MCP_DEVELOPMENT_TEAM"
SIGNING_IDENTITY_CLASS_ENV = "LEDGERFORGE_MCP_SIGNING_IDENTITY_CLASS"
DEFAULT_SIGNING_IDENTITY_CLASS = "Apple Development"
XCODE_PROJECT = REPO / "LedgerForge.xcodeproj"
XCODE_SCHEME = "LedgerForge"
XCODE_TEST_PLAN = "TestPlan"
XCODE_DESTINATION = "platform=macOS"
XCODE_TEST_TARGET = "LedgerForgeTests"

MAX_SOURCE_FILE_BYTES = 4 * 1024 * 1024
MAX_TOOL_OUTPUT_BYTES = 160_000
MAX_SEARCH_RESULTS = 250
MAX_LIST_RESULTS = 4_000
MAX_SEARCH_LINE_CHARS = 800
MAX_FILE_OPS = 20
MAX_VALIDATION_SECONDS = 3600
MAX_SQL_ROWS = 500
MAX_SQL_CELL_BYTES = 32_768
MAX_LEASE_SECONDS = 14_400
DEFAULT_LEASE_SECONDS = 7_200
MAX_LOG_SECONDS = 900
MAX_LOG_LINES = 500
MAX_VALIDATION_STATUS_WAIT_SECONDS = 300
MAX_PROVENANCE_LABEL_CHARS = 120
MAX_PRIVATE_STRUCTURED_RESULT_BYTES = 64 * 1024
PRIVATE_RESULT_FILE_ENV = "LEDGERFORGE_PRIVATE_RESULT_FILE"
PRIVATE_RESULT_DOWNLOADS_PREFIX = ".ledgerforge-executor-private-result-"
PRIVATE_RESULT_MARKER_NAME = ".ledgerforge-executor-private-result"
TASK_WORKSPACE_ROOT = (BRIDGE_ROOT / ".executor-task-workspaces").resolve()
TASK_WORKSPACE_MARKER = ".mcp-task-workspace.json"
TASK_WORKSPACE_TAINT_MARKER = ".mcp-private-source-taint.json"
LOCAL_PROCESS_STATES = RUNS / "local-processes"
LOCAL_PROCESS_OUTPUT = RUNS / "local-process-output"
SECRET_REF_FILE = BRIDGE_ROOT / ".executor-secret-refs.json"
MAINTENANCE_ROOT = (BRIDGE_ROOT / ".mcp-maintenance").resolve()
PREPARED_RELEASE_ROOT = MAINTENANCE_ROOT / "prepared-releases"
MAINTENANCE_OPERATIONS = MAINTENANCE_ROOT / "operations"
ARMED_RELEASE_FILE = MAINTENANCE_ROOT / "armed-release.json"
MAINTENANCE_RELEASE_STATE = "release-state.json"
MAINTENANCE_QUALIFICATION_RESULT = "qualification-result.json"
MAINTENANCE_QUALIFICATION_EXIT = "qualification-exit.json"
MAINTENANCE_MAX_COMPONENT_BYTES = 6 * 1024 * 1024
MAINTENANCE_MAX_BLOB_CHUNK_BYTES = 512 * 1024
MAINTENANCE_BLOB_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{2,119}$"
MAINTENANCE_BLOB_MANIFEST = "blob-manifest.json"
MAINTENANCE_BLOB_FILE = "blob.bin"
MAINTENANCE_RELEASE_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{2,119}$"
GENERIC_FS_PLAN_VERSION = "local-fs-reviewed-plan-v2"
PROCESS_PLAN_VERSION = "local-process-reviewed-plan-v2"
MAX_REPOSITORY_PROCESS_CHANGED_PATHS = 200
MAX_GENERIC_FILE_BYTES = 8 * 1024 * 1024
MAX_GENERIC_READ_BYTES = 96 * 1024
MAX_GENERIC_PROCESS_SECONDS = 3600
MAX_LOCAL_PROCESS_PERSISTED_OUTPUT_BYTES = 512 * 1024
SNAPSHOT_TERMINAL_PROCESS_HISTORY_LIMIT = 32
SNAPSHOT_IDLE_WORKSPACE_HISTORY_LIMIT = 24
SNAPSHOT_WORKSPACE_TERMINAL_PROCESS_ID_LIMIT = 16
JOURNAL_VERSION = 1

UUID_PATTERN = r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
EVIDENCE_JOB_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,79}$"
UUIDString = Annotated[str, Field(pattern=UUID_PATTERN, min_length=36, max_length=36)]
HexDigest32To128 = Annotated[str, Field(pattern=r"^[A-Fa-f0-9]{32,128}$", min_length=32, max_length=128)]
Sha256String = Annotated[str, Field(pattern=r"^[A-Fa-f0-9]{64}$", min_length=64, max_length=64)]
ProvenanceLabel = Annotated[str, Field(min_length=1, max_length=MAX_PROVENANCE_LABEL_CHARS)]
LeaseTTLSeconds = Annotated[int, Field(ge=60, le=MAX_LEASE_SECONDS)]
ValidationIntent = Literal["execute_tests", "compile_only"]
ValidationOperation = Literal["build-debug", "build-release", "test-focused", "test-full", "cycle-close"]
PrivateContextName = Literal["axis-card", "amex", "cbq", "hdfc"]
PrivateResultContract = Literal["structural_evidence_v1"]
ValidationResultDetail = Literal["summary", "failures", "diagnostics", "private_result"]
MaintenanceInspectTarget = Literal["executor_source", "main_launcher", "owner_admin", "owner_wrapper", "owner_version", "static_qualifier", "isolated_qualifier", "release_activator", "release_version", "state_root_pointer", "executor_log", "tunnel_log"]
MaintenanceInspectAction = Literal["stat", "hash", "read_bytes", "read_text"]
MaintenanceReleaseAction = Literal["stage", "qualify", "status", "arm", "discard", "upload_chunk", "finalize_blob"]
RootId = Literal["repo", "originals", "derived_data", "executor_artifacts", "ledgerforge_logs", "task_scratch"]
ArtifactKind = Literal["auto", "metadata", "json", "plist", "xcresult", "sqlite"]
GitInspectMode = Literal["state", "diff", "staged-diff", "log", "show", "blame"]
PerformanceProbeKind = Literal["recent-validations", "built-app-size"]
RegressionCampaignId = Literal["toolchain-smoke", "project-metadata-smoke"]
RepoTaskId = Literal["build-and-run-verify", "swift-version", "xcode-project-list", "xcode-version"]
WaitSeconds = Annotated[int, Field(ge=0, le=MAX_VALIDATION_STATUS_WAIT_SECONDS)]
EvidenceConcurrency = Annotated[int, Field(ge=1, le=4)]
ToolOutputBytes = Annotated[int, Field(ge=1000, le=MAX_TOOL_OUTPUT_BYTES)]
ListResultLimit = Annotated[int, Field(ge=1, le=MAX_LIST_RESULTS)]
SearchResultLimit = Annotated[int, Field(ge=1, le=MAX_SEARCH_RESULTS)]
SQLRowLimit = Annotated[int, Field(ge=1, le=MAX_SQL_ROWS)]
TestDiscoveryLimit = Annotated[int, Field(ge=1, le=3000)]
RuntimeLogSeconds = Annotated[int, Field(ge=1, le=MAX_LOG_SECONDS)]
TestSelector = Annotated[str, Field(pattern=r"^[A-Za-z0-9_.:/-]+$", min_length=1)]
TestSelectorList = Annotated[list[TestSelector], Field(max_length=20)]
QUALIFICATION_CRASH_AFTER_FILE_STEP = int(os.environ.get("LEDGERFORGE_EXECUTOR_QUALIFICATION_CRASH_AFTER_FILE_STEP", "0") or "0")
WORKTREE_FINGERPRINT_REVISION = "2"
INDEX_FINGERPRINT_REVISION = "1"
WORKTREE_FINGERPRINT_SEMANTICS = "HEAD + sorted union of changed tracked/untracked/conflicted paths + current path type/mode/content identity; independent of Git status bucket classification"
INDEX_FINGERPRINT_SEMANTICS = "SHA-256 of cached binary diff plus git ls-files -s index listing"

ALLOWED_VALIDATIONS = {
    "build-debug",
    "build-release",
    "test-focused",
    "test-full",
    "cycle-close",
}

PRIVATE_CONTEXTS: dict[str, tuple[str, ...]] = {
    "axis-card": (
        "LEDGERFORGE_AXIS_CARD_PRIVATE_DIRECTORY",
        "LEDGERFORGE_AXIS_CARD_PRIVATE_PASSWORD",
    ),
    "amex": (
        "LEDGERFORGE_PRIVATE_AMEX_DIRECTORY",
    ),
    "cbq": (
        "LEDGERFORGE_PRIVATE_CBQ_TEXT_DIRECTORY",
    ),
    "hdfc": (
        "LEDGERFORGE_PRIVATE_HDFC_ORIGINALS_ROOT",
    ),
}

ALL_PRIVATE_ENV_KEYS = {
    "LEDGERFORGE_PRIVATE_AMEX_DIRECTORY",
    "LEDGERFORGE_AXIS_CARD_PRIVATE_DIRECTORY",
    "LEDGERFORGE_AXIS_CARD_PRIVATE_PASSWORD",
    "LEDGERFORGE_PRIVATE_CBQ_TEXT_DIRECTORY",
    "LEDGERFORGE_PRIVATE_HDFC_ORACLE_FILE",
    "LEDGERFORGE_PRIVATE_HDFC_ORIGINALS_FILE",
    "LEDGERFORGE_PRIVATE_HDFC_ORIGINALS_ROOT",
}
ALL_TEST_ENV_KEYS = set(ALL_PRIVATE_ENV_KEYS) | {"LEDGERFORGE_TEST_HOST", PRIVATE_RESULT_FILE_ENV}

SELECTOR_RE = re.compile(r"^[A-Za-z0-9_.:/-]+$")

SECRET_EXACT_NAMES = {
    ".executor-token",
    ".executor-admin-token",
    ".executor-auth-header",
    ".netrc",
    "id_rsa",
    "id_ed25519",
}
SECRET_SUFFIXES = {".pem", ".p12", ".pfx", ".key"}
SECRET_CONTENT_PATTERNS = [
    re.compile(r"(?i)(authorization\s*:\s*bearer\s+)[^\s]+"),
    re.compile(r"(?i)((?:password|passwd|passphrase)\s*[=:]\s*)[^\s\"']+"),
]

RUNS.mkdir(parents=True, exist_ok=True)
for _directory in (OPERATIONS, LEASES, JOURNALS, PROCESS_RECORDS, EVIDENCE, LOCAL_PROCESS_STATES, LOCAL_PROCESS_OUTPUT):
    _directory.mkdir(parents=True, exist_ok=True)
    os.chmod(_directory, 0o700)
os.chmod(RUNS, 0o700)
TASK_WORKSPACE_ROOT.mkdir(parents=True, exist_ok=True)
os.chmod(TASK_WORKSPACE_ROOT, 0o700)
MAINTENANCE_BLOB_ROOT = MAINTENANCE_ROOT / "blobs"
for _directory in (MAINTENANCE_ROOT, PREPARED_RELEASE_ROOT, MAINTENANCE_OPERATIONS, MAINTENANCE_BLOB_ROOT):
    _directory.mkdir(parents=True, exist_ok=True)
    os.chmod(_directory, 0o700)
EXECUTOR_BOOT_ID = str(uuid.uuid4())

_file_lock = threading.Lock()
_state_lock = threading.Lock()
_validation_lock = threading.Lock()
_git_mutation_lock = threading.Lock()
_operation_lock = threading.Lock()
_lease_transition_lock = threading.RLock()
_lease_lock = threading.RLock()
_process_lock = threading.RLock()
_active_validation: str | None = None
_active_processes: dict[str, subprocess.Popen[str]] = {}
_cancelled_runs: set[str] = set()


# ==========================================================================
# Generic helpers
# ==========================================================================

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_text(text: str) -> str:
    return sha256_bytes(text.encode("utf-8"))


def source_sha256() -> str:
    try:
        return sha256_bytes(Path(__file__).read_bytes())
    except Exception:
        return "unavailable"


def truncate_text(text: str, max_bytes: int) -> tuple[str, bool]:
    encoded = text.encode("utf-8", errors="replace")
    if len(encoded) <= max_bytes:
        return text, False
    clipped = encoded[-max_bytes:].decode("utf-8", errors="ignore")
    return (
        "...[earlier output truncated by LedgerForge Recovery Executor]...\n" + clipped,
        True,
    )


def validate_output_limit(max_bytes: int) -> int:
    if max_bytes < 1000:
        raise ValueError("max_bytes must be at least 1000.")
    if max_bytes > MAX_TOOL_OUTPUT_BYTES:
        raise ValueError(f"max_bytes cannot exceed {MAX_TOOL_OUTPUT_BYTES}.")
    return max_bytes


def is_secret_name(path: Path) -> bool:
    name = path.name.casefold()
    if name in {value.casefold() for value in SECRET_EXACT_NAMES}:
        return True
    if name == ".env" or name.startswith(".env."):
        return True
    return any(name.endswith(suffix) for suffix in SECRET_SUFFIXES)


def current_secret_values() -> list[str]:
    # Keep credential redaction narrow. Private source paths and ordinary test-host
    # environment values are local development metadata, not credentials.
    values: list[str] = []
    for key in (BEARER_TOKEN_ENV, ADMIN_BEARER_TOKEN_ENV, "LEDGERFORGE_AXIS_CARD_PRIVATE_PASSWORD"):
        value = os.environ.get(key, "")
        if value:
            values.append(value)
    return sorted(set(values), key=len, reverse=True)


def sanitize_text(text: str, extra_values: list[str] | None = None) -> str:
    values = current_secret_values()
    if extra_values:
        values.extend(value for value in extra_values if value)
    for value in sorted(set(values), key=len, reverse=True):
        text = text.replace(value, "[REDACTED]")
    for pattern in SECRET_CONTENT_PATTERNS:
        text = pattern.sub(r"\1[REDACTED]", text)
    return text


def sanitize_source_text(text: str, extra_values: list[str] | None = None) -> str:
    values = current_secret_values()
    if extra_values:
        values.extend(value for value in extra_values if value)
    for value in sorted(set(values), key=len, reverse=True):
        text = text.replace(value, "[REDACTED]")
    for pattern in SECRET_CONTENT_PATTERNS:
        text = pattern.sub(r"\1[REDACTED]", text)
    return text


def read_utf8_source(candidate: Path) -> tuple[bytes, str]:
    data = bounded_file_bytes(candidate)
    if b"\x00" in data:
        raise ValueError("Binary file. Use artifact_inspect for supported binary artifacts.")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("File is not UTF-8 text.") from exc
    return data, sanitize_source_text(text)


def sanitize_object(value: Any) -> Any:
    if isinstance(value, str):
        return sanitize_text(value)
    if isinstance(value, list):
        return [sanitize_object(item) for item in value]
    if isinstance(value, tuple):
        return [sanitize_object(item) for item in value]
    if isinstance(value, dict):
        return {str(k): sanitize_object(v) for k, v in value.items()}
    return value


def bounded_file_bytes(candidate: Path) -> bytes:
    if not candidate.exists():
        raise FileNotFoundError("File does not exist.")
    if not candidate.is_file():
        raise ValueError("Requested path is not a regular file.")
    if is_secret_name(candidate):
        raise PermissionError("Credential/token configuration is not readable through MCP.")
    size = candidate.stat().st_size
    if size > MAX_SOURCE_FILE_BYTES:
        raise ValueError(f"File is too large for direct read ({size} bytes).")
    return candidate.read_bytes()


def read_utf8(candidate: Path) -> tuple[bytes, str]:
    data = bounded_file_bytes(candidate)
    if b"\x00" in data:
        raise ValueError("Binary file. Use artifact_inspect for supported binary artifacts.")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("File is not UTF-8 text.") from exc
    return data, sanitize_text(text)


def safe_remote_url(raw: str) -> str:
    try:
        parts = urlsplit(raw)
        host = parts.hostname or ""
        port = f":{parts.port}" if parts.port else ""
        return urlunsplit((parts.scheme, host + port, parts.path, parts.query, ""))
    except Exception:
        return "[unavailable]"



# ==========================================================================\n# v2.1 execution ownership, recovery, output and feature helpers\n# ==========================================================================\n
SAFE_VALIDATION_ENV_KEYS = {
    "HOME", "USER", "LOGNAME", "SHELL", "PATH", "TMPDIR", "LANG", "LC_ALL",
    "DEVELOPER_DIR", "SDKROOT", "TOOLCHAINS", "NSUnbufferedIO", "CI", "TERM",
    "SSH_AUTH_SOCK", "COMMAND_MODE",
}

CORE_FEATURES = {
    "execution-lease",
    "execution-lease-resume",
    "durable-operation-provenance",
    "startup-reconciliation",
    "durable-file-journal",
    "process-ownership",
    "private-jit-credentials",
    "safe-validation-environment",
    "canonical-remote-identity",
    "bounded-structured-output",
    "sqlite-read-sandbox",
    "schema-contract-digest",
    "disconnect-resilient-inflight-fencing",
    "private-development-signing",
    "binary-safe-filesystem",
    "registered-local-roots",
    "task-workspaces",
    "reviewed-local-process",
    "durable-local-process",
    "secret-reference-non-echo",
    "local-owner-break-glass",
    "synthetic-repo-qualification",
    "durable-validation-result-retrieval",
    "owned-resource-snapshot",
    "task-workspace-close",
    "executor-help",
    "admin-maintenance",
    "durable-release-handoff",
    "durable-release-blob-ingestion",
    "private-source-taint-enforcement",
    "repository-process-effect-bounds",
    "extended-durable-waits",
}

EVIDENCE_FEATURES = {
    "structured-xcresult",
    "validation-failure-taxonomy",
    "validation-state-binding",
    "precommit-privacy-scan",
    "cycle-close-evidence",
    "test-discovery",
    "documentation-sync-preflight",
    "validation-intent-contract",
    "zero-test-fail-closed",
    "private-build-diagnostics",
    "controlled-runtime",
    "bounded-runtime-logs",
    "same-owner-lease-evidence",
}

OPTIONAL_FEATURES = {
    "test-impact-advisor",
    "performance-probes",
    "regression-campaigns",
    "swift-xcode-audit",
    "repository-recovery-analysis",
    "fixture-provenance-inspection",
    "private-context-matrix",
    "ci-status-inspection",
}

TOOL_ANNOTATION_CONTRACT: dict[str, dict[str, bool]] = {
    "executor_capabilities": {"read_only": True, "destructive": False, "idempotent": False, "open_world": False},
    "host_status": {"read_only": True, "destructive": False, "idempotent": False, "open_world": False},
    "workspace_state": {"read_only": True, "destructive": False, "idempotent": False, "open_world": False},
    "execution_lease_status": {"read_only": True, "destructive": False, "idempotent": False, "open_world": False},
    "executor_recovery_status": {"read_only": True, "destructive": False, "idempotent": False, "open_world": False},
    "execution_snapshot": {"read_only": True, "destructive": False, "idempotent": False, "open_world": False},
    "list_files": {"read_only": True, "destructive": False, "idempotent": False, "open_world": False},
    "read_file": {"read_only": True, "destructive": False, "idempotent": False, "open_world": False},
    "search_files": {"read_only": True, "destructive": False, "idempotent": False, "open_world": False},
    "artifact_inspect": {"read_only": True, "destructive": False, "idempotent": False, "open_world": False},
    "git_inspect": {"read_only": True, "destructive": False, "idempotent": False, "open_world": False},
    "test_discovery": {"read_only": True, "destructive": False, "idempotent": False, "open_world": False},
    "documentation_sync_preflight": {"read_only": True, "destructive": False, "idempotent": False, "open_world": False},
    "test_impact_advisor": {"read_only": True, "destructive": False, "idempotent": False, "open_world": False},
    "performance_probe": {"read_only": True, "destructive": False, "idempotent": False, "open_world": False},
    "swift_xcode_audit": {"read_only": True, "destructive": False, "idempotent": False, "open_world": False},
    "repository_recovery_analysis": {"read_only": True, "destructive": False, "idempotent": False, "open_world": False},
    "fixture_provenance_inspect": {"read_only": True, "destructive": False, "idempotent": False, "open_world": False},
    "runtime_status": {"read_only": True, "destructive": False, "idempotent": False, "open_world": False},
    "runtime_logs": {"read_only": True, "destructive": False, "idempotent": False, "open_world": False},
    "precommit_privacy_scan": {"read_only": True, "destructive": False, "idempotent": False, "open_world": False},
    "cycle_close_evidence": {"read_only": True, "destructive": False, "idempotent": False, "open_world": False},
    "acquire_execution_lease": {"read_only": False, "destructive": False, "idempotent": True, "open_world": False},
    "heartbeat_execution_lease": {"read_only": False, "destructive": False, "idempotent": True, "open_world": False},
    "resume_execution_lease": {"read_only": False, "destructive": False, "idempotent": False, "open_world": False},
    "release_execution_lease": {"read_only": False, "destructive": False, "idempotent": True, "open_world": False},
    "apply_file_ops": {"read_only": False, "destructive": True, "idempotent": True, "open_world": False},
    "git_fetch_origin": {"read_only": False, "destructive": False, "idempotent": True, "open_world": True},
    "git_stage": {"read_only": False, "destructive": True, "idempotent": True, "open_world": False},
    "git_commit": {"read_only": False, "destructive": False, "idempotent": True, "open_world": False},
    "git_push": {"read_only": False, "destructive": False, "idempotent": True, "open_world": True},
    "run_repo_task": {"read_only": False, "destructive": False, "idempotent": True, "open_world": False},
    "start_validation": {"read_only": False, "destructive": False, "idempotent": True, "open_world": False},
    "validation_status": {"read_only": True, "destructive": False, "idempotent": False, "open_world": False},
    "validation_result": {"read_only": True, "destructive": False, "idempotent": False, "open_world": False},
    "cancel_validation": {"read_only": False, "destructive": True, "idempotent": True, "open_world": False},
    "runtime_launch": {"read_only": False, "destructive": False, "idempotent": True, "open_world": False},
    "runtime_stop": {"read_only": False, "destructive": True, "idempotent": True, "open_world": False},
    "run_regression_campaign": {"read_only": False, "destructive": False, "idempotent": True, "open_world": False},
    "private_context_matrix": {"read_only": False, "destructive": False, "idempotent": True, "open_world": False},
    "ci_status_inspection": {"read_only": True, "destructive": False, "idempotent": False, "open_world": True},
    "evidence_batch": {"read_only": True, "destructive": False, "idempotent": True, "open_world": False},
    "local_fs_inspect": {"read_only": True, "destructive": False, "idempotent": True, "open_world": False},
    "local_fs_mutate": {"read_only": False, "destructive": True, "idempotent": True, "open_world": False},
    "task_workspace": {"read_only": False, "destructive": True, "idempotent": True, "open_world": False},
    "process_start": {"read_only": False, "destructive": True, "idempotent": True, "open_world": False},
    "process_status": {"read_only": True, "destructive": False, "idempotent": False, "open_world": False},
    "process_wait": {"read_only": True, "destructive": False, "idempotent": False, "open_world": False},
    "process_cancel": {"read_only": False, "destructive": True, "idempotent": True, "open_world": False},
    "process_result": {"read_only": True, "destructive": False, "idempotent": False, "open_world": False},
    "executor_help": {"read_only": True, "destructive": False, "idempotent": False, "open_world": False},
    "validation_wait_result": {"read_only": True, "destructive": False, "idempotent": False, "open_world": False},
    "maintenance_status": {"read_only": True, "destructive": False, "idempotent": False, "open_world": False},
    "maintenance_file_inspect": {"read_only": True, "destructive": False, "idempotent": True, "open_world": False},
    "maintenance_release": {"read_only": False, "destructive": True, "idempotent": True, "open_world": False},
}


def parse_iso(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def atomic_write_json(path: Path, value: dict[str, Any], mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + f".{uuid.uuid4().hex}.tmp")
    data = json.dumps(sanitize_object(value), indent=2, sort_keys=True).encode("utf-8")
    with temp.open("wb") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())
    os.chmod(temp, mode)
    os.replace(temp, path)
    try:
        directory_fd = os.open(str(path.parent), os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except OSError:
        pass


def serialized_size(value: Any) -> int:
    return len(json.dumps(sanitize_object(value), ensure_ascii=False, separators=(",", ":")).encode("utf-8"))


def enforce_structured_output(value: dict[str, Any], max_bytes: int) -> dict[str, Any]:
    validate_output_limit(max_bytes)
    size = serialized_size(value)
    if size > max_bytes:
        raise ValueError(f"Structured output exceeds max_bytes ({size} > {max_bytes}). Narrow the request.")
    return value


def schema_contract_digest() -> str:
    payload = {
        "revision": SCHEMA_CONTRACT_REVISION,
        "toolset_revision": TOOLSET_REVISION,
        "annotations": TOOL_ANNOTATION_CONTRACT,
        "core_features": sorted(CORE_FEATURES),
        "evidence_features": sorted(EVIDENCE_FEATURES),
        "optional_features": sorted(OPTIONAL_FEATURES),
        "validations": sorted(ALLOWED_VALIDATIONS),
        "private_contexts": sorted(PRIVATE_CONTEXTS),
    }
    return sha256_text(json.dumps(payload, sort_keys=True, separators=(",", ":")))


def load_feature_config() -> dict[str, Any]:
    defaults = {
        "core": True,
        "evidence": True,
        "optional": True,
        "ci_status_inspection": False,
    }
    if not FEATURE_FILE.is_file():
        return defaults
    try:
        raw = json.loads(FEATURE_FILE.read_text(encoding="utf-8"))
        if isinstance(raw, dict):
            for key in defaults:
                if key in raw and isinstance(raw[key], bool):
                    defaults[key] = raw[key]
    except Exception:
        pass
    return defaults


def feature_enabled(group: str, name: str | None = None) -> bool:
    config = load_feature_config()
    if not bool(config.get(group, False)):
        return False
    if name == "ci-status-inspection":
        return bool(config.get("ci_status_inspection", False))
    return True


def require_feature(group: str, name: str | None = None) -> None:
    if not feature_enabled(group, name):
        label = name or group
        raise PermissionError(f"Executor feature is installed but disabled: {label}")


def safe_validation_base_env() -> dict[str, str]:
    env: dict[str, str] = {}
    for key in SAFE_VALIDATION_ENV_KEYS:
        value = os.environ.get(key)
        if value:
            env[key] = value
    for key, value in os.environ.items():
        if key.startswith("LC_") and value:
            env[key] = value
    env.setdefault("HOME", str(Path.home()))
    env.setdefault("PATH", "/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin")
    env.setdefault("TMPDIR", os.environ.get("TMPDIR") or "/tmp")
    return env


def keychain_axis_password() -> str:
    result = subprocess.run(
        ["/usr/bin/security", "find-generic-password", "-s", "com.ledgerforge.recovery-executor", "-a", "axis-private-acceptance", "-w"],
        capture_output=True, text=True, check=False, timeout=10,
    )
    value = result.stdout.rstrip("\n") if result.returncode == 0 else ""
    if not value:
        raise RuntimeError("Private context axis-card credential is not available in Keychain.")
    return value


def axis_keychain_available() -> bool:
    result = subprocess.run(
        ["/usr/bin/security", "find-generic-password", "-s", "com.ledgerforge.recovery-executor", "-a", "axis-private-acceptance"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False, timeout=5,
    )
    return result.returncode == 0


def private_context_available(name: str) -> bool:
    if name not in PRIVATE_CONTEXTS:
        return False
    for key in PRIVATE_CONTEXTS[name]:
        if key == "LEDGERFORGE_AXIS_CARD_PRIVATE_PASSWORD":
            if not axis_keychain_available():
                return False
        elif not os.environ.get(key, ""):
            return False
    return True


def lease_token_digest(token: str) -> str:
    return sha256_text("ledgerforge-executor-lease-v1:" + token)


def read_active_lease_raw() -> dict[str, Any] | None:
    if not LEASE_FILE.is_file():
        return None
    try:
        data = json.loads(LEASE_FILE.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def lease_is_expired(lease: dict[str, Any]) -> bool:
    try:
        return datetime.now(timezone.utc) >= parse_iso(str(lease["expires_at"]))
    except Exception:
        return True


def public_lease_view(lease: dict[str, Any] | None) -> dict[str, Any]:
    if not lease:
        return {"active": False}
    return {
        "active": not lease_is_expired(lease) and lease.get("status") == "active",
        "lease_id": lease.get("lease_id"),
        "execution_id": lease.get("execution_id"),
        "authorization_digest": lease.get("authorization_digest"),
        "owner_label": lease.get("owner_label"),
        "provenance_label": lease.get("provenance_label"),
        "baseline_head": lease.get("baseline_head"),
        "baseline_worktree_fingerprint": lease.get("baseline_worktree_fingerprint"),
        "acquired_at": lease.get("acquired_at"),
        "heartbeat_at": lease.get("heartbeat_at"),
        "expires_at": lease.get("expires_at"),
        "sequence": lease.get("sequence"),
        "executor_boot_id": lease.get("executor_boot_id"),
        "status": lease.get("status"),
        "token_exposed": False,
    }


def require_execution_lease(lease_id: str, lease_token: str, *, extend_seconds: int = DEFAULT_LEASE_SECONDS) -> dict[str, Any]:
    if not lease_id or not lease_token:
        raise PermissionError("A valid execution lease_id and lease_token are required.")
    with _lease_lock:
        lease = read_active_lease_raw()
        if not lease or lease.get("status") != "active":
            raise PermissionError("No active execution lease.")
        if lease_is_expired(lease):
            lease["status"] = "expired"
            lease["expired_at"] = now_iso()
            atomic_write_json(LEASE_FILE, lease)
            raise PermissionError("Execution lease expired.")
        if not hmac.compare_digest(str(lease.get("lease_id", "")), lease_id):
            raise PermissionError("Execution lease_id does not own the repository writer lease.")
        expected_digest = str(lease.get("token_digest", ""))
        if not expected_digest or not hmac.compare_digest(expected_digest, lease_token_digest(lease_token)):
            raise PermissionError("Execution lease token mismatch.")
        now = datetime.now(timezone.utc)
        lease["heartbeat_at"] = now.isoformat()
        lease["expires_at"] = (now + timedelta(seconds=min(max(extend_seconds, 60), MAX_LEASE_SECONDS))).isoformat()
        lease["sequence"] = int(lease.get("sequence", 0)) + 1
        atomic_write_json(LEASE_FILE, lease)
        return lease


def latest_owned_file_state_for_lease(lease: dict[str, Any]) -> dict[str, Any] | None:
    # Newest completed non-dry-run file mutation state durably attributed to this lease.
    candidates: list[tuple[str, dict[str, Any]]] = []
    for path in OPERATIONS.glob("*.json"):
        try:
            receipt = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if receipt.get("status") != "completed" or receipt.get("action") != "apply_file_ops":
            continue
        if receipt.get("lease_id") != lease.get("lease_id"):
            continue
        if receipt.get("execution_id") != lease.get("execution_id"):
            continue
        if receipt.get("authorization_digest") != lease.get("authorization_digest"):
            continue
        result = receipt.get("result")
        if not isinstance(result, dict) or result.get("dry_run") is not False:
            continue
        if not result.get("head") or not result.get("ending_worktree_fingerprint") or not result.get("ending_index_fingerprint"):
            continue
        candidates.append((str(receipt.get("completed_at") or ""), result))
    if not candidates:
        return None
    candidates.sort(key=lambda row: row[0])
    return candidates[-1][1]


def resumable_lease_state_binding(lease: dict[str, Any], head: str, worktree: str, index: str) -> str | None:
    if (
        lease.get("baseline_head") == head
        and lease.get("baseline_worktree_fingerprint") == worktree
        and lease.get("baseline_index_fingerprint") == index
    ):
        return "baseline"

    bound = lease.get("validated_state")
    if (
        isinstance(bound, dict)
        and bound.get("repository_mutated") is False
        and bound.get("head") == head
        and bound.get("worktree_fingerprint") == worktree
        and bound.get("index_fingerprint") == index
    ):
        return "validated-state"

    owned = latest_owned_file_state_for_lease(lease)
    if (
        isinstance(owned, dict)
        and owned.get("head") == head
        and owned.get("ending_worktree_fingerprint") == worktree
        and owned.get("ending_index_fingerprint") == index
    ):
        return "owned-file-state"

    return None


def mark_lease_validation_state(lease_id: str, lease_token: str, *, run_id: str, starting: bool) -> dict[str, Any]:
    lease = require_execution_lease(lease_id, lease_token, extend_seconds=MAX_VALIDATION_SECONDS + 600)
    with _lease_lock:
        lease = read_active_lease_raw() or lease
        lease["active_validation_run_id"] = run_id if starting else None
        lease["validation_state_at"] = now_iso()
        atomic_write_json(LEASE_FILE, lease)
        return lease


def invalidate_lease_validation_binding(lease: dict[str, Any], reason: str) -> None:
    with _lease_lock:
        current = read_active_lease_raw()
        if not current or current.get("lease_id") != lease.get("lease_id"):
            return
        current["validated_state"] = None
        current["validation_invalidated_at"] = now_iso()
        current["validation_invalidated_reason"] = reason
        atomic_write_json(LEASE_FILE, current)


def bind_validated_state(lease_id: str, lease_token: str, run_id: str, state: dict[str, Any]) -> None:
    lease = require_execution_lease(lease_id, lease_token)
    with _lease_lock:
        lease = read_active_lease_raw() or lease
        lease["validated_state"] = {
            "run_id": run_id,
            "head": state.get("ending_head"),
            "worktree_fingerprint": state.get("ending_worktree_fingerprint") or worktree_fingerprint(),
            "index_fingerprint": state.get("ending_index_fingerprint") or index_fingerprint(),
            "exit_code": state.get("exit_code"),
            "repository_mutated": state.get("repository_mutated"),
            "failure_classification": state.get("failure_classification"),
            "validation_intent": state.get("validation_intent"),
            "publication_eligible": state.get("publication_eligible", True),
            "bound_at": now_iso(),
        }
        lease["active_validation_run_id"] = None
        atomic_write_json(LEASE_FILE, lease)


def validate_bound_state_for_publication(lease: dict[str, Any], *, require_success: bool = True) -> dict[str, Any]:
    bound = lease.get("validated_state")
    if not isinstance(bound, dict):
        raise RuntimeError("No validation state is bound to this execution lease.")
    if require_success and bound.get("exit_code") != 0:
        raise RuntimeError("Bound validation did not succeed.")
    if require_success and bound.get("publication_eligible") is False:
        raise RuntimeError("Bound validation is compile-only and cannot authorize publication.")
    if bound.get("repository_mutated"):
        raise RuntimeError("Bound validation reported repository mutation.")
    if bound.get("head") != resolve_ref("HEAD"):
        raise RuntimeError("HEAD changed after validation.")
    current_worktree_fingerprint = worktree_fingerprint()
    if bound.get("worktree_fingerprint") != current_worktree_fingerprint:
        raise RuntimeError(
            "Worktree changed after validation; revalidation is required. "
            f"bound_fingerprint={bound.get('worktree_fingerprint')} "
            f"current_fingerprint={current_worktree_fingerprint}"
        )
    return bound


def process_record_path(run_id: str) -> Path:
    return PROCESS_RECORDS / f"{run_id}.json"


def write_process_record(run_id: str, proc: subprocess.Popen[str], command_class: str) -> None:
    record = {
        "run_id": run_id,
        "pid": proc.pid,
        "pgid": proc.pid,
        "command_class": command_class,
        "executor_boot_id": EXECUTOR_BOOT_ID,
        "started_at": now_iso(),
        "status": "running",
        "process_start_identity": pid_start_identity(proc.pid),
    }
    atomic_write_json(process_record_path(run_id), record)


def finish_process_record(run_id: str, status: str) -> None:
    path = process_record_path(run_id)
    if not path.is_file():
        return
    try:
        record = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        record = {"run_id": run_id}
    record["status"] = status
    record["completed_at"] = now_iso()
    atomic_write_json(path, record)


def pid_command(pid: int) -> str:
    result = subprocess.run(["ps", "-p", str(pid), "-o", "command="], capture_output=True, text=True, check=False, timeout=5)
    return result.stdout.strip() if result.returncode == 0 else ""


def pid_start_identity(pid: int) -> str:
    result = subprocess.run(["ps", "-p", str(pid), "-o", "lstart="], capture_output=True, text=True, check=False, timeout=5)
    return result.stdout.strip() if result.returncode == 0 else ""


def pid_is_executor_owned(record: dict[str, Any]) -> bool:
    try:
        pid = int(record["pid"])
    except Exception:
        return False
    command = pid_command(pid)
    if not command:
        return False
    recorded_start = str(record.get("process_start_identity", ""))
    if recorded_start and pid_start_identity(pid) != recorded_start:
        return False
    expected = str(record.get("command_class", ""))
    if expected == "xcodebuild":
        return "xcodebuild" in command
    if expected == "repo-task":
        return "LedgerForge" in command or "build_and_run.sh" in command or "validate.sh" in command
    if expected == "runtime":
        return "LedgerForge.app/Contents/MacOS/LedgerForge" in command
    if expected == "local-process":
        resolved = str(record.get("resolved_executable") or "")
        return bool(resolved) and resolved in command
    return False


def journal_path(operation_id: str) -> Path:
    return JOURNALS / operation_id


def journal_manifest_path(operation_id: str) -> Path:
    return journal_path(operation_id) / "manifest.json"


def path_state(relative: str) -> dict[str, Any]:
    _, candidate = normalize_repo_write_path(relative)
    if not candidate.exists():
        return {"kind": "absent"}
    if candidate.is_file():
        data = candidate.read_bytes()
        return {"kind": "file", "sha256": sha256_bytes(data)}
    if candidate.is_dir():
        return {"kind": "dir", "empty": not any(candidate.iterdir())}
    return {"kind": "other"}


def create_file_journal(
    operation_id: str,
    affected: set[str],
    normalized: list[tuple[str, dict[str, Any]]],
    expected_head: str,
) -> dict[str, Any]:
    root = journal_path(operation_id)
    if root.exists():
        raise RuntimeError("File-operation journal already exists for operation_id.")
    before = root / "before"
    before.mkdir(parents=True, mode=0o700)
    manifest: dict[str, Any] = {
        "journal_version": JOURNAL_VERSION,
        "operation_id": operation_id,
        "executor_boot_id": EXECUTOR_BOOT_ID,
        "baseline_head": expected_head,
        "created_at": now_iso(),
        "status": "prepared",
        "completed_steps": [],
        "entries": {},
        "expected_after_states": {},
    }
    for relative in sorted(affected):
        _, candidate = normalize_repo_write_path(relative)
        entry: dict[str, Any]
        if candidate.exists() and candidate.is_file():
            data = candidate.read_bytes()
            backup_name = sha256_text(relative) + ".bin"
            backup = before / backup_name
            with backup.open("wb") as fh:
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())
            os.chmod(backup, 0o600)
            entry = {"kind": "file", "sha256": sha256_bytes(data), "mode": stat.S_IMODE(candidate.stat().st_mode), "backup": backup_name}
        elif candidate.exists() and candidate.is_dir():
            entry = {"kind": "dir", "empty": not any(candidate.iterdir())}
        else:
            entry = {"kind": "absent"}
        manifest["entries"][relative] = entry
        manifest["expected_after_states"][relative] = entry.copy()

    for kind, item in normalized:
        path = item["path"]
        candidate: Path = item["_candidate"]
        if kind == "create":
            content_bytes = item.get("_content_bytes")
            content_sha = sha256_bytes(content_bytes) if isinstance(content_bytes, bytes) else sha256_text(item["content"])
            manifest["expected_after_states"][path] = {"kind": "file", "sha256": content_sha}
        elif kind == "replace":
            content_bytes = item.get("_content_bytes")
            content_sha = sha256_bytes(content_bytes) if isinstance(content_bytes, bytes) else sha256_text(item["content"])
            manifest["expected_after_states"][path] = {"kind": "file", "sha256": content_sha}
        elif kind == "exact_replace":
            text = candidate.read_text(encoding="utf-8")
            new_text = text.replace(item["old_text"], item["new_text"], 1)
            manifest["expected_after_states"][path] = {"kind": "file", "sha256": sha256_text(new_text)}
        elif kind == "delete":
            manifest["expected_after_states"][path] = {"kind": "absent"}
        elif kind == "move":
            source_sha = sha256_bytes(candidate.read_bytes())
            manifest["expected_after_states"][path] = {"kind": "absent"}
            manifest["expected_after_states"][item["destination"]] = {"kind": "file", "sha256": source_sha}
        elif kind == "mkdir":
            manifest["expected_after_states"][path] = {"kind": "dir", "empty": True}
        elif kind == "rmdir":
            manifest["expected_after_states"][path] = {"kind": "absent"}
    atomic_write_json(journal_manifest_path(operation_id), manifest)
    return manifest


def journal_current_state_is_known(manifest: dict[str, Any]) -> bool:
    entries = manifest.get("entries", {})
    expected = manifest.get("expected_after_states", {})
    if not isinstance(entries, dict) or not isinstance(expected, dict):
        return False
    for relative, before in entries.items():
        current = path_state(relative)
        after = expected.get(relative)
        known = current == before or current == after
        # file entries contain rollback metadata that path_state omits
        if isinstance(before, dict) and before.get("kind") == "file":
            known = current == {"kind": "file", "sha256": before.get("sha256")} or current == after
        if not known:
            return False
    return True


def update_file_journal(operation_id: str, manifest: dict[str, Any], *, status: str | None = None, completed_step: int | None = None) -> None:
    if completed_step is not None:
        manifest.setdefault("completed_steps", []).append(completed_step)
    if status is not None:
        manifest["status"] = status
        manifest[f"{status}_at"] = now_iso()
    atomic_write_json(journal_manifest_path(operation_id), manifest)


def restore_file_journal(operation_id: str, manifest: dict[str, Any]) -> None:
    root = journal_path(operation_id)
    before = root / "before"
    entries = manifest.get("entries", {})
    if not isinstance(entries, dict):
        raise RuntimeError("Invalid file-operation journal manifest.")
    for relative in sorted(entries, key=lambda p: len(Path(p).parts), reverse=True):
        entry = entries[relative]
        _, candidate = normalize_repo_write_path(relative)
        kind = entry.get("kind") if isinstance(entry, dict) else None
        if kind == "absent":
            if candidate.is_file():
                candidate.unlink()
            elif candidate.is_dir() and not any(candidate.iterdir()):
                candidate.rmdir()
        elif kind == "file":
            backup = before / str(entry.get("backup", ""))
            if not backup.is_file():
                raise RuntimeError(f"Missing rollback journal content for {relative}.")
            candidate.parent.mkdir(parents=True, exist_ok=True)
            temp = candidate.with_name(candidate.name + f".journal-rollback-{uuid.uuid4().hex}.tmp")
            data = backup.read_bytes()
            temp.write_bytes(data)
            os.chmod(temp, int(entry.get("mode", 0o600)))
            os.replace(temp, candidate)
        elif kind == "dir" and not candidate.exists():
            candidate.mkdir()
    manifest["status"] = "rolled_back"
    manifest["rolled_back_at"] = now_iso()
    atomic_write_json(journal_manifest_path(operation_id), manifest)


def remove_completed_journal(operation_id: str) -> None:
    root = journal_path(operation_id)
    if root.is_dir():
        shutil.rmtree(root, ignore_errors=False)


def startup_reconcile() -> dict[str, Any]:
    report: dict[str, Any] = {
        "boot_id": EXECUTOR_BOOT_ID,
        "reconciled_at": now_iso(),
        "stale_operations": [],
        "stale_validations": [],
        "stale_processes": [],
        "incomplete_journals": [],
        "auto_recovered_journals": [],
        "stale_private_artifacts_removed": 0,
    }
    for path in OPERATIONS.glob("*.json"):
        try:
            receipt = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if receipt.get("status") == "running":
            receipt["status"] = "abandoned_after_restart"
            receipt["abandoned_at"] = now_iso()
            atomic_write_json(path, receipt)
            report["stale_operations"].append(path.stem)
    for path in RUNS.glob("*.json"):
        if path.parent != RUNS:
            continue
        try:
            state = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if state.get("status") == "running":
            state["status"] = "executor_restarted"
            state["completed_at"] = now_iso()
            state["exit_code"] = None
            atomic_write_json(path, state)
            report["stale_validations"].append(path.stem)
    for path in PROCESS_RECORDS.glob("*.json"):
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if record.get("status") == "running":
            alive = pid_is_executor_owned(record)
            if alive:
                pid = int(record.get("pid", 0))
                pgid = record.get("pgid")
                try:
                    if isinstance(pgid, int) and pgid > 0:
                        os.killpg(pgid, signal.SIGTERM)
                    else:
                        os.kill(pid, signal.SIGTERM)
                except ProcessLookupError:
                    alive = False
                except Exception:
                    pass
                if alive:
                    for _ in range(25):
                        if not pid_is_executor_owned(record):
                            alive = False
                            break
                        time.sleep(0.2)
                if alive and record.get("command_class") in {"xcodebuild", "repo-task", "local-process"}:
                    try:
                        if isinstance(pgid, int) and pgid > 0:
                            os.killpg(pgid, signal.SIGKILL)
                        else:
                            os.kill(pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    except Exception:
                        pass
                    time.sleep(0.2)
                    alive = pid_is_executor_owned(record)
            record["status"] = "orphan_detected" if alive else "orphan_quiesced"
            record["reconciled_at"] = now_iso()
            atomic_write_json(path, record)
            if alive:
                report["stale_processes"].append({"run_id": record.get("run_id"), "pid": record.get("pid"), "command_class": record.get("command_class")})
    for root in JOURNALS.iterdir():
        manifest_path = root / "manifest.json"
        if not root.is_dir() or not manifest_path.is_file():
            continue
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if manifest.get("status") not in {"completed", "rolled_back"}:
            can_recover = manifest.get("baseline_head") == resolve_ref("HEAD") and journal_current_state_is_known(manifest)
            if can_recover:
                try:
                    restore_file_journal(root.name, manifest)
                    shutil.rmtree(root)
                    report["auto_recovered_journals"].append(root.name)
                    continue
                except Exception:
                    pass
            report["incomplete_journals"].append(root.name)
    temp_base = Path(os.environ.get("TMPDIR") or "/tmp")
    for candidate in temp_base.glob("ledgerforge-executor-v*-*-private"):
        if not candidate.is_dir():
            continue
        marker = candidate / ".ledgerforge-executor-private-artifact"
        if marker.is_file():
            try:
                shutil.rmtree(candidate)
                report["stale_private_artifacts_removed"] += 1
            except Exception:
                pass
    downloads_base = (Path.home() / "Downloads").resolve()
    if downloads_base.is_dir():
        for candidate in downloads_base.glob(f"{PRIVATE_RESULT_DOWNLOADS_PREFIX}*-private-result"):
            if not candidate.is_dir() or candidate.is_symlink():
                continue
            marker = candidate / PRIVATE_RESULT_MARKER_NAME
            if not marker.is_file() or marker.is_symlink():
                continue
            try:
                metadata = json.loads(marker.read_text(encoding="utf-8"))
            except Exception:
                continue
            if metadata.get("kind") != "private_result_v1":
                continue
            try:
                shutil.rmtree(candidate)
                report["stale_private_artifacts_removed"] += 1
            except Exception:
                pass
    _reconcile_local_process_states(report)
    lease = read_active_lease_raw()
    if lease and lease.get("status") == "active":
        active_run = lease.get("active_validation_run_id")
        if active_run and active_run in report.get("stale_validations", []):
            lease["active_validation_run_id"] = None
            lease["validated_state"] = None
            lease["validation_invalidated_at"] = now_iso()
            lease["validation_invalidated_reason"] = "executor restarted during validation"
            atomic_write_json(LEASE_FILE, lease)
        if lease_is_expired(lease):
            lease["status"] = "expired"
            lease["expired_at"] = now_iso()
            atomic_write_json(LEASE_FILE, lease)
    report["active_lease"] = public_lease_view(read_active_lease_raw())
    atomic_write_json(BOOT_FILE, report)
    return report


# ==========================================================================
# Git helpers and repository verification
# ==========================================================================

def git_env(mutating: bool = False) -> dict[str, str]:
    env = os.environ.copy()
    if not mutating:
        env["GIT_OPTIONAL_LOCKS"] = "0"
    else:
        env.pop("GIT_OPTIONAL_LOCKS", None)
    env["GIT_TERMINAL_PROMPT"] = "0"
    return env


def run_git(
    *args: str,
    allowed_returncodes: tuple[int, ...] = (0,),
    strip: bool = True,
    timeout: int = 45,
    mutating: bool = False,
    sanitize: bool = True,
) -> str:
    result = subprocess.run(
        ["git", "-C", str(REPO), *args],
        capture_output=True,
        text=True,
        env=git_env(mutating),
        check=False,
        timeout=timeout,
    )
    if result.returncode not in allowed_returncodes:
        detail = result.stderr.strip() or result.stdout.strip() or f"exit status {result.returncode}"
        raise RuntimeError(f"git {' '.join(args)} failed: {sanitize_text(detail)}")
    # Keep internal Git output raw. Sanitizing here can turn absolute paths
    # such as /Users/<user>/Applications/LedgerForge into ~/Applications/...
    # before internal path/ref validation, corrupting the value. Sanitize only
    # at MCP/user-visible boundaries.
    return result.stdout.strip() if strip else result.stdout


def resolve_ref(name: str) -> str | None:
    result = subprocess.run(
        ["git", "-C", str(REPO), "rev-parse", "--verify", name],
        capture_output=True,
        text=True,
        env=git_env(),
        check=False,
        timeout=10,
    )
    if result.returncode != 0:
        return None
    value = result.stdout.strip()
    return value or None


def require_expected_head(expected_head: str) -> str:
    actual = resolve_ref("HEAD")
    if actual != expected_head:
        raise RuntimeError(f"HEAD changed. Expected={expected_head}, actual={actual}")
    return actual


def git_status_raw() -> str:
    result = subprocess.run(
        ["git", "-C", str(REPO), "status", "--porcelain=v2", "--branch", "--untracked-files=all", "-z"],
        capture_output=True,
        text=True,
        env=git_env(),
        check=True,
        timeout=30,
    )
    return result.stdout


def git_worktree_status_raw() -> str:
    result = subprocess.run(
        ["git", "-C", str(REPO), "status", "--porcelain=v2", "--untracked-files=all", "-z"],
        capture_output=True,
        text=True,
        env=git_env(),
        check=True,
        timeout=30,
    )
    return result.stdout


def git_status_display() -> str:
    return git_status_raw().replace("\x00", "\n").strip()


def path_set_from_git(*args: str) -> set[str]:
    raw = run_git(*args, "-z", strip=False)
    return {item for item in raw.split("\0") if item}


def tracked_paths() -> set[str]:
    return path_set_from_git("ls-files", "--cached")


def untracked_paths() -> set[str]:
    return path_set_from_git("ls-files", "--others", "--exclude-standard")


def changed_tracked_paths() -> list[str]:
    raw = run_git("diff", "--name-only", "--no-renames", "-z", "HEAD", "--", strip=False)
    return sorted({item for item in raw.split("\0") if item})


def staged_paths() -> list[str]:
    raw = run_git("diff", "--cached", "--name-only", "--no-renames", "-z", "--", strip=False)
    return sorted({item for item in raw.split("\0") if item})


def conflicted_paths() -> list[str]:
    raw = run_git("diff", "--name-only", "--diff-filter=U", "-z", strip=False)
    return sorted({item for item in raw.split("\0") if item})


def active_git_operation() -> str | None:
    checks = (
        ("MERGE_HEAD", "merge"),
        ("CHERRY_PICK_HEAD", "cherry-pick"),
        ("REVERT_HEAD", "revert"),
        ("REBASE_HEAD", "rebase"),
    )
    for ref, label in checks:
        if resolve_ref(ref):
            return label
    git_dir_text = run_git("rev-parse", "--git-dir", sanitize=False)
    git_dir = (REPO / git_dir_text).resolve() if not Path(git_dir_text).is_absolute() else Path(git_dir_text).resolve()
    if (git_dir / "rebase-merge").exists() or (git_dir / "rebase-apply").exists():
        return "rebase"
    return None


def current_file_hash(relative: str) -> str:
    candidate = (REPO / relative)
    if candidate.is_symlink():
        return "SYMLINK"
    if not candidate.exists():
        return "ABSENT"
    if candidate.is_dir():
        return "DIRECTORY"
    try:
        return sha256_bytes(candidate.read_bytes())
    except OSError:
        return "UNREADABLE"


def current_path_identity(relative: str) -> str:
    candidate = REPO / relative
    if not candidate.exists() and not candidate.is_symlink():
        return "ABSENT"
    try:
        mode = candidate.lstat().st_mode & 0o7777
    except OSError:
        return "UNREADABLE"
    if candidate.is_symlink():
        try:
            target = os.readlink(candidate)
        except OSError:
            target = "<UNREADABLE>"
        return f"SYMLINK:{mode:o}:{sha256_text(target)}"
    if candidate.is_file():
        return f"FILE:{mode:o}:{current_file_hash(relative)}"
    if candidate.is_dir():
        return f"DIRECTORY:{mode:o}"
    return f"OTHER:{mode:o}"


def worktree_fingerprint() -> str:
    changed = sorted(set(changed_tracked_paths()) | set(untracked_paths()) | set(conflicted_paths()))
    payload: list[str] = [
        f"HEAD={resolve_ref('HEAD')}",
        "CHANGED_PATHS=" + json.dumps(changed, separators=(",", ":")),
    ]
    for relative in changed:
        payload.append(relative)
        payload.append(current_path_identity(relative))
    return sha256_text("\n".join(payload))


def index_fingerprint() -> str:
    cached = run_git("diff", "--cached", "--binary", "--no-ext-diff", "--no-renames", "--", strip=False)
    listing = run_git("ls-files", "-s", "-z", strip=False)
    return sha256_text(cached + "\n" + listing)


def require_worktree_fingerprint(expected: str) -> str:
    actual = worktree_fingerprint()
    if actual != expected:
        raise RuntimeError(f"Worktree changed. Expected fingerprint={expected}, actual={actual}")
    return actual


def remote_identity() -> str | None:
    result = subprocess.run(
        ["git", "-C", str(REPO), "remote", "get-url", "origin"],
        capture_output=True,
        text=True,
        env=git_env(),
        check=False,
        timeout=10,
    )
    if result.returncode != 0:
        return None
    return safe_remote_url(result.stdout.strip())


def canonical_github_repository(raw: str) -> tuple[str, str, str] | None:
    value = raw.strip()
    if value.startswith("git@github.com:"):
        path = value.split(":", 1)[1]
        host = "github.com"
    else:
        try:
            parsed = urlsplit(value)
        except Exception:
            return None
        host = (parsed.hostname or "").casefold()
        if parsed.username or parsed.password:
            return None
        if parsed.port not in (None, 22, 443):
            return None
        if parsed.scheme not in {"https", "ssh", "git"}:
            return None
        path = parsed.path.lstrip("/")
    path = path.rstrip("/")
    if path.endswith(".git"):
        path = path[:-4]
    parts = path.split("/")
    if len(parts) != 2:
        return None
    return host, parts[0], parts[1]


def require_expected_origin_identity() -> str:
    result = subprocess.run(
        ["git", "-C", str(REPO), "remote", "get-url", "origin"],
        capture_output=True, text=True, env=git_env(), check=False, timeout=10,
    )
    if result.returncode != 0 or not result.stdout.strip():
        raise RuntimeError("origin remote is unavailable.")
    raw = result.stdout.strip()
    override = os.environ.get(EXPECTED_REMOTE_URL_ENV, "").strip()
    if override:
        if raw != override:
            raise RuntimeError(f"origin does not match explicit executor expected remote: {safe_remote_url(raw)}")
        return safe_remote_url(raw)
    canonical = canonical_github_repository(raw)
    if canonical != ("github.com", "vyom92", "LedgerForge"):
        raise RuntimeError(f"origin does not canonically identify github.com/vyom92/LedgerForge: {safe_remote_url(raw)}")
    return safe_remote_url(raw)


def workspace_snapshot() -> dict[str, Any]:
    head = resolve_ref("HEAD")
    main = resolve_ref("main")
    origin_main = resolve_ref("origin/main")
    ahead = behind = None
    if main and origin_main:
        counts = run_git("rev-list", "--left-right", "--count", "main...origin/main").split()
        if len(counts) == 2:
            ahead, behind = int(counts[0]), int(counts[1])
    return {
        "repository_root": str(REPO),
        "current_branch": run_git("branch", "--show-current") or None,
        "head": head,
        "main": main,
        "origin_main": origin_main,
        "main_ahead_of_origin_main": ahead,
        "main_behind_origin_main": behind,
        "tracked_changed_files": changed_tracked_paths(),
        "staged_files": staged_paths(),
        "visible_untracked_files": sorted(untracked_paths()),
        "conflicted_files": conflicted_paths(),
        "active_git_operation": active_git_operation(),
        "worktree_fingerprint": worktree_fingerprint(),
        "index_fingerprint": index_fingerprint(),
        "status_porcelain_v2": git_status_display(),
        "worktrees": run_git("worktree", "list", "--porcelain"),
        "local_branches": run_git("branch", "--format=%(refname:short)\t%(objectname)"),
        "remote_branches": run_git("branch", "-r", "--format=%(refname:short)\t%(objectname)"),
        "stashes": run_git("stash", "list", "--format=%gd\t%H\t%gs"),
        "remote_origin": remote_identity(),
        "notes": [
            "origin/main is locally recorded unless git_fetch_origin has just run.",
            "No implicit fetch occurs in workspace_state.",
        ],
    }


if not REPO.is_dir():
    raise RuntimeError(f"LedgerForge repository does not exist: {REPO}")
actual_root = Path(run_git("rev-parse", "--show-toplevel", sanitize=False)).resolve()
if actual_root != REPO:
    raise RuntimeError(f"Configured path is not the Git worktree root: {actual_root}")
if not VALIDATE_SCRIPT.is_file():
    raise RuntimeError(f"Repository validation script missing: {VALIDATE_SCRIPT}")


# ==========================================================================
# Root-based path security
# ==========================================================================

def root_registry() -> dict[str, Path]:
    return {
        "repo": REPO,
        "originals": (Path.home() / "Documents" / "Ledger Forge" / "Originals").resolve(),
        "derived_data": (Path.home() / "Library" / "Developer" / "Xcode" / "DerivedData").resolve(),
        "executor_artifacts": BRIDGE_ROOT.resolve(),
        "ledgerforge_logs": (Path.home() / ".config" / "tunnel-client").resolve(),
        "task_scratch": TASK_WORKSPACE_ROOT,
    }


def normalize_root_path(root_id: str, path: str, *, allow_root: bool = False) -> tuple[str, Path, Path]:
    roots = root_registry()
    if root_id not in roots:
        raise PermissionError(f"Unsupported evidence root: {root_id}")
    root = roots[root_id]
    if "\x00" in path:
        raise ValueError("NUL bytes are not permitted.")
    supplied = Path(path or ".")
    if supplied.is_absolute():
        raise PermissionError("Absolute caller paths are not accepted.")
    candidate = (root / supplied).resolve(strict=False)
    try:
        relative = candidate.relative_to(root)
    except ValueError as exc:
        raise PermissionError("Path escapes the selected evidence root.") from exc
    if not allow_root and relative.as_posix() in {"", "."}:
        raise PermissionError("Evidence-root directory itself is not a file target.")
    if is_secret_name(candidate):
        raise PermissionError("Credential/token configuration is not readable through MCP.")
    return relative.as_posix(), candidate, root


def ensure_no_symlink_escape(candidate: Path, root: Path, *, include_candidate: bool = True) -> None:
    try:
        relative = candidate.relative_to(root)
    except ValueError as exc:
        raise PermissionError("Path escapes permitted root.") from exc
    current = root
    parts = relative.parts if include_candidate else relative.parts[:-1]
    for part in parts:
        current = current / part
        if current.exists() and current.is_symlink():
            raise PermissionError("Symlink paths are not permitted for this operation.")


def normalize_repo_write_path(path: str, *, allow_root: bool = False) -> tuple[str, Path]:
    if not path or "\x00" in path:
        raise ValueError("Path must be a non-empty relative path.")
    supplied = Path(path)
    if supplied.is_absolute():
        raise PermissionError("Absolute write paths are not accepted.")
    if any(part in {"..", ".git"} for part in supplied.parts):
        raise PermissionError("Traversal and .git paths are forbidden.")
    candidate = (REPO / supplied).resolve(strict=False)
    try:
        relative = candidate.relative_to(REPO)
    except ValueError as exc:
        raise PermissionError("Write path escapes LedgerForge worktree.") from exc
    if not allow_root and relative.as_posix() in {"", "."}:
        raise PermissionError("Repository root cannot be a mutation target.")
    ensure_no_symlink_escape(candidate, REPO, include_candidate=False)
    if candidate.exists() and candidate.is_symlink():
        raise PermissionError("Symlink targets are not writable through MCP.")
    if is_secret_name(candidate):
        raise PermissionError("Credential/token filenames are not writable through MCP.")
    return relative.as_posix(), candidate



def running_lease_operation_receipts(lease_id: str, exclude_operation_id: str | None = None) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not lease_id or not OPERATIONS.is_dir():
        return rows
    for path in sorted(OPERATIONS.glob("*.json")):
        if exclude_operation_id and path.stem == exclude_operation_id:
            continue
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            rows.append({"operation_id": path.stem, "action": "unreadable-operation-receipt", "status": "running"})
            continue
        if record.get("status") != "running" or record.get("lease_id") != lease_id:
            continue
        if exclude_operation_id and record.get("operation_id") == exclude_operation_id:
            continue
        rows.append({"operation_id": str(record.get("operation_id") or path.stem), "action": str(record.get("action") or "unknown"), "status": "running"})
    return rows


def require_no_running_lease_operations(lease_id: str, exclude_operation_id: str | None = None) -> None:
    running = running_lease_operation_receipts(lease_id, exclude_operation_id)
    if running:
        summary = ", ".join(f"{row['action']}:{row['operation_id']}" for row in running[:8])
        raise RuntimeError("Execution lease has another durable operation still running; capability transition refused. running=" + summary)


def require_no_running_replacement_lease_operations(exclude_operation_id: str | None = None) -> None:
    prior = read_active_lease_raw()
    if not isinstance(prior, dict):
        return
    prior_lease_id = prior.get("lease_id")
    if isinstance(prior_lease_id, str) and prior_lease_id:
        require_no_running_lease_operations(prior_lease_id, exclude_operation_id)

# ==========================================================================
# Operation idempotency
# ==========================================================================

def operation_receipt_path(operation_id: str) -> Path:
    try:
        parsed = uuid.UUID(operation_id)
    except ValueError as exc:
        raise ValueError("operation_id must be a UUID.") from exc
    return OPERATIONS / f"{parsed}.json"


def normalize_provenance_label(value: str | None) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("provenance_label must be a string when provided.")
    normalized = value.strip()
    if not normalized or len(normalized) > MAX_PROVENANCE_LABEL_CHARS:
        raise ValueError(f"provenance_label must contain 1...{MAX_PROVENANCE_LABEL_CHARS} characters.")
    if any(ord(ch) < 32 for ch in normalized):
        raise ValueError("provenance_label may not contain control characters.")
    return sanitize_source_text(normalized)[:MAX_PROVENANCE_LABEL_CHARS]


def request_digest(action: str, payload: dict[str, Any]) -> str:
    # Provenance metadata is deliberately excluded from idempotency/policy identity.
    semantic_payload = {k: v for k, v in payload.items() if k != "provenance_label"}
    return sha256_text(json.dumps({"action": action, "payload": semantic_payload}, sort_keys=True, separators=(",", ":")))


def begin_operation(operation_id: str, action: str, payload: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
    digest = request_digest(action, payload)
    path = operation_receipt_path(operation_id)
    lease_id = payload.get("lease_id")
    active_lease = read_active_lease_raw() if lease_id else None
    with _lease_transition_lock:
        with _operation_lock:
            if path.exists():
                existing = json.loads(path.read_text(encoding="utf-8"))
                if existing.get("request_digest") != digest:
                    raise RuntimeError("operation_id was already used for a different request.")
                if existing.get("status") == "completed":
                    return True, existing.get("result", {})
                raise RuntimeError("An operation with this operation_id is already running, abandoned, or previously failed.")
            receipt = {
                "operation_id": operation_id,
                "action": action,
                "request_digest": digest,
                "status": "running",
                "started_at": now_iso(),
                "executor_boot_id": EXECUTOR_BOOT_ID,
                "executor_source_sha256": source_sha256(),
                "schema_contract_sha256": schema_contract_digest(),
                "lease_id": lease_id,
                "execution_id": active_lease.get("execution_id") if active_lease else None,
                "authorization_digest": active_lease.get("authorization_digest") if active_lease else None,
                "provenance_label": normalize_provenance_label(payload.get("provenance_label")),
            }
            atomic_write_json(path, receipt)
    return False, {}


def finish_operation(operation_id: str, result: dict[str, Any]) -> dict[str, Any]:
    path = operation_receipt_path(operation_id)
    with _operation_lock:
        receipt = json.loads(path.read_text(encoding="utf-8"))
        receipt["status"] = "completed"
        receipt["completed_at"] = now_iso()
        receipt["result"] = sanitize_object(result)
        atomic_write_json(path, receipt)
    return result


def fail_operation(operation_id: str, exc: Exception) -> None:
    path = operation_receipt_path(operation_id)
    if not path.exists():
        return
    with _operation_lock:
        receipt = json.loads(path.read_text(encoding="utf-8"))
        receipt["status"] = "failed"
        receipt["completed_at"] = now_iso()
        receipt["error_type"] = type(exc).__name__
        receipt["error_message"] = sanitize_text(str(exc))[:1000]
        atomic_write_json(path, receipt)


# ==========================================================================
# Validation state/process helpers
# ==========================================================================

def state_path(run_id: str) -> Path:
    try:
        parsed = uuid.UUID(run_id)
    except ValueError as exc:
        raise ValueError("Invalid run_id.") from exc
    return RUNS / f"{parsed}.json"


def log_path(run_id: str) -> Path:
    try:
        parsed = uuid.UUID(run_id)
    except ValueError as exc:
        raise ValueError("Invalid run_id.") from exc
    return RUNS / f"{parsed}.log"


def write_state(run_id: str, state: dict[str, Any]) -> None:
    path = state_path(run_id)
    temp = path.with_suffix(".tmp")
    with _state_lock:
        temp.write_text(json.dumps(sanitize_object(state), indent=2, sort_keys=True), encoding="utf-8")
        os.chmod(temp, 0o600)
        os.replace(temp, path)


def read_state(run_id: str) -> dict[str, Any]:
    path = state_path(run_id)
    if not path.is_file():
        raise FileNotFoundError("Unknown validation run.")
    with _state_lock:
        return json.loads(path.read_text(encoding="utf-8"))


def resolve_private_context(private_context: str | None) -> tuple[dict[str, str], str | None, list[str], dict[str, str]]:
    validation_env = safe_validation_base_env()
    if private_context is None:
        return validation_env, None, [], {}
    if private_context not in PRIVATE_CONTEXTS:
        raise PermissionError(f"Unsupported private_context: {private_context}")
    required = PRIVATE_CONTEXTS[private_context]
    values: dict[str, str] = {}
    redacted: list[str] = []
    for key in required:
        if key == "LEDGERFORGE_AXIS_CARD_PRIVATE_PASSWORD":
            value = keychain_axis_password()
        else:
            value = os.environ.get(key, "")
        if not value:
            raise RuntimeError(f"Private context {private_context} is not fully configured.")
        values[key] = value
        validation_env[key] = value
        if key == "LEDGERFORGE_AXIS_CARD_PRIVATE_PASSWORD":
            redacted.append(value)
    if private_context == "hdfc":
        for key in (
            "LEDGERFORGE_PRIVATE_HDFC_ORACLE_FILE",
            "LEDGERFORGE_PRIVATE_HDFC_ORIGINALS_FILE",
        ):
            value = os.environ.get(key, "")
            if value:
                values[key] = value
                validation_env[key] = value
    validation_env["LEDGERFORGE_TEST_HOST"] = "1"
    values["LEDGERFORGE_TEST_HOST"] = "1"
    return validation_env, private_context, redacted, values


def run_captured(
    command: list[str],
    environment: dict[str, str],
    *,
    run_id: str | None = None,
    timeout: int = MAX_VALIDATION_SECONDS,
    cwd: Path = REPO,
    command_class: str | None = None,
) -> tuple[int, str]:
    proc = subprocess.Popen(
        command,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        env=environment,
        start_new_session=True,
    )
    if run_id:
        resolved_class = command_class or ("xcodebuild" if command and Path(command[0]).name == "xcodebuild" else "repo-task")
        with _validation_lock:
            _active_processes[run_id] = proc
        write_process_record(run_id, proc, resolved_class)
    try:
        output, _ = proc.communicate(timeout=timeout)
        if run_id:
            finish_process_record(run_id, "completed")
        return proc.returncode, output or ""
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            output, _ = proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            output, _ = proc.communicate()
        if run_id:
            finish_process_record(run_id, "timed_out")
        return 124, (output or "") + "\nRecovery Executor: command timed out.\n"
    finally:
        if run_id:
            with _validation_lock:
                if _active_processes.get(run_id) is proc:
                    _active_processes.pop(run_id, None)


def check_cancelled(run_id: str) -> None:
    with _validation_lock:
        if run_id in _cancelled_runs:
            raise RuntimeError("Validation cancelled by user request.")


def locate_generated_xctestrun(derived_data: Path) -> Path:
    candidates = sorted((derived_data / "Build" / "Products").glob("*.xctestrun"))
    if len(candidates) != 1:
        raise RuntimeError(f"Expected one generated xctestrun; found {len(candidates)}.")
    return candidates[0]


def inject_test_environment_into_xctestrun(xctestrun: Path, requested_values: dict[str, str]) -> None:
    data = plistlib.loads(xctestrun.read_bytes())
    configs = data.get("TestConfigurations")
    if not isinstance(configs, list):
        raise RuntimeError("Generated xctestrun has no TestConfigurations array.")
    matching: list[dict[str, Any]] = []
    for config in configs:
        if not isinstance(config, dict):
            continue
        targets = config.get("TestTargets", [])
        if not isinstance(targets, list):
            continue
        for target in targets:
            if not isinstance(target, dict):
                continue
            env = target.get("EnvironmentVariables")
            if not isinstance(env, dict):
                env = {}
                target["EnvironmentVariables"] = env
            for key in ALL_TEST_ENV_KEYS:
                env.pop(key, None)
            if target.get("BlueprintName") == XCODE_TEST_TARGET or target.get("ProductModuleName") == XCODE_TEST_TARGET:
                matching.append(target)
    if len(matching) != 1:
        raise RuntimeError(f"Expected one {XCODE_TEST_TARGET} target; found {len(matching)}.")
    env = matching[0]["EnvironmentVariables"]
    for key, value in requested_values.items():
        if key not in ALL_TEST_ENV_KEYS:
            raise PermissionError(f"Unsupported private test environment key: {key}")
        env[key] = value
    xctestrun.write_bytes(plistlib.dumps(data, fmt=plistlib.FMT_XML, sort_keys=False))
    xctestrun.chmod(0o600)


def xcresult_safe_summary(result_bundle: Path, environment: dict[str, str], *, run_id: str | None = None) -> dict[str, Any]:
    if not result_bundle.exists():
        return {"available": False}
    status, output = run_captured(
        [str(XCRUN), "xcresulttool", "get", "test-results", "summary", "--path", str(result_bundle), "--compact"],
        environment,
        run_id=run_id,
        timeout=120,
    )
    if status != 0:
        return {"available": False, "summary_read_failed": True}
    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        return {"available": False, "summary_read_failed": True}
    safe: dict[str, Any] = {"available": True}
    for key in ("totalTestCount", "passedTests", "failedTests", "skippedTests", "result"):
        if key in data and isinstance(data[key], (str, int, float, bool, type(None))):
            safe[key] = data[key]
    failures = data.get("testFailures")
    safe_failures: list[dict[str, str]] = []
    if isinstance(failures, list):
        for failure in failures:
            if not isinstance(failure, dict):
                continue
            item: dict[str, str] = {}
            for key in ("targetName", "testIdentifier", "testName"):
                value = failure.get(key)
                if isinstance(value, str) and value:
                    item[key] = sanitize_text(value)
            if item:
                safe_failures.append(item)
    if safe_failures:
        safe["testFailures"] = safe_failures[:100]
    return safe



def resolve_private_signing_configuration() -> dict[str, str]:
    identity_class = os.environ.get(SIGNING_IDENTITY_CLASS_ENV, DEFAULT_SIGNING_IDENTITY_CLASS).strip() or DEFAULT_SIGNING_IDENTITY_CLASS
    if identity_class != DEFAULT_SIGNING_IDENTITY_CLASS:
        raise RuntimeError(f"Private validation signing identity class must be {DEFAULT_SIGNING_IDENTITY_CLASS!r}.")
    if not SECURITY.is_file():
        raise RuntimeError("macOS security tool is unavailable; private validation cannot prove a stable signing identity.")
    proc = subprocess.run(
        [str(SECURITY), "find-identity", "-v", "-p", "codesigning"],
        capture_output=True, text=True, check=False, timeout=20,
    )
    if proc.returncode != 0:
        raise RuntimeError("Unable to enumerate valid code-signing identities for private validation.")
    identities: list[dict[str, str]] = []
    pattern = re.compile(r'^\s*\d+\)\s+([0-9A-Fa-f]{40})\s+"(Apple Development: .*? \(([A-Z0-9]{10})\))"')
    for line in (proc.stdout + "\n" + proc.stderr).splitlines():
        match = pattern.search(line)
        if match:
            identities.append({
                "identity_hash": match.group(1).upper(),
                "identity_label": match.group(2),
                "identity_hint": match.group(3),
                "identity_class": identity_class,
            })
    configured = os.environ.get(DEVELOPMENT_TEAM_ENV, "").strip()
    if configured:
        if not re.fullmatch(r"[A-Z0-9]{10}", configured):
            raise RuntimeError(f"{DEVELOPMENT_TEAM_ENV} must be a 10-character Apple Development identity hint.")
        identities = [item for item in identities if item["identity_hint"] == configured]
    if len(identities) != 1:
        qualifier = f" matching {DEVELOPMENT_TEAM_ENV}" if configured else ""
        raise RuntimeError(f"Private validation requires exactly one valid Apple Development identity{qualifier}.")
    return identities[0]


def locate_private_test_host(derived_data: Path) -> Path:
    candidates = sorted(
        p for p in (derived_data / "Build" / "Products").glob("**/LedgerForge.app")
        if p.is_dir()
    )
    if len(candidates) != 1:
        raise RuntimeError(f"Expected one built LedgerForge.app test host; found {len(candidates)}.")
    return candidates[0]


def resign_private_test_host(app: Path, signing: dict[str, str]) -> None:
    if not CODESIGN.is_file():
        raise RuntimeError("codesign is unavailable; private validation test host cannot be re-signed.")
    entitlements_proc = subprocess.run(
        [str(CODESIGN), "-d", "--entitlements", ":-", str(app)],
        capture_output=True, check=False, timeout=20,
    )
    if entitlements_proc.returncode != 0 or not entitlements_proc.stdout:
        raise RuntimeError("Unable to extract existing LedgerForge.app entitlements before private test-host signing.")
    try:
        plistlib.loads(entitlements_proc.stdout)
    except Exception as exc:
        raise RuntimeError("Existing LedgerForge.app entitlements are not a valid property list.") from exc
    entitlement_path = app.parent / f".{app.name}.mcp-private-entitlements.plist"
    entitlement_path.write_bytes(entitlements_proc.stdout)
    os.chmod(entitlement_path, 0o600)
    try:
        sign_proc = subprocess.run(
            [
                str(CODESIGN), "--force", "--sign", signing["identity_hash"],
                "--entitlements", str(entitlement_path), "--timestamp=none", str(app),
            ],
            capture_output=True, text=True, check=False, timeout=60,
        )
        if sign_proc.returncode != 0:
            detail = (sign_proc.stdout or "") + "\n" + (sign_proc.stderr or "")
            raise RuntimeError("Apple Development re-sign of private LedgerForge test host failed: " + sanitize_source_text(detail)[:1200])
        verify_proc = subprocess.run(
            [str(CODESIGN), "--verify", "--strict", "--verbose=2", str(app)],
            capture_output=True, text=True, check=False, timeout=60,
        )
        if verify_proc.returncode != 0:
            detail = (verify_proc.stdout or "") + "\n" + (verify_proc.stderr or "")
            raise RuntimeError("Re-signed private LedgerForge test host failed strict signature verification: " + sanitize_source_text(detail)[:1200])
    finally:
        entitlement_path.unlink(missing_ok=True)


def verify_private_test_host_signing(app: Path) -> dict[str, str]:
    if not CODESIGN.is_file():
        raise RuntimeError("codesign is unavailable; private validation signing cannot be verified.")
    details_proc = subprocess.run(
        [str(CODESIGN), "-d", "--verbose=4", str(app)], capture_output=True, text=True, check=False, timeout=20,
    )
    details = (details_proc.stdout or "") + "\n" + (details_proc.stderr or "")
    if details_proc.returncode != 0:
        raise RuntimeError("Built LedgerForge.app signature could not be inspected.")
    if "Signature=adhoc" in details:
        raise RuntimeError("Private LedgerForge test host is ad-hoc signed; refusing to launch it.")
    identifier = re.search(r"(?m)^Identifier=(.+)$", details)
    team = re.search(r"(?m)^TeamIdentifier=(.+)$", details)
    authorities = re.findall(r"(?m)^Authority=(.+)$", details)
    if not identifier or identifier.group(1).strip() != "com.vyom.LedgerForge":
        raise RuntimeError("Private LedgerForge test host bundle identifier is unexpected.")
    team_identifier = team.group(1).strip() if team else ""
    if not team_identifier or team_identifier == "not set":
        raise RuntimeError("Private LedgerForge test host has no stable TeamIdentifier after signing.")
    if not authorities or not authorities[0].strip().startswith("Apple Development:"):
        raise RuntimeError("Private LedgerForge test host is not signed by an Apple Development identity.")
    req_proc = subprocess.run(
        [str(CODESIGN), "-d", "-r-", str(app)], capture_output=True, text=True, check=False, timeout=20,
    )
    requirement_output = (req_proc.stdout or "") + "\n" + (req_proc.stderr or "")
    match = re.search(r"designated => (.+)", requirement_output)
    if req_proc.returncode != 0 or not match:
        raise RuntimeError("Private LedgerForge test host designated requirement could not be read.")
    requirement = match.group(1).strip()
    if requirement.startswith('cdhash H"') or ("cdhash H\"" in requirement and "certificate" not in requirement):
        raise RuntimeError("Private LedgerForge test host designated requirement is cdhash-bound rather than signer-bound.")
    if "anchor apple" not in requirement or "certificate" not in requirement:
        raise RuntimeError("Private LedgerForge test host designated requirement is not signer-based.")
    entitlements_proc = subprocess.run(
        [str(CODESIGN), "-d", "--entitlements", ":-", str(app)],
        capture_output=True, check=False, timeout=20,
    )
    if entitlements_proc.returncode != 0 or not entitlements_proc.stdout:
        raise RuntimeError("Private LedgerForge test host entitlements could not be read after signing.")
    try:
        signed_entitlements = plistlib.loads(entitlements_proc.stdout)
    except Exception as exc:
        raise RuntimeError("Private LedgerForge test host signed entitlements are not a valid property list.") from exc
    return {
        "bundle_identifier": "com.vyom.LedgerForge",
        "team_identifier": team_identifier,
        "designated_requirement_sha256": sha256_text(requirement),
        "app_sandbox": signed_entitlements.get("com.apple.security.app-sandbox") is True,
        "downloads_read_write": signed_entitlements.get("com.apple.security.files.downloads.read-write") is True,
    }


def classify_validation_failure(exit_code: int | None, output: str, summary: dict[str, Any], *, cancelled: bool = False) -> str:
    if cancelled:
        return "cancelled"
    if summary.get("selection_empty") is True:
        return "test_selection_empty"
    if summary.get("compile_only") is True and exit_code == 0:
        return "compile_success"
    if exit_code == 0:
        return "success"
    if exit_code == 124:
        return "test_timeout"
    failed = summary.get("failedTests") if isinstance(summary, dict) else None
    if isinstance(failed, int) and failed > 0:
        return "test_assertion_failure"
    lowered = output.casefold()
    signing_markers = (
        "no signing certificate",
        "conflicting provisioning settings",
        "ad hoc code signing is not allowed",
        "code signing is required",
        "provisioning profile",
        "signing certificate",
        "codesign failed",
    )
    if any(marker in lowered for marker in signing_markers):
        return "signing_failure"
    if "linker command failed" in lowered or "ld: " in lowered:
        return "linker_failure"
    if "compile" in lowered and ("error:" in lowered or "swift" in lowered):
        return "compiler_failure"
    if "build failed" in lowered or "** build failed **" in lowered:
        return "build_failure"
    if "signal" in lowered or "crashed" in lowered or "fatal error" in lowered:
        return "test_crash"
    return "infrastructure_failure"


def safe_xcresult_evidence(summary: dict[str, Any]) -> dict[str, Any]:
    safe = {
        "available": bool(summary.get("available")),
        "total_test_count": summary.get("totalTestCount"),
        "passed_tests": summary.get("passedTests"),
        "failed_tests": summary.get("failedTests"),
        "skipped_tests": summary.get("skippedTests"),
        "result": summary.get("result"),
        "test_failures": summary.get("testFailures", []),
    }
    return {k: v for k, v in safe.items() if v is not None}



PRIVATE_RESULT_KEY_MAX_CHARS = 128
PRIVATE_PASSWORD_KEY_PARTS = {"password", "passwd", "passphrase"}


def _private_result_password_key(key: str) -> bool:
    normalized = key.casefold().replace("-", "_")
    return bool(set(normalized.split("_")) & PRIVATE_PASSWORD_KEY_PARTS)


def validate_private_structured_payload(value: Any, *, key: str = "root", depth: int = 0, budget: list[int] | None = None) -> Any:
    """Validate bounded JSON and redact only authentication secrets/passwords.

    Private financial content, dates, balances, descriptions, identifiers, local paths and
    filenames are intentionally permitted for this single-user local project.
    """
    if budget is None:
        budget = [512]
    if depth > 6:
        raise ValueError("Private structured result exceeds maximum nesting depth.")
    budget[0] -= 1
    if budget[0] < 0:
        raise ValueError("Private structured result contains too many nodes.")
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise ValueError("Private structured result contains a non-finite number.")
        return value
    if isinstance(value, str):
        if _private_result_password_key(key):
            return "[REDACTED]"
        return sanitize_text(value)
    if isinstance(value, list):
        return [validate_private_structured_payload(item, key=key, depth=depth + 1, budget=budget) for item in value]
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for raw_key, raw_value in value.items():
            if not isinstance(raw_key, str):
                raise ValueError("Private structured-result object keys must be strings.")
            if not raw_key or len(raw_key) > PRIVATE_RESULT_KEY_MAX_CHARS or any(ord(ch) < 32 for ch in raw_key):
                raise ValueError(f"Private structured-result key is invalid or too long: {raw_key!r}")
            if _private_result_password_key(raw_key):
                out[raw_key] = "[REDACTED]"
            else:
                out[raw_key] = validate_private_structured_payload(raw_value, key=raw_key, depth=depth + 1, budget=budget)
        return out
    raise ValueError(f"Unsupported private structured-result type: {type(value).__name__}")


def private_result_downloads_base() -> Path:
    base = (Path.home() / "Downloads").resolve()
    if not base.is_dir():
        raise RuntimeError("Downloads directory is unavailable for sandbox-compatible private-result capture.")
    return base


def create_private_result_artifact_root(run_id: str) -> Path:
    base = private_result_downloads_base()
    root = Path(tempfile.mkdtemp(
        prefix=f"{PRIVATE_RESULT_DOWNLOADS_PREFIX}{run_id}-",
        suffix="-private-result",
        dir=base,
    ))
    try:
        root.chmod(0o700)
        marker = root / PRIVATE_RESULT_MARKER_NAME
        marker.write_text(json.dumps({
            "kind": "private_result_v1",
            "run_id": run_id,
            "boot_id": EXECUTOR_BOOT_ID,
        }, sort_keys=True), encoding="utf-8")
        marker.chmod(0o600)
        return root
    except Exception:
        shutil.rmtree(root, ignore_errors=True)
        raise


def remove_private_result_artifact_root(root: Path | None) -> None:
    if root is None:
        return
    try:
        base = (Path.home() / "Downloads").resolve()
        parent = root.parent.resolve()
    except Exception:
        return
    if parent != base or not root.name.startswith(PRIVATE_RESULT_DOWNLOADS_PREFIX):
        return
    shutil.rmtree(root, ignore_errors=True)


def capture_private_structured_result(path: Path, contract: str) -> dict[str, Any]:
    if contract != "structural_evidence_v1":
        raise PermissionError("Unsupported private_result_contract.")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except FileNotFoundError:
        raise FileNotFoundError("Requested private structured result was not produced.") from None
    except OSError as exc:
        raise PermissionError("Private structured-result path must be a non-symlink regular file.") from exc
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise PermissionError("Private structured-result path must be a regular file.")
        size = st.st_size
        if size < 2 or size > MAX_PRIVATE_STRUCTURED_RESULT_BYTES:
            raise ValueError(f"Private structured result must be 2...{MAX_PRIVATE_STRUCTURED_RESULT_BYTES} bytes.")
        raw = os.read(fd, MAX_PRIVATE_STRUCTURED_RESULT_BYTES + 1)
        if len(raw) != size:
            raise RuntimeError("Private structured-result file changed during capture.")
    finally:
        os.close(fd)
    if b"\x00" in raw:
        raise ValueError("Private structured result must be UTF-8 JSON.")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise ValueError("Private structured result is not valid UTF-8 JSON.") from exc
    if not isinstance(payload, dict):
        raise ValueError("Private structured result top level must be an object.")
    safe_payload = validate_private_structured_payload(payload)
    canonical = json.dumps(safe_payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return {
        "contract_id": "structural_evidence",
        "contract_version": 1,
        "contract": contract,
        "sha256": sha256_bytes(canonical),
        "bytes": len(canonical),
        "payload": safe_payload,
        "privacy_policy": "credential-redaction-only-bounded-json",
    }


def run_private_xcode_test_validation(
    run_id: UUIDString,
    operation: str,
    selectors: list[str],
    validation_env: dict[str, str],
    requested_values: dict[str, str],
    validation_intent: ValidationIntent,
    private_result_contract: PrivateResultContract | None = None,
) -> tuple[int, str, dict[str, Any]]:
    temp_parent = os.environ.get("TMPDIR") or "/tmp"
    artifact_root = Path(tempfile.mkdtemp(prefix=f"ledgerforge-executor-v{EXECUTOR_VERSION}-{run_id}-", suffix="-private", dir=temp_parent))
    artifact_root.chmod(0o700)
    marker = artifact_root / ".ledgerforge-executor-private-artifact"
    marker.write_text(json.dumps({"run_id": run_id, "boot_id": EXECUTOR_BOOT_ID}), encoding="utf-8")
    marker.chmod(0o600)
    combined: list[str] = []
    summary: dict[str, Any] = {"private_test_host_path": "xctestrun"}
    private_result_root: Path | None = None
    private_result_path: Path | None = None
    try:
        if private_result_contract is not None:
            private_result_root = create_private_result_artifact_root(run_id)
            private_result_path = private_result_root / "PrivateSafeResult.json"
            validation_env[PRIVATE_RESULT_FILE_ENV] = str(private_result_path)
            requested_values[PRIVATE_RESULT_FILE_ENV] = str(private_result_path)
            summary["private_result_expected"] = True
            summary["private_result_contract"] = private_result_contract
            summary["private_result_rendezvous"] = "downloads-entitlement"
        needs_private_signing = bool(requested_values) or private_result_contract is not None
        signing = resolve_private_signing_configuration() if needs_private_signing else None
        if signing is not None:
            summary["signing_identity_hint"] = signing["identity_hint"]
        if operation == "cycle-close":
            for build_operation in ("build-debug", "build-release"):
                check_cancelled(run_id)
                status, output = run_captured([str(VALIDATE_SCRIPT), build_operation], validation_env, run_id=run_id)
                combined.append(output)
                if status != 0:
                    summary["_private_build_diagnostics"] = truncate_text(sanitize_source_text(output), MAX_TOOL_OUTPUT_BYTES // 2)[0]
                    return status, "".join(combined), summary
        check_cancelled(run_id)
        derived_data = artifact_root / "DerivedData"
        result_bundle = artifact_root / "TestResults.xcresult"
        build_command = [
            str(XCODEBUILD), "-project", str(XCODE_PROJECT), "-scheme", XCODE_SCHEME,
            "-destination", XCODE_DESTINATION, "-derivedDataPath", str(derived_data),
            "-testPlan", XCODE_TEST_PLAN,
            "build-for-testing",
        ]
        status, output = run_captured(build_command, validation_env, run_id=run_id)
        combined.append(output)
        if status != 0:
            summary["_private_build_diagnostics"] = truncate_text(
                sanitize_source_text(output), MAX_TOOL_OUTPUT_BYTES // 2
            )[0]
            return status, "".join(combined), summary
        if signing is not None:
            app = locate_private_test_host(derived_data)
            resign_private_test_host(app, signing)
            summary["private_test_host_signing"] = verify_private_test_host_signing(app)
            if private_result_contract is not None and summary["private_test_host_signing"].get("downloads_read_write") is not True:
                raise RuntimeError("Private structured-result capture requires the signed LedgerForge test host Downloads read/write entitlement.")
        xctestrun = locate_generated_xctestrun(derived_data)
        if requested_values:
            inject_test_environment_into_xctestrun(xctestrun, requested_values)
        if validation_intent == "compile_only":
            summary["compile_only"] = True
            summary["build_succeeded"] = True
            return 0, "".join(combined), summary
        check_cancelled(run_id)
        test_command = [
            str(XCODEBUILD), "-xctestrun", str(xctestrun), "-destination", XCODE_DESTINATION,
            "-resultBundlePath", str(result_bundle),
        ]
        if operation == "test-focused":
            for selector in selectors:
                test_command.append(f"-only-testing:{selector}")
        test_command.append("test-without-building")
        status, output = run_captured(test_command, validation_env, run_id=run_id)
        combined.append(output)
        summary.update(xcresult_safe_summary(result_bundle, validation_env, run_id=run_id))
        if private_result_contract is not None:
            try:
                if private_result_path is None:
                    raise RuntimeError("Private structured-result path was not initialized.")
                summary["_private_structured_result"] = capture_private_structured_result(private_result_path, private_result_contract)
                summary["private_result_captured"] = True
            except Exception as exc:
                summary["private_result_captured"] = False
                summary["private_result_error"] = sanitize_source_text(f"{type(exc).__name__}: {exc}")[:1000]
                if status == 0:
                    status = 67
        total = summary.get("totalTestCount")
        if operation in {"test-focused", "test-full"} and isinstance(total, int) and total == 0:
            summary["selection_empty"] = True
            if status == 0:
                status = 66
        return status, "".join(combined), summary
    finally:
        shutil.rmtree(artifact_root, ignore_errors=True)
        remove_private_result_artifact_root(private_result_root)


def execute_validation(
    run_id: UUIDString,
    operation: str,
    selectors: list[str],
    validation_env: dict[str, str],
    requested_values: dict[str, str],
    validation_intent: ValidationIntent,
    private_result_contract: PrivateResultContract | None = None,
) -> tuple[int, str, dict[str, Any]]:
    command = [str(VALIDATE_SCRIPT), operation, *selectors]
    if operation in {"test-focused", "test-full", "cycle-close"}:
        return run_private_xcode_test_validation(
            run_id, operation, selectors, validation_env, requested_values, validation_intent, private_result_contract
        )
    status, output = run_captured(command, validation_env, run_id=run_id)
    return status, output, {}


def validation_worker(
    run_id: str,
    operation: str,
    selectors: list[str],
    starting_status: str,
    starting_head: str,
    validation_env: dict[str, str],
    redacted_values: list[str],
    requested_values: dict[str, str],
    private_context: str | None,
    validation_intent: ValidationIntent,
    private_result_contract: PrivateResultContract | None,
    lease_id: UUIDString,
    lease_token: str,
) -> None:
    global _active_validation
    started = time.monotonic()
    try:
        exit_code, raw_output, safe_summary = execute_validation(
            run_id, operation, selectors, validation_env, requested_values, validation_intent, private_result_contract
        )
        private_build_diagnostics = safe_summary.pop("_private_build_diagnostics", None)
        private_structured_result = safe_summary.pop("_private_structured_result", None)
        if isinstance(private_structured_result, dict):
            current_state = read_state(run_id)
            private_structured_result = {
                **private_structured_result,
                "run_id": run_id,
                "operation_id": current_state.get("operation_id"),
                "lease_id": current_state.get("lease_id"),
                "execution_id": current_state.get("execution_id"),
                "binding": "validation-run-and-start-receipt-v1",
            }
        cancelled = run_id in _cancelled_runs
        failure_classification = classify_validation_failure(exit_code, raw_output, safe_summary, cancelled=cancelled)
        output = sanitize_text(raw_output, redacted_values)
        path = log_path(run_id)
        clipped, _ = truncate_text(output, MAX_TOOL_OUTPUT_BYTES)
        path.write_text(clipped, encoding="utf-8")
        os.chmod(path, 0o600)
        ending_status = git_worktree_status_raw()
        ending_head = resolve_ref("HEAD")
        ending_worktree_fingerprint = worktree_fingerprint()
        ending_index_fingerprint = index_fingerprint()
        state = read_state(run_id)
        state.update({
            "status": "cancelled" if cancelled else "completed",
            "exit_code": exit_code,
            "failure_classification": failure_classification,
            "completed_at": now_iso(),
            "duration_seconds": round(time.monotonic() - started, 3),
            "ending_head": ending_head,
            "ending_worktree_fingerprint": ending_worktree_fingerprint,
            "ending_index_fingerprint": ending_index_fingerprint,
            "repository_mutated": (
                ending_head != starting_head
                or ending_worktree_fingerprint != state.get("starting_worktree_fingerprint")
                or ending_index_fingerprint != state.get("starting_index_fingerprint")
            ),
            "safe_test_summary": safe_summary,
            "xcresult_evidence": safe_xcresult_evidence(safe_summary),
            "validation_intent": validation_intent,
            "publication_eligible": not (operation in {"test-focused", "test-full"} and validation_intent == "compile_only"),
            "private_build_diagnostics": private_build_diagnostics,
            "private_structured_result": private_structured_result,
            "private_result_contract": private_result_contract,
        })
        try:
            bind_validated_state(lease_id, lease_token, run_id, state)
        except Exception:
            state["validation_binding_failed"] = True
        write_state(run_id, state)
    except Exception as exc:
        state = read_state(run_id)
        state.update({
            "status": "cancelled" if run_id in _cancelled_runs else "failed_to_run",
            "exit_code": None,
            "failure_classification": "cancelled" if run_id in _cancelled_runs else "infrastructure_failure",
            "completed_at": now_iso(),
            "duration_seconds": round(time.monotonic() - started, 3),
            "error_type": type(exc).__name__,
            "error_message": sanitize_source_text(str(exc), redacted_values)[:1000],
        })
        try:
            state["ending_head"] = resolve_ref("HEAD")
            state["repository_mutated"] = (
                state["ending_head"] != starting_head
                or worktree_fingerprint() != state.get("starting_worktree_fingerprint")
                or index_fingerprint() != state.get("starting_index_fingerprint")
            )
        except Exception:
            state["repository_mutated"] = None
        log_path(run_id).write_text("Validation failed or was cancelled. Detailed private output is not persisted.\n", encoding="utf-8")
        os.chmod(log_path(run_id), 0o600)
        write_state(run_id, state)
        try:
            mark_lease_validation_state(lease_id, lease_token, run_id=run_id, starting=False)
        except Exception:
            pass
    finally:
        requested_values.clear()
        validation_env.clear()
        redacted_values.clear()
        with _validation_lock:
            if _active_validation == run_id:
                _active_validation = None
            _active_processes.pop(run_id, None)
            _cancelled_runs.discard(run_id)



# ========================================================================== 
# MCP 2.6 generic local capability substrate
# ========================================================================== 

_LOCAL_PROCESS_LOCK = threading.RLock()
_LOCAL_PROCESSES: dict[str, subprocess.Popen[Any]] = {}
_SECRET_PLACEHOLDER_RE = re.compile(r"\$\{secret:([A-Za-z0-9_.:-]{1,120})\}")

def _require_uuid(value: str, label: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(UUID_PATTERN, value):
        raise ValueError(f"{label} must be a UUID.")
    return value

def task_workspace_path(workspace_id: str) -> Path:
    _require_uuid(workspace_id, "workspace_id")
    candidate = (TASK_WORKSPACE_ROOT / workspace_id).resolve(strict=False)
    try:
        candidate.relative_to(TASK_WORKSPACE_ROOT)
    except ValueError as exc:
        raise PermissionError("Task workspace escapes the registered scratch root.") from exc
    return candidate

def task_workspace_marker(workspace_id: str) -> Path:
    return task_workspace_path(workspace_id) / TASK_WORKSPACE_MARKER

def require_task_workspace(workspace_id: str) -> Path:
    root = task_workspace_path(workspace_id)
    marker = root / TASK_WORKSPACE_MARKER
    if not root.is_dir() or root.is_symlink() or not marker.is_file() or marker.is_symlink():
        raise FileNotFoundError(f"Task workspace is not registered: {workspace_id}")
    try:
        metadata = json.loads(marker.read_text(encoding="utf-8"))
    except Exception as exc:
        raise RuntimeError(f"Task workspace marker is unreadable: {workspace_id}") from exc
    if metadata.get("workspace_id") != workspace_id or metadata.get("kind") != "mcp_task_workspace_v1":
        raise RuntimeError("Task workspace marker identity mismatch.")
    return root

def task_workspace_taint_marker(workspace_id: str) -> Path:
    return task_workspace_path(workspace_id) / TASK_WORKSPACE_TAINT_MARKER

def _task_workspace_is_tainted(workspace_id: str) -> bool:
    marker = task_workspace_taint_marker(workspace_id)
    if not marker.is_file() or marker.is_symlink():
        return False
    try:
        data = json.loads(marker.read_text(encoding="utf-8"))
    except Exception as exc:
        raise RuntimeError(f"Task workspace taint marker is unreadable: {workspace_id}") from exc
    if data.get("kind") != "mcp_private_source_taint_v1" or data.get("workspace_id") != workspace_id or data.get("tainted") is not True:
        raise RuntimeError(f"Task workspace taint marker identity mismatch: {workspace_id}")
    return True

def _mark_task_workspace_tainted(workspace_id: str, source_class: str) -> None:
    require_task_workspace(workspace_id)
    marker = task_workspace_taint_marker(workspace_id)
    if _task_workspace_is_tainted(workspace_id):
        return
    atomic_write_json(marker, {
        "kind": "mcp_private_source_taint_v1",
        "workspace_id": workspace_id,
        "tainted": True,
        "source_class": source_class,
        "marked_at": now_iso(),
        "executor_version": EXECUTOR_VERSION,
    })

def _task_workspace_for_relative(relative: str) -> tuple[str, Path]:
    parts = Path(relative).parts
    if not parts:
        raise PermissionError("Task scratch root itself is not a mutation target.")
    workspace_id = parts[0]
    root = require_task_workspace(workspace_id)
    return workspace_id, root

def _root_is_mutable(root_id: str) -> bool:
    return root_id in {"repo", "task_scratch"}

def _strict_generic_root_path(root_id: str, path: str, *, allow_root: bool = False, allow_final_symlink: bool = False) -> tuple[str, Path, Path]:
    roots = root_registry()
    if root_id not in roots:
        raise PermissionError(f"Unsupported local root: {root_id}")
    if not isinstance(path, str) or "\x00" in path:
        raise ValueError("Path must be a bounded root-relative string without NUL bytes.")
    supplied = Path(path or ".")
    if supplied.is_absolute():
        raise PermissionError("Absolute caller paths are not accepted.")
    parts = tuple(part for part in supplied.parts if part not in {"", "."})
    if any(part == ".." for part in parts):
        raise PermissionError("Path traversal is forbidden.")
    relative = Path(*parts) if parts else Path(".")
    if not allow_root and relative.as_posix() in {"", "."}:
        raise PermissionError("Selected root itself is not a file target.")
    root = roots[root_id]
    current = root
    for index, part in enumerate(parts):
        current = current / part
        is_final = index == len(parts) - 1
        if current.is_symlink() and (not is_final or not allow_final_symlink):
            raise PermissionError("Symlink path components are not permitted for this operation.")
    candidate = root if not parts else root.joinpath(*parts)
    if is_secret_name(candidate):
        raise PermissionError("Credential/token configuration is not readable through generic local filesystem capability.")
    return relative.as_posix(), candidate, root

def _normalize_local_mutation_target(root_id: str, path: str, *, allow_root: bool = False) -> tuple[str, Path, Path, str | None]:
    if root_id == "repo":
        relative, candidate = normalize_repo_write_path(path, allow_root=allow_root)
        return relative, candidate, REPO, None
    if root_id != "task_scratch":
        raise PermissionError(f"Root is read-only for MCP mutations: {root_id}")
    relative, candidate, root = _strict_generic_root_path(root_id, path, allow_root=allow_root, allow_final_symlink=False)
    workspace_id, workspace_root = _task_workspace_for_relative(relative)
    try:
        candidate.relative_to(workspace_root)
    except ValueError as exc:
        raise PermissionError("Task mutation escapes its owning workspace.") from exc
    if candidate in {task_workspace_marker(workspace_id), task_workspace_taint_marker(workspace_id)}:
        raise PermissionError("Task workspace ownership/taint markers may only be changed by executor lifecycle controls.")
    return relative, candidate, root, workspace_id

def _local_file_metadata(root_id: str, relative: str, candidate: Path) -> dict[str, Any]:
    if not candidate.exists():
        return {
            "root_id": root_id,
            "path": relative,
            "resolved_path": str(candidate),
            "type": "absent",
            "tracked": relative in tracked_paths() if root_id == "repo" else None,
        }
    if candidate.is_symlink():
        return {
            "root_id": root_id,
            "path": relative,
            "resolved_path": str(candidate),
            "type": "symlink",
            "tracked": relative in tracked_paths() if root_id == "repo" else None,
        }
    st = candidate.stat()
    if candidate.is_file():
        data = candidate.read_bytes()
        return {
            "root_id": root_id,
            "path": relative,
            "resolved_path": str(candidate),
            "type": "file",
            "size": len(data),
            "sha256": sha256_bytes(data),
            "mode": stat.S_IMODE(st.st_mode),
            "tracked": relative in tracked_paths() if root_id == "repo" else None,
        }
    if candidate.is_dir():
        return {
            "root_id": root_id,
            "path": relative,
            "resolved_path": str(candidate),
            "type": "directory",
            "empty": not any(candidate.iterdir()),
            "mode": stat.S_IMODE(st.st_mode),
            "tracked": None,
        }
    return {"root_id": root_id, "path": relative, "resolved_path": str(candidate), "type": "other", "tracked": None}

def _decode_fs_content(item: dict[str, Any], path: str) -> bytes:
    text = item.get("content_text")
    encoded = item.get("content_base64")
    if (text is None) == (encoded is None):
        raise ValueError(f"{path}: exactly one of content_text/content_base64 is required.")
    if text is not None:
        if not isinstance(text, str):
            raise ValueError(f"{path}: content_text must be a string.")
        data = text.encode("utf-8")
    else:
        if not isinstance(encoded, str):
            raise ValueError(f"{path}: content_base64 must be a string.")
        try:
            data = base64.b64decode(encoded, validate=True)
        except Exception as exc:
            raise ValueError(f"{path}: invalid base64 content.") from exc
    if len(data) > MAX_GENERIC_FILE_BYTES:
        raise RuntimeError(f"{path}: content exceeds {MAX_GENERIC_FILE_BYTES} bytes.")
    return data

def _validate_expected_file(item: dict[str, Any], relative: str, candidate: Path) -> dict[str, Any]:
    if not candidate.is_file() or candidate.is_symlink():
        raise FileNotFoundError(f"{relative} must be an existing ordinary file.")
    data = candidate.read_bytes()
    actual_sha = sha256_bytes(data)
    actual_size = len(data)
    expected_sha = str(item.get("expected_sha256") or "")
    expected_size = item.get("expected_size")
    if not re.fullmatch(r"[A-Fa-f0-9]{64}", expected_sha):
        raise ValueError(f"{relative}: expected_sha256 is required.")
    if expected_sha.casefold() != actual_sha:
        raise RuntimeError(f"{relative}: SHA changed. expected={expected_sha} actual={actual_sha}")
    if not isinstance(expected_size, int) or expected_size < 0:
        raise ValueError(f"{relative}: expected_size is required.")
    if expected_size != actual_size:
        raise RuntimeError(f"{relative}: size changed. expected={expected_size} actual={actual_size}")
    return {"sha256": actual_sha, "size": actual_size, "data": data}

def _local_fs_receipt_operations(operations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    safe: list[dict[str, Any]] = []
    for raw in operations:
        row = {k: v for k, v in raw.items() if k not in {"content_text", "content_base64"}}
        if "content_text" in raw or "content_base64" in raw:
            try:
                data = _decode_fs_content(raw, str(raw.get("path") or "[unknown]"))
                row["content_sha256"] = sha256_bytes(data)
                row["content_size"] = len(data)
            except Exception:
                row["content_present"] = True
        safe.append(row)
    return safe

def _local_fs_preflight(operations: list[dict[str, Any]]) -> tuple[str, list[tuple[str, dict[str, Any]]]]:
    if not isinstance(operations, list) or not operations or len(operations) > MAX_FILE_OPS:
        raise ValueError(f"operations must contain 1...{MAX_FILE_OPS} entries.")
    root_ids = {str(item.get("root_id") or "") for item in operations if isinstance(item, dict)}
    if len(root_ids) != 1:
        raise ValueError("One reviewed filesystem batch may target exactly one mutable root.")
    root_id = next(iter(root_ids))
    if not _root_is_mutable(root_id):
        raise PermissionError(f"Root is not mutable: {root_id}")
    normalized: list[tuple[str, dict[str, Any]]] = []
    touched: set[str] = set()
    for index, raw in enumerate(operations):
        if not isinstance(raw, dict):
            raise ValueError(f"Operation {index} must be an object.")
        kind = str(raw.get("op") or "")
        if kind not in {"create", "replace", "copy", "move", "delete", "mkdir", "rmdir"}:
            raise ValueError(f"Operation {index}: unsupported op {kind!r}.")
        if not isinstance(raw.get("path"), str) or not raw["path"]:
            raise ValueError(f"Operation {index}: path is required.")
        relative, candidate, _, workspace_id = _normalize_local_mutation_target(root_id, raw["path"])
        if relative in touched:
            raise ValueError("A mutation path may appear only once in a reviewed batch.")
        touched.add(relative)
        item = dict(raw)
        item["root_id"] = root_id
        item["path"] = relative
        item["_candidate"] = candidate
        item["_workspace_id"] = workspace_id
        item["_effective_kind"] = kind
        if kind == "create":
            if candidate.exists():
                raise FileExistsError(relative)
            if not candidate.parent.is_dir():
                raise FileNotFoundError(f"Parent does not exist: {relative}")
            item["_content_bytes"] = _decode_fs_content(item, relative)
        elif kind == "replace":
            before = _validate_expected_file(item, relative, candidate)
            item["_before_sha256"] = before["sha256"]
            item["_before_size"] = before["size"]
            item["_content_bytes"] = _decode_fs_content(item, relative)
        elif kind == "copy":
            if candidate.exists():
                raise FileExistsError(relative)
            if not candidate.parent.is_dir():
                raise FileNotFoundError(f"Parent does not exist: {relative}")
            source_root_id = str(item.get("source_root_id") or "")
            source_path = item.get("source_path")
            if not isinstance(source_path, str) or not source_path:
                raise ValueError(f"{relative}: copy requires source_path.")
            source_relative, source, source_root = _strict_generic_root_path(source_root_id, source_path, allow_final_symlink=False)
            source_check = _validate_expected_file(item, source_relative, source)
            source_tainted = source_root_id == "originals"
            if source_root_id == "task_scratch":
                source_workspace_id, _ = _task_workspace_for_relative(source_relative)
                source_tainted = _task_workspace_is_tainted(source_workspace_id)
            if root_id == "repo" and source_tainted:
                raise PermissionError("Private-original-derived data may not be copied into the product repository.")
            if root_id == "task_scratch" and source_tainted:
                item["_taint_destination_workspace"] = workspace_id
            item["source_root_id"] = source_root_id
            item["source_path"] = source_relative
            item["_source_candidate"] = source
            item["_content_bytes"] = source_check["data"]
            item["_effective_kind"] = "create"
            item["_source_sha256"] = source_check["sha256"]
            item["_source_size"] = source_check["size"]
        elif kind == "move":
            before = _validate_expected_file(item, relative, candidate)
            destination = item.get("destination")
            if not isinstance(destination, str) or not destination:
                raise ValueError(f"{relative}: move requires destination.")
            dest_relative, dest, _, dest_workspace = _normalize_local_mutation_target(root_id, destination)
            if dest_relative in touched:
                raise ValueError("Move destination conflicts with another mutation path.")
            touched.add(dest_relative)
            if dest.exists():
                raise FileExistsError(dest_relative)
            if not dest.parent.is_dir():
                raise FileNotFoundError(f"Move destination parent does not exist: {dest_relative}")
            if workspace_id != dest_workspace:
                raise PermissionError("Task workspace moves may not cross workspace ownership.")
            item["destination"] = dest_relative
            item["_destination"] = dest
            item["_before_sha256"] = before["sha256"]
            item["_before_size"] = before["size"]
        elif kind == "delete":
            before = _validate_expected_file(item, relative, candidate)
            item["_before_sha256"] = before["sha256"]
            item["_before_size"] = before["size"]
        elif kind == "mkdir":
            if candidate.exists():
                raise FileExistsError(relative)
            if not candidate.parent.is_dir():
                raise FileNotFoundError(f"mkdir parent does not exist: {relative}")
        elif kind == "rmdir":
            if not candidate.is_dir() or candidate.is_symlink():
                raise FileNotFoundError(f"{relative} is not an ordinary directory.")
            if any(candidate.iterdir()):
                raise PermissionError("rmdir only removes an explicitly empty directory.")
        normalized.append((kind, item))
    return root_id, normalized

def _local_fs_plan(root_id: str, normalized: list[tuple[str, dict[str, Any]]], expected_head: str | None, expected_worktree_fingerprint: str | None, expected_index_fingerprint: str | None) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    for kind, item in normalized:
        candidate: Path = item["_candidate"]
        before = _local_file_metadata(root_id, item["path"], candidate)
        row: dict[str, Any] = {"op": kind, "root_id": root_id, "path": item["path"], "before": before}
        if kind in {"create", "replace", "copy"}:
            data = item["_content_bytes"]
            row["after"] = {"type": "file", "sha256": sha256_bytes(data), "size": len(data)}
        elif kind == "move":
            row["destination"] = item["destination"]
            row["after"] = {"type": "file", "sha256": item["_before_sha256"], "size": item["_before_size"]}
        elif kind in {"delete", "rmdir"}:
            row["after"] = {"type": "absent"}
        elif kind == "mkdir":
            row["after"] = {"type": "directory", "empty": True}
        if kind == "copy":
            row["source"] = {"root_id": item["source_root_id"], "path": item["source_path"], "sha256": item["_source_sha256"], "size": item["_source_size"]}
        rows.append(row)
    canonical = {
        "version": GENERIC_FS_PLAN_VERSION,
        "root_id": root_id,
        "expected_head": expected_head if root_id == "repo" else None,
        "expected_worktree_fingerprint": expected_worktree_fingerprint if root_id == "repo" else None,
        "expected_index_fingerprint": expected_index_fingerprint if root_id == "repo" else None,
        "operations": rows,
    }
    digest = sha256_text(json.dumps(canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=False))
    return {**canonical, "reviewed_plan_digest": digest}

def _atomic_binary_write(candidate: Path, data: bytes, mode: int | None = None) -> None:
    temp = candidate.with_name(candidate.name + f".executor-{uuid.uuid4().hex}.tmp")
    with temp.open("wb") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())
    if mode is not None:
        os.chmod(temp, mode)
    os.replace(temp, candidate)

def _apply_local_fs_operations(root_id: str, normalized: list[tuple[str, dict[str, Any]]]) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for kind, item in normalized:
        candidate: Path = item["_candidate"]
        # Re-check the exact reviewed input immediately before each mutation.
        if kind in {"replace", "move", "delete"}:
            _validate_expected_file(item, item["path"], candidate)
        elif kind == "copy":
            source: Path = item["_source_candidate"]
            current = source.read_bytes() if source.is_file() and not source.is_symlink() else None
            if current is None or sha256_bytes(current) != item["_source_sha256"] or len(current) != item["_source_size"]:
                raise RuntimeError(f"{item['source_path']}: copy source changed after review.")
            if candidate.exists():
                raise RuntimeError(f"{item['path']}: copy destination appeared after review.")
        elif kind in {"create", "mkdir"} and candidate.exists():
            raise RuntimeError(f"{item['path']}: target appeared after review.")
        elif kind == "rmdir":
            if not candidate.is_dir() or candidate.is_symlink() or any(candidate.iterdir()):
                raise RuntimeError(f"{item['path']}: directory changed after review.")

        before = _local_file_metadata(root_id, item["path"], candidate)
        if kind == "create":
            _atomic_binary_write(candidate, item["_content_bytes"], 0o600)
        elif kind == "replace":
            mode = stat.S_IMODE(candidate.stat().st_mode)
            _atomic_binary_write(candidate, item["_content_bytes"], mode)
        elif kind == "copy":
            _atomic_binary_write(candidate, item["_content_bytes"], 0o600)
        elif kind == "move":
            destination: Path = item["_destination"]
            if destination.exists():
                raise RuntimeError(f"{item['destination']}: move destination appeared after review.")
            os.replace(candidate, destination)
        elif kind == "delete":
            candidate.unlink()
        elif kind == "mkdir":
            candidate.mkdir()
        elif kind == "rmdir":
            candidate.rmdir()

        after_candidate = item.get("_destination") if kind == "move" else candidate
        after_path = item.get("destination") if kind == "move" else item["path"]
        after = _local_file_metadata(root_id, after_path, after_candidate)
        if kind in {"create", "replace", "copy"}:
            expected_data = item["_content_bytes"]
            if after.get("type") != "file" or after.get("sha256") != sha256_bytes(expected_data) or after.get("size") != len(expected_data):
                raise RuntimeError(f"{after_path}: resulting file differs from reviewed bytes.")
        elif kind == "move":
            if candidate.exists() or after.get("type") != "file" or after.get("sha256") != item["_before_sha256"] or after.get("size") != item["_before_size"]:
                raise RuntimeError(f"{after_path}: resulting move differs from reviewed metadata.")
        elif kind in {"delete", "rmdir"} and after.get("type") != "absent":
            raise RuntimeError(f"{after_path}: target still exists after reviewed deletion.")
        elif kind == "mkdir" and (after.get("type") != "directory" or after.get("empty") is not True):
            raise RuntimeError(f"{after_path}: resulting directory differs from reviewed metadata.")
        taint_workspace = item.get("_taint_destination_workspace")
        if taint_workspace:
            _mark_task_workspace_tainted(str(taint_workspace), "private-original-derived-copy")
        results.append({"op": kind, "root_id": root_id, "path": item["path"], "before": before, "after": after, **({"destination": item["destination"]} if kind == "move" else {})})
    return results

def registered_secret_refs() -> dict[str, dict[str, str]]:
    refs: dict[str, dict[str, str]] = {
        "axis-card-password": {"provider": "axis-keychain"},
        "qualification-generated": {"provider": "generated"},
    }
    if SECRET_REF_FILE.is_file() and not SECRET_REF_FILE.is_symlink():
        try:
            raw = json.loads(SECRET_REF_FILE.read_text(encoding="utf-8"))
        except Exception as exc:
            raise RuntimeError("Registered secret-ref configuration is invalid JSON.") from exc
        if not isinstance(raw, dict):
            raise RuntimeError("Registered secret-ref configuration must be an object.")
        for name, spec in raw.items():
            if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,120}", name):
                raise RuntimeError("Invalid registered secret-ref name.")
            if not isinstance(spec, dict):
                raise RuntimeError(f"Invalid secret-ref configuration: {name}")
            provider = str(spec.get("provider") or "")
            if provider == "keychain":
                service = str(spec.get("service") or "")
                account = str(spec.get("account") or "")
                if not service or not account:
                    raise RuntimeError(f"Keychain secret-ref {name} requires service/account.")
                refs[name] = {"provider": "keychain", "service": service, "account": account}
            elif provider == "environment":
                env_name = str(spec.get("name") or "")
                if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", env_name):
                    raise RuntimeError(f"Environment secret-ref {name} has invalid name.")
                refs[name] = {"provider": "environment", "name": env_name}
            else:
                raise RuntimeError(f"Unsupported secret-ref provider for {name}: {provider}")
    return refs

def resolve_secret_ref(name: str) -> str:
    refs = registered_secret_refs()
    if name not in refs:
        raise PermissionError(f"Secret reference is not registered: {name}")
    spec = refs[name]
    provider = spec["provider"]
    if provider == "generated":
        return secrets.token_urlsafe(36)
    if provider == "axis-keychain":
        return keychain_axis_password()
    if provider == "environment":
        value = os.environ.get(spec["name"], "")
        if not value:
            raise RuntimeError(f"Registered environment secret is unavailable: {name}")
        return value
    if provider == "keychain":
        result = subprocess.run(
            [str(SECURITY), "find-generic-password", "-s", spec["service"], "-a", spec["account"], "-w"],
            capture_output=True, text=True, check=False, timeout=10,
        )
        value = result.stdout.rstrip("\n") if result.returncode == 0 else ""
        if not value:
            raise RuntimeError(f"Registered Keychain secret is unavailable: {name}")
        return value
    raise RuntimeError(f"Unsupported secret provider: {provider}")

def _substitute_secrets(value: str, cache: dict[str, str]) -> str:
    def repl(match: re.Match[str]) -> str:
        name = match.group(1)
        if name not in cache:
            cache[name] = resolve_secret_ref(name)
        return cache[name]
    return _SECRET_PLACEHOLDER_RE.sub(repl, value)

def _validate_env_additions(env_additions: dict[str, str] | None) -> dict[str, str]:
    additions = env_additions or {}
    if not isinstance(additions, dict) or len(additions) > 32:
        raise ValueError("env_additions must contain at most 32 string entries.")
    forbidden = {
        MCP_PATH_ENV, PUBLIC_HOST_ENV, BEARER_TOKEN_ENV, PUBLIC_URL_ENV, PORT_ENV,
        "LEDGERFORGE_EXECUTOR_STATE_ROOT", "LEDGERFORGE_EXECUTOR_REPO_ROOT",
        "LEDGERFORGE_EXECUTOR_EXPECTED_REMOTE_URL",
    }
    clean: dict[str, str] = {}
    for key, value in additions.items():
        if not isinstance(key, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", key):
            raise ValueError(f"Invalid environment key: {key!r}")
        if key in forbidden:
            raise PermissionError(f"Executor identity environment cannot be overridden: {key}")
        if not isinstance(value, str) or "\x00" in value or len(value) > 8192:
            raise ValueError(f"Environment value is invalid or too large: {key}")
        if re.search(r"(?i)(password|passwd|passphrase|token|api[_-]?key|secret)", key) and "${secret:" not in value:
            raise PermissionError(f"Credential-like environment key {key} must use a registered secret reference.")
        clean[key] = value
    return clean

def _allowed_executable_roots(workspace: Path, execution_class: str) -> list[Path]:
    roots = [
        Path("/bin"), Path("/usr/bin"), Path("/usr/sbin"), Path("/sbin"),
        Path("/usr/local/bin"), Path("/opt/homebrew/bin"),
        Path("/Applications/Xcode.app/Contents/Developer"),
        Path("/Library/Developer/CommandLineTools"),
        workspace,
    ]
    if execution_class == "repository":
        roots.append(REPO / "script")
    return [path.resolve(strict=False) for path in roots]

def _is_under(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False

def _resolve_local_executable(raw: str, workspace: Path, execution_class: str) -> Path:
    if not isinstance(raw, str) or not raw or "\x00" in raw:
        raise ValueError("argv[0] must be a non-empty executable.")
    if "/" in raw:
        candidate = Path(raw).expanduser()
    else:
        located = shutil.which(raw, path=safe_validation_base_env().get("PATH"))
        if not located:
            raise FileNotFoundError(f"Executable not found in registered PATH: {raw}")
        candidate = Path(located)
    resolved = candidate.resolve(strict=True)
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        raise PermissionError(f"Executable is not an executable regular file: {resolved}")
    if not any(_is_under(resolved, root) for root in _allowed_executable_roots(workspace, execution_class)):
        raise PermissionError(f"Executable is outside registered executable roots: {resolved}")
    return resolved

def _safe_local_process_base_env(workspace: Path) -> dict[str, str]:
    env: dict[str, str] = {
        "HOME": str(workspace / "home"),
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin",
        "TMPDIR": str(workspace / "tmp"),
        "USER": os.environ.get("USER", ""),
        "LOGNAME": os.environ.get("LOGNAME", ""),
        "LANG": os.environ.get("LANG", "en_US.UTF-8"),
    }
    for key in ("LC_ALL", "DEVELOPER_DIR", "SDKROOT", "TOOLCHAINS", "TERM"):
        value = os.environ.get(key)
        if value:
            env[key] = value
    for key, value in os.environ.items():
        if key.startswith("LC_") and value:
            env[key] = value
    return {key: value for key, value in env.items() if value}

def _sandbox_escape(path: Path) -> str:
    return str(path.resolve(strict=False)).replace("\\", "\\\\").replace('"', '\\"')

def _sandbox_profile(workspace: Path, execution_class: str) -> str:
    """Seatbelt profile: no network, no ambient user-home reads, writes only to owned scratch/repo, never .git."""
    home = Path.home().resolve()
    repo = REPO.resolve()
    workspace = workspace.resolve()
    lines = [
        "(version 1)",
        "(allow default)",
        "(deny network*)",
        "(deny file-write*)",
        f'(deny file-read* (subpath "{_sandbox_escape(home)}"))',
        f'(allow file-read* (subpath "{_sandbox_escape(workspace)}"))',
        f'(allow file-write* (subpath "{_sandbox_escape(workspace)}"))',
        '(allow file-write* (literal "/dev/null"))',
        '(deny process-exec (literal "/usr/bin/security"))',
        '(deny mach-lookup (global-name "com.apple.securityd"))',
        '(deny mach-lookup (global-name "com.apple.SecurityServer"))',
    ]
    if execution_class == "repository":
        lines.extend([
            f'(allow file-read* (subpath "{_sandbox_escape(repo)}"))',
            f'(allow file-write* (subpath "{_sandbox_escape(repo)}"))',
            f'(deny file-write* (subpath "{_sandbox_escape(repo / ".git")}"))',
        ])
    return "\n".join(lines) + "\n"

def _materialized_input_path(workspace: Path, index: int, source_name: str) -> Path:
    safe_name = re.sub(r"[^A-Za-z0-9._-]", "_", source_name)[:120] or "input.bin"
    return workspace / "input" / ".mcp-process-inputs" / f"{index:02d}-{safe_name}"

def _materialize_process_inputs(workspace_id: str, planned: list[dict[str, Any]]) -> dict[str, str]:
    """Re-check exact source metadata and copy immutable snapshots into owned scratch. Returns placeholder map."""
    workspace = require_task_workspace(workspace_id)
    root = workspace / "input" / ".mcp-process-inputs"
    if root.exists():
        shutil.rmtree(root)
    root.mkdir(parents=True, mode=0o700)
    replacements: dict[str, str] = {}
    for index, row in enumerate(planned):
        relative, source, _ = _strict_generic_root_path(str(row["root_id"]), str(row["path"]), allow_final_symlink=False)
        if not source.is_file() or source.is_symlink():
            raise FileNotFoundError(f"Process input disappeared: {row['root_id']}:{relative}")
        current_sha, current_size = _sha256_file_stream(source)
        if current_sha != row.get("sha256") or current_size != row.get("size"):
            raise RuntimeError(f"Process input changed after review: {row['root_id']}:{relative}")
        target = _materialized_input_path(workspace, index, source.name)
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        data = source.read_bytes()
        _atomic_binary_write(target, data, 0o600)
        check_sha, check_size = _sha256_file_stream(target)
        if check_sha != current_sha or check_size != current_size:
            raise RuntimeError("Materialized process input failed digest verification.")
        row["materialized_path"] = target.relative_to(workspace).as_posix()
        replacements[f"${{input:{index}}}"] = str(target)
    return replacements

def _substitute_process_inputs(value: str, replacements: dict[str, str]) -> str:
    for marker, path in replacements.items():
        value = value.replace(marker, path)
    if "${input:" in value:
        raise ValueError("Process argv/env contains an unresolved input placeholder.")
    return value

def _local_process_state_path(run_id: str) -> Path:
    _require_uuid(run_id, "run_id")
    return LOCAL_PROCESS_STATES / f"{run_id}.json"

def _local_process_stdout_path(run_id: str) -> Path:
    return LOCAL_PROCESS_OUTPUT / f"{run_id}.stdout"

def _local_process_stderr_path(run_id: str) -> Path:
    return LOCAL_PROCESS_OUTPUT / f"{run_id}.stderr"

def _read_local_process_state(run_id: str) -> dict[str, Any]:
    path = _local_process_state_path(run_id)
    if not path.is_file():
        raise FileNotFoundError(f"Unknown local process run: {run_id}")
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise RuntimeError("Local process state is unreadable.") from exc
    if not isinstance(state, dict):
        raise RuntimeError("Local process state is invalid.")
    return state

def _write_local_process_state(run_id: str, state: dict[str, Any]) -> None:
    atomic_write_json(_local_process_state_path(run_id), state)

def _sha256_file_stream(candidate: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with candidate.open("rb") as fh:
        while True:
            chunk = fh.read(1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            digest.update(chunk)
    return digest.hexdigest(), size

def _repository_changed_path_identities() -> dict[str, str]:
    changed = sorted(set(changed_tracked_paths()) | set(untracked_paths()) | set(conflicted_paths()))
    return {relative: current_path_identity(relative) for relative in changed}

def _repository_process_effect_verdict(
    starting_map: dict[str, str],
    ending_map: dict[str, str],
    expected_changed_paths: list[str],
    max_changed_path_count: int,
    starting_head: str | None,
    ending_head: str | None,
    starting_index_fingerprint: str | None,
    ending_index_fingerprint: str | None,
) -> dict[str, Any]:
    effect_paths = sorted(path for path in set(starting_map) | set(ending_map) if starting_map.get(path, "ABSENT_FROM_CHANGED_SET") != ending_map.get(path, "ABSENT_FROM_CHANGED_SET"))
    expected_effects = set(expected_changed_paths)
    unexpected_effects = sorted(set(effect_paths) - expected_effects)
    violations: list[str] = []
    if unexpected_effects:
        violations.append("unexpected_changed_path")
    if len(effect_paths) > max_changed_path_count:
        violations.append("changed_path_count_exceeded")
    if ending_head != starting_head:
        violations.append("head_changed")
    if ending_index_fingerprint != starting_index_fingerprint:
        violations.append("index_changed")
    return {
        "repository_effect_paths": effect_paths,
        "repository_unexpected_effect_paths": unexpected_effects,
        "repository_effect_violations": violations,
        "repository_effects_verified": not violations,
    }

def _normalize_repository_process_effect_bounds(execution_class: str, expected_changed_paths: list[str] | None, max_changed_path_count: int | None) -> tuple[list[str], int]:
    if execution_class != "repository":
        if expected_changed_paths is not None or max_changed_path_count is not None:
            raise ValueError("Repository effect bounds are only valid for execution_class=repository.")
        return [], 0
    if not isinstance(expected_changed_paths, list) or not expected_changed_paths:
        raise ValueError("Repository process execution requires a non-empty expected_changed_paths allowlist.")
    if len(expected_changed_paths) > MAX_REPOSITORY_PROCESS_CHANGED_PATHS:
        raise ValueError(f"expected_changed_paths accepts at most {MAX_REPOSITORY_PROCESS_CHANGED_PATHS} paths.")
    normalized: list[str] = []
    seen: set[str] = set()
    for raw in expected_changed_paths:
        if not isinstance(raw, str) or not raw:
            raise ValueError("expected_changed_paths entries must be non-empty strings.")
        relative, _ = normalize_repo_write_path(raw)
        if relative in seen:
            raise ValueError("expected_changed_paths entries must be unique.")
        seen.add(relative)
        normalized.append(relative)
    normalized.sort()
    limit = len(normalized) if max_changed_path_count is None else max_changed_path_count
    if not isinstance(limit, int) or limit < 0 or limit > len(normalized):
        raise ValueError("max_changed_path_count must be between 0 and the expected_changed_paths count.")
    return normalized, limit

def _process_plan(
    *,
    workspace_id: str,
    argv: list[str],
    cwd_path: str,
    cwd_root: str,
    execution_class: str,
    env_additions: dict[str, str],
    stdin_descriptor: dict[str, Any],
    input_files: list[dict[str, Any]],
    expected_changed_paths: list[str] | None,
    max_changed_path_count: int | None,
    timeout_seconds: int,
    expected_exit_codes: list[int],
    output_paths: list[str],
    expected_head: str | None,
    expected_worktree_fingerprint: str | None,
    expected_index_fingerprint: str | None,
) -> dict[str, Any]:
    workspace = require_task_workspace(workspace_id)
    if execution_class not in {"scratch", "repository"}:
        raise ValueError("execution_class must be scratch or repository.")
    if not isinstance(argv, list) or not argv or len(argv) > 128 or any(not isinstance(v, str) or "\x00" in v or len(v) > 32768 for v in argv):
        raise ValueError("argv must contain 1...128 bounded string arguments.")
    resolved = _resolve_local_executable(argv[0], workspace, execution_class)
    executable_sha, executable_size = _sha256_file_stream(resolved)
    if cwd_root not in {"task_workspace", "repo"}:
        raise ValueError("cwd_root must be task_workspace or repo.")
    if cwd_root == "repo" and execution_class != "repository":
        raise PermissionError("Repository cwd requires execution_class=repository.")
    if cwd_root == "task_workspace":
        _, cwd_candidate, _ = _strict_generic_root_path(
            "task_scratch", f"{workspace_id}/{cwd_path}", allow_root=False, allow_final_symlink=False
        )
        try:
            cwd_rel = cwd_candidate.relative_to(workspace).as_posix()
        except ValueError as exc:
            raise PermissionError("Process cwd escapes its task workspace.") from exc
    else:
        cwd_rel, cwd_candidate = normalize_repo_write_path(cwd_path, allow_root=True)
    if not cwd_candidate.is_dir():
        raise FileNotFoundError(f"Process cwd does not exist: {cwd_candidate}")
    if not isinstance(timeout_seconds, int) or not 1 <= timeout_seconds <= MAX_GENERIC_PROCESS_SECONDS:
        raise ValueError(f"timeout_seconds must be 1...{MAX_GENERIC_PROCESS_SECONDS}.")
    if not isinstance(expected_exit_codes, list) or not expected_exit_codes or len(expected_exit_codes) > 16 or any(not isinstance(v, int) or v < -255 or v > 255 for v in expected_exit_codes):
        raise ValueError("expected_exit_codes must contain 1...16 bounded integers.")
    if not isinstance(output_paths, list) or len(output_paths) > 20:
        raise ValueError("output_paths accepts at most 20 task-workspace-relative paths.")
    normalized_outputs: list[str] = []
    for path in output_paths:
        if not isinstance(path, str) or not path:
            raise ValueError("output_paths entries must be non-empty strings.")
        _, candidate, _ = _strict_generic_root_path(
            "task_scratch", f"{workspace_id}/{path}", allow_root=False, allow_final_symlink=False
        )
        try:
            rel = candidate.relative_to(workspace).as_posix()
        except ValueError as exc:
            raise PermissionError("Output artifact path escapes task workspace.") from exc
        normalized_outputs.append(rel)
    if not isinstance(input_files, list) or len(input_files) > 32:
        raise ValueError("input_files accepts at most 32 registered-root file bindings.")
    normalized_inputs: list[dict[str, Any]] = []
    for index, spec in enumerate(input_files):
        if not isinstance(spec, dict):
            raise ValueError(f"input_files[{index}] must be an object.")
        root_id = str(spec.get("root_id") or "")
        path = spec.get("path")
        if not isinstance(path, str) or not path:
            raise ValueError(f"input_files[{index}].path is required.")
        relative, candidate, _ = _strict_generic_root_path(root_id, path, allow_final_symlink=False)
        if not candidate.is_file():
            raise FileNotFoundError(f"Process input is not an ordinary file: {root_id}:{relative}")
        actual_sha, actual_size = _sha256_file_stream(candidate)
        expected_sha = spec.get("expected_sha256")
        expected_size = spec.get("expected_size")
        if expected_sha is not None and str(expected_sha).casefold() != actual_sha:
            raise RuntimeError(f"Process input SHA changed: {root_id}:{relative}")
        if expected_size is not None and expected_size != actual_size:
            raise RuntimeError(f"Process input size changed: {root_id}:{relative}")
        input_tainted = root_id == "originals"
        if root_id == "task_scratch":
            source_workspace_id, _ = _task_workspace_for_relative(relative)
            input_tainted = _task_workspace_is_tainted(source_workspace_id)
        normalized_inputs.append({
            "root_id": root_id,
            "path": relative,
            "resolved_path": str(candidate),
            "sha256": actual_sha,
            "size": actual_size,
            "private_source_tainted": input_tainted,
            "materialized_path": _materialized_input_path(workspace, index, candidate.name).relative_to(workspace).as_posix(),
        })
    workspace_tainted = _task_workspace_is_tainted(workspace_id)
    private_input_tainted = any(bool(row.get("private_source_tainted")) for row in normalized_inputs)
    if execution_class == "repository" and (workspace_tainted or private_input_tainted):
        raise PermissionError("Private-original-derived task workspaces or inputs may not receive repository process write scope.")
    normalized_expected_changes, changed_path_limit = _normalize_repository_process_effect_bounds(execution_class, expected_changed_paths, max_changed_path_count)
    canonical = {
        "version": PROCESS_PLAN_VERSION,
        "workspace_id": workspace_id,
        "execution_class": execution_class,
        "resolved_executable": str(resolved),
        "executable_sha256": executable_sha,
        "executable_size": executable_size,
        "argv": argv,
        "cwd_root": cwd_root,
        "cwd_path": cwd_rel,
        "env_additions": env_additions,
        "stdin": stdin_descriptor,
        "input_files": normalized_inputs,
        "workspace_private_source_tainted": workspace_tainted,
        "private_source_tainted": workspace_tainted or private_input_tainted,
        "would_taint_workspace": execution_class == "scratch" and private_input_tainted,
        "expected_changed_paths": normalized_expected_changes,
        "max_changed_path_count": changed_path_limit,
        "timeout_seconds": timeout_seconds,
        "expected_exit_codes": expected_exit_codes,
        "output_paths": normalized_outputs,
        "network_policy": "deny",
        "write_scope": ["task_workspace"] + (["repo"] if execution_class == "repository" else []),
        "expected_head": expected_head if execution_class == "repository" else None,
        "expected_worktree_fingerprint": expected_worktree_fingerprint if execution_class == "repository" else None,
        "expected_index_fingerprint": expected_index_fingerprint if execution_class == "repository" else None,
    }
    digest = sha256_text(json.dumps(canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=False))
    return {**canonical, "process_plan_digest": digest}

def _process_output_artifacts(workspace_id: str, paths: list[str]) -> list[dict[str, Any]]:
    workspace = require_task_workspace(workspace_id)
    out: list[dict[str, Any]] = []
    for relative in paths:
        candidate = (workspace / relative).resolve(strict=False)
        try:
            candidate.relative_to(workspace)
        except ValueError:
            continue
        if candidate.is_file() and not candidate.is_symlink():
            data = candidate.read_bytes()
            out.append({"path": relative, "resolved_path": str(candidate), "type": "file", "size": len(data), "sha256": sha256_bytes(data)})
        elif candidate.is_dir() and not candidate.is_symlink():
            out.append({"path": relative, "resolved_path": str(candidate), "type": "directory", "empty": not any(candidate.iterdir())})
        else:
            out.append({"path": relative, "resolved_path": str(candidate), "type": "absent"})
    return out

def _local_process_worker(run_id: str, command: list[str], environment: dict[str, str], cwd: Path, stdin_bytes: bytes | None, timeout_seconds: int, expected_exit_codes: list[int], secret_values: list[str]) -> None:
    started = time.monotonic()
    proc: subprocess.Popen[Any] | None = None
    try:
        proc = subprocess.Popen(
            command,
            cwd=cwd,
            stdin=subprocess.PIPE if stdin_bytes is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            start_new_session=True,
        )
        with _LOCAL_PROCESS_LOCK:
            _LOCAL_PROCESSES[run_id] = proc
        state = _read_local_process_state(run_id)
        state.update({"pid": proc.pid, "pgid": proc.pid, "process_start_identity": pid_start_identity(proc.pid)})
        _write_local_process_state(run_id, state)
        write_process_record(run_id, proc, "local-process")
        record = json.loads(process_record_path(run_id).read_text(encoding="utf-8"))
        record["resolved_executable"] = state.get("resolved_executable")
        atomic_write_json(process_record_path(run_id), record)
        timed_out = False
        try:
            stdout_b, stderr_b = proc.communicate(input=stdin_bytes, timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                os.killpg(proc.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                stdout_b, stderr_b = proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                stdout_b, stderr_b = proc.communicate()
        state = _read_local_process_state(run_id)
        cancel_requested = bool(state.get("cancel_requested"))
        stdout_text = (stdout_b or b"").decode("utf-8", errors="replace")
        stderr_text = (stderr_b or b"").decode("utf-8", errors="replace")
        stdout_safe = sanitize_text(stdout_text, secret_values)
        stderr_safe = sanitize_text(stderr_text, secret_values)
        out_clip, out_trunc = truncate_text(stdout_safe, MAX_LOCAL_PROCESS_PERSISTED_OUTPUT_BYTES)
        err_clip, err_trunc = truncate_text(stderr_safe, MAX_LOCAL_PROCESS_PERSISTED_OUTPUT_BYTES)
        _local_process_stdout_path(run_id).write_text(out_clip, encoding="utf-8")
        _local_process_stderr_path(run_id).write_text(err_clip, encoding="utf-8")
        os.chmod(_local_process_stdout_path(run_id), 0o600)
        os.chmod(_local_process_stderr_path(run_id), 0o600)
        if cancel_requested:
            final_status = "cancelled"
            classification = "cancelled"
        elif timed_out:
            final_status = "timed_out"
            classification = "timeout"
        else:
            final_status = "completed"
            classification = "expected_exit" if proc.returncode in expected_exit_codes else "unexpected_exit"
        if state.get("execution_class") == "repository":
            try:
                ending_head = resolve_ref("HEAD")
                ending_worktree = worktree_fingerprint()
                ending_index = index_fingerprint()
                state["ending_head"] = ending_head
                state["ending_worktree_fingerprint"] = ending_worktree
                state["ending_index_fingerprint"] = ending_index
                state["repository_mutated"] = (
                    ending_head != state.get("starting_head")
                    or ending_worktree != state.get("starting_worktree_fingerprint")
                    or ending_index != state.get("starting_index_fingerprint")
                )
                starting_map = state.get("starting_changed_path_identities") or {}
                ending_map = _repository_changed_path_identities()
                verdict = _repository_process_effect_verdict(
                    starting_map, ending_map, list(state.get("expected_changed_paths") or []), int(state.get("max_changed_path_count") or 0),
                    state.get("starting_head"), ending_head, state.get("starting_index_fingerprint"), ending_index,
                )
                state.update(verdict)
                if verdict["repository_effect_violations"]:
                    classification = "repository_effect_violation"
                if state["repository_mutated"] and state.get("lease_id"):
                    lease = read_active_lease_raw()
                    if lease and lease.get("status") == "active" and lease.get("lease_id") == state.get("lease_id"):
                        invalidate_lease_validation_binding(lease, "generic repository process changed repository state")
            except Exception as repo_exc:
                state["repository_evidence_error"] = sanitize_text(str(repo_exc), secret_values)[:1000]
                state["repository_effects_verified"] = False
                state["repository_effect_violations"] = ["effect_evidence_failure"]
                classification = "repository_effect_evidence_failure"
        state.update({
            "status": final_status,
            "classification": classification,
            "exit_code": proc.returncode,
            "signal": -proc.returncode if isinstance(proc.returncode, int) and proc.returncode < 0 else None,
            "completed_at": now_iso(),
            "duration_seconds": round(time.monotonic() - started, 3),
            "stdout_truncated": out_trunc,
            "stderr_truncated": err_trunc,
            "output_artifacts": _process_output_artifacts(state["workspace_id"], state.get("output_paths", [])),
        })
        _write_local_process_state(run_id, state)
        finish_process_record(run_id, final_status)
    except Exception as exc:
        try:
            state = _read_local_process_state(run_id)
            state.update({
                "status": "failed_to_run",
                "classification": "infrastructure_failure",
                "completed_at": now_iso(),
                "duration_seconds": round(time.monotonic() - started, 3),
                "error_type": type(exc).__name__,
                "error_message": sanitize_text(str(exc), secret_values)[:1000],
            })
            _write_local_process_state(run_id, state)
        finally:
            finish_process_record(run_id, "failed_to_run")
    finally:
        environment.clear()
        secret_values.clear()
        with _LOCAL_PROCESS_LOCK:
            _LOCAL_PROCESSES.pop(run_id, None)

def _reconcile_local_process_states(report: dict[str, Any]) -> None:
    for path in LOCAL_PROCESS_STATES.glob("*.json"):
        try:
            state = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if state.get("status") != "running":
            continue
        run_id = str(state.get("run_id") or path.stem)
        record_path = process_record_path(run_id)
        record: dict[str, Any] = {}
        if record_path.is_file():
            try:
                record = json.loads(record_path.read_text(encoding="utf-8"))
            except Exception:
                record = {}
        alive = bool(record) and pid_is_executor_owned(record)
        state["status"] = "orphan_detected" if alive else "executor_restarted"
        state["classification"] = "orphan_detected" if alive else "executor_restart"
        state["completed_at"] = now_iso()
        _write_local_process_state(run_id, state)
        report.setdefault("stale_local_processes", []).append({"run_id": run_id, "pid": record.get("pid"), "alive": alive})

def require_execution_lease_no_refresh(lease_id: str, lease_token: str) -> dict[str, Any]:
    """Validate same-owner lease capability without heartbeat/sequence mutation."""
    lease = read_active_lease_raw()
    if not lease or lease.get("status") != "active":
        raise RuntimeError("No active execution lease.")
    if lease_is_expired(lease):
        raise RuntimeError("Execution lease is expired.")
    if lease.get("lease_id") != lease_id:
        raise PermissionError("Execution lease ID mismatch.")
    expected = str(lease.get("token_digest") or "")
    if not expected or not hmac.compare_digest(expected, lease_token_digest(lease_token)):
        raise PermissionError("Execution lease token mismatch.")
    return lease

STARTUP_RECONCILIATION = startup_reconcile()

# ==========================================================================
# Auth / MCP construction
# ==========================================================================

BEARER_TOKEN = os.environ.get(BEARER_TOKEN_ENV, "").strip()
ADMIN_BEARER_TOKEN = os.environ.get(ADMIN_BEARER_TOKEN_ENV, "").strip()
PUBLIC_URL = os.environ.get(PUBLIC_URL_ENV, "").strip()
if not BEARER_TOKEN:
    raise RuntimeError(f"{BEARER_TOKEN_ENV} is not set.")
if len(BEARER_TOKEN) < 32:
    raise RuntimeError("Executor bearer token is unexpectedly short.")
if ADMIN_BEARER_TOKEN and len(ADMIN_BEARER_TOKEN) < 32:
    raise RuntimeError("Executor admin bearer token is unexpectedly short.")
if ADMIN_BEARER_TOKEN and hmac.compare_digest(ADMIN_BEARER_TOKEN, BEARER_TOKEN):
    raise RuntimeError("Executor admin bearer token must differ from the normal executor token.")
if not PUBLIC_URL.startswith("https://"):
    raise RuntimeError(f"{PUBLIC_URL_ENV} must be an HTTPS URL.")
parsed_public_url = urlsplit(PUBLIC_URL)
if not parsed_public_url.netloc:
    raise RuntimeError(f"{PUBLIC_URL_ENV} has no hostname.")
ISSUER_URL = f"{parsed_public_url.scheme}://{parsed_public_url.netloc}"


class StaticBearerVerifier(TokenVerifier):
    def __init__(self, expected_token: str, admin_token: str = ""):
        self.expected_token = expected_token
        self.admin_token = admin_token

    async def verify_token(self, token: str) -> AccessToken | None:
        if hmac.compare_digest(token, self.expected_token):
            return AccessToken(
                token=token,
                client_id="chatgpt-ledgerforge-recovery",
                scopes=["ledgerforge:execute"],
                subject="ledgerforge-owner",
            )
        if self.admin_token and hmac.compare_digest(token, self.admin_token):
            return AccessToken(
                token=token,
                client_id="chatgpt-ledgerforge-maintenance",
                scopes=["ledgerforge:execute", "ledgerforge:admin"],
                subject="ledgerforge-admin",
            )
        return None


def require_admin_scope() -> AccessToken:
    access = get_access_token()
    scopes = set(access.scopes or []) if access is not None else set()
    if "ledgerforge:admin" not in scopes:
        raise PermissionError("MCP administration requires the separate ledgerforge:admin bearer credential.")
    return access


mcp = MCPServer(
    "LedgerForge Recovery Executor",
    token_verifier=StaticBearerVerifier(BEARER_TOKEN, ADMIN_BEARER_TOKEN),
    auth=AuthSettings(
        issuer_url=AnyHttpUrl(ISSUER_URL),
        resource_server_url=AnyHttpUrl(PUBLIC_URL),
        required_scopes=["ledgerforge:execute"],
    ),
    instructions=(
        "Guarded LedgerForge coding executor. It provides bounded repository/evidence reads, "
        "worktree-confined text file mutations, registered repository tasks, build/test validation, "
        "and guarded exact Git stage/commit/normal-push operations, plus reviewed binary/root operations, task workspaces, and sandbox-confined argv execution. "
        "It does not expose unreviewed process execution, Git reset/restore/clean/rebase/history rewrite, live self-overwrite during an MCP request, "
        "a generic admin shell, or secret credential values. A separate ledgerforge:admin credential can inspect/stage/qualify/arm immutable MCP releases; activation remains local/manual. Private originals are read-only. Snapshot/lease/provenance state is mechanical only, "
        "never project authorization."
    ),
)


def tool(*, read_only: bool, destructive: bool = False, idempotent: bool = False, open_world: bool = False):
    def decorator(fn):
        kwargs: dict[str, Any] = {}
        if ToolAnnotations is not None:
            try:
                kwargs["annotations"] = ToolAnnotations(
                    read_only_hint=read_only,
                    destructive_hint=destructive,
                    idempotent_hint=idempotent,
                    open_world_hint=open_world,
                )
            except Exception:
                try:
                    kwargs["annotations"] = ToolAnnotations(
                        readOnlyHint=read_only,
                        destructiveHint=destructive,
                        idempotentHint=idempotent,
                        openWorldHint=open_world,
                    )
                except Exception:
                    kwargs = {}
        try:
            signature = inspect.signature(mcp.tool)
            if "annotations" not in signature.parameters:
                kwargs = {}
        except Exception:
            pass
        return mcp.tool(**kwargs)(fn)
    return decorator


# ==========================================================================
# Read-only MCP tools
# ==========================================================================

@tool(read_only=True)
def executor_capabilities() -> dict[str, Any]:
    """Return live executor capability/version information without secret values."""
    roots = {name: {"available": path.exists(), "writable": name in {"repo", "task_scratch"}, "resolved_path": str(path), "mutation_requires_lease": name == "repo"} for name, path in root_registry().items()}
    config = load_feature_config()
    return enforce_structured_output({
        "executor_version": EXECUTOR_VERSION,
        "toolset_revision": TOOLSET_REVISION,
        "schema_contract_revision": SCHEMA_CONTRACT_REVISION,
        "schema_contract_sha256": schema_contract_digest(),
        "source_sha256": source_sha256(),
        "executor_boot_id": EXECUTOR_BOOT_ID,
        "evidence_roots": roots,
        "file_operations": ["create", "replace", "exact_replace", "move", "delete", "mkdir", "rmdir"],
        "binary_file_operations": ["stat", "hash", "read-bytes", "create", "replace", "copy", "move", "delete", "mkdir", "rmdir-empty"],
        "task_workspace_lifecycle": ["create", "status", "cleanup", "close"],
        "generic_process_lifecycle": ["review", "start", "status", "wait", "cancel", "result"],
        "generic_process_network_policy": "deny",
        "generic_process_write_scopes": ["task-workspace", "repository-with-lease-effect-bounded-excluding-dotgit"],
        "generic_process_input_semantics": "exact registered-root source digest rechecked then snapshot-copied into task workspace; private-original-derived inputs taint scratch and cannot receive repository write scope; declared inputs become verified workspace-local paths",
        "private_source_taint_policy": {
            "marker_contract": "mcp_private_source_taint_v1",
            "direct_originals_to_repo_copy": "denied",
            "tainted_scratch_to_repo_copy": "denied",
            "tainted_repository_process": "denied",
            "semantic_llm_declassification": "outside-executor-information-flow-boundary",
        },
        "repository_process_effect_policy": {
            "expected_changed_paths_required": True,
            "maximum_allowlist_paths": MAX_REPOSITORY_PROCESS_CHANGED_PATHS,
            "preexisting_dirty_path_identity_compared": True,
            "head_change_allowed": False,
            "index_change_allowed": False,
            "automatic_rollback": False,
        },
        "registered_secret_refs": sorted(registered_secret_refs()),
        "owner_break_glass_command": str(Path.home() / "Desktop" / "LedgerForge MCP Owner Recovery.command"),
        "git_operations": ["inspect", "fetch-origin", "stage-exact", "commit-staged", "push-origin-main"],
        "repo_tasks": sorted(repo_task_registry()),
        "validation_operations": sorted(ALLOWED_VALIDATIONS),
        "private_contexts": sorted(PRIVATE_CONTEXTS),
        "core_features": sorted(CORE_FEATURES),
        "evidence_features": sorted(EVIDENCE_FEATURES),
        "optional_features": sorted(OPTIONAL_FEATURES),
        "state_root_mode": "default" if RUNS == DEFAULT_STATE_ROOT else "explicit",
        "feature_groups_enabled": {
            "core": bool(config.get("core")),
            "evidence": bool(config.get("evidence")),
            "optional": bool(config.get("optional")),
            "ci_status_inspection": bool(config.get("ci_status_inspection")),
        },
        "mutation_lease_required": True,
        "private_credentials_jit": True,
        "execution_snapshot_schema_revision": SNAPSHOT_SCHEMA_REVISION,
        "provenance_label_semantics": "metadata-only; excluded from idempotency and authorization",
        "private_structured_result_contracts": ["structural_evidence_v1"],
        "validation_status_wait_max_seconds": MAX_VALIDATION_STATUS_WAIT_SECONDS,
        "validation_wait_result_durable": True,
        "fingerprint_contract": {"worktree_revision": WORKTREE_FINGERPRINT_REVISION, "worktree_semantics": WORKTREE_FINGERPRINT_SEMANTICS, "index_revision": INDEX_FINGERPRINT_REVISION, "index_semantics": INDEX_FINGERPRINT_SEMANTICS},
        "admin_maintenance": {"configured": bool(ADMIN_BEARER_TOKEN), "scope": "ledgerforge:admin", "normal_token_has_admin_scope": False, "prepared_release_state_durable_across_chats": True, "qualification_network_policy": "loopback-only"},
        "release_transport": {
            "inline_content_base64": "supported-for-small-components",
            "immutable_blob_chunks": "supported",
            "chunk_size_limit": MAINTENANCE_MAX_BLOB_CHUNK_BYTES,
            "component_size_limit": MAINTENANCE_MAX_COMPONENT_BYTES,
            "whole_file_sha256_required": True,
            "cross_chat_resume": True,
            "arbitrary_caller_paths": False,
        },
        "ci_status_inspection_enabled": feature_enabled("optional", "ci-status-inspection"),
        "unsupported": [
            "unreviewed process execution", "network/browser automation", "git reset", "git restore", "git clean",
            "git rebase", "git cherry-pick", "force push", "branch deletion", "stash destruction",
            "history rewriting", "live self-overwrite during MCP request", "tunnel restart through MCP", "unowned recursive directory deletion",
            "arbitrary Keychain lookup", "unrestricted unified logs", "unconstrained SQL", "generic admin shell", "arbitrary home-directory admin access",
        ],
        "annotation_support_detected": ToolAnnotations is not None,
        "annotation_contract_count": len(TOOL_ANNOTATION_CONTRACT),
    }, MAX_TOOL_OUTPUT_BYTES)



@tool(read_only=True)
def executor_help(topic: Literal["overview", "reads", "mutation", "validation", "process", "recovery", "maintenance"] = "overview") -> dict[str, Any]:
    """Return a concise executor usage FAQ intended for new or resumed Executor chats."""
    common = {
        "authority": "Repository/project authorization is external to MCP. Tool state is mechanical evidence only.",
        "mutation_rule": "Use one execution lease; bind exact HEAD/worktree/index; dry-run reviewed mutations before apply.",
        "long_running": "Use validation_wait_result or process_wait/process_result. Results are durable across chat interruptions.",
        "cleanup": "Use task_workspace action=close to wait boundedly for owned processes, then clean safely.",
    }
    topics = {
        "overview": ["Inspect: execution_snapshot/workspace_state", "Mutate: lease then reviewed file/process operations", "Validate: start_validation then validation_wait_result", "Publish: exact git_stage/commit/push", "Admin maintenance requires a separate ledgerforge:admin credential."],
        "reads": ["Use evidence_batch for a stable grouped read.", "Use local_fs_inspect for binary-safe registered-root stat/hash/range reads."],
        "mutation": ["Never reuse stale fingerprints.", "Repository writes require lease + exact HEAD/worktree/index.", "Generic Git metadata writes remain forbidden."],
        "validation": ["test-focused/test-full fail closed on zero tests.", "test_discovery reports conservative selector capability metadata.", "validation_wait_result combines bounded wait and retained result retrieval."],
        "process": ["process_start is reviewed argv execution with network denied.", "Use task workspaces; declared external inputs are snapshot-copied.", "Private-original-derived inputs taint scratch and cannot receive repository write scope.", "Repository-class processes require an expected changed-path allowlist and bounded effect count.", "process state/results survive client disconnect."],
        "recovery": ["execution_snapshot groups lease, validation, processes, workspaces and cleanup safety.", "Owner Recovery remains local break-glass and independent of ChatGPT."],
        "maintenance": ["Maintenance tools require ledgerforge:admin.", "They can inspect allowlisted MCP control files and stage/qualify/arm immutable releases.", "Large components use resumable immutable blob chunks with per-chunk and whole-file SHA-256 verification; arbitrary caller paths are never read.", "They cannot expose arbitrary home files, Keychain secrets or a generic admin shell.", "Prepared release state is durable and resumable from a fresh admin chat."],
    }
    return {"executor_version": EXECUTOR_VERSION, "toolset_revision": TOOLSET_REVISION, "topic": topic, "quick_rules": common, "usage": topics[topic]}

@tool(read_only=True)
def host_status() -> dict[str, Any]:
    """Return bounded non-secret executor/tunnel host health."""
    def pgrep(pattern: str) -> list[int]:
        result = subprocess.run(["pgrep", "-f", pattern], capture_output=True, text=True, check=False, timeout=5)
        return [int(v) for v in result.stdout.split() if v.isdigit()]
    health = False
    ready = False
    for endpoint, key in (("http://127.0.0.1:8080/healthz", "health"), ("http://127.0.0.1:8080/readyz", "ready")):
        try:
            with urlopen(endpoint, timeout=1.5) as response:
                ok = 200 <= response.status < 300
        except Exception:
            ok = False
        if key == "health":
            health = ok
        else:
            ready = ok
    port = int(os.environ.get(PORT_ENV, "8768"))
    listening = False
    try:
        result = subprocess.run(["lsof", "-tiTCP:%d" % port, "-sTCP:LISTEN"], capture_output=True, text=True, check=False, timeout=5)
        listening = bool(result.stdout.strip())
    except Exception:
        pass
    recovery = STARTUP_RECONCILIATION
    return {
        "executor_version": EXECUTOR_VERSION,
        "executor_source_sha256": source_sha256(),
        "schema_contract_sha256": schema_contract_digest(),
        "executor_boot_id": EXECUTOR_BOOT_ID,
        "executor_pid": os.getpid(),
        "repo_root": str(REPO),
        "executor_port": port,
        "executor_port_listening": listening,
        "tunnel_client_processes": pgrep("tunnel-client run --profile ledgerforge-recovery"),
        "tunnel_healthz": health,
        "tunnel_readyz": ready,
        "run_state_root_ready": RUNS.is_dir(),
        "private_contexts": {name: private_context_available(name) for name in PRIVATE_CONTEXTS},
        "active_execution_lease": public_lease_view(read_active_lease_raw()),
        "startup_recovery_required": bool(recovery.get("incomplete_journals") or recovery.get("stale_processes")),
        "startup_reconciliation": {
            "stale_operation_count": len(recovery.get("stale_operations", [])),
            "stale_validation_count": len(recovery.get("stale_validations", [])),
            "stale_process_count": len(recovery.get("stale_processes", [])),
            "incomplete_journal_count": len(recovery.get("incomplete_journals", [])),
            "stale_private_artifacts_removed": recovery.get("stale_private_artifacts_removed", 0),
        },
        "credential_values_exposed": False,
    }


@tool(read_only=True)
def workspace_state() -> dict[str, Any]:
    """Return complete local LedgerForge Git/worktree safety state."""
    state = workspace_snapshot()
    state["execution_lease"] = public_lease_view(read_active_lease_raw())
    state["executor_boot_id"] = EXECUTOR_BOOT_ID
    state["fingerprint_contract"] = {"worktree_revision": WORKTREE_FINGERPRINT_REVISION, "worktree_semantics": WORKTREE_FINGERPRINT_SEMANTICS, "index_revision": INDEX_FINGERPRINT_REVISION, "index_semantics": INDEX_FINGERPRINT_SEMANTICS}
    return state



def _public_local_process_rows(lease_id: str | None = None) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in sorted(LOCAL_PROCESS_STATES.glob("*.json")):
        try:
            state = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not isinstance(state, dict) or not state.get("run_id"):
            continue
        if lease_id is not None and state.get("lease_id") != lease_id:
            continue
        rows.append({k: state.get(k) for k in (
            "run_id", "operation_id", "workspace_id", "lease_id", "execution_id", "execution_class",
            "status", "classification", "resolved_executable", "started_at", "completed_at", "pid", "pgid",
        )})
    rows.sort(key=lambda row: str(row.get("completed_at") or row.get("started_at") or ""), reverse=True)
    return rows


def _task_workspace_resource_rows(process_rows: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    processes = process_rows if process_rows is not None else _public_local_process_rows()
    by_workspace: dict[str, list[dict[str, Any]]] = {}
    for row in processes:
        wid = row.get("workspace_id")
        if isinstance(wid, str) and wid:
            by_workspace.setdefault(wid, []).append(row)
    rows: list[dict[str, Any]] = []
    for root in sorted(TASK_WORKSPACE_ROOT.iterdir() if TASK_WORKSPACE_ROOT.is_dir() else []):
        if not root.is_dir() or root.is_symlink():
            continue
        marker = root / TASK_WORKSPACE_MARKER
        if not marker.is_file() or marker.is_symlink():
            continue
        try:
            metadata = json.loads(marker.read_text(encoding="utf-8"))
        except Exception:
            metadata = {}
        owned = by_workspace.get(root.name, [])
        running = [row.get("run_id") for row in owned if row.get("status") == "running" and row.get("run_id")]
        terminal = [row.get("run_id") for row in owned if row.get("status") != "running" and row.get("run_id")]
        terminal_presented = terminal[:SNAPSHOT_WORKSPACE_TERMINAL_PROCESS_ID_LIMIT]
        rows.append({
            "workspace_id": root.name,
            "task_label": metadata.get("task_label"),
            "created_at": metadata.get("created_at"),
            "entry_count": sum(1 for _ in root.rglob("*")),
            "owned_process_count": len(running) + len(terminal),
            "owned_process_ids": running + terminal_presented,
            "owned_process_ids_truncated": len(terminal) > len(terminal_presented),
            "running_process_ids": running,
            "cleanup_safe": not running,
        })
    rows.sort(key=lambda row: str(row.get("created_at") or ""), reverse=True)
    return rows

@tool(read_only=True)
def execution_lease_status(lease_id: UUIDString | None = None) -> dict[str, Any]:
    """Return writer-lease lifecycle plus owned-resource evidence without exposing its capability token."""
    lease = read_active_lease_raw()
    view = public_lease_view(lease)
    if lease_id and view.get("lease_id") != lease_id:
        return {"active": False, "requested_lease_id": lease_id, "another_lease_active": bool(view.get("active"))}
    selected = str(view.get("lease_id") or "") or None
    processes = _public_local_process_rows(selected) if selected else []
    live_processes = [row for row in processes if row.get("status") == "running"]
    active_validation, _ = _validation_state_rows()
    validation_owned = isinstance(active_validation, dict) and selected is not None and active_validation.get("lease_id") == selected
    running_ops = running_lease_operation_receipts(selected) if selected else []
    view["expired"] = bool(lease and lease_is_expired(lease))
    view["associated_processes"] = processes[:32]
    view["associated_live_processes"] = live_processes[:32]
    view["active_validation_run_id"] = active_validation.get("run_id") if validation_owned else None
    view["running_operation_receipts"] = running_ops[:32]
    view["safe_to_release"] = not live_processes and not validation_owned and not running_ops
    return view


@tool(read_only=True)
def executor_recovery_status() -> dict[str, Any]:
    """Return startup-recovery/journal/process evidence without mutation."""
    incomplete: list[dict[str, Any]] = []
    for root in sorted(JOURNALS.iterdir() if JOURNALS.exists() else []):
        manifest_path = root / "manifest.json"
        if not manifest_path.is_file():
            continue
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if manifest.get("status") not in {"completed", "rolled_back"}:
            incomplete.append({
                "operation_id": manifest.get("operation_id"),
                "status": manifest.get("status"),
                "completed_steps": manifest.get("completed_steps", []),
                "entry_count": len(manifest.get("entries", {})) if isinstance(manifest.get("entries"), dict) else None,
            })
    stale_processes: list[dict[str, Any]] = []
    for path in PROCESS_RECORDS.glob("*.json"):
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if record.get("status") in {"orphan_detected", "running"}:
            stale_processes.append({k: record.get(k) for k in ("run_id", "pid", "pgid", "command_class", "status", "started_at")})
    return {
        "executor_boot_id": EXECUTOR_BOOT_ID,
        "startup_reconciliation": STARTUP_RECONCILIATION,
        "active_lease": public_lease_view(read_active_lease_raw()),
        "incomplete_file_journals": incomplete,
        "stale_or_owned_processes": stale_processes,
        "mutation_safe": not incomplete and not stale_processes,
    }


SNAPSHOT_SCHEMA_REVISION = "execution-snapshot-v2"


def _canonical_state_digest(value: dict[str, Any]) -> str:
    return sha256_text(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False))


def _validation_state_rows() -> tuple[dict[str, Any] | None, list[dict[str, Any]]]:
    active: dict[str, Any] | None = None
    terminal: list[dict[str, Any]] = []
    for path in RUNS.glob("*.json"):
        try:
            row = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not isinstance(row, dict) or not row.get("run_id"):
            continue
        public = {k: row.get(k) for k in (
            "run_id", "operation_id", "lease_id", "execution_id", "status", "operation",
            "private_context", "validation_intent", "starting_head", "ending_head",
            "repository_mutated", "failure_classification", "started_at", "completed_at",
            "provenance_label",
        )}
        structured = row.get("private_structured_result")
        expected_contract = row.get("private_result_contract")
        if expected_contract is not None or isinstance(structured, dict):
            public["structured_result"] = {
                "expected": expected_contract is not None,
                "captured": isinstance(structured, dict),
                "contract_id": structured.get("contract_id") if isinstance(structured, dict) else ("structural_evidence" if expected_contract == "structural_evidence_v1" else None),
                "contract_version": structured.get("contract_version") if isinstance(structured, dict) else (1 if expected_contract == "structural_evidence_v1" else None),
                "digest": structured.get("sha256") if isinstance(structured, dict) else None,
            }
        if row.get("status") == "running":
            active = public
        else:
            terminal.append(public)
    terminal.sort(key=lambda item: str(item.get("completed_at") or item.get("started_at") or ""), reverse=True)
    return active, terminal[:8]


def _most_recent_mutation_receipts() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    mutation_actions = {
        "apply_file_ops", "git_stage", "git_commit", "git_push", "git_fetch_origin",
        "runtime_launch", "runtime_stop", "start_validation", "cancel_validation",
    }
    for path in OPERATIONS.glob("*.json"):
        try:
            receipt = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not isinstance(receipt, dict) or receipt.get("action") not in mutation_actions:
            continue
        result = receipt.get("result") if isinstance(receipt.get("result"), dict) else {}
        rows.append({
            "operation_id": receipt.get("operation_id"),
            "action": receipt.get("action"),
            "status": receipt.get("status"),
            "lease_id": receipt.get("lease_id"),
            "execution_id": receipt.get("execution_id"),
            "authorization_digest": receipt.get("authorization_digest"),
            "provenance_label": receipt.get("provenance_label"),
            "completed_at": receipt.get("completed_at"),
            "result_digest": _canonical_state_digest(result) if result else None,
        })
    rows.sort(key=lambda item: str(item.get("completed_at") or ""), reverse=True)
    return rows[:8]


@tool(read_only=True)
def execution_snapshot(
    expected_machine_state_digest: Sha256String | None = None,
    expected_continuation_digest: Sha256String | None = None,
    max_bytes: ToolOutputBytes = 120_000,
) -> dict[str, Any]:
    """Return one read-only mechanical continuation snapshot. It carries no project authorization."""
    validate_output_limit(max_bytes)
    repository = workspace_snapshot()
    lease_raw = read_active_lease_raw()
    lease = public_lease_view(lease_raw)
    recovery = executor_recovery_status()
    active_validation, recent_terminal = _validation_state_rows()
    recent_mutations = _most_recent_mutation_receipts()
    all_owned_processes = _public_local_process_rows()
    running_processes = [row for row in all_owned_processes if row.get("status") == "running"]
    terminal_processes = [row for row in all_owned_processes if row.get("status") != "running"]
    presented_terminal_processes = terminal_processes[:SNAPSHOT_TERMINAL_PROCESS_HISTORY_LIMIT]
    owned_processes = running_processes + presented_terminal_processes
    owned_processes.sort(key=lambda row: str(row.get("completed_at") or row.get("started_at") or ""), reverse=True)
    all_task_workspaces = _task_workspace_resource_rows(all_owned_processes)
    running_task_workspaces = [row for row in all_task_workspaces if not row.get("cleanup_safe", False)]
    idle_task_workspaces = [row for row in all_task_workspaces if row.get("cleanup_safe", False)]
    presented_idle_task_workspaces = idle_task_workspaces[:SNAPSHOT_IDLE_WORKSPACE_HISTORY_LIMIT]
    task_workspaces = running_task_workspaces + presented_idle_task_workspaces
    task_workspaces.sort(key=lambda row: str(row.get("created_at") or ""), reverse=True)

    repository_material = {k: repository.get(k) for k in (
        "current_branch", "head", "origin_main", "ahead", "behind", "worktree_fingerprint",
        "index_fingerprint", "staged_files", "conflicted_files", "worktree_count", "stash_count",
        "active_git_operation",
    )}
    lease_material = {k: lease.get(k) for k in (
        "active", "lease_id", "execution_id", "authorization_digest", "baseline_head",
        "baseline_worktree_fingerprint", "status", "sequence", "executor_boot_id",
    )}
    active_validation_material = None
    if isinstance(active_validation, dict):
        active_validation_material = {k: active_validation.get(k) for k in (
            "run_id", "operation_id", "lease_id", "execution_id", "status", "operation",
            "private_context", "validation_intent", "starting_head", "ending_head", "repository_mutated",
        )}
    recovery_material = {
        "mutation_safe": recovery.get("mutation_safe"),
        "incomplete_file_journals": recovery.get("incomplete_file_journals", []),
        "stale_or_owned_processes": recovery.get("stale_or_owned_processes", []),
    }
    machine_material = {
        "executor": {
            "version": EXECUTOR_VERSION,
            "source_sha256": source_sha256(),
            "schema_sha256": schema_contract_digest(),
            "toolset_revision": TOOLSET_REVISION,
            "boot_id": EXECUTOR_BOOT_ID,
            "fingerprint_contract": {"worktree_revision": WORKTREE_FINGERPRINT_REVISION, "worktree_semantics": WORKTREE_FINGERPRINT_SEMANTICS, "index_revision": INDEX_FINGERPRINT_REVISION, "index_semantics": INDEX_FINGERPRINT_SEMANTICS},
        },
        "repository": repository_material,
        "lease": lease_material,
        "validation": active_validation_material,
        "recovery": recovery_material,
        # Receipt/history rows are presentation evidence only. Excluding them prevents
        # timestamps and bounded-history aging from creating meaningless digest churn.
    }
    continuation_material = {
        "repository": repository_material,
        "execution": {
            "execution_id": lease.get("execution_id"),
            "authorization_digest": lease.get("authorization_digest"),
            "baseline_head": lease.get("baseline_head"),
            "baseline_worktree_fingerprint": lease.get("baseline_worktree_fingerprint"),
        },
        # Continuation intentionally excludes transient lease status, validation state,
        # owned processes, heartbeat/expiry, timestamps, and receipt history. A RUNNING→PASS
        # validation transition therefore changes machine_state_digest but not continuation_digest
        # when durable repository/execution identity is unchanged.
        "incomplete_file_journals": recovery.get("incomplete_file_journals", []),
    }
    machine_digest = _canonical_state_digest(machine_material)
    continuation_digest = _canonical_state_digest(continuation_material)
    response = {
        "snapshot_schema_revision": SNAPSHOT_SCHEMA_REVISION,
        "executor": machine_material["executor"],
        "repository": repository_material,
        "execution": {
            "execution_id": lease.get("execution_id"),
            "authorization_digest": lease.get("authorization_digest"),
            "provenance_label": lease.get("provenance_label"),
        },
        "lease": lease,
        "validation": {"active_run": active_validation, "recent_terminal_runs": recent_terminal},
        "processes": {
            "owned": owned_processes,
            "running": running_processes,
            "total_count": len(all_owned_processes),
            "running_count": len(running_processes),
            "returned_count": len(owned_processes),
            "terminal_history_limit": SNAPSHOT_TERMINAL_PROCESS_HISTORY_LIMIT,
            "history_truncated": len(terminal_processes) > len(presented_terminal_processes),
        },
        "task_workspaces": task_workspaces,
        "task_workspace_presentation": {
            "total_count": len(all_task_workspaces),
            "active_count": len(running_task_workspaces),
            "returned_count": len(task_workspaces),
            "idle_history_limit": SNAPSHOT_IDLE_WORKSPACE_HISTORY_LIMIT,
            "history_truncated": len(idle_task_workspaces) > len(presented_idle_task_workspaces),
        },
        "cleanup_safe": not running_processes and active_validation is None and not recovery_material.get("incomplete_file_journals"),
        "mutation": {"recent_receipts": recent_mutations},
        "recovery": recovery_material,
        "machine_state_digest": machine_digest,
        "continuation_digest": continuation_digest,
        "machine_digest_matches": None if expected_machine_state_digest is None else hmac.compare_digest(machine_digest, expected_machine_state_digest),
        "continuation_digest_matches": None if expected_continuation_digest is None else hmac.compare_digest(continuation_digest, expected_continuation_digest),
        "reconciliation_required": bool(
            (expected_machine_state_digest is not None and not hmac.compare_digest(machine_digest, expected_machine_state_digest))
            or (expected_continuation_digest is not None and not hmac.compare_digest(continuation_digest, expected_continuation_digest))
        ),
        "mechanical_state_only": True,
        "mutation_authority_implied": False,
        "active_lease_is_authorization": False,
        "mutation_safe_semantics": "mechanically safe only if separately authorized",
        "digest_mismatch_semantics": "reconcile; never infer project authorization or automatic rejection",
        "observed_at": now_iso(),
    }
    return enforce_structured_output(response, max_bytes)


@tool(read_only=False, destructive=False, idempotent=True)
def acquire_execution_lease(
    operation_id: UUIDString,
    expected_head: str,
    expected_worktree_fingerprint: str,
    authorization_digest: HexDigest32To128,
    execution_id: UUIDString | None = None,
    owner_label: str | None = None,
    provenance_label: ProvenanceLabel | None = None,
    ttl_seconds: LeaseTTLSeconds = DEFAULT_LEASE_SECONDS,
) -> dict[str, Any]:
    """Acquire the single LedgerForge mutable execution lease and return its opaque capability token once."""
    payload = {
        "expected_head": expected_head,
        "expected_worktree_fingerprint": expected_worktree_fingerprint,
        "authorization_digest": authorization_digest,
        "execution_id": execution_id,
        "owner_label": owner_label,
        "provenance_label": provenance_label,
        "ttl_seconds": ttl_seconds,
    }
    replay, prior = begin_operation(operation_id, "acquire_execution_lease", payload)
    if replay:
        return prior
    try:
        if ttl_seconds < 60 or ttl_seconds > MAX_LEASE_SECONDS:
            raise ValueError(f"ttl_seconds must be 60...{MAX_LEASE_SECONDS}.")
        if not re.fullmatch(r"[A-Fa-f0-9]{32,128}", authorization_digest or ""):
            raise ValueError("authorization_digest must be a 32...128 character hexadecimal digest.")
        require_expected_head(expected_head)
        require_worktree_fingerprint(expected_worktree_fingerprint)
        if STARTUP_RECONCILIATION.get("incomplete_journals") or STARTUP_RECONCILIATION.get("stale_processes"):
            raise RuntimeError("Executor recovery reconciliation is required before acquiring a writer lease.")
        with _lease_transition_lock:
            with _lease_lock:
                require_no_running_replacement_lease_operations(operation_id)
                existing = read_active_lease_raw()
                if existing and existing.get("status") == "active" and not lease_is_expired(existing):
                    raise RuntimeError("EXECUTION_LEASE_HELD")
                lease_id = str(uuid.uuid4())
                token = secrets.token_urlsafe(48)
                now = datetime.now(timezone.utc)
                lease = {
                    "lease_id": lease_id,
                    "token_digest": lease_token_digest(token),
                    "execution_id": execution_id or str(uuid.uuid4()),
                    "authorization_digest": authorization_digest.casefold(),
                    "owner_label": sanitize_text(owner_label or "unspecified")[:160],
                    "provenance_label": normalize_provenance_label(provenance_label),
                    "baseline_head": expected_head,
                    "baseline_worktree_fingerprint": expected_worktree_fingerprint,
                    "baseline_index_fingerprint": index_fingerprint(),
                    "acquired_at": now.isoformat(),
                    "heartbeat_at": now.isoformat(),
                    "expires_at": (now + timedelta(seconds=ttl_seconds)).isoformat(),
                    "sequence": 0,
                    "executor_boot_id": EXECUTOR_BOOT_ID,
                    "executor_source_sha256": source_sha256(),
                    "schema_contract_sha256": schema_contract_digest(),
                    "status": "active",
                    "validated_state": None,
                    "active_validation_run_id": None,
                }
                atomic_write_json(LEASE_FILE, lease)
        public_result = {**public_lease_view(lease), "lease_token_returned_once": True}
        finish_operation(operation_id, public_result)
        return {**public_result, "lease_token": token}
    except Exception as exc:
        fail_operation(operation_id, exc)
        raise


@tool(read_only=False, destructive=False, idempotent=False)
def resume_execution_lease(
    operation_id: UUIDString,
    lease_id: UUIDString,
    execution_id: UUIDString,
    authorization_digest: HexDigest32To128,
    expected_head: str,
    expected_worktree_fingerprint: str,
    expected_index_fingerprint: str,
    provenance_label: ProvenanceLabel | None = None,
    ttl_seconds: LeaseTTLSeconds = DEFAULT_LEASE_SECONDS,
) -> dict[str, Any]:
    # Rotate and reissue one lease capability after exact durable continuation-state verification.
    payload = {
        "lease_id": lease_id,
        "execution_id": execution_id,
        "authorization_digest": authorization_digest,
        "expected_head": expected_head,
        "expected_worktree_fingerprint": expected_worktree_fingerprint,
        "expected_index_fingerprint": expected_index_fingerprint,
        "provenance_label": provenance_label,
        "ttl_seconds": ttl_seconds,
    }
    replay, prior = begin_operation(operation_id, "resume_execution_lease", payload)
    if replay:
        raise RuntimeError("This resume operation already completed. Use a new operation_id to rotate the capability again.")
    try:
        if ttl_seconds < 60 or ttl_seconds > MAX_LEASE_SECONDS:
            raise ValueError(f"ttl_seconds must be 60...{MAX_LEASE_SECONDS}.")
        if not re.fullmatch(r"[A-Fa-f0-9]{32,128}", authorization_digest or ""):
            raise ValueError("authorization_digest must be a 32...128 character hexadecimal digest.")

        with _lease_transition_lock:
            with _lease_lock:
                require_no_running_lease_operations(lease_id, operation_id)
                lease = read_active_lease_raw()
                if not lease or lease.get("status") != "active":
                    raise PermissionError("No resumable execution lease exists.")
                if lease_is_expired(lease):
                    lease["status"] = "expired"
                    lease["expired_at"] = now_iso()
                    atomic_write_json(LEASE_FILE, lease)
                    raise PermissionError("Execution lease expired.")
                if not hmac.compare_digest(str(lease.get("lease_id", "")), lease_id):
                    raise PermissionError("Execution lease_id does not match the durable lease.")
                if not hmac.compare_digest(str(lease.get("execution_id", "")), execution_id):
                    raise PermissionError("Execution identity does not match the durable lease.")
                if not hmac.compare_digest(str(lease.get("authorization_digest", "")), authorization_digest.casefold()):
                    raise PermissionError("Authorization identity does not match the durable lease.")
                if lease.get("active_validation_run_id") or _active_validation is not None:
                    raise RuntimeError("Cannot resume a lease while validation is active.")
    
                recovery = executor_recovery_status()
                if not recovery.get("mutation_safe"):
                    raise RuntimeError("Executor recovery state is not mutation-safe.")
                if active_git_operation():
                    raise RuntimeError("Cannot resume a lease during an active Git operation.")
                if conflicted_paths():
                    raise RuntimeError("Cannot resume a lease while Git conflicts exist.")
    
                head = resolve_ref("HEAD")
                worktree = worktree_fingerprint()
                index = index_fingerprint()
                if head != expected_head:
                    raise RuntimeError(f"HEAD changed. Expected={expected_head}, actual={head}")
                if worktree != expected_worktree_fingerprint:
                    raise RuntimeError("Worktree fingerprint does not match the continuation request.")
                if index != expected_index_fingerprint:
                    raise RuntimeError("Index fingerprint does not match the continuation request.")
    
                binding = resumable_lease_state_binding(lease, head, worktree, index)
                if binding is None:
                    raise RuntimeError("Current repository state is not durably attributable to this execution lease.")
    
                token = secrets.token_urlsafe(48)
                now = datetime.now(timezone.utc)
                lease["token_digest"] = lease_token_digest(token)
                lease["heartbeat_at"] = now.isoformat()
                lease["expires_at"] = (now + timedelta(seconds=ttl_seconds)).isoformat()
                if provenance_label is not None:
                    lease["provenance_label"] = normalize_provenance_label(provenance_label)
                lease["sequence"] = int(lease.get("sequence", 0)) + 1
                lease["resumed_at"] = now.isoformat()
                lease["resume_count"] = int(lease.get("resume_count", 0)) + 1
                lease["resume_binding"] = binding
                lease["executor_boot_id"] = EXECUTOR_BOOT_ID
                lease["executor_source_sha256"] = source_sha256()
                lease["schema_contract_sha256"] = schema_contract_digest()
                atomic_write_json(LEASE_FILE, lease)

        public_result = {
            **public_lease_view(lease),
            "resumed": True,
            "resume_binding": binding,
            "lease_token_returned_once": True,
        }
        finish_operation(operation_id, public_result)
        return {**public_result, "lease_token": token}
    except Exception as exc:
        fail_operation(operation_id, exc)
        raise


@tool(read_only=False, destructive=False, idempotent=True)
def heartbeat_execution_lease(operation_id: UUIDString, lease_id: UUIDString, lease_token: str, ttl_seconds: LeaseTTLSeconds = DEFAULT_LEASE_SECONDS) -> dict[str, Any]:
    """Refresh an owned execution lease without exposing the token in persisted state."""
    if ttl_seconds < 60 or ttl_seconds > MAX_LEASE_SECONDS:
        raise ValueError(f"ttl_seconds must be between 60 and {MAX_LEASE_SECONDS} seconds.")
    payload = {"lease_id": lease_id, "ttl_seconds": ttl_seconds}
    replay, prior = begin_operation(operation_id, "heartbeat_execution_lease", payload)
    if replay:
        return prior
    try:
        lease = require_execution_lease(lease_id, lease_token, extend_seconds=ttl_seconds)
        return finish_operation(operation_id, public_lease_view(lease))
    except Exception as exc:
        fail_operation(operation_id, exc)
        raise


@tool(read_only=False, destructive=False, idempotent=True)
def release_execution_lease(operation_id: UUIDString, lease_id: UUIDString, lease_token: str, require_clean_execution: bool = False) -> dict[str, Any]:
    """Release the writer lease. No repository rollback/cleanup is performed."""
    payload = {"lease_id": lease_id, "require_clean_execution": require_clean_execution}
    replay, prior = begin_operation(operation_id, "release_execution_lease", payload)
    if replay:
        return prior
    try:
        lease = require_execution_lease(lease_id, lease_token)
        if lease.get("active_validation_run_id"):
            raise RuntimeError("Cannot release execution lease while its validation is active.")
        if require_clean_execution:
            # Releasing a writer lease requires repository-state cleanliness, not passing tests.
            # Publication still requires successful validation at the stage/commit/push boundaries.
            validate_bound_state_for_publication(lease, require_success=False)
        with _lease_transition_lock:
            with _lease_lock:
                require_no_running_lease_operations(lease_id, operation_id)
                current = read_active_lease_raw() or lease
                current["status"] = "released"
                current["released_at"] = now_iso()
                atomic_write_json(LEASE_FILE, current)
        return finish_operation(operation_id, {**public_lease_view(current), "released": True})
    except Exception as exc:
        fail_operation(operation_id, exc)
        raise


@tool(read_only=True)
def list_files(
    root_id: RootId = "repo",
    path: str = "",
    glob: str | None = None,
    max_results: ListResultLimit = 500,
) -> dict[str, Any]:
    """List files under one approved LedgerForge evidence root, including ignored repo files."""
    if max_results < 1 or max_results > MAX_LIST_RESULTS:
        raise ValueError(f"max_results must be 1...{MAX_LIST_RESULTS}.")
    relative, base, root = normalize_root_path(root_id, path, allow_root=True)
    if not base.exists() or not base.is_dir():
        raise FileNotFoundError("Requested directory does not exist.")
    ensure_no_symlink_escape(base, root)
    results: list[str] = []
    for current, dirs, files in os.walk(base, followlinks=False):
        current_path = Path(current)
        dirs[:] = [d for d in dirs if d != ".git" and not (current_path / d).is_symlink()]
        for name in files:
            candidate = current_path / name
            if candidate.is_symlink() or is_secret_name(candidate):
                continue
            try:
                rel = candidate.resolve().relative_to(root).as_posix()
            except ValueError:
                continue
            if glob and not fnmatch.fnmatch(rel, glob):
                continue
            results.append(rel)
            if len(results) >= max_results:
                return {"root_id": root_id, "files": sorted(results), "returned": len(results), "truncated": True}
    return {"root_id": root_id, "files": sorted(results), "returned": len(results), "truncated": False}


@tool(read_only=True)
def read_file(
    path: str,
    root_id: RootId = "repo",
    start_line: Annotated[int, Field(ge=1)] = 1,
    end_line: int | None = None,
    max_bytes: ToolOutputBytes = 80_000,
) -> dict[str, Any]:
    """Read bounded sanitized UTF-8 text from an approved LedgerForge evidence root."""
    validate_output_limit(max_bytes)
    if start_line < 1:
        raise ValueError("start_line must be at least 1.")
    relative, candidate, root = normalize_root_path(root_id, path)
    ensure_no_symlink_escape(candidate, root)
    data, text = read_utf8_source(candidate) if root_id == "repo" else read_utf8(candidate)
    lines = text.splitlines()
    resolved_end = len(lines) if end_line is None else min(end_line, len(lines))
    if resolved_end < start_line:
        raise ValueError("end_line must be >= start_line.")
    rendered = "\n".join(
        f"{number:6d}: {line}"
        for number, line in enumerate(lines[start_line - 1:resolved_end], start=start_line)
    )
    rendered, truncated = truncate_text(rendered, max_bytes)
    return {
        "root_id": root_id,
        "path": relative,
        "sha256": sha256_bytes(data),
        "size_bytes": len(data),
        "total_lines": len(lines),
        "start_line": start_line,
        "end_line": resolved_end,
        "truncated": truncated,
        "content": rendered,
    }


@tool(read_only=True)
def search_files(
    query: str,
    root_id: RootId = "repo",
    path: str = "",
    regex: bool = False,
    case_sensitive: bool = False,
    path_glob: str | None = None,
    max_results: SearchResultLimit = 100,
) -> dict[str, Any]:
    """Search bounded UTF-8 files under one approved evidence root."""
    if not query:
        raise ValueError("query must not be empty.")
    if max_results < 1 or max_results > MAX_SEARCH_RESULTS:
        raise ValueError(f"max_results must be 1...{MAX_SEARCH_RESULTS}.")
    _, base, root = normalize_root_path(root_id, path, allow_root=True)
    if not base.exists() or not base.is_dir():
        raise FileNotFoundError("Search directory does not exist.")
    flags = 0 if case_sensitive else re.IGNORECASE
    compiled = re.compile(query, flags) if regex else None
    literal = query if case_sensitive else query.casefold()
    matches: list[dict[str, Any]] = []
    for current, dirs, files in os.walk(base, followlinks=False):
        current_path = Path(current)
        dirs[:] = [d for d in dirs if d != ".git" and not (current_path / d).is_symlink()]
        for name in files:
            candidate = current_path / name
            if candidate.is_symlink() or is_secret_name(candidate):
                continue
            try:
                rel = candidate.resolve().relative_to(root).as_posix()
            except ValueError:
                continue
            if path_glob and not fnmatch.fnmatch(rel, path_glob):
                continue
            try:
                _, text = read_utf8_source(candidate) if root_id == "repo" else read_utf8(candidate)
            except (OSError, ValueError, PermissionError):
                continue
            for line_number, line in enumerate(text.splitlines(), start=1):
                matched = compiled.search(line) is not None if compiled else literal in (line if case_sensitive else line.casefold())
                if matched:
                    matches.append({"path": rel, "line": line_number, "text": line[:MAX_SEARCH_LINE_CHARS]})
                    if len(matches) >= max_results:
                        return {"root_id": root_id, "matches": matches, "returned": len(matches), "truncated": True}
    return {"root_id": root_id, "matches": matches, "returned": len(matches), "truncated": False}


def sqlite_authorizer(action: int, arg1: str | None, arg2: str | None, dbname: str | None, source: str | None) -> int:
    allowed = {
        sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ, sqlite3.SQLITE_FUNCTION,
    }
    pragma_code = getattr(sqlite3, "SQLITE_PRAGMA", None)
    if pragma_code is not None and action == pragma_code:
        allowed_pragmas = {"table_info", "table_xinfo", "index_list", "index_info", "foreign_key_list", "integrity_check", "quick_check", "journal_mode"}
        if (arg1 or "").casefold() in allowed_pragmas:
            return sqlite3.SQLITE_OK
        return sqlite3.SQLITE_DENY
    return sqlite3.SQLITE_OK if action in allowed else sqlite3.SQLITE_DENY


def sanitize_sqlite_value(value: Any) -> Any:
    if value is None or isinstance(value, (int, float)):
        return value
    if isinstance(value, bytes):
        if len(value) > MAX_SQL_CELL_BYTES:
            return {"binary": True, "size_bytes": len(value), "truncated": True}
        return {"binary": True, "size_bytes": len(value), "sha256": sha256_bytes(value)}
    text = sanitize_text(str(value))
    encoded = text.encode("utf-8", errors="replace")
    if len(encoded) > MAX_SQL_CELL_BYTES:
        text = encoded[:MAX_SQL_CELL_BYTES].decode("utf-8", errors="ignore") + "...[cell truncated]"
    return text


def open_readonly_sqlite(candidate: Path) -> sqlite3.Connection:
    uri = f"file:{candidate}?mode=ro&immutable=1"
    db = sqlite3.connect(uri, uri=True)
    db.set_authorizer(sqlite_authorizer)
    start = time.monotonic()
    def progress() -> int:
        return 1 if time.monotonic() - start > 2.5 else 0
    db.set_progress_handler(progress, 10_000)
    return db


@tool(read_only=True)
def artifact_inspect(
    path: str,
    root_id: RootId = "repo",
    kind: ArtifactKind = "auto",
    sqlite_query: str | None = None,
    max_rows: SQLRowLimit = 100,
    max_bytes: ToolOutputBytes = 80_000,
) -> dict[str, Any]:
    """Inspect supported LedgerForge artifacts with aggregate byte limits and private-safe xcresult handling."""
    validate_output_limit(max_bytes)
    relative, candidate, root = normalize_root_path(root_id, path)
    ensure_no_symlink_escape(candidate, root)
    if not candidate.exists():
        raise FileNotFoundError("Artifact does not exist.")
    resolved_kind = kind
    if kind == "auto":
        if candidate.is_dir() and candidate.suffix == ".xcresult":
            resolved_kind = "xcresult"
        elif candidate.suffix in {".plist", ".xctestrun"}:
            resolved_kind = "plist"
        elif candidate.suffix == ".json":
            resolved_kind = "json"
        elif candidate.suffix in {".sqlite", ".sqlite3", ".db"}:
            resolved_kind = "sqlite"
        else:
            resolved_kind = "metadata"
    base_result: dict[str, Any] = {
        "root_id": root_id,
        "path": relative,
        "kind": resolved_kind,
        "is_directory": candidate.is_dir(),
    }
    if candidate.is_file():
        size = candidate.stat().st_size
        base_result["size_bytes"] = size
        base_result["sha256"] = sha256_bytes(candidate.read_bytes()) if size <= 64 * 1024 * 1024 else None
    if resolved_kind == "metadata":
        return enforce_structured_output(base_result, max_bytes)
    if resolved_kind == "json":
        data = json.loads(bounded_file_bytes(candidate).decode("utf-8"))
        base_result["content"] = sanitize_object(data)
        return enforce_structured_output(base_result, max_bytes)
    if resolved_kind == "plist":
        data = plistlib.loads(bounded_file_bytes(candidate))
        # Never surface known private environment values from an xctestrun/plist.
        def redact_private_keys(value: Any) -> Any:
            if isinstance(value, dict):
                return {
                    str(k): ("[REDACTED_PRIVATE_ENV]" if str(k) in ALL_PRIVATE_ENV_KEYS else redact_private_keys(v))
                    for k, v in value.items()
                }
            if isinstance(value, list):
                return [redact_private_keys(v) for v in value]
            return sanitize_object(value)
        base_result["content"] = redact_private_keys(data)
        return enforce_structured_output(base_result, max_bytes)
    if resolved_kind == "xcresult":
        require_feature("evidence", "structured-xcresult")
        if not candidate.is_dir():
            raise ValueError("xcresult kind requires an .xcresult directory.")
        summary = xcresult_safe_summary(candidate, safe_validation_base_env())
        base_result["summary"] = summary
        base_result["privacy_mode"] = "structured-safe-summary-only"
        return enforce_structured_output(base_result, max_bytes)
    if resolved_kind == "sqlite":
        if max_rows < 1 or max_rows > MAX_SQL_ROWS:
            raise ValueError(f"max_rows must be 1...{MAX_SQL_ROWS}.")
        with open_readonly_sqlite(candidate) as db:
            if not sqlite_query:
                rows = db.execute("SELECT name, type FROM sqlite_master WHERE type IN ('table','view') ORDER BY name").fetchall()
                base_result["tables"] = [{"name": sanitize_sqlite_value(r[0]), "type": sanitize_sqlite_value(r[1])} for r in rows]
                return enforce_structured_output(base_result, max_bytes)
            query = sqlite_query.strip()
            lowered = query.casefold()
            if ";" in query.rstrip(";"):
                raise PermissionError("Only one SQLite statement is allowed.")
            if not (lowered.startswith("select ") or lowered.startswith("pragma ")):
                raise PermissionError("Only read-only SELECT or approved PRAGMA inspection is allowed.")
            cursor = db.execute(query)
            names = [desc[0] for desc in cursor.description or []]
            rows = cursor.fetchmany(max_rows + 1)
        base_result["columns"] = [sanitize_text(str(v)) for v in names]
        base_result["rows"] = [
            {str(name): sanitize_sqlite_value(value) for name, value in zip(names, row)}
            for row in rows[:max_rows]
        ]
        base_result["truncated"] = len(rows) > max_rows
        return enforce_structured_output(base_result, max_bytes)
    raise ValueError(f"Unsupported artifact kind: {resolved_kind}")


@tool(read_only=True)
def git_inspect(
    mode: GitInspectMode = "diff",
    path: str | None = None,
    ref: str | None = None,
    max_bytes: ToolOutputBytes = 100_000,
) -> dict[str, Any]:
    """Inspect bounded Git state/diffs/log/show/blame without mutation or fetch."""
    validate_output_limit(max_bytes)
    if mode == "state":
        return workspace_snapshot()
    args: list[str]
    if mode == "diff":
        args = ["diff", "--no-color", "--no-ext-diff", "--no-renames", "HEAD", "--"]
        if path:
            relative, _ = normalize_repo_write_path(path)
            args.append(relative)
    elif mode == "staged-diff":
        args = ["diff", "--cached", "--no-color", "--no-ext-diff", "--no-renames", "--"]
        if path:
            relative, _ = normalize_repo_write_path(path)
            args.append(relative)
    elif mode == "log":
        args = ["log", "--oneline", "--decorate", "-n", "50"]
        if ref:
            args.append(ref)
    elif mode == "show":
        if not ref:
            raise ValueError("show requires ref.")
        args = ["show", "--no-color", "--stat", "--patch", ref]
    elif mode == "blame":
        if not path:
            raise ValueError("blame requires path.")
        relative, _ = normalize_repo_write_path(path)
        args = ["blame", "--", relative]
    else:
        raise PermissionError(f"Unsupported git_inspect mode: {mode}")
    output = run_git(*args, strip=False, timeout=60)
    output, truncated = truncate_text(output, max_bytes)
    return {"mode": mode, "output": output, "truncated": truncated, "head": resolve_ref("HEAD")}


# ========================================================================== 
# MCP 2.6 generic local filesystem / task workspace / process tools
# ========================================================================== 

@tool(read_only=True, destructive=False, idempotent=True)
def local_fs_inspect(
    root_id: RootId,
    path: str = "",
    action: Literal["stat", "hash", "read_bytes", "list"] = "stat",
    offset: Annotated[int, Field(ge=0)] = 0,
    length: Annotated[int, Field(ge=1, le=MAX_GENERIC_READ_BYTES)] = 65536,
    max_results: ListResultLimit = 500,
) -> dict[str, Any]:
    """Inspect registered local roots with binary-safe bounded reads. Financial/private content is not suppressed."""
    allow_root = action == "list"
    relative, candidate, root = _strict_generic_root_path(
        root_id, path, allow_root=allow_root, allow_final_symlink=(action == "stat")
    )
    if action == "stat":
        return _local_file_metadata(root_id, relative, candidate)
    if action == "hash":
        if not candidate.is_file() or candidate.is_symlink():
            raise FileNotFoundError("hash requires an ordinary file.")
        data = candidate.read_bytes()
        return {"root_id": root_id, "path": relative, "resolved_path": str(candidate), "size": len(data), "sha256": sha256_bytes(data)}
    if action == "read_bytes":
        if not candidate.is_file() or candidate.is_symlink():
            raise FileNotFoundError("read_bytes requires an ordinary file.")
        size = candidate.stat().st_size
        if offset > size:
            raise ValueError("offset exceeds file size.")
        with candidate.open("rb") as fh:
            fh.seek(offset)
            data = fh.read(length)
        return {
            "root_id": root_id,
            "path": relative,
            "resolved_path": str(candidate),
            "offset": offset,
            "returned_bytes": len(data),
            "file_size": size,
            "eof": offset + len(data) >= size,
            "base64": base64.b64encode(data).decode("ascii"),
            "sha256_of_returned_bytes": sha256_bytes(data),
        }
    if action == "list":
        if not candidate.is_dir() or candidate.is_symlink():
            raise FileNotFoundError("list requires an ordinary directory.")
        all_children = sorted(candidate.iterdir(), key=lambda p: p.name.casefold())
        rows: list[dict[str, Any]] = []
        for child in all_children[:max_results]:
            if is_secret_name(child):
                continue
            if child.is_symlink():
                kind = "symlink"; size = None
            elif child.is_file():
                kind = "file"; size = child.stat().st_size
            elif child.is_dir():
                kind = "directory"; size = None
            else:
                kind = "other"; size = None
            rows.append({"name": child.name, "type": kind, "size": size})
        return {"root_id": root_id, "path": relative, "resolved_path": str(candidate), "entries": rows, "returned": len(rows), "truncated": len(all_children) > max_results}
    raise ValueError("Unsupported local_fs_inspect action.")

@tool(read_only=False, destructive=True, idempotent=True)
def local_fs_mutate(
    operation_id: UUIDString,
    operations: list[dict[str, Any]],
    dry_run: bool = True,
    reviewed_plan_digest: Sha256String | None = None,
    lease_id: UUIDString | None = None,
    lease_token: str | None = None,
    expected_head: str | None = None,
    expected_worktree_fingerprint: str | None = None,
    expected_index_fingerprint: str | None = None,
    provenance_label: ProvenanceLabel | None = None,
) -> dict[str, Any]:
    """Apply one reviewed binary-safe mutation batch to repo-with-lease or an owned task workspace."""
    receipt_ops = _local_fs_receipt_operations(operations)
    payload = {
        "operations": receipt_ops,
        "dry_run": dry_run,
        "lease_id": lease_id,
        "expected_head": expected_head,
        "expected_worktree_fingerprint": expected_worktree_fingerprint,
        "expected_index_fingerprint": expected_index_fingerprint,
        "reviewed_plan_digest": reviewed_plan_digest,
        "provenance_label": provenance_label,
    }
    replay, prior = begin_operation(operation_id, "local_fs_mutate", payload)
    if replay:
        return prior
    manifest = None
    try:
        raw_roots = {str(item.get("root_id") or "") for item in operations if isinstance(item, dict)}
        if len(raw_roots) != 1:
            raise ValueError("One filesystem mutation batch must target exactly one root.")
        raw_root = next(iter(raw_roots))
        lease = None
        if raw_root == "repo":
            if not lease_id or not lease_token:
                raise PermissionError("Repository filesystem mutation requires the active execution lease.")
            if not expected_head or not expected_worktree_fingerprint or not expected_index_fingerprint:
                raise ValueError("Repository filesystem mutation requires exact HEAD/worktree/index preconditions.")
            lease = require_execution_lease(lease_id, lease_token)
            require_expected_head(expected_head)
            require_worktree_fingerprint(expected_worktree_fingerprint)
            if index_fingerprint() != expected_index_fingerprint:
                raise RuntimeError("Repository index changed before reviewed binary mutation.")
        root_id, normalized = _local_fs_preflight(operations)
        plan = _local_fs_plan(root_id, normalized, expected_head, expected_worktree_fingerprint, expected_index_fingerprint)
        if dry_run:
            return finish_operation(operation_id, {**plan, "dry_run": True, "lease_id": lease_id})
        if not reviewed_plan_digest or not hmac.compare_digest(plan["reviewed_plan_digest"], reviewed_plan_digest.casefold()):
            raise RuntimeError("Reviewed filesystem plan digest does not match current target metadata.")
        if root_id == "repo":
            require_expected_head(str(expected_head))
            require_worktree_fingerprint(str(expected_worktree_fingerprint))
            if index_fingerprint() != expected_index_fingerprint:
                raise RuntimeError("Repository index changed immediately before binary mutation.")
            journal_normalized: list[tuple[str, dict[str, Any]]] = []
            affected: set[str] = set()
            for kind, item in normalized:
                effective = item.get("_effective_kind", kind)
                journal_kind = "create" if kind == "copy" else effective
                journal_normalized.append((journal_kind, item))
                affected.add(item["path"])
                if kind == "move":
                    affected.add(item["destination"])
            manifest = create_file_journal(operation_id, affected, journal_normalized, str(expected_head))
        with _file_lock:
            results = _apply_local_fs_operations(root_id, normalized)
        if root_id == "repo":
            update_file_journal(operation_id, manifest, status="completed")
            remove_completed_journal(operation_id)
            if lease is not None:
                invalidate_lease_validation_binding(lease, "binary/root filesystem mutation after validation")
        return finish_operation(operation_id, {
            "dry_run": False,
            "root_id": root_id,
            "lease_id": lease_id,
            "reviewed_plan_digest_verified": True,
            "operations": results,
            "provenance_label": normalize_provenance_label(provenance_label),
            "ending_worktree_fingerprint": worktree_fingerprint() if root_id == "repo" else None,
            "ending_index_fingerprint": index_fingerprint() if root_id == "repo" else None,
            "durable_repository_journal_residue": False if root_id == "repo" else None,
        })
    except Exception as exc:
        if manifest is not None:
            try:
                restore_file_journal(operation_id, manifest)
                remove_completed_journal(operation_id)
            except Exception:
                pass
        fail_operation(operation_id, exc)
        raise

@tool(read_only=False, destructive=True, idempotent=True)
def task_workspace(
    operation_id: UUIDString,
    workspace_id: UUIDString,
    action: Literal["create", "status", "cleanup", "close"],
    task_label: str | None = None,
    provenance_label: ProvenanceLabel | None = None,
    wait_seconds: WaitSeconds = 60,
) -> dict[str, Any]:
    """Create/status/cleanup or safely close one exact MCP-owned task scratch workspace outside the product repository."""
    payload = {"workspace_id": workspace_id, "action": action, "task_label": task_label, "provenance_label": provenance_label, "wait_seconds": wait_seconds}
    replay, prior = begin_operation(operation_id, "task_workspace", payload)
    if replay:
        return prior
    try:
        root = task_workspace_path(workspace_id)
        marker = root / TASK_WORKSPACE_MARKER
        if action == "status":
            if not root.exists():
                return finish_operation(operation_id, {"workspace_id": workspace_id, "exists": False, "resolved_path": str(root)})
            require_task_workspace(workspace_id)
            entries = sum(1 for _ in root.rglob("*"))
            return finish_operation(operation_id, {"workspace_id": workspace_id, "exists": True, "resolved_path": str(root), "entry_count": entries, "private_source_tainted": _task_workspace_is_tainted(workspace_id)})
        if action == "create":
            if root.exists():
                raise FileExistsError(f"Task workspace already exists: {workspace_id}")
            root.mkdir(parents=True, mode=0o700)
            for name in ("input", "work", "output", "DerivedData", "tmp", "home"):
                (root / name).mkdir(mode=0o700)
            atomic_write_json(marker, {
                "kind": "mcp_task_workspace_v1",
                "workspace_id": workspace_id,
                "task_label": task_label,
                "created_at": now_iso(),
                "executor_boot_id": EXECUTOR_BOOT_ID,
                "provenance_label": normalize_provenance_label(provenance_label),
            })
            return finish_operation(operation_id, {"workspace_id": workspace_id, "created": True, "resolved_path": str(root), "subdirectories": ["input", "work", "output", "DerivedData", "tmp", "home"]})
        if action in {"cleanup", "close"}:
            require_task_workspace(workspace_id)
            deadline = time.monotonic() + (wait_seconds if action == "close" else 0)
            while True:
                running: list[str] = []
                for state_path in LOCAL_PROCESS_STATES.glob("*.json"):
                    try:
                        state = json.loads(state_path.read_text(encoding="utf-8"))
                    except Exception:
                        continue
                    if state.get("workspace_id") == workspace_id and state.get("status") == "running":
                        running.append(str(state.get("run_id") or state_path.stem))
                if not running:
                    break
                if action == "cleanup":
                    raise RuntimeError(f"Task workspace owns a running local process: {running[0]}")
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return finish_operation(operation_id, {"workspace_id": workspace_id, "closed": False, "cleaned": False, "cleanup_safe": False, "running_process_ids": running, "resolved_path": str(root), "exists_after": True})
                time.sleep(min(0.25, remaining))
            shutil.rmtree(root)
            return finish_operation(operation_id, {"workspace_id": workspace_id, "closed": action == "close", "cleaned": True, "cleanup_safe": True, "running_process_ids": [], "resolved_path": str(root), "exists_after": root.exists()})
        raise ValueError("Unsupported task_workspace action.")
    except Exception as exc:
        fail_operation(operation_id, exc)
        raise

def _stdin_descriptor_and_bytes(workspace_id: str, stdin_text: str | None, stdin_base64: str | None, stdin_path: str | None, stdin_secret_ref: str | None, secret_cache: dict[str, str]) -> tuple[dict[str, Any], bytes | None]:
    choices = [stdin_text is not None, stdin_base64 is not None, stdin_path is not None, stdin_secret_ref is not None]
    if sum(1 for v in choices if v) > 1:
        raise ValueError("Specify at most one stdin source.")
    if stdin_text is not None:
        data = _substitute_secrets(stdin_text, secret_cache).encode("utf-8")
        return {"mode": "text", "sha256": sha256_bytes(data), "size": len(data)}, data
    if stdin_base64 is not None:
        try:
            data = base64.b64decode(stdin_base64, validate=True)
        except Exception as exc:
            raise ValueError("stdin_base64 is invalid.") from exc
        return {"mode": "base64", "sha256": sha256_bytes(data), "size": len(data)}, data
    if stdin_path is not None:
        workspace = require_task_workspace(workspace_id)
        candidate = (workspace / stdin_path).resolve(strict=False)
        try:
            rel = candidate.relative_to(workspace)
        except ValueError as exc:
            raise PermissionError("stdin file escapes task workspace.") from exc
        ensure_no_symlink_escape(candidate, workspace)
        if not candidate.is_file():
            raise FileNotFoundError("stdin_path is not an ordinary file.")
        data = candidate.read_bytes()
        return {"mode": "file", "path": rel.as_posix(), "sha256": sha256_bytes(data), "size": len(data)}, data
    if stdin_secret_ref is not None:
        value = resolve_secret_ref(stdin_secret_ref)
        secret_cache[stdin_secret_ref] = value
        data = value.encode("utf-8")
        return {"mode": "secret_ref", "ref": stdin_secret_ref, "size": len(data)}, data
    return {"mode": "none"}, None

@tool(read_only=False, destructive=True, idempotent=True)
def process_start(
    operation_id: UUIDString,
    workspace_id: UUIDString,
    argv: list[str],
    cwd_path: str = "work",
    cwd_root: Literal["task_workspace", "repo"] = "task_workspace",
    execution_class: Literal["scratch", "repository"] = "scratch",
    env_additions: dict[str, str] | None = None,
    stdin_text: str | None = None,
    stdin_base64: str | None = None,
    stdin_path: str | None = None,
    stdin_secret_ref: str | None = None,
    input_files: list[dict[str, Any]] = [],
    expected_changed_paths: list[str] | None = None,
    max_changed_path_count: Annotated[int, Field(ge=0, le=MAX_REPOSITORY_PROCESS_CHANGED_PATHS)] | None = None,
    timeout_seconds: Annotated[int, Field(ge=1, le=MAX_GENERIC_PROCESS_SECONDS)] = 300,
    expected_exit_codes: list[int] = [0],
    output_paths: list[str] = [],
    dry_run: bool = True,
    reviewed_plan_digest: Sha256String | None = None,
    lease_id: UUIDString | None = None,
    lease_token: str | None = None,
    expected_head: str | None = None,
    expected_worktree_fingerprint: str | None = None,
    expected_index_fingerprint: str | None = None,
    provenance_label: ProvenanceLabel | None = None,
) -> dict[str, Any]:
    """Review/start one bounded argv process in an MCP task workspace. Network is denied; repo writes require the active lease."""
    env_clean = _validate_env_additions(env_additions)
    secret_cache: dict[str, str] = {}
    stdin_descriptor, stdin_bytes = _stdin_descriptor_and_bytes(workspace_id, stdin_text, stdin_base64, stdin_path, stdin_secret_ref, secret_cache)
    plan = _process_plan(
        workspace_id=workspace_id,
        argv=argv,
        cwd_path=cwd_path,
        cwd_root=cwd_root,
        execution_class=execution_class,
        env_additions=env_clean,
        stdin_descriptor=stdin_descriptor,
        input_files=input_files,
        expected_changed_paths=expected_changed_paths,
        max_changed_path_count=max_changed_path_count,
        timeout_seconds=timeout_seconds,
        expected_exit_codes=expected_exit_codes,
        output_paths=output_paths,
        expected_head=expected_head,
        expected_worktree_fingerprint=expected_worktree_fingerprint,
        expected_index_fingerprint=expected_index_fingerprint,
    )
    payload = {
        "workspace_id": workspace_id,
        "process_plan_digest": plan["process_plan_digest"],
        "dry_run": dry_run,
        "lease_id": lease_id,
        "provenance_label": provenance_label,
    }
    replay, prior = begin_operation(operation_id, "process_start", payload)
    if replay:
        secret_cache.clear()
        return prior
    try:
        if dry_run:
            secret_cache.clear()
            return finish_operation(operation_id, {**plan, "dry_run": True, "lease_required": execution_class == "repository"})
        if not reviewed_plan_digest or not hmac.compare_digest(plan["process_plan_digest"], reviewed_plan_digest.casefold()):
            raise RuntimeError("Reviewed process plan digest does not match the current execution plan.")
        lease = None
        if execution_class == "repository":
            if not lease_id or not lease_token or not expected_head or not expected_worktree_fingerprint or not expected_index_fingerprint:
                raise PermissionError("Repository process execution requires lease plus exact repository state.")
            lease = require_execution_lease(lease_id, lease_token, extend_seconds=timeout_seconds + 300)
            require_expected_head(expected_head)
            require_worktree_fingerprint(expected_worktree_fingerprint)
            if index_fingerprint() != expected_index_fingerprint:
                raise RuntimeError("Repository index changed before process start.")
        sandbox = Path("/usr/bin/sandbox-exec")
        if not sandbox.is_file():
            raise RuntimeError("Generic process execution requires /usr/bin/sandbox-exec for write/network confinement.")
        workspace = require_task_workspace(workspace_id)
        # Re-check executable identity and materialize exact declared inputs after review, before spawn.
        executable_now = Path(plan["resolved_executable"]).resolve(strict=True)
        executable_sha_now, executable_size_now = _sha256_file_stream(executable_now)
        if executable_sha_now != plan["executable_sha256"] or executable_size_now != plan["executable_size"]:
            raise RuntimeError("Executable changed after reviewed process plan.")
        if execution_class == "scratch" and plan.get("would_taint_workspace"):
            _mark_task_workspace_tainted(workspace_id, "private-original-derived-process-input")
        input_replacements = _materialize_process_inputs(workspace_id, plan["input_files"])
        profile_path = workspace / f".mcp-sandbox-{uuid.uuid4().hex}.sb"
        profile_path.write_text(_sandbox_profile(workspace, execution_class), encoding="utf-8")
        profile_path.chmod(0o600)
        resolved_executable = Path(plan["resolved_executable"])
        resolved_argv = list(argv)
        resolved_argv[0] = str(resolved_executable)
        for i, value in enumerate(resolved_argv):
            resolved_argv[i] = _substitute_process_inputs(_substitute_secrets(value, secret_cache), input_replacements)
        runtime_env = _safe_local_process_base_env(workspace)
        for key, value in env_clean.items():
            runtime_env[key] = _substitute_process_inputs(_substitute_secrets(value, secret_cache), input_replacements)
        command = [str(sandbox), "-f", str(profile_path), *resolved_argv]
        run_id = str(uuid.uuid4())
        state = {
            "run_id": run_id,
            "operation_id": operation_id,
            "workspace_id": workspace_id,
            "lease_id": lease_id,
            "execution_id": lease.get("execution_id") if isinstance(lease, dict) else None,
            "execution_class": execution_class,
            "status": "running",
            "classification": None,
            "resolved_executable": str(resolved_executable),
            "executable_sha256": plan["executable_sha256"],
            "executable_size": plan["executable_size"],
            "argv": argv,
            "input_files": plan["input_files"],
            "expected_changed_paths": plan["expected_changed_paths"],
            "max_changed_path_count": plan["max_changed_path_count"],
            "cwd_root": plan["cwd_root"],
            "cwd_path": plan["cwd_path"],
            "env_keys": sorted(env_clean),
            "secret_refs": sorted(secret_cache),
            "timeout_seconds": timeout_seconds,
            "expected_exit_codes": expected_exit_codes,
            "output_paths": plan["output_paths"],
            "network_policy": "deny",
            "write_scope": plan["write_scope"],
            "process_plan_digest": plan["process_plan_digest"],
            "reviewed_plan_digest_verified": True,
            "provenance_label": normalize_provenance_label(provenance_label),
            "started_at": now_iso(),
            "completed_at": None,
            "exit_code": None,
            "signal": None,
            "pid": None,
            "pgid": None,
            "starting_head": resolve_ref("HEAD") if execution_class == "repository" else None,
            "starting_worktree_fingerprint": worktree_fingerprint() if execution_class == "repository" else None,
            "starting_index_fingerprint": index_fingerprint() if execution_class == "repository" else None,
            "starting_changed_path_identities": _repository_changed_path_identities() if execution_class == "repository" else None,
            "repository_effects_verified": None,
            "repository_effect_paths": [],
            "repository_unexpected_effect_paths": [],
            "repository_effect_violations": [],
            "ending_head": None,
            "ending_worktree_fingerprint": None,
            "ending_index_fingerprint": None,
            "repository_mutated": None,
        }
        _write_local_process_state(run_id, state)
        worker = threading.Thread(
            target=_local_process_worker,
            args=(run_id, command, runtime_env, (workspace / plan["cwd_path"]) if plan["cwd_root"] == "task_workspace" else (REPO / plan["cwd_path"]), stdin_bytes, timeout_seconds, expected_exit_codes, list(secret_cache.values())),
            daemon=True,
        )
        worker.start()
        return finish_operation(operation_id, state)
    except Exception as exc:
        secret_cache.clear()
        fail_operation(operation_id, exc)
        raise

@tool(read_only=True, destructive=False, idempotent=False)
def process_status(run_id: UUIDString) -> dict[str, Any]:
    """Return durable local process state without output bodies."""
    state = _read_local_process_state(run_id)
    return {k: state.get(k) for k in (
        "run_id", "operation_id", "workspace_id", "lease_id", "execution_id", "execution_class",
        "status", "classification", "resolved_executable", "executable_sha256", "executable_size", "argv", "input_files", "expected_changed_paths", "max_changed_path_count", "cwd_root", "cwd_path", "env_keys", "secret_refs",
        "timeout_seconds", "expected_exit_codes", "output_paths", "network_policy", "write_scope",
        "process_plan_digest", "reviewed_plan_digest_verified", "started_at", "completed_at",
        "duration_seconds", "pid", "pgid", "exit_code", "signal", "starting_head", "starting_worktree_fingerprint", "starting_index_fingerprint",
        "ending_head", "ending_worktree_fingerprint", "ending_index_fingerprint", "repository_mutated", "repository_effects_verified", "repository_effect_paths", "repository_unexpected_effect_paths", "repository_effect_violations", "repository_evidence_error", "error_type", "error_message",
    )}

@tool(read_only=True, destructive=False, idempotent=False)
def process_wait(run_id: UUIDString, wait_seconds: WaitSeconds = 0) -> dict[str, Any]:
    """Wait boundedly for one durable local process without cancelling it."""
    deadline = time.monotonic() + wait_seconds
    while True:
        state = process_status(run_id)
        if state.get("status") != "running" or wait_seconds == 0:
            return state
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return state
        time.sleep(min(0.25, remaining))

@tool(read_only=False, destructive=True, idempotent=True)
def process_cancel(run_id: UUIDString, operation_id: UUIDString, lease_id: UUIDString | None = None, lease_token: str | None = None) -> dict[str, Any]:
    """Cancel only the exact executor-owned generic process group."""
    state = _read_local_process_state(run_id)
    payload = {"run_id": run_id, "lease_id": lease_id}
    replay, prior = begin_operation(operation_id, "process_cancel", payload)
    if replay:
        return prior
    try:
        if state.get("execution_class") == "repository":
            if not lease_id or not lease_token or lease_id != state.get("lease_id"):
                raise PermissionError("Repository process cancellation requires its owning lease.")
            require_execution_lease(lease_id, lease_token)
        if state.get("status") != "running":
            return finish_operation(operation_id, {"run_id": run_id, "cancelled": False, "status": state.get("status")})
        state["cancel_requested"] = True
        state["cancel_requested_at"] = now_iso()
        _write_local_process_state(run_id, state)
        proc = None
        with _LOCAL_PROCESS_LOCK:
            proc = _LOCAL_PROCESSES.get(run_id)
        record = {}
        path = process_record_path(run_id)
        if path.is_file():
            try:
                record = json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                record = {}
        if proc is not None:
            try:
                os.killpg(proc.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
        elif record and pid_is_executor_owned(record):
            try:
                os.killpg(int(record.get("pgid") or record["pid"]), signal.SIGTERM)
            except ProcessLookupError:
                pass
        return finish_operation(operation_id, {"run_id": run_id, "cancelled": True, "status": "cancellation_requested"})
    except Exception as exc:
        fail_operation(operation_id, exc)
        raise

@tool(read_only=True, destructive=False, idempotent=False)
def process_result(run_id: UUIDString, max_bytes: ToolOutputBytes = 120_000) -> dict[str, Any]:
    """Return bounded stdout/stderr and output artifact references for a completed generic local process."""
    validate_output_limit(max_bytes)
    state = _read_local_process_state(run_id)
    stdout = _local_process_stdout_path(run_id).read_text(encoding="utf-8", errors="replace") if _local_process_stdout_path(run_id).is_file() else ""
    stderr = _local_process_stderr_path(run_id).read_text(encoding="utf-8", errors="replace") if _local_process_stderr_path(run_id).is_file() else ""
    stdout, stdout_truncated = truncate_text(sanitize_text(stdout), max_bytes // 3)
    stderr, stderr_truncated = truncate_text(sanitize_text(stderr), max_bytes // 3)
    result = {
        **process_status(run_id),
        "stdout": stdout,
        "stderr": stderr,
        "stdout_truncated": stdout_truncated or bool(state.get("stdout_truncated")),
        "stderr_truncated": stderr_truncated or bool(state.get("stderr_truncated")),
        "output_artifacts": state.get("output_artifacts", []),
    }
    return enforce_structured_output(result, max_bytes)

# ==========================================================================
# File mutation
# ==========================================================================

def validate_file_op(op: dict[str, Any], index: int) -> tuple[str, dict[str, Any]]:
    kind = str(op.get("op", ""))
    allowed = {"create", "replace", "exact_replace", "move", "delete", "mkdir", "rmdir"}
    if kind not in allowed:
        raise ValueError(f"Operation {index}: unsupported op {kind!r}.")
    if "path" not in op:
        raise ValueError(f"Operation {index}: path is required.")
    relative, candidate = normalize_repo_write_path(str(op["path"]))
    normalized = dict(op)
    normalized["path"] = relative
    normalized["_candidate"] = candidate
    if kind == "move":
        if "destination" not in op:
            raise ValueError(f"Operation {index}: destination is required.")
        dest_rel, dest = normalize_repo_write_path(str(op["destination"]))
        normalized["destination"] = dest_rel
        normalized["_destination"] = dest
    return kind, normalized


def preflight_file_ops(ops: list[dict[str, Any]]) -> list[tuple[str, dict[str, Any]]]:
    if not ops or len(ops) > MAX_FILE_OPS:
        raise ValueError(f"operations must contain 1...{MAX_FILE_OPS} items.")
    normalized: list[tuple[str, dict[str, Any]]] = []
    touched: set[str] = set()
    for index, op in enumerate(ops):
        kind, item = validate_file_op(op, index)
        path = item["path"]
        if path in touched:
            raise ValueError("A path may appear only once per mutation batch.")
        touched.add(path)
        candidate: Path = item["_candidate"]
        if kind in {"replace", "exact_replace", "delete", "move"}:
            if not candidate.exists() or not candidate.is_file() or candidate.is_symlink():
                raise FileNotFoundError(f"{path} must be an existing regular file.")
            expected = str(item.get("expected_sha256", ""))
            actual = sha256_bytes(candidate.read_bytes())
            if not expected or expected != actual:
                raise RuntimeError(f"{path} SHA mismatch. Expected={expected or '[missing]'}, actual={actual}")
        if kind == "create":
            if candidate.exists():
                raise FileExistsError(f"{path} already exists.")
            if not candidate.parent.is_dir():
                raise FileNotFoundError(f"Parent directory does not exist for {path}.")
            if not isinstance(item.get("content"), str):
                raise ValueError(f"{path}: create requires string content.")
        if kind == "replace":
            if not isinstance(item.get("content"), str):
                raise ValueError(f"{path}: replace requires string content.")
        if kind == "exact_replace":
            old = item.get("old_text")
            new = item.get("new_text")
            if not isinstance(old, str) or not old or not isinstance(new, str) or old == new:
                raise ValueError(f"{path}: exact_replace requires distinct non-empty old_text/new_text.")
            text = candidate.read_text(encoding="utf-8")
            count = text.count(old)
            if count != 1:
                raise RuntimeError(f"{path}: old_text must occur exactly once; found {count}.")
        if kind == "move":
            dest: Path = item["_destination"]
            if item["destination"] in touched:
                raise ValueError("Move destination conflicts with another path in this batch.")
            touched.add(item["destination"])
            if dest.exists():
                raise FileExistsError(f"Move destination already exists: {item['destination']}")
            if not dest.parent.is_dir():
                raise FileNotFoundError("Move destination parent does not exist.")
        if kind == "mkdir":
            if candidate.exists():
                raise FileExistsError(f"Directory target exists: {path}")
            if not candidate.parent.is_dir():
                raise FileNotFoundError("mkdir parent does not exist.")
        if kind == "rmdir":
            if not candidate.is_dir() or candidate.is_symlink():
                raise FileNotFoundError(f"{path} is not an ordinary directory.")
            if any(candidate.iterdir()):
                raise PermissionError("rmdir only removes empty directories.")
        normalized.append((kind, item))
    return normalized



MAX_EVIDENCE_BATCH_JOBS = 12
MAX_EVIDENCE_BATCH_CONCURRENCY = 4
MAX_EVIDENCE_BATCH_RESULT_BYTES = 1500000
EVIDENCE_BATCH_ALLOWED_KINDS = {
    "executor_capabilities", "workspace_state", "execution_lease_status",
    "executor_recovery_status", "list_files", "read_file", "search_files",
    "artifact_inspect", "git_inspect", "test_discovery",
    "documentation_sync_preflight", "cycle_close_evidence",
    "test_impact_advisor", "swift_xcode_audit",
    "repository_recovery_analysis", "fixture_provenance_inspect",
    "execution_snapshot",
}
EvidenceBatchKind = Literal[
    "executor_capabilities", "workspace_state", "execution_lease_status", "executor_recovery_status",
    "list_files", "read_file", "search_files", "artifact_inspect", "git_inspect", "test_discovery",
    "documentation_sync_preflight", "cycle_close_evidence", "test_impact_advisor", "swift_xcode_audit",
    "repository_recovery_analysis", "fixture_provenance_inspect", "execution_snapshot",
]
EvidenceJobId = Annotated[str, Field(pattern=EVIDENCE_JOB_ID_PATTERN, min_length=1, max_length=80)]


class EvidenceArgsBase(BaseModel):
    model_config = ConfigDict(extra="forbid")


class EvidenceNoArgs(EvidenceArgsBase):
    pass


class EvidenceLeaseStatusArgs(EvidenceArgsBase):
    lease_id: UUIDString | None = None


class EvidenceListFilesArgs(EvidenceArgsBase):
    root_id: RootId = "repo"
    path: str = ""
    glob: str | None = None
    max_results: ListResultLimit = 500


class EvidenceReadFileArgs(EvidenceArgsBase):
    path: str
    root_id: RootId = "repo"
    start_line: Annotated[int, Field(ge=1)] = 1
    end_line: int | None = None
    max_bytes: ToolOutputBytes = 80_000


class EvidenceSearchFilesArgs(EvidenceArgsBase):
    query: str
    root_id: RootId = "repo"
    path: str = ""
    regex: bool = False
    case_sensitive: bool = False
    path_glob: str | None = None
    max_results: SearchResultLimit = 100


class EvidenceArtifactInspectArgs(EvidenceArgsBase):
    path: str
    root_id: RootId = "repo"
    kind: ArtifactKind = "auto"
    sqlite_query: str | None = None
    max_rows: SQLRowLimit = 100
    max_bytes: ToolOutputBytes = 80_000


class EvidenceGitInspectArgs(EvidenceArgsBase):
    mode: GitInspectMode = "diff"
    path: str | None = None
    ref: str | None = None
    max_bytes: ToolOutputBytes = 100_000


class EvidenceTestDiscoveryArgs(EvidenceArgsBase):
    max_results: TestDiscoveryLimit = 1000
    max_bytes: ToolOutputBytes = 120_000


class EvidenceMaxBytes120Args(EvidenceArgsBase):
    max_bytes: ToolOutputBytes = 120_000


class EvidenceCycleCloseArgs(EvidenceArgsBase):
    run_ids: list[UUIDString] | None = None
    max_bytes: ToolOutputBytes = 120_000


class EvidenceTestImpactArgs(EvidenceArgsBase):
    changed_paths: list[str] | None = None
    max_bytes: ToolOutputBytes = 80_000


class EvidenceMaxBytes100Args(EvidenceArgsBase):
    max_bytes: ToolOutputBytes = 100_000


class EvidenceFixtureProvenanceArgs(EvidenceArgsBase):
    path: str
    max_bytes: ToolOutputBytes = 80_000


class EvidenceSnapshotArgs(EvidenceArgsBase):
    expected_machine_state_digest: Sha256String | None = None
    expected_continuation_digest: Sha256String | None = None
    max_bytes: ToolOutputBytes = 120_000


def _job_model(name: str, kind_value: str, args_type: type[BaseModel]):
    return type(name, (BaseModel,), {
        "__annotations__": {"id": EvidenceJobId, "kind": Literal[kind_value], "arguments": args_type},
        "model_config": ConfigDict(extra="forbid"),
        "kind": kind_value,
        "arguments": Field(default_factory=args_type),
    })


EvidenceExecutorCapabilitiesJob = _job_model("EvidenceExecutorCapabilitiesJob", "executor_capabilities", EvidenceNoArgs)
EvidenceWorkspaceStateJob = _job_model("EvidenceWorkspaceStateJob", "workspace_state", EvidenceNoArgs)
EvidenceExecutionLeaseStatusJob = _job_model("EvidenceExecutionLeaseStatusJob", "execution_lease_status", EvidenceLeaseStatusArgs)
EvidenceExecutorRecoveryStatusJob = _job_model("EvidenceExecutorRecoveryStatusJob", "executor_recovery_status", EvidenceNoArgs)
EvidenceListFilesJob = _job_model("EvidenceListFilesJob", "list_files", EvidenceListFilesArgs)
EvidenceReadFileJob = _job_model("EvidenceReadFileJob", "read_file", EvidenceReadFileArgs)
EvidenceSearchFilesJob = _job_model("EvidenceSearchFilesJob", "search_files", EvidenceSearchFilesArgs)
EvidenceArtifactInspectJob = _job_model("EvidenceArtifactInspectJob", "artifact_inspect", EvidenceArtifactInspectArgs)
EvidenceGitInspectJob = _job_model("EvidenceGitInspectJob", "git_inspect", EvidenceGitInspectArgs)
EvidenceTestDiscoveryJob = _job_model("EvidenceTestDiscoveryJob", "test_discovery", EvidenceTestDiscoveryArgs)
EvidenceDocumentationSyncJob = _job_model("EvidenceDocumentationSyncJob", "documentation_sync_preflight", EvidenceMaxBytes120Args)
EvidenceCycleCloseJob = _job_model("EvidenceCycleCloseJob", "cycle_close_evidence", EvidenceCycleCloseArgs)
EvidenceTestImpactJob = _job_model("EvidenceTestImpactJob", "test_impact_advisor", EvidenceTestImpactArgs)
EvidenceSwiftXcodeJob = _job_model("EvidenceSwiftXcodeJob", "swift_xcode_audit", EvidenceMaxBytes100Args)
EvidenceRepositoryRecoveryJob = _job_model("EvidenceRepositoryRecoveryJob", "repository_recovery_analysis", EvidenceMaxBytes120Args)
EvidenceFixtureProvenanceJob = _job_model("EvidenceFixtureProvenanceJob", "fixture_provenance_inspect", EvidenceFixtureProvenanceArgs)
EvidenceSnapshotJob = _job_model("EvidenceSnapshotJob", "execution_snapshot", EvidenceSnapshotArgs)

EvidenceBatchJob = Annotated[
    Union[
        EvidenceExecutorCapabilitiesJob, EvidenceWorkspaceStateJob, EvidenceExecutionLeaseStatusJob,
        EvidenceExecutorRecoveryStatusJob, EvidenceListFilesJob, EvidenceReadFileJob, EvidenceSearchFilesJob,
        EvidenceArtifactInspectJob, EvidenceGitInspectJob, EvidenceTestDiscoveryJob, EvidenceDocumentationSyncJob,
        EvidenceCycleCloseJob, EvidenceTestImpactJob, EvidenceSwiftXcodeJob, EvidenceRepositoryRecoveryJob,
        EvidenceFixtureProvenanceJob, EvidenceSnapshotJob,
    ],
    Field(discriminator="kind"),
]


def _evidence_batch_running_receipts() -> list[str]:
    rows=[]
    if not OPERATIONS.is_dir():
        return rows
    for path in sorted(OPERATIONS.glob("*.json")):
        try:
            record=json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            rows.append(f"unreadable:{path.stem}")
            continue
        if record.get("status")=="running":
            rows.append(f"{record.get('action') or 'unknown'}:{record.get('operation_id') or path.stem}")
    return rows


def _evidence_batch_require_snapshot(expected_head: str, expected_worktree_fingerprint: str, expected_index_fingerprint: str) -> None:
    require_expected_head(expected_head)
    require_worktree_fingerprint(expected_worktree_fingerprint)
    actual=index_fingerprint()
    if not hmac.compare_digest(actual,expected_index_fingerprint):
        raise RuntimeError(f"Index fingerprint changed during evidence batch. Expected={expected_index_fingerprint}, actual={actual}")


def _evidence_preflight_error(code: str, job_id: str, expected: str, actual: str) -> None:
    raise ValueError(f"{code}: job_id={job_id}; expected={expected}; actual={actual}; executed_jobs=0")


def _evidence_batch_path_kind_preflight(job_id: str, kind: str, arguments: dict[str, Any]) -> None:
    if kind in {"list_files", "search_files"}:
        root_id = str(arguments.get("root_id", "repo"))
        path = str(arguments.get("path", ""))
        _, candidate, root = normalize_root_path(root_id, path, allow_root=True)
        ensure_no_symlink_escape(candidate, root)
        actual = "missing" if not candidate.exists() else "directory" if candidate.is_dir() else "file"
        if actual != "directory":
            _evidence_preflight_error("INVALID_JOB_PATH_KIND", job_id, "directory", actual)
    elif kind == "read_file":
        root_id = str(arguments.get("root_id", "repo"))
        path = str(arguments.get("path", ""))
        _, candidate, root = normalize_root_path(root_id, path, allow_root=True)
        ensure_no_symlink_escape(candidate, root)
        actual = "missing" if not candidate.exists() else "file" if candidate.is_file() else "directory"
        if actual != "file":
            _evidence_preflight_error("INVALID_JOB_PATH_KIND", job_id, "file", actual)
    elif kind == "artifact_inspect":
        root_id = str(arguments.get("root_id", "repo"))
        path = str(arguments.get("path", ""))
        _, candidate, root = normalize_root_path(root_id, path)
        ensure_no_symlink_escape(candidate, root)
        if not candidate.exists():
            _evidence_preflight_error("INVALID_JOB_PATH_KIND", job_id, "existing file or supported artifact directory", "missing")
    elif kind == "fixture_provenance_inspect":
        _, candidate = normalize_repo_write_path(str(arguments.get("path", "")))
        actual = "missing" if not candidate.exists() else "file" if candidate.is_file() else "directory"
        if actual != "file":
            _evidence_preflight_error("INVALID_JOB_PATH_KIND", job_id, "file", actual)


def _evidence_batch_manifest_preflight(jobs: list[EvidenceBatchJob]) -> list[dict[str, Any]]:
    if not isinstance(jobs, list) or not jobs or len(jobs) > MAX_EVIDENCE_BATCH_JOBS:
        raise ValueError(f"INVALID_JOB_MANIFEST: jobs must contain 1...{MAX_EVIDENCE_BATCH_JOBS} items; executed_jobs=0")
    try:
        typed_jobs = TypeAdapter(list[EvidenceBatchJob]).validate_python(jobs)
    except ValidationError as exc:
        raise ValueError(f"INVALID_JOB_MANIFEST: typed validation failed; executed_jobs=0; {exc.errors(include_url=False)}") from exc
    normalized: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, raw in enumerate(typed_jobs):
        if isinstance(raw, BaseModel):
            raw = raw.model_dump()
        if not isinstance(raw, dict):
            raise ValueError(f"INVALID_JOB_MANIFEST: job_index={index}; expected=object; executed_jobs=0")
        job_id = raw.get("id")
        kind = raw.get("kind")
        arguments = raw.get("arguments", {})
        if not isinstance(job_id, str) or not re.fullmatch(EVIDENCE_JOB_ID_PATTERN, job_id):
            raise ValueError(f"INVALID_JOB_ID: job_index={index}; executed_jobs=0")
        if job_id in seen:
            raise ValueError(f"DUPLICATE_JOB_ID: job_id={job_id}; executed_jobs=0")
        seen.add(job_id)
        if kind not in EVIDENCE_BATCH_ALLOWED_KINDS:
            raise ValueError(f"UNSUPPORTED_JOB_KIND: job_id={job_id}; kind={kind!r}; executed_jobs=0")
        if isinstance(arguments, BaseModel):
            arguments = arguments.model_dump(exclude_none=True)
        if not isinstance(arguments, dict):
            raise ValueError(f"INVALID_JOB_ARGUMENTS: job_id={job_id}; expected=object; executed_jobs=0")
        fn = globals().get(str(kind))
        if not callable(fn):
            raise RuntimeError(f"JOB_IMPLEMENTATION_UNAVAILABLE: job_id={job_id}; executed_jobs=0")
        try:
            inspect.signature(fn).bind(**arguments)
        except TypeError as exc:
            raise ValueError(f"INVALID_JOB_ARGUMENTS: job_id={job_id}; {exc}; executed_jobs=0") from exc
        _evidence_batch_path_kind_preflight(job_id, str(kind), arguments)
        normalized.append({"id": job_id, "kind": str(kind), "arguments": arguments})
    return normalized


@tool(read_only=True, destructive=False, idempotent=True)
def evidence_batch(
    expected_head: str,
    expected_worktree_fingerprint: str,
    expected_index_fingerprint: str,
    jobs: list[EvidenceBatchJob],
    max_concurrency: EvidenceConcurrency = 4,
    lease_id: UUIDString | None = None,
    lease_token: str | None = None,
) -> dict[str, Any]:
    """Run bounded read-only evidence jobs against one stable repository snapshot after whole-manifest preflight."""
    import concurrent.futures
    if not isinstance(max_concurrency, int) or not 1 <= max_concurrency <= MAX_EVIDENCE_BATCH_CONCURRENCY:
        raise ValueError(f"max_concurrency must be 1...{MAX_EVIDENCE_BATCH_CONCURRENCY}.")
    # Absolutely no job invocation occurs before this completes successfully.
    normalized = _evidence_batch_manifest_preflight(jobs)
    with _lease_transition_lock:
        active_raw = read_active_lease_raw()
        active_view = public_lease_view(active_raw)
        same_owner_active_lease = False
        lease_sequence_before = None
        lease_heartbeat_before = None
        if active_view.get("active"):
            if not lease_id or not lease_token:
                raise RuntimeError("Evidence batch with an active mutable lease requires the same-owner lease capability.")
            owned = require_execution_lease_no_refresh(lease_id, lease_token)
            same_owner_active_lease = True
            lease_sequence_before = owned.get("sequence")
            lease_heartbeat_before = owned.get("heartbeat_at")
        elif lease_id or lease_token:
            raise RuntimeError("Evidence batch lease capability was supplied but no active lease exists.")
        recovery=executor_recovery_status()
        if recovery.get("mutation_safe") is not True:
            raise RuntimeError("Evidence batch requires mutation_safe=true before starting.")
        running=_evidence_batch_running_receipts()
        if running:
            raise RuntimeError("Evidence batch requires zero running durable operation receipts. running="+", ".join(running[:8]))
        _evidence_batch_require_snapshot(expected_head,expected_worktree_fingerprint,expected_index_fingerprint)
        results=[None]*len(normalized)
        def invoke(pair):
            index,job=pair
            fn=globals().get(job["kind"])
            if not callable(fn):
                raise RuntimeError(f"Evidence job {job['id']}: implementation unavailable.")
            result=fn(**job["arguments"])
            encoded=json.dumps(result,sort_keys=True,separators=(",",":"),ensure_ascii=False)
            results[index]={"id":job["id"],"kind":job["kind"],"result":result,"result_digest":sha256_text(encoded)}
        errors=[]
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_concurrency,thread_name_prefix="ledgerforge-evidence") as pool:
            futures={pool.submit(invoke,item): item[1]["id"] for item in enumerate(normalized)}
            for future,job_id in futures.items():
                try:
                    future.result()
                except Exception as exc:
                    errors.append(f"{job_id}:{type(exc).__name__}:{exc}")
        if errors:
            raise RuntimeError("Evidence batch failed closed; no partial result is authoritative. "+" | ".join(errors[:8]))
        _evidence_batch_require_snapshot(expected_head,expected_worktree_fingerprint,expected_index_fingerprint)
        if same_owner_active_lease:
            current_owned = require_execution_lease_no_refresh(str(lease_id), str(lease_token))
            if current_owned.get("sequence") != lease_sequence_before or current_owned.get("heartbeat_at") != lease_heartbeat_before:
                raise RuntimeError("Evidence batch invalidated because same-owner lease heartbeat/sequence changed.")
        elif public_lease_view(read_active_lease_raw()).get("active"):
            raise RuntimeError("Evidence batch invalidated because a mutable lease became active.")
        if executor_recovery_status().get("mutation_safe") is not True:
            raise RuntimeError("Evidence batch invalidated because executor recovery state changed.")
        ordered=[row for row in results if row is not None]
        canonical={"expected_head":expected_head,"expected_worktree_fingerprint":expected_worktree_fingerprint,"expected_index_fingerprint":expected_index_fingerprint,"same_owner_active_lease":same_owner_active_lease,"lease_id":lease_id if same_owner_active_lease else None,"jobs":normalized,"result_digests":[{"id":row["id"],"digest":row["result_digest"]} for row in ordered]}
        batch_digest=sha256_text(json.dumps(canonical,sort_keys=True,separators=(",",":"),ensure_ascii=False))
        response={"head":expected_head,"worktree_fingerprint":expected_worktree_fingerprint,"index_fingerprint":expected_index_fingerprint,"same_owner_active_lease":same_owner_active_lease,"lease_id":lease_id if same_owner_active_lease else None,"job_count":len(normalized),"max_concurrency":max_concurrency,"jobs":ordered,"batch_digest":batch_digest,"snapshot_unchanged":True}
        if len(json.dumps(response,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode("utf-8"))>MAX_EVIDENCE_BATCH_RESULT_BYTES:
            raise RuntimeError(f"Evidence batch result exceeds {MAX_EVIDENCE_BATCH_RESULT_BYTES} bytes; split the evidence manifest.")
        return response


PATCH_PLAN_VERSION = "apply-file-ops-reviewed-plan-v1"
MAX_PATCH_PLAN_DIFF_BYTES = 750_000


def collapse_reviewed_same_path_exact_replaces(operations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not operations or len(operations) > MAX_FILE_OPS:
        raise ValueError(f"operations must contain 1...{MAX_FILE_OPS} items.")
    grouped: dict[str, list[dict[str, Any]]] = {}
    order: list[str] = []
    for index, raw in enumerate(operations):
        if not isinstance(raw, dict):
            raise ValueError(f"Operation {index}: operation must be an object.")
        kind = str(raw.get("op", ""))
        if kind not in {"create", "replace", "exact_replace", "move", "delete", "mkdir", "rmdir"}:
            raise ValueError(f"Operation {index}: unsupported op {kind!r}.")
        if "path" not in raw:
            raise ValueError(f"Operation {index}: path is required.")
        relative, _ = normalize_repo_write_path(str(raw["path"]))
        if relative not in grouped:
            grouped[relative] = []
            order.append(relative)
        item = dict(raw)
        item["path"] = relative
        grouped[relative].append(item)
    collapsed: list[dict[str, Any]] = []
    for path in order:
        group = grouped[path]
        if len(group) == 1:
            collapsed.append(group[0])
            continue
        if any(str(item.get("op", "")) != "exact_replace" for item in group):
            raise ValueError(f"{path}: repeated-path batching is supported only for exact_replace operations.")
        relative, candidate = normalize_repo_write_path(path)
        if not candidate.exists() or not candidate.is_file() or candidate.is_symlink():
            raise FileNotFoundError(f"{path} must be an existing regular file.")
        original_bytes = candidate.read_bytes()
        original_sha = sha256_bytes(original_bytes)
        expected_values = [str(item.get("expected_sha256", "")) for item in group]
        if any(not value or value != original_sha for value in expected_values):
            raise RuntimeError(f"{path}: every repeated exact_replace must carry the same current source SHA.")
        current = candidate.read_text(encoding="utf-8")
        logical: list[dict[str, Any]] = []
        for step, item in enumerate(group, start=1):
            old = item.get("old_text")
            new = item.get("new_text")
            if not isinstance(old, str) or not old or not isinstance(new, str) or old == new:
                raise ValueError(f"{path}: repeated exact_replace step {step} requires distinct non-empty old_text/new_text.")
            count = current.count(old)
            if count != 1:
                raise RuntimeError(f"{path}: repeated exact_replace step {step} old_text must occur exactly once in evolving content; found {count}.")
            logical.append({"op":"exact_replace","path":relative,"expected_sha256":original_sha,"old_text":old,"new_text":new})
            current = current.replace(old, new, 1)
        collapsed.append({"op":"replace","path":relative,"expected_sha256":original_sha,"content":current,"_reviewed_logical_operations":logical})
    return collapsed


def patch_plan_semantic_operation(kind: str, item: dict[str, Any]) -> dict[str, Any]:
    logical = item.get("_reviewed_logical_operations")
    if isinstance(logical, list) and logical:
        return {"op":"composite_exact_replace","path":item["path"],"expected_sha256":item.get("expected_sha256"),"logical_operations":logical}
    keys = {
        "create": ("path", "content"),
        "replace": ("path", "expected_sha256", "content"),
        "exact_replace": ("path", "expected_sha256", "old_text", "new_text"),
        "move": ("path", "expected_sha256", "destination"),
        "delete": ("path", "expected_sha256"),
        "mkdir": ("path",),
        "rmdir": ("path",),
    }[kind]
    return {"op": kind, **{key: item.get(key) for key in keys}}


def patch_plan_operation_digest(kind: str, item: dict[str, Any]) -> str:
    return sha256_text(json.dumps(patch_plan_semantic_operation(kind, item), sort_keys=True, separators=(",", ":"), ensure_ascii=False))


def patch_plan_utf8(data: bytes, path: str) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"{path}: reviewed patch-plan diff requires UTF-8 text.") from exc


def build_apply_file_ops_patch_plan(normalized: list[tuple[str, dict[str, Any]]], expected_head: str, expected_worktree_fingerprint: str) -> dict[str, Any]:
    import difflib
    rows=[]; diff_parts=[]
    for kind,item in normalized:
        candidate: Path = item["_candidate"]
        before_bytes = candidate.read_bytes() if candidate.is_file() else None
        before_sha = sha256_bytes(before_bytes) if before_bytes is not None else None
        result_path = item["destination"] if kind == "move" else item["path"]
        if kind == "create": after_bytes=item["content"].encode("utf-8")
        elif kind == "replace": after_bytes=item["content"].encode("utf-8")
        elif kind == "exact_replace":
            before_text=patch_plan_utf8(before_bytes or b"",item["path"]); after_bytes=before_text.replace(item["old_text"],item["new_text"],1).encode("utf-8")
        elif kind == "move": after_bytes=before_bytes
        elif kind in {"delete","mkdir","rmdir"}: after_bytes=None
        else: raise ValueError(f"Unsupported reviewed patch-plan op: {kind}")
        after_sha=sha256_bytes(after_bytes) if after_bytes is not None else None
        row={"op":"composite_exact_replace" if item.get("_reviewed_logical_operations") else kind,"path":item["path"],"result_path":result_path,"before_sha256":before_sha,"after_sha256":after_sha,"operation_digest":patch_plan_operation_digest(kind,item)}
        if kind=="move": row["destination"]=item["destination"]
        rows.append(row)
        if kind in {"create","replace","exact_replace"}:
            old_text="" if before_bytes is None else patch_plan_utf8(before_bytes,item["path"]); new_text="" if after_bytes is None else patch_plan_utf8(after_bytes,result_path)
            fromfile="/dev/null" if kind=="create" else f"a/{item['path']}"; tofile=f"b/{result_path}"
            body="".join(difflib.unified_diff(old_text.splitlines(keepends=True),new_text.splitlines(keepends=True),fromfile=fromfile,tofile=tofile,n=3))
            if body: diff_parts.append(f"diff --git a/{item['path']} b/{result_path}\n{body}")
        elif kind=="delete":
            try:
                old_text=patch_plan_utf8(before_bytes or b"",item["path"])
            except ValueError:
                row["binary_metadata"]={"before_sha256":before_sha,"before_size":len(before_bytes or b""),"after_type":"absent"}
            else:
                body="".join(difflib.unified_diff(old_text.splitlines(keepends=True),[],fromfile=f"a/{item['path']}",tofile="/dev/null",n=3))
                if body: diff_parts.append(f"diff --git a/{item['path']} b/{item['path']}\n{body}")
        elif kind=="move":
            diff_parts.append(f"diff --git a/{item['path']} b/{item['destination']}\nsimilarity index 100%\nrename from {item['path']}\nrename to {item['destination']}\n")
    unified_diff="".join(diff_parts)
    if len(unified_diff.encode("utf-8"))>MAX_PATCH_PLAN_DIFF_BYTES: raise RuntimeError(f"Reviewed patch-plan diff exceeds {MAX_PATCH_PLAN_DIFF_BYTES} bytes; split the batch without weakening guards.")
    canonical={"version":PATCH_PLAN_VERSION,"expected_head":expected_head,"expected_worktree_fingerprint":expected_worktree_fingerprint,"normalized_operations":rows,"unified_diff_sha256":sha256_text(unified_diff)}
    digest=sha256_text(json.dumps(canonical,sort_keys=True,separators=(",", ":"),ensure_ascii=False))
    return {**canonical,"unified_diff":unified_diff,"patch_plan_digest":digest}


def verify_apply_file_ops_plan_results(normalized: list[tuple[str, dict[str, Any]]], plan: dict[str, Any]) -> None:
    rows=plan["normalized_operations"]
    if len(rows)!=len(normalized): raise RuntimeError("Reviewed patch-plan operation count changed.")
    for (kind,item),row in zip(normalized,rows):
        candidate: Path=item["_candidate"]
        if kind=="move":
            destination: Path=item["_destination"]
            if candidate.exists() or not destination.is_file() or destination.is_symlink(): raise RuntimeError(f"{item['path']}: invalid move result.")
            actual=sha256_bytes(destination.read_bytes())
        elif kind=="delete":
            if candidate.exists(): raise RuntimeError(f"{item['path']}: delete target still exists.")
            actual=None
        elif kind=="mkdir":
            if not candidate.is_dir() or candidate.is_symlink(): raise RuntimeError(f"{item['path']}: invalid mkdir result.")
            actual=None
        elif kind=="rmdir":
            if candidate.exists(): raise RuntimeError(f"{item['path']}: rmdir target still exists.")
            actual=None
        else:
            if not candidate.is_file() or candidate.is_symlink(): raise RuntimeError(f"{item['path']}: invalid file result.")
            actual=sha256_bytes(candidate.read_bytes())
        if actual!=row.get("after_sha256"): raise RuntimeError(f"{item['path']}: resulting SHA does not match reviewed plan. Expected={row.get('after_sha256')}, actual={actual}")


@tool(read_only=False, destructive=True, idempotent=True)
def apply_file_ops(expected_head: str, expected_worktree_fingerprint: str, operation_id: UUIDString, lease_id: UUIDString, lease_token: str, operations: list[dict[str, Any]], dry_run: bool = True, reviewed_plan_digest: str | None = None, provenance_label: ProvenanceLabel | None = None) -> dict[str, Any]:
    "Create/edit/move/delete worktree text files under one repository-wide execution lease."
    payload={"expected_head":expected_head,"expected_worktree_fingerprint":expected_worktree_fingerprint,"lease_id":lease_id,"operations":operations,"dry_run":dry_run,"reviewed_plan_digest":reviewed_plan_digest,"provenance_label":provenance_label}
    replay,prior=begin_operation(operation_id,"apply_file_ops",payload)
    if replay: return prior
    manifest=None
    try:
        lease=require_execution_lease(lease_id,lease_token); require_expected_head(expected_head); require_worktree_fingerprint(expected_worktree_fingerprint)
        with _file_lock:
            reviewed_operations=collapse_reviewed_same_path_exact_replaces(operations); normalized=preflight_file_ops(reviewed_operations); plan=build_apply_file_ops_patch_plan(normalized,expected_head,expected_worktree_fingerprint)
            if dry_run:
                return finish_operation(operation_id,{"dry_run":True,"lease_id":lease_id,"head":resolve_ref("HEAD"),"worktree_fingerprint":worktree_fingerprint(),"normalized_operations":plan["normalized_operations"],"unified_diff":plan["unified_diff"],"unified_diff_sha256":plan["unified_diff_sha256"],"patch_plan_version":plan["version"],"patch_plan_digest":plan["patch_plan_digest"]})
            if not isinstance(reviewed_plan_digest,str) or not re.fullmatch(r"[A-Fa-f0-9]{64}",reviewed_plan_digest): raise ValueError("Actual apply_file_ops requires a 64-character reviewed_plan_digest returned by dry-run planning.")
            if not hmac.compare_digest(plan["patch_plan_digest"],reviewed_plan_digest.casefold()): raise RuntimeError("Reviewed patch-plan digest does not match the current plan.")
            require_expected_head(expected_head); require_worktree_fingerprint(expected_worktree_fingerprint)
            affected=set()
            for kind,item in normalized:
                affected.add(item["path"]); affected.add(item["destination"]) if kind=="move" else None
            manifest=create_file_journal(operation_id,affected,normalized,expected_head); results=[]
            def atomic_text_write(candidate: Path, content: str, mode: int | None = None) -> None:
                temp=candidate.with_name(candidate.name+f".executor-{uuid.uuid4().hex}.tmp")
                with temp.open("w",encoding="utf-8") as fh: fh.write(content); fh.flush(); os.fsync(fh.fileno())
                if mode is not None: os.chmod(temp,mode)
                os.replace(temp,candidate)
            for step,(kind,item) in enumerate(normalized):
                require_expected_head(expected_head); candidate: Path=item["_candidate"]
                if kind in {"replace","exact_replace","delete","move"}:
                    expected_sha=str(item.get("expected_sha256","")); actual_sha=sha256_bytes(candidate.read_bytes()) if candidate.is_file() else ""
                    if not expected_sha or not hmac.compare_digest(expected_sha,actual_sha): raise RuntimeError(f"{item['path']} changed after reviewed planning; refusing mutation.")
                before_sha=sha256_bytes(candidate.read_bytes()) if candidate.is_file() else None; planned=plan["normalized_operations"][step]
                if before_sha!=planned.get("before_sha256"): raise RuntimeError(f"{item['path']}: pre-mutation SHA differs from reviewed plan.")
                if kind=="create": atomic_text_write(candidate,item["content"])
                elif kind=="replace": atomic_text_write(candidate,item["content"],stat.S_IMODE(candidate.stat().st_mode))
                elif kind=="exact_replace":
                    mode=stat.S_IMODE(candidate.stat().st_mode); current=candidate.read_text(encoding="utf-8")
                    if current.count(item["old_text"])!=1: raise RuntimeError(f"{item['path']}: exact_replace precondition changed.")
                    atomic_text_write(candidate,current.replace(item["old_text"],item["new_text"],1),mode)
                elif kind=="move": os.replace(candidate,item["_destination"])
                elif kind=="delete": candidate.unlink()
                elif kind=="mkdir": candidate.mkdir()
                elif kind=="rmdir": candidate.rmdir()
                after_candidate=item["_destination"] if kind=="move" else candidate
                after_sha=sha256_bytes(after_candidate.read_bytes()) if isinstance(after_candidate,Path) and after_candidate.is_file() else None
                if after_sha!=planned.get("after_sha256"): raise RuntimeError(f"{item['path']}: resulting SHA differs from reviewed plan.")
                row={"op":planned.get("op",kind),"path":item["path"],"before_sha256":before_sha,"after_sha256":after_sha}
                if kind=="move": row["destination"]=item["destination"]
                results.append(row); update_file_journal(operation_id,manifest,completed_step=step)
                if QUALIFICATION_CRASH_AFTER_FILE_STEP and (step+1)==QUALIFICATION_CRASH_AFTER_FILE_STEP: os._exit(97)
            verify_apply_file_ops_plan_results(normalized,plan); update_file_journal(operation_id,manifest,status="completed"); remove_completed_journal(operation_id); invalidate_lease_validation_binding(lease,"file mutation after validation")
            return finish_operation(operation_id,{"dry_run":False,"lease_id":lease_id,"head":resolve_ref("HEAD"),"operations":results,"patch_plan_version":plan["version"],"patch_plan_digest":plan["patch_plan_digest"],"unified_diff_sha256":plan["unified_diff_sha256"],"reviewed_plan_digest_verified":True,"provenance_label":normalize_provenance_label(provenance_label),"ending_worktree_fingerprint":worktree_fingerprint(),"ending_index_fingerprint":index_fingerprint(),"durable_journal_residue":False})
    except Exception as exc:
        if manifest is not None:
            try: restore_file_journal(operation_id,manifest); remove_completed_journal(operation_id)
            except Exception: pass
        fail_operation(operation_id,exc); raise


def staged_blob_bytes(relative: str, max_bytes: int = 8 * 1024 * 1024) -> bytes | None:
    size_result = subprocess.run(
        ["git", "-C", str(REPO), "cat-file", "-s", f":{relative}"],
        capture_output=True, text=True, env=git_env(), check=False, timeout=10,
    )
    if size_result.returncode != 0:
        return None
    try:
        size = int(size_result.stdout.strip())
    except ValueError:
        return None
    if size > max_bytes:
        return None
    result = subprocess.run(
        ["git", "-C", str(REPO), "show", f":{relative}"],
        capture_output=True, env=git_env(), check=False, timeout=20,
    )
    return result.stdout if result.returncode == 0 else None


def scan_staged_blobs(max_paths: int = 100) -> dict[str, Any]:
    paths = staged_paths()
    violations: list[dict[str, str]] = []
    suspicious: list[dict[str, str]] = []
    known_secret_values = current_secret_values()
    try:
        if axis_keychain_available():
            known_secret_values.append(keychain_axis_password())
    except Exception:
        pass
    forbidden_fragments = (
        ".executor-token", ".executor-path", ".mcp-path", "DerivedData", ".xcresult",
        "xcuserdata", ".sqlite-wal", ".sqlite-shm",
    )
    forbidden_suffixes = (".sqlite", ".sqlite3", ".db", ".p12", ".pfx", ".pem", ".key")
    private_path_markers = (
        str(Path.home() / "Documents" / "Ledger Forge" / "Originals"),
        "LEDGERFORGE_AXIS_CARD_PRIVATE_PASSWORD=",
        "LEDGERFORGE_AXIS_CARD_PRIVATE_DIRECTORY=",
        "LEDGERFORGE_PRIVATE_AMEX_DIRECTORY=",
        "LEDGERFORGE_PRIVATE_CBQ_TEXT_DIRECTORY=",
        "LEDGERFORGE_PRIVATE_HDFC_ORIGINALS_ROOT=",
    )
    for relative in paths[:max_paths]:
        low = relative.casefold()
        if any(fragment.casefold() in low for fragment in forbidden_fragments) or any(low.endswith(s.casefold()) for s in forbidden_suffixes):
            violations.append({"path": relative, "category": "prohibited-artifact-path"})
            continue
        blob = staged_blob_bytes(relative)
        if blob is None:
            suspicious.append({"path": relative, "category": "blob-too-large-or-unreadable"})
            continue
        text = blob.decode("utf-8", errors="ignore")
        if any(marker and marker in text for marker in private_path_markers):
            violations.append({"path": relative, "category": "private-path-or-environment-marker"})
            continue
        if any(secret and secret.encode("utf-8", errors="ignore") in blob for secret in known_secret_values):
            violations.append({"path": relative, "category": "known-secret-value"})
            continue
    known_secret_values.clear()
    return {
        "staged_paths": paths,
        "scanned_path_count": min(len(paths), max_paths),
        "violations": violations,
        "suspicious": suspicious,
        "pass": not violations,
        "financial_sanitization_proven": False,
    }


def update_lease_after_stage(lease_id: str, lease_token: str) -> dict[str, Any]:
    lease = require_execution_lease(lease_id, lease_token)
    bound = validate_bound_state_for_publication(lease, require_success=True)
    with _lease_lock:
        lease = read_active_lease_raw() or lease
        lease["validated_stage"] = {
            "validation_run_id": bound.get("run_id"),
            "index_fingerprint": index_fingerprint(),
            "staged_paths": staged_paths(),
            "worktree_fingerprint": worktree_fingerprint(),
            "bound_at": now_iso(),
        }
        atomic_write_json(LEASE_FILE, lease)
    return lease


def update_lease_after_commit(lease_id: str, lease_token: str, previous_head: str, new_head: str) -> dict[str, Any]:
    lease = require_execution_lease(lease_id, lease_token)
    stage = lease.get("validated_stage")
    if not isinstance(stage, dict):
        raise RuntimeError("No validated staged state is bound to this lease.")
    with _lease_lock:
        lease = read_active_lease_raw() or lease
        lease["publication_candidate"] = {
            "previous_head": previous_head,
            "commit_head": new_head,
            "validation_run_id": stage.get("validation_run_id"),
            "committed_paths": stage.get("staged_paths", []),
            "created_at": now_iso(),
        }
        atomic_write_json(LEASE_FILE, lease)
    return lease

# ==========================================================================
# Git mutation tools
# ==========================================================================

def ensure_git_mutation_preconditions(expected_head: str) -> None:
    require_expected_head(expected_head)
    if run_git("branch", "--show-current") != "main":
        raise RuntimeError("Git mutations are permitted only on main.")
    if conflicted_paths():
        raise RuntimeError("Git mutation refused while conflicts exist.")
    operation = active_git_operation()
    if operation:
        raise RuntimeError(f"Git mutation refused during active {operation} operation.")


@tool(read_only=False, destructive=False, idempotent=True, open_world=True)
def git_fetch_origin(operation_id: UUIDString, expected_head: str, lease_id: UUIDString, lease_token: str) -> dict[str, Any]:
    """Refresh only origin remote-tracking refs under the active execution lease."""
    payload = {"expected_head": expected_head, "lease_id": lease_id}
    replay, prior = begin_operation(operation_id, "git_fetch_origin", payload)
    if replay:
        return prior
    try:
        require_execution_lease(lease_id, lease_token)
        ensure_git_mutation_preconditions(expected_head)
        require_expected_origin_identity()
        before = resolve_ref("origin/main")
        before_fingerprint = worktree_fingerprint()
        with _git_mutation_lock:
            run_git("fetch", "origin", mutating=True, timeout=120)
        require_expected_head(expected_head)
        if worktree_fingerprint() != before_fingerprint:
            raise RuntimeError("Worktree changed during fetch.")
        result = {
            "lease_id": lease_id,
            "head": resolve_ref("HEAD"),
            "origin_main_before": before,
            "origin_main_after": resolve_ref("origin/main"),
            "remote_identity": require_expected_origin_identity(),
            "worktree_unchanged": True,
            "fetched_at": now_iso(),
        }
        return finish_operation(operation_id, result)
    except Exception as exc:
        fail_operation(operation_id, exc)
        raise


@tool(read_only=False, destructive=True, idempotent=True)
def git_stage(
    operation_id: UUIDString,
    expected_head: str,
    expected_worktree_fingerprint: str,
    expected_index_fingerprint: str,
    lease_id: UUIDString,
    lease_token: str,
    paths: list[str],
    dry_run: bool = True,
) -> dict[str, Any]:
    """Stage only explicitly named paths after a successful lease-bound validation."""
    payload = {
        "expected_head": expected_head,
        "expected_worktree_fingerprint": expected_worktree_fingerprint,
        "expected_index_fingerprint": expected_index_fingerprint,
        "lease_id": lease_id,
        "paths": paths,
        "dry_run": dry_run,
    }
    replay, prior = begin_operation(operation_id, "git_stage", payload)
    if replay:
        return prior
    try:
        lease = require_execution_lease(lease_id, lease_token)
        ensure_git_mutation_preconditions(expected_head)
        require_worktree_fingerprint(expected_worktree_fingerprint)
        if index_fingerprint() != expected_index_fingerprint:
            raise RuntimeError("Index changed since staging was planned.")
        if not paths:
            raise ValueError("At least one exact path is required.")
        normalized: list[str] = []
        for raw in paths:
            if raw in {".", "-A", "--all", "*"} or raw.startswith("-"):
                raise PermissionError("add-all/options are not permitted.")
            relative, candidate = normalize_repo_write_path(raw)
            if not candidate.exists() and relative not in tracked_paths():
                raise FileNotFoundError(f"Path is neither present nor a tracked deletion: {relative}")
            normalized.append(relative)
        if len(normalized) != len(set(normalized)):
            raise ValueError("Duplicate stage paths are not permitted.")
        if dry_run:
            return finish_operation(operation_id, {
                "dry_run": True,
                "lease_id": lease_id,
                "head": resolve_ref("HEAD"),
                "paths": normalized,
                "index_fingerprint": expected_index_fingerprint,
                "validation_bound": isinstance(lease.get("validated_state"), dict),
            })
        validate_bound_state_for_publication(lease, require_success=True)
        with _git_mutation_lock:
            require_expected_head(expected_head)
            require_worktree_fingerprint(expected_worktree_fingerprint)
            if index_fingerprint() != expected_index_fingerprint:
                raise RuntimeError("Index changed immediately before staging.")
            run_git("add", "--", *normalized, mutating=True)
        lease = update_lease_after_stage(lease_id, lease_token)
        return finish_operation(operation_id, {
            "dry_run": False,
            "lease_id": lease_id,
            "head": resolve_ref("HEAD"),
            "staged_paths": staged_paths(),
            "index_fingerprint_before": expected_index_fingerprint,
            "index_fingerprint_after": index_fingerprint(),
            "worktree_fingerprint": worktree_fingerprint(),
            "validation_run_id": (lease.get("validated_stage") or {}).get("validation_run_id"),
        })
    except Exception as exc:
        fail_operation(operation_id, exc)
        raise


@tool(read_only=True)
def precommit_privacy_scan(max_bytes: ToolOutputBytes = 80_000) -> dict[str, Any]:
    """Scan exact staged blobs for prohibited private/residue classes without claiming financial correctness."""
    require_feature("evidence", "precommit-privacy-scan")
    return enforce_structured_output(scan_staged_blobs(), max_bytes)


@tool(read_only=False, destructive=False, idempotent=True)
def git_commit(
    operation_id: UUIDString,
    expected_head: str,
    expected_index_fingerprint: str,
    expected_staged_paths: list[str],
    lease_id: UUIDString,
    lease_token: str,
    message: str,
    dry_run: bool = True,
) -> dict[str, Any]:
    """Commit exactly the validated staged index on main after privacy/residue scanning."""
    payload = {
        "expected_head": expected_head,
        "expected_index_fingerprint": expected_index_fingerprint,
        "expected_staged_paths": expected_staged_paths,
        "lease_id": lease_id,
        "message": message,
        "dry_run": dry_run,
    }
    replay, prior = begin_operation(operation_id, "git_commit", payload)
    if replay:
        return prior
    try:
        lease = require_execution_lease(lease_id, lease_token)
        ensure_git_mutation_preconditions(expected_head)
        if not message.strip() or len(message) > 500 or "\x00" in message:
            raise ValueError("Commit message must be non-empty and <= 500 characters.")
        if message.lstrip().startswith("-"):
            raise ValueError("Commit message may not begin with an option-like prefix.")
        actual_index = index_fingerprint()
        if actual_index != expected_index_fingerprint:
            raise RuntimeError("Staged index changed since planning.")
        actual_staged = staged_paths()
        normalized_expected = sorted({normalize_repo_write_path(p)[0] for p in expected_staged_paths})
        if actual_staged != normalized_expected:
            raise RuntimeError(f"Unexpected staged paths. Expected={normalized_expected}, actual={actual_staged}")
        if not actual_staged:
            raise RuntimeError("Nothing is staged for commit.")
        stage_binding = lease.get("validated_stage")
        if not isinstance(stage_binding, dict):
            raise RuntimeError("Staged state is not bound to a successful validation.")
        if stage_binding.get("index_fingerprint") != actual_index or sorted(stage_binding.get("staged_paths", [])) != actual_staged:
            raise RuntimeError("Current staged index differs from the validated staging binding.")
        scan = scan_staged_blobs()
        if not scan.get("pass"):
            raise RuntimeError("Pre-commit privacy/residue scan failed.")
        if dry_run:
            return finish_operation(operation_id, {
                "dry_run": True,
                "lease_id": lease_id,
                "head": resolve_ref("HEAD"),
                "staged_paths": actual_staged,
                "index_fingerprint": actual_index,
                "privacy_scan": scan,
                "validation_run_id": stage_binding.get("validation_run_id"),
            })
        with _git_mutation_lock:
            ensure_git_mutation_preconditions(expected_head)
            if index_fingerprint() != expected_index_fingerprint:
                raise RuntimeError("Staged index changed immediately before commit.")
            run_git("commit", "-m", message, mutating=True, timeout=120)
        new_head = resolve_ref("HEAD")
        update_lease_after_commit(lease_id, lease_token, expected_head, str(new_head))
        result = {
            "dry_run": False,
            "lease_id": lease_id,
            "previous_head": expected_head,
            "head": new_head,
            "committed_paths": actual_staged,
            "remaining_staged_paths": staged_paths(),
            "remaining_tracked_changes": changed_tracked_paths(),
            "remaining_untracked_files": sorted(untracked_paths()),
            "privacy_scan_passed": True,
            "validation_run_id": stage_binding.get("validation_run_id"),
        }
        return finish_operation(operation_id, result)
    except Exception as exc:
        fail_operation(operation_id, exc)
        raise


@tool(read_only=False, destructive=False, idempotent=True, open_world=True)
def git_push(
    operation_id: UUIDString,
    expected_head: str,
    expected_origin_main: str,
    lease_id: UUIDString,
    lease_token: str,
    dry_run: bool = True,
) -> dict[str, Any]:
    """Push the lease-bound validated commit to origin/main and prove post-push convergence."""
    payload = {"expected_head": expected_head, "expected_origin_main": expected_origin_main, "lease_id": lease_id, "dry_run": dry_run}
    replay, prior = begin_operation(operation_id, "git_push", payload)
    if replay:
        return prior
    try:
        lease = require_execution_lease(lease_id, lease_token)
        ensure_git_mutation_preconditions(expected_head)
        identity = require_expected_origin_identity()
        candidate = lease.get("publication_candidate")
        if dry_run:
            actual_origin = resolve_ref("origin/main")
            if actual_origin != expected_origin_main:
                raise RuntimeError(f"origin/main differs from expected local record. Expected={expected_origin_main}, actual={actual_origin}")
            return finish_operation(operation_id, {
                "dry_run": True,
                "lease_id": lease_id,
                "head": expected_head,
                "origin_main": actual_origin,
                "remote": "origin",
                "remote_identity": identity,
                "refspec": "main:main",
                "publication_candidate_present": isinstance(candidate, dict),
            })
        if not isinstance(candidate, dict) or candidate.get("commit_head") != expected_head:
            raise RuntimeError("HEAD is not the validated publication candidate for this lease.")
        before_fingerprint = worktree_fingerprint()
        with _git_mutation_lock:
            run_git("fetch", "origin", mutating=True, timeout=120)
            ensure_git_mutation_preconditions(expected_head)
            actual_origin = resolve_ref("origin/main")
            if actual_origin != expected_origin_main:
                raise RuntimeError(f"Remote main changed. Expected={expected_origin_main}, actual={actual_origin}")
            counts = run_git("rev-list", "--left-right", "--count", "main...origin/main").split()
            ahead, behind = (int(counts[0]), int(counts[1])) if len(counts) == 2 else (None, None)
            if behind not in {0, None}:
                raise RuntimeError("origin/main is ahead/diverged; normal push refused.")
            if resolve_ref("HEAD") != resolve_ref("main"):
                raise RuntimeError("HEAD must equal local main for push.")
            run_git("push", "origin", "main:main", mutating=True, timeout=180)
            run_git("fetch", "origin", mutating=True, timeout=120)
            local_head = resolve_ref("HEAD")
            local_main = resolve_ref("main")
            remote_main = resolve_ref("origin/main")
            if not (local_head == local_main == remote_main == expected_head):
                raise RuntimeError("Post-push convergence failed: HEAD, main and origin/main are not identical.")
        if worktree_fingerprint() != before_fingerprint:
            raise RuntimeError("Worktree changed during push.")
        with _lease_lock:
            current = read_active_lease_raw() or lease
            current["publication_verified"] = {
                "head": expected_head,
                "origin_main": expected_head,
                "verified_at": now_iso(),
            }
            atomic_write_json(LEASE_FILE, current)
        return finish_operation(operation_id, {
            "dry_run": False,
            "lease_id": lease_id,
            "head": expected_head,
            "main": resolve_ref("main"),
            "origin_main": resolve_ref("origin/main"),
            "remote_identity": identity,
            "verified": True,
            "post_push_converged": True,
            "validation_run_id": candidate.get("validation_run_id"),
        })
    except Exception as exc:
        fail_operation(operation_id, exc)
        raise



# ==========================================================================
# Server-owned repo tasks
# ==========================================================================

def repo_task_registry() -> dict[str, dict[str, Any]]:
    tasks: dict[str, dict[str, Any]] = {
        "xcode-project-list": {
            "command": [str(XCODEBUILD), "-list", "-json", "-project", str(XCODE_PROJECT)],
            "timeout": 120,
            "description": "Read Xcode project/scheme metadata.",
        },
        "xcode-version": {
            "command": [str(XCODEBUILD), "-version"],
            "timeout": 30,
            "description": "Read selected Xcode version.",
        },
        "swift-version": {
            "command": [str(XCRUN), "swift", "--version"],
            "timeout": 30,
            "description": "Read selected Swift toolchain version.",
        },
    }
    if BUILD_RUN_SCRIPT.is_file():
        tasks["build-and-run-verify"] = {
            "command": [str(BUILD_RUN_SCRIPT), "--verify"],
            "timeout": MAX_VALIDATION_SECONDS,
            "description": "Run repository-owned singleton build/run verification.",
        }
    return tasks


@tool(read_only=False, destructive=False, idempotent=True)
def run_repo_task(
    operation_id: UUIDString,
    expected_head: str,
    task_id: RepoTaskId,
    lease_id: UUIDString | None = None,
    lease_token: str | None = None,
    dry_run: bool = True,
    max_bytes: ToolOutputBytes = 80_000,
) -> dict[str, Any]:
    """Run one fixed server-registered task. Actual execution requires the repository lease."""
    validate_output_limit(max_bytes)
    payload = {"expected_head": expected_head, "task_id": task_id, "lease_id": lease_id, "dry_run": dry_run, "max_bytes": max_bytes}
    replay, prior = begin_operation(operation_id, "run_repo_task", payload)
    if replay:
        return prior
    try:
        require_expected_head(expected_head)
        tasks = repo_task_registry()
        if task_id not in tasks:
            raise PermissionError(f"Unknown repo task: {task_id}")
        task = tasks[task_id]
        if dry_run:
            return finish_operation(operation_id, {
                "dry_run": True,
                "task_id": task_id,
                "description": task["description"],
                "head": resolve_ref("HEAD"),
                "lease_required_for_execution": True,
            })
        if not lease_id or not lease_token:
            raise PermissionError("Actual repo-task execution requires an execution lease.")
        lease = require_execution_lease(lease_id, lease_token, extend_seconds=int(task["timeout"]) + 300)
        before = git_worktree_status_raw()
        before_fp = worktree_fingerprint()
        status, output = run_captured(task["command"], safe_validation_base_env(), timeout=int(task["timeout"]))
        output = sanitize_text(output)
        output, truncated = truncate_text(output, max_bytes)
        mutated = worktree_fingerprint() != before_fp
        if mutated:
            invalidate_lease_validation_binding(lease, f"repo task {task_id} changed repository state")
        return finish_operation(operation_id, {
            "dry_run": False,
            "lease_id": lease_id,
            "task_id": task_id,
            "exit_code": status,
            "head": resolve_ref("HEAD"),
            "repository_mutated": mutated,
            "output": output,
            "truncated": truncated,
        })
    except Exception as exc:
        fail_operation(operation_id, exc)
        raise



# ==========================================================================
# Validation MCP tools
# ==========================================================================

@tool(read_only=False, destructive=False, idempotent=True)
def start_validation(
    expected_head: str,
    operation: ValidationOperation,
    operation_id: UUIDString,
    lease_id: UUIDString,
    lease_token: str,
    selectors: TestSelectorList | None = None,
    private_context: PrivateContextName | None = None,
    validation_intent: ValidationIntent | None = None,
    provenance_label: ProvenanceLabel | None = None,
    private_result_contract: PrivateResultContract | None = None,
) -> dict[str, Any]:
    """Start one bounded validation bound to the active repository execution lease."""
    global _active_validation
    selectors = selectors or []
    payload = {
        "expected_head": expected_head,
        "operation": operation,
        "selectors": selectors,
        "private_context": private_context,
        "validation_intent": validation_intent,
        "lease_id": lease_id,
        "provenance_label": provenance_label,
        "private_result_contract": private_result_contract,
    }
    replay, prior = begin_operation(operation_id, "start_validation", payload)
    if replay:
        return prior
    try:
        lease = require_execution_lease(lease_id, lease_token, extend_seconds=MAX_VALIDATION_SECONDS + 600)
        require_expected_head(expected_head)
        if operation not in ALLOWED_VALIDATIONS:
            raise PermissionError(f"Unsupported validation operation: {operation}")
        if operation in {"test-focused", "test-full"}:
            resolved_intent = validation_intent or "execute_tests"
            if resolved_intent not in {"execute_tests", "compile_only"}:
                raise ValueError("validation_intent must be execute_tests or compile_only for test validations.")
        elif operation == "cycle-close":
            resolved_intent = validation_intent or "execute_tests"
            if resolved_intent != "execute_tests":
                raise ValueError("cycle-close requires validation_intent=execute_tests.")
        else:
            if validation_intent not in {None, "compile_only"}:
                raise ValueError(f"{operation} only supports compile_only validation intent.")
            resolved_intent = "compile_only"
        if operation == "test-focused":
            if resolved_intent == "execute_tests" and (not selectors or len(selectors) > 20):
                raise ValueError("test-focused execute_tests requires 1...20 selectors.")
            if resolved_intent == "compile_only" and len(selectors) > 20:
                raise ValueError("test-focused compile_only accepts at most 20 optional selectors.")
            for selector in selectors:
                if not SELECTOR_RE.fullmatch(selector):
                    raise ValueError(f"Invalid test selector: {selector}")
        elif selectors:
            raise ValueError(f"{operation} does not accept selectors.")
        if private_result_contract is not None:
            if private_context is None:
                raise ValueError("private_result_contract requires a private_context.")
            if resolved_intent != "execute_tests" or operation not in {"test-focused", "test-full"}:
                raise ValueError("private_result_contract requires an executing test validation.")
        validation_env, resolved_context, redacted_values, requested_values = resolve_private_context(private_context)
        with _validation_lock:
            if _active_validation is not None:
                raise RuntimeError(f"Validation already running: {_active_validation}")
            run_id = str(uuid.uuid4())
            _active_validation = run_id
        mark_lease_validation_state(lease_id, lease_token, run_id=run_id, starting=True)
        starting_status = git_worktree_status_raw()
        starting_head = require_expected_head(expected_head)
        state = {
            "run_id": run_id,
            "operation_id": operation_id,
            "lease_id": lease_id,
            "execution_id": lease.get("execution_id"),
            "status": "running",
            "operation": operation,
            "selectors": selectors,
            "private_context": resolved_context,
            "private_context_configured": resolved_context is not None,
            "validation_intent": resolved_intent,
            "provenance_label": normalize_provenance_label(provenance_label) or lease.get("provenance_label"),
            "private_result_contract": private_result_contract,
            "starting_head": starting_head,
            "starting_worktree_fingerprint": worktree_fingerprint(),
            "starting_index_fingerprint": index_fingerprint(),
            "started_at": now_iso(),
            "completed_at": None,
            "duration_seconds": None,
            "exit_code": None,
            "failure_classification": None,
            "ending_head": None,
            "repository_mutated": None,
            "safe_test_summary": {},
            "xcresult_evidence": {},
        }
        write_state(run_id, state)
        worker = threading.Thread(
            target=validation_worker,
            args=(
                run_id, operation, selectors, starting_status, starting_head,
                validation_env, redacted_values, requested_values, resolved_context, resolved_intent,
                private_result_contract, lease_id, lease_token,
            ),
            daemon=True,
        )
        worker.start()
        finish_operation(operation_id, state)
        return state
    except Exception as exc:
        fail_operation(operation_id, exc)
        raise


@tool(read_only=True)
def validation_status(run_id: UUIDString, wait_seconds: WaitSeconds = 0) -> dict[str, Any]:
    """Return validation state, optionally waiting boundedly for terminal state. Waiting never cancels the run."""
    if not isinstance(wait_seconds, int) or wait_seconds < 0 or wait_seconds > MAX_VALIDATION_STATUS_WAIT_SECONDS:
        raise ValueError(f"wait_seconds must be 0...{MAX_VALIDATION_STATUS_WAIT_SECONDS}.")
    deadline = time.monotonic() + wait_seconds
    while True:
        state = read_state(run_id)
        if state.get("status") != "running" or wait_seconds == 0:
            return state
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return state
        time.sleep(min(0.25, remaining))


@tool(read_only=True)
def validation_result(run_id: UUIDString, detail: ValidationResultDetail = "summary", max_bytes: ToolOutputBytes = 80_000) -> dict[str, Any]:
    """Return typed validation evidence. Credentials are redacted; private validation content may be returned."""
    validate_output_limit(max_bytes)
    state = read_state(run_id)
    result = {
        "run_id": run_id,
        "lease_id": state.get("lease_id"),
        "execution_id": state.get("execution_id"),
        "status": state.get("status"),
        "operation": state.get("operation"),
        "selectors": state.get("selectors"),
        "private_context": state.get("private_context"),
        "validation_intent": state.get("validation_intent"),
        "starting_head": state.get("starting_head"),
        "ending_head": state.get("ending_head"),
        "ending_worktree_fingerprint": state.get("ending_worktree_fingerprint"),
        "ending_index_fingerprint": state.get("ending_index_fingerprint"),
        "exit_code": state.get("exit_code"),
        "failure_classification": state.get("failure_classification"),
        "repository_mutated": state.get("repository_mutated"),
        "duration_seconds": state.get("duration_seconds"),
        "safe_test_summary": state.get("safe_test_summary", {}),
        "xcresult_evidence": state.get("xcresult_evidence", {}),
        "validation_binding_failed": state.get("validation_binding_failed", False),
        "provenance_label": state.get("provenance_label"),
        "private_result_contract": state.get("private_result_contract"),
        "private_result_captured": isinstance(state.get("private_structured_result"), dict),
    }
    if detail not in {"summary", "failures", "diagnostics", "private_result"}:
        raise ValueError("detail must be summary, failures, diagnostics, or private_result.")
    if detail == "summary":
        return enforce_structured_output(result, max_bytes)
    if detail == "failures":
        summary = state.get("safe_test_summary", {})
        return enforce_structured_output({**result, "test_failures": summary.get("testFailures", []) if isinstance(summary, dict) else []}, max_bytes)
    if detail == "private_result":
        structured = state.get("private_structured_result")
        if not isinstance(structured, dict):
            return enforce_structured_output({**result, "private_result": None}, max_bytes)
        return enforce_structured_output({**result, "private_result": structured}, max_bytes)
    path = log_path(run_id)
    if not path.exists():
        return enforce_structured_output({**result, "diagnostics": ""}, max_bytes)
    text = sanitize_text(path.read_text(encoding="utf-8", errors="replace"))
    text, truncated = truncate_text(text, max_bytes // 2)
    return enforce_structured_output({**result, "diagnostics": text, "truncated": truncated}, max_bytes)



@tool(read_only=True)
def validation_wait_result(
    run_id: UUIDString,
    wait_seconds: WaitSeconds = 60,
    detail: ValidationResultDetail = "summary",
    max_bytes: ToolOutputBytes = 80_000,
) -> dict[str, Any]:
    """Wait boundedly for a durable validation, then return its retained result when terminal."""
    state = validation_status(run_id, wait_seconds)
    if state.get("status") == "running":
        return enforce_structured_output({
            "run_id": run_id,
            "status": "running",
            "result_ready": False,
            "retry_safe": True,
        }, max_bytes)
    result = validation_result(run_id, detail=detail, max_bytes=max_bytes)
    result["result_ready"] = True
    result["retry_safe"] = True
    return result

@tool(read_only=False, destructive=True, idempotent=True)
def cancel_validation(run_id: UUIDString, operation_id: UUIDString, lease_id: UUIDString, lease_token: str) -> dict[str, Any]:
    """Terminate only the exact executor-owned validation process group and verify cleanup."""
    payload = {"run_id": run_id, "lease_id": lease_id}
    replay, prior = begin_operation(operation_id, "cancel_validation", payload)
    if replay:
        return prior
    try:
        require_execution_lease(lease_id, lease_token)
        state = read_state(run_id)
        if state.get("lease_id") != lease_id:
            raise PermissionError("Validation belongs to another execution lease.")
        if state.get("status") != "running":
            return finish_operation(operation_id, {"run_id": run_id, "cancelled": False, "status": state.get("status")})
        with _validation_lock:
            _cancelled_runs.add(run_id)
            proc = _active_processes.get(run_id)
        terminated = False
        escalated = False
        if proc is not None and proc.poll() is None:
            try:
                os.killpg(proc.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            for _ in range(25):
                if proc.poll() is not None:
                    terminated = True
                    break
                time.sleep(0.2)
            if proc.poll() is None:
                escalated = True
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                try:
                    proc.wait(timeout=5)
                except Exception:
                    pass
                terminated = proc.poll() is not None
            finish_process_record(run_id, "cancelled")
        record_path = process_record_path(run_id)
        surviving_owned_process = False
        if record_path.is_file():
            try:
                record = json.loads(record_path.read_text(encoding="utf-8"))
                surviving_owned_process = pid_is_executor_owned(record)
            except Exception:
                pass
        return finish_operation(operation_id, {
            "run_id": run_id,
            "lease_id": lease_id,
            "cancel_requested": True,
            "terminated": terminated,
            "sigkill_escalated": escalated,
            "surviving_owned_process": surviving_owned_process,
        })
    except Exception as exc:
        fail_operation(operation_id, exc)
        raise




# ==========================================================================\n# v2.1 evidence and optional engineering tools\n# ==========================================================================\n
PROJECT_STATE_PATH = "Project documents/PROJECT_STATE.md"
FUTURE_WORK_PATH = "Project documents/FUTURE_WORK.MD"
ADR_PATH = "Project documents/ADR.md"


def file_summary(relative: str, *, head_chars: int = 3000, tail_chars: int = 3000) -> dict[str, Any]:
    rel, candidate = normalize_repo_write_path(relative)
    if not candidate.is_file():
        return {"path": rel, "available": False}
    data = candidate.read_bytes()
    text = data.decode("utf-8", errors="replace")
    return {
        "path": rel,
        "available": True,
        "sha256": sha256_bytes(data),
        "size_bytes": len(data),
        "head": sanitize_text(text[:head_chars]),
        "tail": sanitize_text(text[-tail_chars:]) if len(text) > tail_chars else "",
        "changed": rel in set(changed_tracked_paths()) | set(staged_paths()) | set(untracked_paths()),
    }


def source_test_inventory(max_results: int = 3000) -> dict[str, Any]:
    tests: list[dict[str, Any]] = []
    test_root = REPO / "LedgerForgeTests"
    if not test_root.is_dir():
        candidates = list(REPO.rglob("*Tests.swift"))
    else:
        candidates = list(test_root.rglob("*.swift"))
    suite_re = re.compile(r"(?:final\s+)?class\s+([A-Za-z0-9_]+Tests)\b|@Suite(?:\([^)]*\))?\s*(?:struct|final\s+class|class)\s+([A-Za-z0-9_]+)")
    xctest_re = re.compile(r"\bfunc\s+(test[A-Za-z0-9_]+)\s*\(")
    swift_test_re = re.compile(r"@Test(?:\([^)]*\))?\s*(?:func\s+)?([A-Za-z0-9_]+)?")
    for candidate in candidates:
        try:
            text = candidate.read_text(encoding="utf-8")
            rel = candidate.relative_to(REPO).as_posix()
        except Exception:
            continue
        suites = []
        for match in suite_re.finditer(text):
            suites.append(match.group(1) or match.group(2))
        xctests = xctest_re.findall(text)
        swift_tests = [m.group(1) for m in swift_test_re.finditer(text) if m.group(1)]
        if suites or xctests or swift_tests:
            tests.append({"path": rel, "suites": sorted(set(suites)), "xctest_methods": sorted(set(xctests)), "swift_testing_symbols": sorted(set(swift_tests))})
        if len(tests) >= max_results:
            break
    return {"mode": "source-fallback", "files": tests, "file_count": len(tests), "authoritative_selector_inventory": False}


@tool(read_only=True)
def test_discovery(max_results: TestDiscoveryLimit = 1000, max_bytes: ToolOutputBytes = 120_000) -> dict[str, Any]:
    """Discover the current test surface conservatively; never silently treats impact analysis as acceptance authority."""
    require_feature("evidence", "test-discovery")
    if max_results < 1 or max_results > 3000:
        raise ValueError("max_results must be 1...3000.")
    inventory = source_test_inventory(max_results=max_results)
    inventory["test_plan"] = XCODE_TEST_PLAN
    inventory["scheme"] = XCODE_SCHEME
    inventory["selector_capabilities"] = {
        "suite_selector": {"syntax": "LedgerForgeTests/<Suite>", "executor_bindability": "supported-with-zero-test-fail-closed"},
        "xctest_method_selector": {"syntax": "LedgerForgeTests/<Suite>/<testMethod>", "executor_bindability": "candidate-from-source; execution remains authoritative"},
        "swift_testing_method_selector": {"syntax": "framework-dependent", "executor_bindability": "not-prevalidated; prefer suite selector unless an executing probe proves binding"},
        "zero_test_result_is_acceptance": False,
    }
    inventory["note"] = "Source fallback is conservative; selector execution remains authoritative and zero-test runs fail closed."
    return enforce_structured_output(inventory, max_bytes)


@tool(read_only=True)
def documentation_sync_preflight(max_bytes: ToolOutputBytes = 120_000) -> dict[str, Any]:
    """Collect authority-aware documentation state for Chat-owned documentation synchronization."""
    require_feature("evidence", "documentation-sync-preflight")
    docs = [file_summary(PROJECT_STATE_PATH), file_summary(FUTURE_WORK_PATH), file_summary(ADR_PATH)]
    roadmap_hits: list[str] = []
    for candidate in (REPO / "Project documents").glob("*70*79*.md") if (REPO / "Project documents").is_dir() else []:
        roadmap_hits.append(candidate.relative_to(REPO).as_posix())
    result = {
        "head": resolve_ref("HEAD"),
        "branch": run_git("branch", "--show-current") or None,
        "origin_main_local_record": resolve_ref("origin/main"),
        "documents": docs,
        "roadmap_candidates": roadmap_hits,
        "changed_production_and_test_paths": changed_tracked_paths(),
        "staged_paths": staged_paths(),
        "untracked_paths": sorted(untracked_paths()),
        "recent_commits": run_git("log", "--oneline", "-n", "20"),
        "decision_owner": "Chat",
        "automatic_document_semantics": False,
    }
    return enforce_structured_output(result, max_bytes)


@tool(read_only=True)
def cycle_close_evidence(run_ids: list[UUIDString] | None = None, max_bytes: ToolOutputBytes = 120_000) -> dict[str, Any]:
    """Assemble an immutable-style structured cycle-close evidence view from completed validation runs."""
    require_feature("evidence", "cycle-close-evidence")
    runs: list[dict[str, Any]] = []
    for run_id in run_ids or []:
        state = read_state(run_id)
        runs.append({
            "run_id": run_id,
            "operation": state.get("operation"),
            "status": state.get("status"),
            "exit_code": state.get("exit_code"),
            "failure_classification": state.get("failure_classification"),
            "private_context": state.get("private_context"),
            "repository_mutated": state.get("repository_mutated"),
            "duration_seconds": state.get("duration_seconds"),
            "xcresult_evidence": state.get("xcresult_evidence", {}),
        })
    lease = read_active_lease_raw()
    result = {
        "generated_at": now_iso(),
        "executor_boot_id": EXECUTOR_BOOT_ID,
        "executor_source_sha256": source_sha256(),
        "schema_contract_sha256": schema_contract_digest(),
        "workspace": workspace_snapshot(),
        "execution_lease": public_lease_view(lease),
        "validation_runs": runs,
        "privacy_scan": scan_staged_blobs(),
        "recovery_status": {
            "incomplete_journals": STARTUP_RECONCILIATION.get("incomplete_journals", []),
            "stale_processes": STARTUP_RECONCILIATION.get("stale_processes", []),
        },
        "acceptance_authority": False,
    }
    return enforce_structured_output(result, max_bytes)


def ledgerforge_processes() -> list[dict[str, Any]]:
    result = subprocess.run(["pgrep", "-x", "LedgerForge"], capture_output=True, text=True, check=False, timeout=5)
    rows: list[dict[str, Any]] = []
    for value in result.stdout.split():
        if not value.isdigit():
            continue
        pid = int(value)
        command = pid_command(pid)
        rows.append({"pid": pid, "command": sanitize_text(command), "exact_name": True})
    return rows


def runtime_record() -> dict[str, Any] | None:
    path = PROCESS_RECORDS / "runtime.json"
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else None
    except Exception:
        return None


@tool(read_only=False, destructive=False, idempotent=True)
def runtime_launch(operation_id: UUIDString, expected_head: str, lease_id: UUIDString, lease_token: str) -> dict[str, Any]:
    """Launch the repository-owned freshly built LedgerForge runtime through the canonical build/run verifier."""
    require_feature("evidence", "controlled-runtime")
    payload = {"expected_head": expected_head, "lease_id": lease_id}
    replay, prior = begin_operation(operation_id, "runtime_launch", payload)
    if replay:
        return prior
    try:
        require_execution_lease(lease_id, lease_token, extend_seconds=MAX_VALIDATION_SECONDS + 600)
        require_expected_head(expected_head)
        if ledgerforge_processes():
            raise RuntimeError("LedgerForge process already exists; runtime_launch refuses ambiguous ownership.")
        if not BUILD_RUN_SCRIPT.is_file():
            raise RuntimeError("Repository build_and_run.sh is unavailable.")
        status, output = run_captured([str(BUILD_RUN_SCRIPT), "--verify"], safe_validation_base_env(), timeout=MAX_VALIDATION_SECONDS)
        if status != 0:
            clipped, _ = truncate_text(sanitize_text(output), 20_000)
            raise RuntimeError(f"Repository runtime verifier failed: {clipped}")
        processes = ledgerforge_processes()
        if len(processes) != 1:
            raise RuntimeError(f"Expected exactly one LedgerForge process after launch; found {len(processes)}.")
        row = processes[0]
        if "LedgerForge.app/Contents/MacOS/LedgerForge" not in row.get("command", ""):
            raise RuntimeError("Launched LedgerForge process executable path could not be verified.")
        record = {
            "run_id": "runtime",
            "pid": row["pid"],
            "pgid": None,
            "command_class": "runtime",
            "lease_id": lease_id,
            "executor_boot_id": EXECUTOR_BOOT_ID,
            "started_at": now_iso(),
            "status": "running",
            "command": row["command"],
            "process_start_identity": pid_start_identity(int(row["pid"])),
        }
        atomic_write_json(PROCESS_RECORDS / "runtime.json", record)
        return finish_operation(operation_id, {"lease_id": lease_id, "pid": row["pid"], "executable_verified": True, "repository_mutated": False})
    except Exception as exc:
        fail_operation(operation_id, exc)
        raise


@tool(read_only=True)
def runtime_status() -> dict[str, Any]:
    """Return the executor-owned LedgerForge runtime identity if present."""
    require_feature("evidence", "controlled-runtime")
    record = runtime_record()
    processes = ledgerforge_processes()
    owned = False
    if record:
        owned = any(p.get("pid") == record.get("pid") and "LedgerForge.app/Contents/MacOS/LedgerForge" in p.get("command", "") for p in processes)
    return {"owned_runtime": record, "owned_runtime_alive": owned, "exact_name_process_count": len(processes), "ambiguous": len(processes) > 1}


@tool(read_only=True)
def runtime_logs(seconds: RuntimeLogSeconds = 120, max_bytes: ToolOutputBytes = 80_000) -> dict[str, Any]:
    """Return privacy-filtered unified logs only for the executor-owned LedgerForge PID and bounded interval."""
    require_feature("evidence", "bounded-runtime-logs")
    validate_output_limit(max_bytes)
    if seconds < 1 or seconds > MAX_LOG_SECONDS:
        raise ValueError(f"seconds must be 1...{MAX_LOG_SECONDS}.")
    record = runtime_record()
    if not record or record.get("status") != "running":
        raise RuntimeError("No executor-owned LedgerForge runtime is recorded.")
    pid = int(record.get("pid", 0))
    command = pid_command(pid)
    if "LedgerForge.app/Contents/MacOS/LedgerForge" not in command:
        raise RuntimeError("Recorded runtime PID no longer identifies LedgerForge.")
    predicate = f"processID == {pid}"
    result = subprocess.run(
        ["/usr/bin/log", "show", "--style", "compact", "--last", f"{seconds}s", "--predicate", predicate],
        capture_output=True, text=True, check=False, timeout=30,
    )
    text = sanitize_text(result.stdout if result.returncode == 0 else "")
    lines = text.splitlines()[-MAX_LOG_LINES:]
    text, truncated = truncate_text("\n".join(lines), max_bytes)
    return {"pid": pid, "seconds": seconds, "logs": text, "truncated": truncated, "predicate_user_controlled": False}


@tool(read_only=False, destructive=True, idempotent=True)
def runtime_stop(operation_id: UUIDString, lease_id: UUIDString, lease_token: str) -> dict[str, Any]:
    """Stop only the exact LedgerForge PID previously recorded by runtime_launch."""
    require_feature("evidence", "controlled-runtime")
    payload = {"lease_id": lease_id}
    replay, prior = begin_operation(operation_id, "runtime_stop", payload)
    if replay:
        return prior
    try:
        require_execution_lease(lease_id, lease_token)
        record = runtime_record()
        if not record or record.get("status") != "running":
            return finish_operation(operation_id, {"stopped": False, "reason": "no-owned-runtime"})
        if record.get("lease_id") != lease_id:
            raise PermissionError("Runtime belongs to another execution lease.")
        pid = int(record.get("pid", 0))
        command = pid_command(pid)
        if "LedgerForge.app/Contents/MacOS/LedgerForge" not in command:
            raise RuntimeError("Recorded PID no longer identifies the owned LedgerForge executable.")
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        for _ in range(25):
            if not pid_command(pid):
                break
            time.sleep(0.2)
        alive = bool(pid_command(pid))
        if alive:
            raise RuntimeError("Owned LedgerForge runtime did not terminate normally; no SIGKILL was issued.")
        record["status"] = "stopped"
        record["stopped_at"] = now_iso()
        atomic_write_json(PROCESS_RECORDS / "runtime.json", record)
        return finish_operation(operation_id, {"stopped": True, "pid": pid, "sigkill_used": False})
    except Exception as exc:
        fail_operation(operation_id, exc)
        raise


@tool(read_only=True)
def test_impact_advisor(changed_paths: list[str] | None = None, max_bytes: ToolOutputBytes = 80_000) -> dict[str, Any]:
    """Return conservative test-impact suggestions. It never has acceptance authority."""
    require_feature("optional", "test-impact-advisor")
    paths = changed_paths or changed_tracked_paths()
    normalized = [normalize_repo_write_path(p)[0] for p in paths]
    inventory = source_test_inventory(max_results=3000)
    suggestions: list[dict[str, Any]] = []
    broad_triggers: list[str] = []
    for path in normalized:
        stem = Path(path).stem
        hits: list[str] = []
        for entry in inventory.get("files", []):
            if stem.casefold() in json.dumps(entry).casefold():
                hits.append(entry.get("path"))
        suggestions.append({"changed_path": path, "test_files": hits[:30]})
        low = path.casefold()
        if any(token in low for token in ("migration", "repository", "persistence", "importengine", "hydrator", "money", "financial")):
            broad_triggers.append(path)
    result = {
        "changed_paths": normalized,
        "suggestions": suggestions,
        "broad_validation_triggers": broad_triggers,
        "advisory_only": True,
        "acceptance_authority": False,
        "may_not_waive_full_suite": True,
    }
    return enforce_structured_output(result, max_bytes)


@tool(read_only=True)
def performance_probe(kind: PerformanceProbeKind = "recent-validations", max_bytes: ToolOutputBytes = 80_000) -> dict[str, Any]:
    """Return bounded engineering performance measurements already observable locally."""
    require_feature("optional", "performance-probes")
    if kind == "recent-validations":
        rows: list[dict[str, Any]] = []
        for path in sorted(RUNS.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)[:30]:
            try:
                state = json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                continue
            if "run_id" in state:
                rows.append({k: state.get(k) for k in ("run_id", "operation", "duration_seconds", "exit_code", "failure_classification", "completed_at")})
        return enforce_structured_output({"kind": kind, "measurements": rows, "financial_data_retained": False}, max_bytes)
    if kind == "built-app-size":
        candidates = sorted((Path.home() / "Library" / "Developer" / "Xcode" / "DerivedData").glob("LedgerForge-*/Build/Products/Debug/LedgerForge.app"), key=lambda p: p.stat().st_mtime if p.exists() else 0, reverse=True)
        if not candidates:
            return {"kind": kind, "available": False}
        app = candidates[0]
        total = sum(p.stat().st_size for p in app.rglob("*") if p.is_file())
        return {"kind": kind, "available": True, "size_bytes": total, "path_exposed": False}
    raise PermissionError("Unsupported performance probe kind.")


@tool(read_only=True)
def swift_xcode_audit(max_bytes: ToolOutputBytes = 100_000) -> dict[str, Any]:
    """Return fixed Swift/Xcode/toolchain and selected build-setting evidence."""
    require_feature("optional", "swift-xcode-audit")
    xcode = subprocess.run([str(XCODEBUILD), "-version"], capture_output=True, text=True, check=False, timeout=30)
    swift = subprocess.run([str(XCRUN), "swift", "--version"], capture_output=True, text=True, check=False, timeout=30)
    settings = subprocess.run(
        [str(XCODEBUILD), "-project", str(XCODE_PROJECT), "-scheme", XCODE_SCHEME, "-showBuildSettings"],
        capture_output=True, text=True, check=False, timeout=120, env=safe_validation_base_env(),
    )
    wanted = {"SWIFT_VERSION", "SWIFT_STRICT_CONCURRENCY", "MACOSX_DEPLOYMENT_TARGET", "SDKROOT", "ENABLE_TESTABILITY", "PRODUCT_BUNDLE_IDENTIFIER"}
    selected: dict[str, str] = {}
    for line in settings.stdout.splitlines():
        if " = " not in line:
            continue
        key, value = [part.strip() for part in line.split(" = ", 1)]
        if key in wanted or key.startswith("SWIFT_UPCOMING_FEATURE_"):
            selected[key] = sanitize_text(value)
    return enforce_structured_output({
        "xcode_version": sanitize_text(xcode.stdout.strip()),
        "swift_version": sanitize_text(swift.stdout.strip()),
        "build_settings": selected,
        "audit_only": True,
    }, max_bytes)


@tool(read_only=True)
def repository_recovery_analysis(max_bytes: ToolOutputBytes = 120_000) -> dict[str, Any]:
    """Return read-only repository/executor recovery evidence; never performs cleanup."""
    require_feature("optional", "repository-recovery-analysis")
    receipts: dict[str, int] = {}
    for path in OPERATIONS.glob("*.json"):
        try:
            state = json.loads(path.read_text(encoding="utf-8")).get("status", "unknown")
        except Exception:
            state = "unreadable"
        receipts[state] = receipts.get(state, 0) + 1
    result = {
        "workspace": workspace_snapshot(),
        "lease": public_lease_view(read_active_lease_raw()),
        "startup_reconciliation": STARTUP_RECONCILIATION,
        "operation_receipt_counts": receipts,
        "recovery_status": executor_recovery_status(),
        "automatic_cleanup_authorized": False,
    }
    return enforce_structured_output(result, max_bytes)


@tool(read_only=True)
def fixture_provenance_inspect(path: str, max_bytes: ToolOutputBytes = 80_000) -> dict[str, Any]:
    """Inspect Git-safe fixture provenance signals without inventing source authority."""
    require_feature("optional", "fixture-provenance-inspection")
    relative, candidate = normalize_repo_write_path(path)
    if not candidate.is_file():
        raise FileNotFoundError("Fixture path is not a regular file.")
    tracked = relative in tracked_paths()
    blob_sha = None
    if tracked:
        result = subprocess.run(["git", "-C", str(REPO), "rev-parse", f"HEAD:{relative}"], capture_output=True, text=True, check=False, timeout=10)
        blob_sha = result.stdout.strip() or None if result.returncode == 0 else None
    name = candidate.name
    refs = subprocess.run(["git", "-C", str(REPO), "grep", "-n", "-F", name, "--", "Project documents", "LedgerForgeTests"], capture_output=True, text=True, check=False, timeout=30)
    lines = [sanitize_text(line)[:500] for line in refs.stdout.splitlines()[:100]]
    return enforce_structured_output({
        "path": relative,
        "tracked": tracked,
        "head_blob_sha": blob_sha,
        "worktree_sha256": sha256_bytes(candidate.read_bytes()),
        "reference_hits": lines,
        "authoritative_source_provenance_proven": False,
        "production_parser_output_is_not_oracle": True,
    }, max_bytes)


@tool(read_only=False, destructive=False, idempotent=True)
def run_regression_campaign(
    operation_id: UUIDString,
    expected_head: str,
    lease_id: UUIDString,
    lease_token: str,
    campaign_id: RegressionCampaignId,
    dry_run: bool = True,
) -> dict[str, Any]:
    """Run one small server-owned engineering campaign; large acceptance remains start_validation/cycle-close."""
    require_feature("optional", "regression-campaigns")
    registry = {
        "toolchain-smoke": [[str(XCODEBUILD), "-version"], [str(XCRUN), "swift", "--version"]],
        "project-metadata-smoke": [[str(XCODEBUILD), "-list", "-json", "-project", str(XCODE_PROJECT)]],
    }
    payload = {"expected_head": expected_head, "lease_id": lease_id, "campaign_id": campaign_id, "dry_run": dry_run}
    replay, prior = begin_operation(operation_id, "run_regression_campaign", payload)
    if replay:
        return prior
    try:
        require_execution_lease(lease_id, lease_token)
        require_expected_head(expected_head)
        if campaign_id not in registry:
            raise PermissionError("Unknown server-owned regression campaign.")
        if dry_run:
            return finish_operation(operation_id, {"dry_run": True, "campaign_id": campaign_id, "steps": len(registry[campaign_id]), "arbitrary_argv": False})
        rows = []
        for command in registry[campaign_id]:
            code, output = run_captured(command, safe_validation_base_env(), timeout=120)
            clipped, truncated = truncate_text(sanitize_text(output), 20_000)
            rows.append({"exit_code": code, "output": clipped, "truncated": truncated})
            if code != 0:
                break
        return finish_operation(operation_id, {"dry_run": False, "campaign_id": campaign_id, "steps": rows, "repository_mutated": False})
    except Exception as exc:
        fail_operation(operation_id, exc)
        raise


@tool(read_only=False, destructive=False, idempotent=True)
def private_context_matrix(
    operation_id: UUIDString,
    expected_head: str,
    lease_id: UUIDString,
    lease_token: str,
    contexts: list[PrivateContextName] | None = None,
    dry_run: bool = True,
) -> dict[str, Any]:
    """Qualify private-context availability sequentially. Actual financial tests remain explicit start_validation calls."""
    require_feature("optional", "private-context-matrix")
    selected = contexts or sorted(PRIVATE_CONTEXTS)
    payload = {"expected_head": expected_head, "lease_id": lease_id, "contexts": selected, "dry_run": dry_run}
    replay, prior = begin_operation(operation_id, "private_context_matrix", payload)
    if replay:
        return prior
    try:
        require_execution_lease(lease_id, lease_token)
        require_expected_head(expected_head)
        for name in selected:
            if name not in PRIVATE_CONTEXTS:
                raise PermissionError(f"Unknown private context: {name}")
        matrix = [{"context": name, "configured": private_context_available(name)} for name in selected]
        # Deliberately does not aggregate credentials or auto-run source-dependent tests.
        return finish_operation(operation_id, {
            "dry_run": dry_run,
            "contexts": matrix,
            "sequential_only": True,
            "credentials_aggregated": False,
            "actual_test_execution": False,
            "instruction": "Run explicit lease-bound start_validation per context using Chat-approved selectors.",
        })
    except Exception as exc:
        fail_operation(operation_id, exc)
        raise


@tool(read_only=True, open_world=True)
def ci_status_inspection() -> dict[str, Any]:
    """Optional CI/status surface; installed disabled until dedicated read-only authorization is configured."""
    return {
        "installed": True,
        "enabled": False,
        "reason": "Dedicated repository-specific read-only CI authorization has not been configured.",
        "ambient_credentials_used": False,
    }



# ==========================================================================
# MCP 2.6.2 admin maintenance control plane
# ==========================================================================

_MAINTENANCE_COMPONENT_FILES = {
    "executor": "executor_v2_1.py",
    "static_qualifier": "qualify_executor_current_static.py",
    "isolated_qualifier": "qualify_executor_current_isolated.py",
    "release_qualifier": "qualify_release.py",
    "main_launcher": "LedgerForge MCP.command",
    "owner_admin": "ledgerforge_mcp_owner_admin.py",
    "owner_wrapper": "LedgerForge MCP Owner Recovery.command",
    "owner_version": ".mcp-owner-recovery-version",
    "release_activator": "ledgerforge_mcp_release_activator.py",
    "release_version": ".mcp-release-version",
}
_MAINTENANCE_EXECUTABLE_ROLES = {"executor", "static_qualifier", "isolated_qualifier", "release_qualifier", "main_launcher", "owner_admin", "owner_wrapper", "release_activator"}
_MAINTENANCE_REQUIRED_ARM_ROLES = {
    "executor", "static_qualifier", "isolated_qualifier", "release_qualifier",
    "main_launcher", "owner_admin", "owner_wrapper", "owner_version",
    "release_activator", "release_version",
}


def _maintenance_control_targets() -> dict[str, Path]:
    return {
        "executor_source": BRIDGE_ROOT / "executor_v2_1.py",
        "main_launcher": MAINTENANCE_DESKTOP / "LedgerForge MCP.command",
        "owner_admin": BRIDGE_ROOT / "ledgerforge_mcp_owner_admin.py",
        "owner_wrapper": MAINTENANCE_DESKTOP / "LedgerForge MCP Owner Recovery.command",
        "owner_version": BRIDGE_ROOT / ".mcp-owner-recovery-version",
        "static_qualifier": BRIDGE_ROOT / "qualify_executor_current_static.py",
        "isolated_qualifier": BRIDGE_ROOT / "qualify_executor_current_isolated.py",
        "release_activator": BRIDGE_ROOT / "ledgerforge_mcp_release_activator.py",
        "release_version": BRIDGE_ROOT / ".mcp-release-version",
        "state_root_pointer": BRIDGE_ROOT / ".executor-v2.1-state-root",
        "executor_log": MAINTENANCE_TUNNEL_CONFIG / "ledgerforge-executor.log",
        "tunnel_log": MAINTENANCE_TUNNEL_CONFIG / "ledgerforge-recovery.log",
    }


def _maintenance_file_metadata(path: Path) -> dict[str, Any]:
    if path.is_symlink():
        return {"exists": True, "type": "symlink", "path": str(path)}
    if not path.exists():
        return {"exists": False, "type": "absent", "path": str(path)}
    if path.is_file():
        sha, size = _sha256_file_stream(path)
        return {"exists": True, "type": "file", "path": str(path), "sha256": sha, "size": size, "mode": stat.S_IMODE(path.stat().st_mode)}
    if path.is_dir():
        return {"exists": True, "type": "directory", "path": str(path), "mode": stat.S_IMODE(path.stat().st_mode)}
    return {"exists": True, "type": "other", "path": str(path)}


def _maintenance_release_root(release_id: str) -> Path:
    if not isinstance(release_id, str) or not re.fullmatch(MAINTENANCE_RELEASE_ID_PATTERN, release_id):
        raise ValueError("release_id must contain 3..120 letters, numbers, dot, underscore or hyphen and may not start with punctuation.")
    root = (PREPARED_RELEASE_ROOT / release_id).resolve(strict=False)
    try:
        root.relative_to(PREPARED_RELEASE_ROOT)
    except ValueError as exc:
        raise PermissionError("Prepared release path escapes the maintenance root.") from exc
    return root


def _maintenance_release_state_path(release_id: str) -> Path:
    return _maintenance_release_root(release_id) / MAINTENANCE_RELEASE_STATE


def _maintenance_read_release_state(release_id: str) -> dict[str, Any]:
    path = _maintenance_release_state_path(release_id)
    if not path.is_file() or path.is_symlink():
        raise FileNotFoundError(f"Prepared release state is unavailable: {release_id}")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or value.get("release_id") != release_id:
        raise RuntimeError("Prepared release state identity mismatch.")
    return value


def _maintenance_release_identity_digest(state: dict[str, Any]) -> str:
    identity = {
        "release_id": state.get("release_id"),
        "target_version": state.get("target_version"),
        "expected_current_source_sha256": state.get("expected_current_source_sha256"),
        "expected_current_launcher_sha256": state.get("expected_current_launcher_sha256"),
        "components": state.get("components", {}),
    }
    return sha256_text(json.dumps(identity, sort_keys=True, separators=(",", ":"), ensure_ascii=False))


def _maintenance_blob_root(blob_id: str) -> Path:
    if not isinstance(blob_id, str) or not re.fullmatch(MAINTENANCE_BLOB_ID_PATTERN, blob_id):
        raise ValueError("blob_id must contain 3..120 letters, numbers, dot, underscore or hyphen and may not start with punctuation.")
    root = (MAINTENANCE_BLOB_ROOT / blob_id).resolve(strict=False)
    try:
        root.relative_to(MAINTENANCE_BLOB_ROOT)
    except ValueError as exc:
        raise PermissionError("Release blob path escapes the maintenance root.") from exc
    return root


def _maintenance_blob_manifest_path(blob_id: str) -> Path:
    return _maintenance_blob_root(blob_id) / MAINTENANCE_BLOB_MANIFEST


def _maintenance_read_blob_manifest(blob_id: str) -> dict[str, Any]:
    path = _maintenance_blob_manifest_path(blob_id)
    if not path.is_file() or path.is_symlink():
        raise FileNotFoundError(f"Release blob manifest is unavailable: {blob_id}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise RuntimeError("Release blob manifest is unreadable.") from exc
    if not isinstance(value, dict) or value.get("blob_id") != blob_id:
        raise RuntimeError("Release blob manifest identity mismatch.")
    return value


def _maintenance_blob_chunks(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    chunks = manifest.get("chunks")
    if not isinstance(chunks, list):
        raise RuntimeError("Release blob manifest chunk index is invalid.")
    result: list[dict[str, Any]] = []
    seen: set[int] = set()
    for row in chunks:
        if not isinstance(row, dict):
            raise RuntimeError("Release blob manifest contains an invalid chunk entry.")
        try:
            offset = int(row["offset"])
            size = int(row["size"])
        except (KeyError, TypeError, ValueError) as exc:
            raise RuntimeError("Release blob manifest contains an invalid chunk identity.") from exc
        digest = str(row.get("sha256") or "").casefold()
        if offset < 0 or size < 1 or size > MAINTENANCE_MAX_BLOB_CHUNK_BYTES or offset in seen or not re.fullmatch(r"[a-f0-9]{64}", digest):
            raise RuntimeError("Release blob manifest contains an invalid chunk identity.")
        seen.add(offset)
        result.append({"offset": offset, "size": size, "sha256": digest})
    return sorted(result, key=lambda row: int(row["offset"]))


def _maintenance_blob_summary(blob_id: str, manifest: dict[str, Any]) -> dict[str, Any]:
    chunks = _maintenance_blob_chunks(manifest)
    received = sum(int(row["size"]) for row in chunks)
    expected_size = int(manifest.get("size") or 0)
    contiguous = 0
    for row in chunks:
        if int(row["offset"]) != contiguous:
            break
        contiguous += int(row["size"])
    finalized = bool(manifest.get("finalized"))
    return {
        "blob_id": blob_id,
        "release_id": manifest.get("release_id"),
        "component_role": manifest.get("component_role"),
        "size": expected_size,
        "sha256": manifest.get("sha256"),
        "received_bytes": received,
        "received_chunks": len(chunks),
        "contiguous_bytes": contiguous,
        "complete": contiguous == expected_size and received == expected_size,
        "finalized": finalized,
        "blob_ref": blob_id if finalized else None,
    }


def _maintenance_upload_blob_chunk(
    release_id: str,
    component_role: str,
    blob_id: str,
    blob_size: int,
    blob_sha256: str,
    chunk_offset: int,
    chunk_sha256: str,
    chunk_base64: str,
) -> dict[str, Any]:
    if component_role not in _MAINTENANCE_COMPONENT_FILES:
        raise ValueError(f"Unsupported release component role: {component_role!r}")
    if not isinstance(blob_size, int) or isinstance(blob_size, bool) or not 1 <= blob_size <= MAINTENANCE_MAX_COMPONENT_BYTES:
        raise ValueError(f"blob_size must be 1..{MAINTENANCE_MAX_COMPONENT_BYTES} bytes.")
    blob_sha256 = str(blob_sha256 or "").casefold()
    chunk_sha256 = str(chunk_sha256 or "").casefold()
    if not re.fullmatch(r"[a-f0-9]{64}", blob_sha256) or not re.fullmatch(r"[a-f0-9]{64}", chunk_sha256):
        raise ValueError("blob_sha256 and chunk_sha256 must be exact SHA-256 digests.")
    if not isinstance(chunk_offset, int) or isinstance(chunk_offset, bool) or chunk_offset < 0:
        raise ValueError("chunk_offset must be a non-negative integer.")
    if not isinstance(chunk_base64, str):
        raise ValueError("chunk_base64 is required.")
    try:
        body = base64.b64decode(chunk_base64, validate=True)
    except Exception as exc:
        raise ValueError("chunk_base64 is invalid.") from exc
    if not body or len(body) > MAINTENANCE_MAX_BLOB_CHUNK_BYTES:
        raise ValueError(f"Each release blob chunk must be 1..{MAINTENANCE_MAX_BLOB_CHUNK_BYTES} bytes.")
    if chunk_offset + len(body) > blob_size:
        raise ValueError("Release blob chunk exceeds the declared blob size.")
    if not hmac.compare_digest(sha256_bytes(body), chunk_sha256):
        raise RuntimeError("Release blob chunk SHA mismatch.")

    root = _maintenance_blob_root(blob_id)
    if root.exists() and (root.is_symlink() or not root.is_dir()):
        raise PermissionError("Release blob identity is not an owned directory.")
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(root, 0o700)
    manifest_path = root / MAINTENANCE_BLOB_MANIFEST
    if manifest_path.exists() and manifest_path.is_symlink():
        raise PermissionError("Release blob manifest may not be a symlink.")
    if manifest_path.exists():
        manifest = _maintenance_read_blob_manifest(blob_id)
        if (
            manifest.get("release_id") != release_id
            or manifest.get("component_role") != component_role
            or int(manifest.get("size") or 0) != blob_size
            or str(manifest.get("sha256") or "").casefold() != blob_sha256
        ):
            raise RuntimeError("Release blob identity does not match the resumed upload.")
        if manifest.get("finalized"):
            existing = next((row for row in _maintenance_blob_chunks(manifest) if int(row["offset"]) == chunk_offset), None)
            if existing and existing["size"] == len(body) and hmac.compare_digest(existing["sha256"], chunk_sha256):
                return _maintenance_blob_summary(blob_id, manifest)
            raise RuntimeError("Finalized release blobs are immutable.")
    else:
        manifest = {
            "schema": "mcp_release_blob_v1",
            "blob_id": blob_id,
            "release_id": release_id,
            "component_role": component_role,
            "size": blob_size,
            "sha256": blob_sha256,
            "created_at": now_iso(),
            "finalized": False,
            "chunks": [],
        }
    chunks = _maintenance_blob_chunks(manifest)
    existing = next((row for row in chunks if int(row["offset"]) == chunk_offset), None)
    chunk_path = root / f"chunk-{chunk_offset:012d}.bin"
    if chunk_path.exists() and (chunk_path.is_symlink() or not chunk_path.is_file()):
        raise PermissionError("Release blob chunk identity is not an ordinary file.")
    if existing:
        if existing["size"] != len(body) or not hmac.compare_digest(existing["sha256"], chunk_sha256):
            raise RuntimeError("Conflicting bytes were supplied for an already-uploaded release blob offset.")
        if not chunk_path.is_file() or _sha256_file_stream(chunk_path) != (chunk_sha256, len(body)):
            raise RuntimeError("Existing release blob chunk failed integrity verification.")
    else:
        _atomic_binary_write(chunk_path, body, 0o600)
        chunks.append({"offset": chunk_offset, "size": len(body), "sha256": chunk_sha256})
        manifest["chunks"] = sorted(chunks, key=lambda row: int(row["offset"]))
        atomic_write_json(manifest_path, manifest, 0o600)
    return _maintenance_blob_summary(blob_id, manifest)


def _maintenance_finalize_blob(blob_id: str) -> dict[str, Any]:
    root = _maintenance_blob_root(blob_id)
    manifest = _maintenance_read_blob_manifest(blob_id)
    if manifest.get("finalized"):
        final_path = root / MAINTENANCE_BLOB_FILE
        if final_path.is_symlink() or not final_path.is_file():
            raise RuntimeError("Finalized release blob bytes are missing.")
        actual_sha, actual_size = _sha256_file_stream(final_path)
        if actual_sha != manifest.get("sha256") or actual_size != manifest.get("size"):
            raise RuntimeError("Finalized release blob failed whole-file integrity verification.")
        return _maintenance_blob_summary(blob_id, manifest)
    chunks = _maintenance_blob_chunks(manifest)
    expected_size = int(manifest.get("size") or 0)
    expected_sha = str(manifest.get("sha256") or "").casefold()
    cursor = 0
    digest = hashlib.sha256()
    final_path = root / MAINTENANCE_BLOB_FILE
    temp_path = root / f"{MAINTENANCE_BLOB_FILE}.{uuid.uuid4().hex}.tmp"
    try:
        with temp_path.open("wb") as output:
            for row in chunks:
                offset = int(row["offset"])
                size = int(row["size"])
                if offset != cursor:
                    raise RuntimeError("Release blob chunks must form one contiguous ordered byte stream before finalization.")
                chunk_path = root / f"chunk-{offset:012d}.bin"
                if chunk_path.is_symlink() or not chunk_path.is_file():
                    raise RuntimeError("Release blob chunk is missing or is not an ordinary file.")
                actual_sha, actual_size = _sha256_file_stream(chunk_path)
                if actual_sha != row["sha256"] or actual_size != size:
                    raise RuntimeError("Release blob chunk failed integrity verification.")
                data = chunk_path.read_bytes()
                output.write(data)
                digest.update(data)
                cursor += size
            output.flush()
            os.fsync(output.fileno())
        if cursor != expected_size or not hmac.compare_digest(digest.hexdigest(), expected_sha):
            raise RuntimeError("Release blob whole-file SHA or size does not match the declared identity.")
        os.chmod(temp_path, 0o600)
        os.replace(temp_path, final_path)
        manifest.update({"finalized": True, "finalized_at": now_iso(), "final_size": cursor, "final_sha256": digest.hexdigest()})
        atomic_write_json(root / MAINTENANCE_BLOB_MANIFEST, manifest, 0o600)
        return _maintenance_blob_summary(blob_id, manifest)
    finally:
        temp_path.unlink(missing_ok=True)


def _maintenance_blob_payload(blob_ref: str, release_id: str, component_role: str, expected_sha256: str) -> tuple[bytes, dict[str, Any]]:
    manifest = _maintenance_read_blob_manifest(blob_ref)
    if manifest.get("release_id") != release_id or manifest.get("component_role") != component_role or manifest.get("finalized") is not True:
        raise RuntimeError("Release component blob is not finalized for this release role.")
    final_path = _maintenance_blob_root(blob_ref) / MAINTENANCE_BLOB_FILE
    if final_path.is_symlink() or not final_path.is_file():
        raise RuntimeError("Release component blob bytes are unavailable.")
    body = final_path.read_bytes()
    actual = sha256_bytes(body)
    if actual != str(manifest.get("sha256") or "").casefold() or actual != expected_sha256 or len(body) != int(manifest.get("size") or 0):
        raise RuntimeError("Release component blob failed whole-file integrity verification.")
    return body, {"blob_ref": blob_ref, "blob_sha256": actual, "blob_size": len(body)}


def _maintenance_component_payload(components: list[dict[str, Any]] | None, release_id: str | None = None) -> tuple[list[dict[str, Any]], dict[str, bytes]]:
    rows: list[dict[str, Any]] = []
    bodies: dict[str, bytes] = {}
    seen: set[str] = set()
    for index, raw in enumerate(components or []):
        if not isinstance(raw, dict):
            raise ValueError(f"components[{index}] must be an object.")
        role = str(raw.get("role") or "")
        if role not in _MAINTENANCE_COMPONENT_FILES or role in seen:
            raise ValueError(f"components[{index}] has unsupported or duplicate role: {role!r}")
        seen.add(role)
        expected = str(raw.get("sha256") or "").casefold()
        if not re.fullmatch(r"[a-f0-9]{64}", expected):
            raise ValueError(f"components[{index}] requires an exact sha256.")
        encoded = raw.get("content_base64")
        blob_ref = raw.get("blob_ref")
        if isinstance(encoded, str) and blob_ref is not None:
            raise ValueError(f"components[{index}] may use content_base64 or blob_ref, not both.")
        blob_metadata: dict[str, Any] = {}
        if blob_ref is not None:
            if release_id is None:
                raise ValueError("blob_ref component transport requires a release identity.")
            body, blob_metadata = _maintenance_blob_payload(str(blob_ref), release_id, role, expected)
        else:
            if not isinstance(encoded, str):
                raise ValueError(f"components[{index}] requires content_base64 or finalized blob_ref.")
            try:
                body = base64.b64decode(encoded, validate=True)
            except Exception as exc:
                raise ValueError(f"components[{index}] content_base64 is invalid.") from exc
        if len(body) < 1 or len(body) > MAINTENANCE_MAX_COMPONENT_BYTES:
            raise ValueError(f"components[{index}] size must be 1..{MAINTENANCE_MAX_COMPONENT_BYTES} bytes.")
        actual = sha256_bytes(body)
        if not hmac.compare_digest(actual, expected):
            raise RuntimeError(f"components[{index}] SHA mismatch for role={role}.")
        row = {"role": role, "filename": _MAINTENANCE_COMPONENT_FILES[role], "sha256": actual, "size": len(body), "mode": 0o700 if role in _MAINTENANCE_EXECUTABLE_ROLES else 0o600, "transport": "blob" if blob_ref is not None else "inline"}
        row.update(blob_metadata)
        rows.append(row)
        bodies[role] = body
    if "executor" not in seen or "static_qualifier" not in seen or "release_qualifier" not in seen:
        raise ValueError("Prepared release requires executor, static_qualifier and release_qualifier components.")
    rows.sort(key=lambda row: str(row["role"]))
    return rows, bodies


def _maintenance_release_files_match(state: dict[str, Any], root: Path) -> bool:
    components = state.get("components")
    if not isinstance(components, dict):
        return False
    for role, row in components.items():
        if role not in _MAINTENANCE_COMPONENT_FILES or not isinstance(row, dict):
            return False
        candidate = root / str(row.get("filename") or "")
        if candidate.is_symlink() or not candidate.is_file():
            return False
        sha, size = _sha256_file_stream(candidate)
        if sha != row.get("sha256") or size != row.get("size"):
            return False
    return True


def _maintenance_pid_live(state: dict[str, Any]) -> bool:
    try:
        pid = int(state.get("qualification_pid") or 0)
    except Exception:
        return False
    if pid <= 0:
        return False
    command = pid_command(pid)
    if not command or "qualification-runner.py" not in command:
        return False
    recorded = str(state.get("qualification_process_start_identity") or "")
    return not recorded or pid_start_identity(pid) == recorded


def _maintenance_finalize_qualification(release_id: str, state: dict[str, Any]) -> dict[str, Any]:
    if state.get("status") != "qualifying" or _maintenance_pid_live(state):
        return state
    root = _maintenance_release_root(release_id)
    exit_path = root / MAINTENANCE_QUALIFICATION_EXIT
    result_path = root / MAINTENANCE_QUALIFICATION_RESULT
    result: dict[str, Any] = {}
    exit_record: dict[str, Any] = {}
    try:
        if result_path.is_file() and not result_path.is_symlink():
            loaded = json.loads(result_path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                result = loaded
        if exit_path.is_file() and not exit_path.is_symlink():
            loaded = json.loads(exit_path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                exit_record = loaded
    except Exception:
        pass
    expected_executor = ((state.get("components") or {}).get("executor") or {}).get("sha256")
    passed = exit_record.get("exit_code") == 0 and result.get("qualification") == "PASS" and result.get("candidate_source_sha256") == expected_executor
    state["status"] = "qualified" if passed else "qualification_failed"
    state["qualification_completed_at"] = now_iso()
    state["qualification"] = {
        "passed": passed,
        "exit_code": exit_record.get("exit_code"),
        "candidate_source_sha256": result.get("candidate_source_sha256"),
        "tool_count": result.get("tool_count"),
        "summary": sanitize_text(str(result.get("summary") or ""))[:4000],
        "log_sha256": _sha256_file_stream(root / "qualification.log")[0] if (root / "qualification.log").is_file() else None,
    }
    atomic_write_json(_maintenance_release_state_path(release_id), state)
    return state


def _maintenance_running_operation_receipts() -> list[str]:
    rows: list[str] = []
    for path in OPERATIONS.glob("*.json"):
        try:
            receipt = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if isinstance(receipt, dict) and receipt.get("status") == "running":
            rows.append(str(receipt.get("operation_id") or path.stem))
    return sorted(rows)


def _maintenance_quiescence() -> dict[str, Any]:
    lease = public_lease_view(read_active_lease_raw())
    active_validation, _ = _validation_state_rows()
    local_processes = [row for row in _public_local_process_rows() if row.get("status") == "running"]
    recovery = executor_recovery_status()
    running_ops = _maintenance_running_operation_receipts()
    safe = not lease.get("active") and active_validation is None and not local_processes and recovery.get("mutation_safe") is True and not running_ops
    return {
        "safe": safe,
        "lease_active": bool(lease.get("active")),
        "active_validation_run_id": active_validation.get("run_id") if isinstance(active_validation, dict) else None,
        "running_local_process_ids": [row.get("run_id") for row in local_processes],
        "incomplete_file_journals": recovery.get("incomplete_file_journals", []),
        "stale_or_owned_processes": recovery.get("stale_or_owned_processes", []),
        "running_operation_receipts": running_ops,
    }


@tool(read_only=True)
def maintenance_status(max_bytes: ToolOutputBytes = 120_000) -> dict[str, Any]:
    """Admin-only durable control-plane/release handoff status. It contains no credential values."""
    require_admin_scope()
    releases: list[dict[str, Any]] = []
    for root in sorted(PREPARED_RELEASE_ROOT.iterdir() if PREPARED_RELEASE_ROOT.is_dir() else []):
        if not root.is_dir() or root.is_symlink():
            continue
        try:
            state = _maintenance_finalize_qualification(root.name, _maintenance_read_release_state(root.name))
        except Exception:
            continue
        releases.append({k: state.get(k) for k in ("release_id", "target_version", "status", "release_digest", "staged_at", "qualification_started_at", "qualification_completed_at", "armed_at")})
    armed = None
    if ARMED_RELEASE_FILE.is_file() and not ARMED_RELEASE_FILE.is_symlink():
        try:
            armed = json.loads(ARMED_RELEASE_FILE.read_text(encoding="utf-8"))
        except Exception:
            armed = {"unreadable": True}
    blobs: list[dict[str, Any]] = []
    for blob_root in sorted(MAINTENANCE_BLOB_ROOT.iterdir() if MAINTENANCE_BLOB_ROOT.is_dir() else []):
        if not blob_root.is_dir() or blob_root.is_symlink():
            continue
        try:
            blobs.append(_maintenance_blob_summary(blob_root.name, _maintenance_read_blob_manifest(blob_root.name)))
        except Exception:
            blobs.append({"blob_id": blob_root.name, "status": "unreadable"})
    controls = {name: _maintenance_file_metadata(path) for name, path in _maintenance_control_targets().items()}
    response = {
        "executor_version": EXECUTOR_VERSION,
        "admin_scope_verified": True,
        "admin_token_configured": bool(ADMIN_BEARER_TOKEN),
        "maintenance_root": str(MAINTENANCE_ROOT),
        "control_targets": controls,
        "prepared_releases": releases,
        "armed_release": armed,
        "release_blobs": blobs,
        "quiescence": _maintenance_quiescence(),
        "cross_chat_resume": {"supported": True, "authority": "admin bearer credential + durable release state", "conversation_id_required": False},
        "arbitrary_shell_exposed": False,
        "arbitrary_home_access_exposed": False,
        "credential_values_exposed": False,
    }
    return enforce_structured_output(response, max_bytes)


@tool(read_only=True, idempotent=True)
def maintenance_file_inspect(
    target: MaintenanceInspectTarget,
    action: MaintenanceInspectAction = "stat",
    offset: Annotated[int, Field(ge=0)] = 0,
    length: Annotated[int, Field(ge=1, le=MAX_GENERIC_READ_BYTES)] = 65536,
) -> dict[str, Any]:
    """Admin-only bounded inspection of explicit MCP control-plane files. No arbitrary caller path exists."""
    require_admin_scope()
    path = _maintenance_control_targets()[target]
    if is_secret_name(path):
        raise PermissionError("Credential/token files are never exposed by maintenance inspection.")
    meta = _maintenance_file_metadata(path)
    if action == "stat":
        return {"target": target, **meta}
    if not path.is_file() or path.is_symlink():
        raise FileNotFoundError(f"Maintenance target is not an ordinary file: {target}")
    if action == "hash":
        return {"target": target, **meta}
    size = path.stat().st_size
    if offset > size:
        raise ValueError("offset exceeds file size.")
    with path.open("rb") as fh:
        fh.seek(offset)
        data = fh.read(length)
    if action == "read_text":
        text = sanitize_text(data.decode("utf-8", errors="replace"))
        return {"target": target, "path": str(path), "offset": offset, "returned_bytes": len(data), "file_size": size, "eof": offset + len(data) >= size, "text": text, "sha256_of_returned_bytes": sha256_bytes(data), "credential_values_exposed": False}
    if target in {"executor_log", "tunnel_log"}:
        raise PermissionError("Raw maintenance log bytes are not exposed; use read_text for credential-redacted diagnostics.")
    return {"target": target, "path": str(path), "offset": offset, "returned_bytes": len(data), "file_size": size, "eof": offset + len(data) >= size, "base64": base64.b64encode(data).decode("ascii"), "sha256_of_returned_bytes": sha256_bytes(data)}


@tool(read_only=False, destructive=True, idempotent=True)
def maintenance_release(
    operation_id: UUIDString,
    release_id: str,
    action: MaintenanceReleaseAction,
    target_version: str | None = None,
    expected_current_source_sha256: Sha256String | None = None,
    expected_current_launcher_sha256: Sha256String | None = None,
    components: list[dict[str, Any]] | None = None,
    dry_run: bool = True,
    reviewed_plan_digest: Sha256String | None = None,
    expected_release_digest: Sha256String | None = None,
    component_role: str | None = None,
    blob_id: str | None = None,
    blob_size: int | None = None,
    blob_sha256: Sha256String | None = None,
    chunk_offset: int | None = None,
    chunk_sha256: Sha256String | None = None,
    chunk_base64: str | None = None,
    blob_ref: str | None = None,
) -> dict[str, Any]:
    """Admin-only immutable release staging, resumable blob ingestion, qualification and arm/discard controls. It never activates a release."""
    require_admin_scope()
    _require_uuid(operation_id, "operation_id")
    root = _maintenance_release_root(release_id)
    state_path = _maintenance_release_state_path(release_id)
    if action == "upload_chunk":
        if not all(value is not None for value in (component_role, blob_id, blob_size, blob_sha256, chunk_offset, chunk_sha256, chunk_base64)):
            raise ValueError("upload_chunk requires component_role, blob_id, blob_size, blob_sha256, chunk_offset, chunk_sha256 and chunk_base64.")
        if dry_run:
            # Validate the transport envelope without creating durable bytes.
            body = base64.b64decode(str(chunk_base64), validate=True)
            if not body or len(body) > MAINTENANCE_MAX_BLOB_CHUNK_BYTES:
                raise ValueError(f"Each release blob chunk must be 1..{MAINTENANCE_MAX_BLOB_CHUNK_BYTES} bytes.")
            if not hmac.compare_digest(sha256_bytes(body), str(chunk_sha256).casefold()):
                raise RuntimeError("Release blob chunk SHA mismatch.")
            if int(chunk_offset) < 0 or int(chunk_offset) + len(body) > int(blob_size):
                raise ValueError("Release blob chunk exceeds the declared blob size.")
            return {"release_id": release_id, "component_role": component_role, "blob_id": blob_id, "chunk_offset": chunk_offset, "chunk_size": len(body), "blob_size": blob_size, "blob_sha256": str(blob_sha256).casefold(), "chunk_sha256": str(chunk_sha256).casefold(), "transport": "immutable_chunk", "live_files_mutated": False}
        summary = _maintenance_upload_blob_chunk(release_id, str(component_role), str(blob_id), int(blob_size), str(blob_sha256), int(chunk_offset), str(chunk_sha256), str(chunk_base64))
        return {**summary, "transport": "immutable_chunk", "live_files_mutated": False}
    if action == "finalize_blob":
        if not blob_ref:
            raise ValueError("finalize_blob requires blob_ref.")
        if dry_run:
            manifest = _maintenance_read_blob_manifest(blob_ref)
            if manifest.get("release_id") != release_id:
                raise RuntimeError("Release blob belongs to a different release identity.")
            return {**_maintenance_blob_summary(blob_ref, manifest), "transport": "immutable_blob", "would_finalize": not bool(manifest.get("finalized")), "live_files_mutated": False}
        summary = _maintenance_finalize_blob(blob_ref)
        if summary.get("release_id") != release_id:
            raise RuntimeError("Release blob belongs to a different release identity.")
        return {**summary, "transport": "immutable_blob", "live_files_mutated": False}
    if action == "status":
        state = _maintenance_finalize_qualification(release_id, _maintenance_read_release_state(release_id))
        state["files_match"] = _maintenance_release_files_match(state, root)
        state["quiescence"] = _maintenance_quiescence()
        return enforce_structured_output(state, MAX_TOOL_OUTPUT_BYTES)
    if action == "stage":
        if not isinstance(target_version, str) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9._-]+)?", target_version):
            raise ValueError("target_version must be a semantic version string.")
        if not expected_current_source_sha256 or not expected_current_launcher_sha256:
            raise ValueError("stage requires exact current source and launcher SHA-256 baselines.")
        rows, bodies = _maintenance_component_payload(components, release_id)
        identity = {"release_id": release_id, "target_version": target_version, "expected_current_source_sha256": expected_current_source_sha256, "expected_current_launcher_sha256": expected_current_launcher_sha256, "components": {row["role"]: row for row in rows}}
        release_digest = _maintenance_release_identity_digest(identity)
        plan_digest = sha256_text(json.dumps({"action": "stage", **identity}, sort_keys=True, separators=(",", ":")))
        if dry_run:
            return {"release_id": release_id, "target_version": target_version, "release_digest": release_digest, "reviewed_plan_digest": plan_digest, "component_count": len(rows), "live_files_mutated": False}
        if not reviewed_plan_digest or not hmac.compare_digest(plan_digest, reviewed_plan_digest.casefold()):
            raise RuntimeError("Reviewed maintenance release plan digest mismatch.")
        current_source = _maintenance_control_targets()["executor_source"]
        current_launcher = _maintenance_control_targets()["main_launcher"]
        if not current_source.is_file() or sha256_bytes(current_source.read_bytes()) != expected_current_source_sha256:
            raise RuntimeError("Live executor source differs from staged release baseline.")
        if not current_launcher.is_file() or sha256_bytes(current_launcher.read_bytes()) != expected_current_launcher_sha256:
            raise RuntimeError("Live launcher differs from staged release baseline.")
        if root.exists():
            prior = _maintenance_read_release_state(release_id)
            if prior.get("release_digest") == release_digest and _maintenance_release_files_match(prior, root):
                return prior
            raise FileExistsError("Prepared release_id already exists with different or incomplete identity.")
        root.mkdir(parents=True, mode=0o700)
        try:
            component_map: dict[str, Any] = {}
            for row in rows:
                role = str(row["role"])
                target = root / str(row["filename"])
                _atomic_binary_write(target, bodies[role], int(row["mode"]))
                component_map[role] = row
            state = {**identity, "components": component_map, "release_digest": release_digest, "status": "staged", "staged_at": now_iso(), "qualification": None, "armed_at": None, "live_files_mutated": False, "conversation_id_bound": False}
            atomic_write_json(state_path, state)
            return state
        except Exception:
            shutil.rmtree(root, ignore_errors=True)
            raise
    state = _maintenance_finalize_qualification(release_id, _maintenance_read_release_state(release_id))
    release_digest = str(state.get("release_digest") or "")
    if not expected_release_digest or not hmac.compare_digest(release_digest, expected_release_digest.casefold()):
        raise RuntimeError("Prepared release digest precondition mismatch.")
    if not _maintenance_release_files_match(state, root):
        raise RuntimeError("Prepared release component identity changed.")
    if action == "qualify":
        if dry_run:
            return {"release_id": release_id, "release_digest": release_digest, "status": state.get("status"), "would_start_qualification": state.get("status") in {"staged", "qualification_failed"}, "live_files_mutated": False}
        if state.get("status") == "qualifying" and _maintenance_pid_live(state):
            return state
        if state.get("status") == "qualified":
            return state
        executor = root / _MAINTENANCE_COMPONENT_FILES["executor"]
        staticq = root / _MAINTENANCE_COMPONENT_FILES["static_qualifier"]
        releaseq = root / _MAINTENANCE_COMPONENT_FILES["release_qualifier"]
        py_compile = subprocess.run([sys.executable, "-m", "py_compile", str(executor)], capture_output=True, text=True, check=False, timeout=60)
        if py_compile.returncode != 0:
            raise RuntimeError("Prepared executor py_compile failed: " + sanitize_text((py_compile.stdout or "") + (py_compile.stderr or ""))[-4000:])
        static = subprocess.run([sys.executable, str(staticq), str(executor)], capture_output=True, text=True, check=False, timeout=120)
        if static.returncode != 0:
            raise RuntimeError("Prepared executor static qualification failed: " + sanitize_text((static.stdout or "") + (static.stderr or ""))[-8000:])
        sandbox = Path("/usr/bin/sandbox-exec")
        if not sandbox.is_file():
            raise RuntimeError("Maintenance qualification requires /usr/bin/sandbox-exec.")
        runner = root / "qualification-runner.py"
        runner.write_text('import json,subprocess,sys\nfrom pathlib import Path\nroot=Path(sys.argv[1])\nq=root/"qualify_release.py"\np=subprocess.run([sys.executable,str(q),"--prepared-slot",str(root)],cwd=root)\n(root/"qualification-exit.json").write_text(json.dumps({"exit_code":p.returncode})+"\\n")\nraise SystemExit(p.returncode)\n', encoding="utf-8")
        runner.chmod(0o700)
        profile = root / "qualification.sb"
        home = Path.home().resolve()
        # Bind qualification access to the interpreter actually executing this server.
        # BRIDGE_ROOT is overrideable for isolated qualification and need not own the venv.
        venv = Path(sys.prefix).resolve()
        profile.write_text("\n".join([
            "(version 1)", "(allow default)", "(deny network*)",
            '(allow network-bind (local ip "localhost:*"))',
            '(allow network-inbound (local ip "localhost:*"))',
            '(allow network-outbound (remote ip "localhost:*"))',
            "(deny file-write*)",
            f'(deny file-read* (subpath "{_sandbox_escape(home)}"))',
            '(allow file-read-metadata)',
            f'(allow file-read* (subpath "{_sandbox_escape(root)}"))',
            f'(allow file-write* (subpath "{_sandbox_escape(root)}"))',
            f'(allow file-read* (subpath "{_sandbox_escape(venv)}"))',
            '(allow file-write* (literal "/dev/null"))',
            '(deny process-exec (literal "/usr/bin/security"))',
            '(deny mach-lookup (global-name "com.apple.securityd"))',
            '(deny mach-lookup (global-name "com.apple.SecurityServer"))',
        ]) + "\n", encoding="utf-8")
        profile.chmod(0o600)
        for stale in (root / MAINTENANCE_QUALIFICATION_RESULT, root / MAINTENANCE_QUALIFICATION_EXIT):
            stale.unlink(missing_ok=True)
        log = (root / "qualification.log").open("ab", buffering=0)
        env = {k: v for k, v in os.environ.items() if k not in {BEARER_TOKEN_ENV, ADMIN_BEARER_TOKEN_ENV} and not k.startswith("LEDGERFORGE_PRIVATE_") and not k.startswith("LEDGERFORGE_AXIS_CARD_PRIVATE_")}
        env["TMPDIR"] = str(root / "tmp")
        (root / "tmp").mkdir(exist_ok=True, mode=0o700)
        env[BRIDGE_ROOT_ENV] = str(root / "qualification-bridge")
        proc = subprocess.Popen([str(sandbox), "-f", str(profile), sys.executable, str(runner), str(root)], cwd=root, stdout=log, stderr=subprocess.STDOUT, env=env, start_new_session=True)
        log.close()
        state["status"] = "qualifying"
        state["qualification_started_at"] = now_iso()
        state["qualification_pid"] = proc.pid
        state["qualification_process_start_identity"] = pid_start_identity(proc.pid)
        atomic_write_json(state_path, state)
        return state
    if action == "arm":
        component_roles = set((state.get("components") or {}).keys())
        missing_arm_roles = sorted(_MAINTENANCE_REQUIRED_ARM_ROLES - component_roles)
        if dry_run:
            return {"release_id": release_id, "release_digest": release_digest, "status": state.get("status"), "quiescence": _maintenance_quiescence(), "complete_component_set": not missing_arm_roles, "missing_activation_roles": missing_arm_roles, "would_arm": state.get("status") == "qualified" and not missing_arm_roles, "live_files_mutated": False}
        if missing_arm_roles:
            raise RuntimeError("Prepared release lacks the complete activation component set: " + ", ".join(missing_arm_roles))
        if state.get("status") != "qualified" or not isinstance(state.get("qualification"), dict) or state["qualification"].get("passed") is not True:
            raise RuntimeError("Only a successfully qualified prepared release may be armed.")
        current_source = _maintenance_control_targets()["executor_source"]
        current_launcher = _maintenance_control_targets()["main_launcher"]
        if sha256_bytes(current_source.read_bytes()) != state.get("expected_current_source_sha256"):
            raise RuntimeError("Live executor source changed after release staging.")
        if sha256_bytes(current_launcher.read_bytes()) != state.get("expected_current_launcher_sha256"):
            raise RuntimeError("Live launcher changed after release staging.")
        quiescence = _maintenance_quiescence()
        if quiescence.get("safe") is not True:
            raise RuntimeError("Prepared release cannot be armed while executor durable state is not quiescent: " + json.dumps(quiescence, sort_keys=True))
        armed = {"release_id": release_id, "release_digest": release_digest, "target_version": state.get("target_version"), "prepared_root": str(root), "armed_at": now_iso(), "manual_activation_required": True}
        atomic_write_json(ARMED_RELEASE_FILE, armed)
        state["status"] = "armed"
        state["armed_at"] = armed["armed_at"]
        atomic_write_json(state_path, state)
        return {**state, "manual_activation_required": True, "activation_via_mcp": False}
    if action == "discard":
        if dry_run:
            return {"release_id": release_id, "release_digest": release_digest, "would_discard": state.get("status") not in {"qualifying", "armed"}, "live_files_mutated": False}
        if state.get("status") in {"qualifying", "armed"}:
            raise RuntimeError("A qualifying or armed release may not be discarded.")
        shutil.rmtree(root)
        return {"release_id": release_id, "release_digest": release_digest, "discarded": True, "exists_after": root.exists(), "live_files_mutated": False}
    raise ValueError("Unsupported maintenance_release action.")

# ==========================================================================
# HTTP transport
# ==========================================================================

MCP_PATH = os.environ.get(MCP_PATH_ENV, "").strip()
if not MCP_PATH:
    raise RuntimeError(f"{MCP_PATH_ENV} is not set.")
if not MCP_PATH.startswith("/mcp_") or "/" in MCP_PATH[1:]:
    raise RuntimeError(f"{MCP_PATH_ENV} must be one /mcp_* path component.")
PUBLIC_HOST = os.environ.get(PUBLIC_HOST_ENV, "").strip()
allowed_hosts = ["127.0.0.1:*", "localhost:*", "[::1]:*"]
allowed_origins = ["http://127.0.0.1:*", "http://localhost:*", "http://[::1]:*"]
if PUBLIC_HOST:
    allowed_hosts.extend([PUBLIC_HOST, f"{PUBLIC_HOST}:*"])
    allowed_origins.extend([f"https://{PUBLIC_HOST}", f"https://{PUBLIC_HOST}:*"])
transport_security = TransportSecuritySettings(
    enable_dns_rebinding_protection=True,
    allowed_hosts=allowed_hosts,
    allowed_origins=allowed_origins,
)


if __name__ == "__main__":
    port = int(os.environ.get(PORT_ENV, "8768"))
    mcp.run(
        transport="streamable-http",
        host="127.0.0.1",
        port=port,
        streamable_http_path=MCP_PATH,
        stateless_http=False,
        json_response=True,
        max_request_body_size=16_000_000,
        transport_security=transport_security,
    )
