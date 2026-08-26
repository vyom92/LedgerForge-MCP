#!/usr/bin/env python3
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ADMIN_VERSION = "mcp-2.6.2-owner-recovery-r1"
ROOT = (Path.home() / "ledgerforge-mcp-prototype").resolve()
STATE_PTR = ROOT / ".executor-v2.1-state-root"
EXECUTOR_SOURCE = ROOT / "executor_v2_1.py"
EXECUTOR_SOURCE_ALIASES = frozenset({
    str(EXECUTOR_SOURCE),
    str(Path.home() / "ledgerforge-mcp-prototype" / "executor_v2_1.py"),
})
PORT = 8768
AUDIT_DIR = ROOT / "mcp-owner-recovery-audit"
BACKUP_DIR = ROOT / "mcp-owner-recovery-backups"
LOCK_FILE = ROOT / ".mcp-owner-recovery.lock"
DESKTOP_LAUNCHER = Path.home() / "Desktop" / "LedgerForge MCP.command"

SAFE_STALE_ACTIONS = {
    "acquire_execution_lease",
    "heartbeat_execution_lease",
    "resume_execution_lease",
    "release_execution_lease",
}
PROCESS_CLASSES = {"xcodebuild", "repo-task", "runtime", "local-process"}

class RecoveryError(RuntimeError):
    pass

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def sha_file(path: Path) -> str | None:
    return sha256_bytes(path.read_bytes()) if path.is_file() else None

def atomic_write_json(path: Path, value: dict[str, Any], mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + f".{os.getpid()}.{time.time_ns()}.tmp")
    data = json.dumps(value, indent=2, sort_keys=True).encode("utf-8")
    with temp.open("wb") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())
    os.chmod(temp, mode)
    os.replace(temp, path)
    try:
        fd = os.open(str(path.parent), os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError:
        pass

def read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise
    except Exception as exc:
        raise RecoveryError(f"Invalid JSON state: {path}: {type(exc).__name__}: {exc}") from exc
    if not isinstance(value, dict):
        raise RecoveryError(f"State is not a JSON object: {path}")
    return value

def state_root(override: str | None = None) -> Path:
    if override:
        root = Path(override).expanduser().resolve()
    else:
        if not STATE_PTR.is_file():
            raise RecoveryError(
                f"State-root pointer missing: {STATE_PTR}. "
                "Owner may supply --state-root with an exact production state root under the MCP bridge root."
            )
        raw = STATE_PTR.read_text(encoding="utf-8").strip()
        if not raw:
            raise RecoveryError("State-root pointer is empty.")
        root = Path(raw).expanduser().resolve()
    try:
        root.relative_to(ROOT)
    except ValueError as exc:
        raise RecoveryError(f"State root escapes MCP bridge root: {root}") from exc
    if not root.name.startswith(".executor-runs-v2_1-production-"):
        raise RecoveryError(f"Refusing non-production state-root namespace: {root.name}")
    if not root.is_dir():
        raise RecoveryError(f"Production state root missing: {root}")
    return root

def paths(sr: Path) -> dict[str, Path]:
    return {
        "operations": sr / "operations",
        "leases": sr / "leases",
        "lease": sr / "leases" / "active.json",
        "journals": sr / "journals",
        "processes": sr / "processes",
    }

def process_command(pid: int) -> str:
    p = subprocess.run(
        ["ps", "-p", str(pid), "-o", "command="],
        capture_output=True, text=True, check=False, timeout=5,
    )
    return p.stdout.strip() if p.returncode == 0 else ""

def process_start(pid: int) -> str:
    p = subprocess.run(
        ["ps", "-p", str(pid), "-o", "lstart="],
        capture_output=True, text=True, check=False, timeout=5,
    )
    return p.stdout.strip() if p.returncode == 0 else ""

def pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except (ProcessLookupError, PermissionError):
        return False

def executor_script_identity(command: str) -> str | None:
    """Return the exact accepted executor script spelling in a process argv.

    The launcher is allowed to retain the historical compatibility-symlink spelling,
    but no arbitrary Python process or similarly named script is accepted.  The
    lexical spelling must be one of the two known paths and its resolved target must
    be the canonical executor source.
    """
    try:
        argv = shlex.split(command)
    except ValueError:
        return None
    for token in argv[1:]:
        if token not in EXECUTOR_SOURCE_ALIASES:
            continue
        try:
            if Path(token).resolve(strict=False) == EXECUTOR_SOURCE:
                return token
        except OSError:
            continue
    return None

def executor_pids() -> list[int]:
    result: list[int] = []
    p = subprocess.run(
        ["ps", "-axo", "pid=,command="],
        capture_output=True, text=True, check=False, timeout=10,
    )
    for line in p.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        head, _, cmd = line.partition(" ")
        if head.isdigit() and executor_script_identity(cmd) is not None:
            result.append(int(head))
    return sorted(set(result))

def listener_pids() -> list[int]:
    p = subprocess.run(
        ["lsof", f"-tiTCP:{PORT}", "-sTCP:LISTEN"],
        capture_output=True, text=True, check=False, timeout=5,
    )
    return sorted({int(v) for v in p.stdout.split() if v.isdigit()})

def process_record_live(record: dict[str, Any]) -> bool:
    try:
        pid = int(record["pid"])
    except Exception:
        return False
    if not pid_alive(pid):
        return False
    recorded_start = str(record.get("process_start_identity") or "")
    if recorded_start and process_start(pid) != recorded_start:
        return False
    cmd = process_command(pid)
    kind = str(record.get("command_class") or "")
    if kind == "xcodebuild":
        return "xcodebuild" in cmd
    if kind == "repo-task":
        return "LedgerForge" in cmd or "build_and_run.sh" in cmd or "validate.sh" in cmd
    if kind == "runtime":
        return "LedgerForge.app/Contents/MacOS/LedgerForge" in cmd
    if kind == "local-process":
        resolved = str(record.get("resolved_executable") or "")
        return bool(resolved) and resolved in cmd
    return False

def parse_iso(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))

def lease_expired(lease: dict[str, Any]) -> bool:
    try:
        return datetime.now(timezone.utc) >= parse_iso(str(lease["expires_at"]))
    except Exception:
        return True

def public_lease(lease: dict[str, Any] | None) -> dict[str, Any] | None:
    if not lease:
        return None
    return {
        "active": lease.get("status") == "active" and not lease_expired(lease),
        "lease_id": lease.get("lease_id"),
        "execution_id": lease.get("execution_id"),
        "authorization_digest": lease.get("authorization_digest"),
        "owner_label": lease.get("owner_label"),
        "status": lease.get("status"),
        "acquired_at": lease.get("acquired_at"),
        "heartbeat_at": lease.get("heartbeat_at"),
        "expires_at": lease.get("expires_at"),
        "sequence": lease.get("sequence"),
        "executor_boot_id": lease.get("executor_boot_id"),
        "token_exposed": False,
    }

def scan_state(sr: Path) -> dict[str, Any]:
    p = paths(sr)
    lease = None
    lease_error = None
    if p["lease"].exists():
        try:
            lease = read_json(p["lease"])
        except Exception as exc:
            lease_error = str(exc)

    incomplete_journals: list[str] = []
    if p["journals"].is_dir():
        for root in sorted(p["journals"].iterdir()):
            manifest = root / "manifest.json"
            if not root.is_dir() or not manifest.is_file():
                continue
            try:
                obj = read_json(manifest)
            except Exception:
                incomplete_journals.append(root.name + ":unreadable")
                continue
            if obj.get("status") not in {"completed", "rolled_back"}:
                incomplete_journals.append(root.name)

    running_operations: list[dict[str, Any]] = []
    if p["operations"].is_dir():
        for f in sorted(p["operations"].glob("*.json")):
            try:
                obj = read_json(f)
            except Exception:
                continue
            if obj.get("status") == "running":
                running_operations.append({
                    "operation_id": str(obj.get("operation_id") or f.stem),
                    "action": str(obj.get("action") or "unknown"),
                    "lease_id": obj.get("lease_id"),
                })

    running_validations: list[dict[str, Any]] = []
    for f in sorted(sr.glob("*.json")):
        try:
            obj = read_json(f)
        except Exception:
            continue
        if obj.get("run_id") and obj.get("status") == "running":
            running_validations.append({
                "run_id": str(obj.get("run_id")),
                "lease_id": obj.get("lease_id"),
                "operation": obj.get("operation"),
            })

    process_records_internal: list[dict[str, Any]] = []
    if p["processes"].is_dir():
        for f in sorted(p["processes"].glob("*.json")):
            try:
                obj = read_json(f)
            except Exception:
                continue
            if obj.get("status") == "running":
                process_records_internal.append({
                    "run_id": obj.get("run_id") or f.stem,
                    "pid": obj.get("pid"),
                    "pgid": obj.get("pgid"),
                    "command_class": obj.get("command_class"),
                    "alive_and_owned": process_record_live(obj),
                    "_path": str(f),
                })

    return {
        "admin_version": ADMIN_VERSION,
        "state_root": str(sr),
        "executor_source_sha256": sha_file(EXECUTOR_SOURCE),
        "executor_pids": executor_pids(),
        "listener_pids": listener_pids(),
        "lease": public_lease(lease) if isinstance(lease, dict) else None,
        "lease_error": lease_error,
        "incomplete_journals": incomplete_journals,
        "running_operations": running_operations,
        "running_validations": running_validations,
        "process_records": [{k: v for k, v in row.items() if k != "_path"} for row in process_records_internal],
    }

def ensure_executor_stopped() -> None:
    ep = executor_pids()
    lp = listener_pids()
    if ep or lp:
        raise RecoveryError(
            f"Executor must be stopped before offline owner recovery. executor_pids={ep} listener_pids={lp}"
        )

def stop_executor(*, kill_after_timeout: bool = False, all_exact: bool = False) -> dict[str, Any]:
    ep = executor_pids()
    lp = listener_pids()
    if not ep and not lp:
        return {"stopped": True, "already_stopped": True}
    if not ep and lp:
        raise RecoveryError(f"Port {PORT} is occupied by a non-executor process: {lp}")
    if len(ep) > 1 and not all_exact:
        raise RecoveryError(
            f"Multiple exact production executor processes detected: {ep}. "
            "Use --all-exact-executors only for explicit owner break-glass quiesce."
        )
    if any(pid not in ep for pid in lp):
        raise RecoveryError(f"Port {PORT} listener is not one of the exact executor processes: listeners={lp} executors={ep}")

    stopped = []
    for pid in ep:
        start = process_start(pid)
        cmd = process_command(pid)
        if executor_script_identity(cmd) is None:
            raise RecoveryError(f"Executor PID {pid} identity changed before stop.")
        os.kill(pid, signal.SIGTERM)
        deadline = time.monotonic() + 8.0
        while time.monotonic() < deadline and pid_alive(pid):
            time.sleep(0.2)
        used_kill = False
        if pid_alive(pid):
            if not kill_after_timeout:
                raise RecoveryError(
                    f"Executor PID {pid} did not terminate after SIGTERM. "
                    "Re-run with --kill-after-timeout only for explicit break-glass termination."
                )
            if process_start(pid) != start or executor_script_identity(process_command(pid)) is None:
                raise RecoveryError(f"Executor PID {pid} identity changed; refusing SIGKILL.")
            os.kill(pid, signal.SIGKILL)
            used_kill = True
            deadline = time.monotonic() + 3.0
            while time.monotonic() < deadline and pid_alive(pid):
                time.sleep(0.1)
        if pid_alive(pid):
            raise RecoveryError(f"Executor PID {pid} remains alive.")
        stopped.append({"pid": pid, "sigkill_used": used_kill})
    if listener_pids():
        raise RecoveryError(f"Port {PORT} remains occupied after executor stop: {listener_pids()}")
    return {"stopped": True, "processes": stopped}

def terminate_owned_processes(sr: Path, *, kill_after_timeout: bool = False) -> list[dict[str, Any]]:
    p = paths(sr)
    results: list[dict[str, Any]] = []
    if not p["processes"].is_dir():
        return results
    for f in sorted(p["processes"].glob("*.json")):
        try:
            obj = read_json(f)
        except Exception:
            continue
        if obj.get("status") != "running" or not process_record_live(obj):
            continue
        kind = str(obj.get("command_class") or "")
        if kind not in PROCESS_CLASSES:
            raise RecoveryError(f"Unknown live executor-owned process class in {f.name}: {kind}")
        pid = int(obj["pid"])
        pgid = obj.get("pgid")
        start = process_start(pid)
        target = -int(pgid) if isinstance(pgid, int) and pgid > 0 else pid
        os.kill(target, signal.SIGTERM)
        deadline = time.monotonic() + 8.0
        while time.monotonic() < deadline and process_record_live(obj):
            time.sleep(0.2)
        used_kill = False
        if process_record_live(obj):
            if not kill_after_timeout:
                raise RecoveryError(
                    f"Owned {kind} process PID {pid} did not stop after SIGTERM. Use --kill-after-timeout for explicit break-glass termination."
                )
            if process_start(pid) != start or not process_record_live(obj):
                raise RecoveryError("Owned process identity changed; refusing SIGKILL.")
            os.kill(target, signal.SIGKILL)
            used_kill = True
            deadline = time.monotonic() + 3.0
            while time.monotonic() < deadline and process_record_live(obj):
                time.sleep(0.1)
        if process_record_live(obj):
            raise RecoveryError(f"Owned process PID {pid} remains alive.")
        obj["status"] = "owner_recovery_quiesced"
        obj["completed_at"] = now_iso()
        obj["owner_recovery_version"] = ADMIN_VERSION
        atomic_write_json(f, obj)
        results.append({"run_id": obj.get("run_id"), "pid": pid, "command_class": kind, "sigkill_used": used_kill})
    return results

def offline_reconcile_stale_state(sr: Path, *, allow_stale_nonjournal_ops: bool = False) -> dict[str, Any]:
    ensure_executor_stopped()
    state = scan_state(sr)
    if state["incomplete_journals"]:
        raise RecoveryError(
            "Incomplete file-operation journal exists. Owner recovery will not unlock a potentially half-mutated repository."
        )
    if any(row["alive_and_owned"] for row in state["process_records"]):
        raise RecoveryError("Live executor-owned process remains; quiesce it before release.")
    unsafe_ops = [
        row for row in state["running_operations"]
        if str(row.get("action") or "") not in SAFE_STALE_ACTIONS
    ]
    if unsafe_ops and not allow_stale_nonjournal_ops:
        rendered = ", ".join(f"{row.get('action')}:{row.get('operation_id')}" for row in unsafe_ops[:8])
        raise RecoveryError(
            "Stale non-journal mutating operation receipts exist. "
            "Safe owner recovery refuses to guess whether their effects completed. "
            "After an independent state review, --allow-stale-nonjournal-ops may be used as explicit owner break-glass. "
            f"running={rendered}"
        )

    p = paths(sr)
    abandoned_ops: list[str] = []
    if p["operations"].is_dir():
        for f in sorted(p["operations"].glob("*.json")):
            try:
                obj = read_json(f)
            except Exception:
                continue
            if obj.get("status") != "running":
                continue
            action = str(obj.get("action") or "unknown")
            obj["status"] = "abandoned_by_owner_recovery"
            obj["completed_at"] = now_iso()
            obj["owner_recovery_version"] = ADMIN_VERSION
            if action not in SAFE_STALE_ACTIONS:
                obj["owner_recovery_note"] = "executor stopped; no live owned process; no incomplete file journal"
            atomic_write_json(f, obj)
            abandoned_ops.append(str(obj.get("operation_id") or f.stem))

    recovered_runs: list[str] = []
    for f in sorted(sr.glob("*.json")):
        try:
            obj = read_json(f)
        except Exception:
            continue
        if not obj.get("run_id") or obj.get("status") != "running":
            continue
        obj["status"] = "owner_recovery_quiesced"
        obj["completed_at"] = now_iso()
        obj["exit_code"] = None
        obj["failure_classification"] = "owner_recovery"
        obj["owner_recovery_version"] = ADMIN_VERSION
        atomic_write_json(f, obj)
        recovered_runs.append(str(obj.get("run_id")))

    return {"abandoned_operations": abandoned_ops, "recovered_validations": recovered_runs}

def backup_state(sr: Path, lease_id: str) -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    dest = BACKUP_DIR / f"{stamp}-{time.time_ns()}-{lease_id[:12]}"
    dest.mkdir(parents=True, mode=0o700, exist_ok=False)
    p = paths(sr)
    if p["lease"].is_file():
        shutil.copy2(p["lease"], dest / "active.json.before")
    atomic_write_json(dest / "state-summary.before.json", scan_state(sr))
    return dest

def write_audit(action: str, before: dict[str, Any], after: dict[str, Any], details: dict[str, Any]) -> Path:
    AUDIT_DIR.mkdir(parents=True, mode=0o700, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    path = AUDIT_DIR / f"{stamp}-{action}.json"
    atomic_write_json(path, {
        "admin_version": ADMIN_VERSION,
        "action": action,
        "performed_at": now_iso(),
        "before": before,
        "after": after,
        "details": details,
        "product_repository_touched_by_admin_tool": False,
    })
    return path

def release_lease(
    sr: Path,
    *,
    lease_id: str,
    reason: str,
    terminate_owned: bool,
    kill_after_timeout: bool,
    allow_stale_nonjournal_ops: bool,
) -> dict[str, Any]:
    ensure_executor_stopped()
    before_scan = scan_state(sr)
    p = paths(sr)
    if before_scan["lease_error"]:
        raise RecoveryError(
            "Durable lease record is unreadable. Refusing automatic unlock; preserve state for manual MCP Developer recovery."
        )
    lease = read_json(p["lease"]) if p["lease"].is_file() else None
    if not lease:
        return {"released": False, "already_inactive": True, "reason": "no lease record"}

    durable_id = str(lease.get("lease_id") or "")
    if durable_id != lease_id:
        raise RecoveryError(f"Lease ID mismatch. requested={lease_id} durable={durable_id}")

    if lease.get("status") != "active":
        return {"released": False, "already_inactive": True, "status": lease.get("status")}

    if lease_expired(lease):
        backup = backup_state(sr, lease_id)
        lease["status"] = "expired"
        lease["expired_at"] = now_iso()
        lease["owner_recovery_version"] = ADMIN_VERSION
        atomic_write_json(p["lease"], lease)
        after = scan_state(sr)
        audit = write_audit("mark-expired", before_scan, after, {"backup": str(backup), "reason": reason})
        return {"released": False, "expired": True, "audit": str(audit), "backup": str(backup)}

    if before_scan["incomplete_journals"]:
        raise RecoveryError(
            "Incomplete file-operation journal exists. Refusing unlock until journal recovery is established: "
            + ", ".join(before_scan["incomplete_journals"])
        )

    live = [row for row in before_scan["process_records"] if row["alive_and_owned"]]
    quiesced: list[dict[str, Any]] = []
    if live:
        if not terminate_owned:
            raise RecoveryError(
                "Live executor-owned child process exists. Re-run with --terminate-owned to quiesce exact owned processes first."
            )
        quiesced = terminate_owned_processes(sr, kill_after_timeout=kill_after_timeout)

    reconciled = offline_reconcile_stale_state(
        sr, allow_stale_nonjournal_ops=allow_stale_nonjournal_ops
    )
    mid = scan_state(sr)
    if mid["incomplete_journals"] or any(row["alive_and_owned"] for row in mid["process_records"]):
        raise RecoveryError("Recovery state is still unsafe after quiesce/reconciliation.")

    backup = backup_state(sr, lease_id)
    lease = read_json(p["lease"])
    if str(lease.get("lease_id") or "") != lease_id or lease.get("status") != "active":
        raise RecoveryError("Lease state changed during owner recovery; refusing to overwrite.")

    previous_validation = lease.get("active_validation_run_id")
    lease["status"] = "owner_released"
    lease["owner_released_at"] = now_iso()
    lease["owner_recovery_version"] = ADMIN_VERSION
    lease["owner_recovery_reason"] = reason[:500]
    lease["active_validation_run_id"] = None
    if previous_validation:
        lease["validated_state"] = None
        lease["validation_invalidated_at"] = now_iso()
        lease["validation_invalidated_reason"] = "owner recovery released orphaned lease"
    atomic_write_json(p["lease"], lease)

    after = scan_state(sr)
    if isinstance(after.get("lease"), dict) and after["lease"].get("active") is True:
        raise RecoveryError("Owner release write completed but lease still appears active.")
    audit = write_audit("release-lease", before_scan, after, {
        "backup": str(backup),
        "reason": reason,
        "quiesced_processes": quiesced,
        "offline_reconciliation": reconciled,
        "prior_active_validation_run_id": previous_validation,
    })
    return {
        "released": True,
        "lease_id": lease_id,
        "status": "owner_released",
        "audit": str(audit),
        "backup": str(backup),
        "quiesced_processes": quiesced,
        "offline_reconciliation": reconciled,
    }

def restart_executor() -> dict[str, Any]:
    if not DESKTOP_LAUNCHER.is_file():
        raise RecoveryError(f"Desktop launcher missing: {DESKTOP_LAUNCHER}")
    p = subprocess.run(
        ["/bin/zsh", str(DESKTOP_LAUNCHER), "start"],
        capture_output=True, text=True, check=False, timeout=90,
    )
    if p.returncode != 0:
        raise RecoveryError("Executor restart failed:\n" + (p.stdout + "\n" + p.stderr)[-8000:])
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        ep, lp = executor_pids(), listener_pids()
        if len(ep) == 1 and lp == ep:
            return {"restarted": True, "pid": ep[0], "launcher_output": p.stdout[-4000:]}
        time.sleep(0.25)
    raise RecoveryError(f"Executor did not return on port {PORT}. executor_pids={executor_pids()} listener_pids={listener_pids()}")

def lock_admin():
    ROOT.mkdir(parents=True, exist_ok=True)
    fh = LOCK_FILE.open("a+")
    fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
    return fh

def self_test() -> None:
    global BACKUP_DIR, AUDIT_DIR
    old_backup, old_audit = BACKUP_DIR, AUDIT_DIR
    old_executor_pids = globals()["executor_pids"]
    old_listener_pids = globals()["listener_pids"]

    def make_state(root: Path, *, validation: bool = False, journal: bool = False, op: str | None = None, expired: bool = False) -> str:
        for d in ("operations", "leases", "journals", "processes"):
            (root / d).mkdir(parents=True, exist_ok=True)
        lease_id = "11111111-1111-4111-8111-111111111111"
        run_id = "33333333-3333-4333-8333-333333333333"
        lease = {
            "lease_id": lease_id,
            "execution_id": "22222222-2222-4222-8222-222222222222",
            "authorization_digest": "a" * 64,
            "status": "active",
            "expires_at": "2000-01-01T00:00:00+00:00" if expired else "2999-01-01T00:00:00+00:00",
            "sequence": 3,
            "active_validation_run_id": run_id if validation else None,
        }
        atomic_write_json(root / "leases" / "active.json", lease)
        if validation:
            atomic_write_json(root / f"{run_id}.json", {
                "run_id": run_id,
                "status": "running",
                "lease_id": lease_id,
                "operation": "test-focused",
            })
        if journal:
            j = root / "journals" / "j1"
            j.mkdir()
            atomic_write_json(j / "manifest.json", {"status": "prepared"})
        if op:
            atomic_write_json(root / "operations" / "44444444-4444-4444-8444-444444444444.json", {
                "operation_id": "44444444-4444-4444-8444-444444444444",
                "status": "running",
                "action": op,
                "lease_id": lease_id,
            })
        return lease_id

    try:
        with tempfile.TemporaryDirectory(prefix="mcp-owner-recovery-selftest-") as td:
            base = Path(td)
            BACKUP_DIR = base / "backups"
            AUDIT_DIR = base / "audit"
            globals()["executor_pids"] = lambda: []
            globals()["listener_pids"] = lambda: []

            # The live launcher may spell the same executor through either the
            # canonical checkout or its preserved compatibility symlink.  Only
            # those two exact identities are accepted; arbitrary Python argv is not.
            canonical_cmd = f"/usr/bin/python3 {EXECUTOR_SOURCE}"
            symlink_cmd = f"/usr/bin/python3 {Path.home() / 'ledgerforge-mcp-prototype' / 'executor_v2_1.py'}"
            assert executor_script_identity(canonical_cmd) == str(EXECUTOR_SOURCE)
            assert executor_script_identity(symlink_cmd) == str(Path.home() / "ledgerforge-mcp-prototype" / "executor_v2_1.py")
            assert executor_script_identity("/usr/bin/python3 /tmp/executor_v2_1.py") is None
            assert executor_script_identity("/usr/bin/python3 -c 'import executor_v2_1'") is None

            # CASE 1: active clean lease, no validation -> local owner release.
            c1 = base / "case1"
            lid = make_state(c1)
            out = release_lease(
                c1, lease_id=lid, reason="self-test case1",
                terminate_owned=False, kill_after_timeout=False,
                allow_stale_nonjournal_ops=False,
            )
            assert out["released"] is True
            assert read_json(c1 / "leases" / "active.json")["status"] == "owner_released"

            # CASE 2: stale validation state but no live process -> reconcile then release.
            c2 = base / "case2"
            lid = make_state(c2, validation=True)
            out = release_lease(
                c2, lease_id=lid, reason="self-test case2",
                terminate_owned=False, kill_after_timeout=False,
                allow_stale_nonjournal_ops=False,
            )
            assert out["released"] is True
            state = read_json(c2 / "33333333-3333-4333-8333-333333333333.json")
            assert state["status"] == "owner_recovery_quiesced"

            # CASE 3: incomplete file journal -> hard refusal, lock preserved.
            c3 = base / "case3"
            lid = make_state(c3, journal=True)
            try:
                release_lease(
                    c3, lease_id=lid, reason="self-test case3",
                    terminate_owned=False, kill_after_timeout=False,
                    allow_stale_nonjournal_ops=False,
                )
                raise AssertionError("incomplete journal was incorrectly unlocked")
            except RecoveryError as exc:
                assert "journal" in str(exc).lower()
            assert read_json(c3 / "leases" / "active.json")["status"] == "active"

            # CASE 4: stale non-journal mutating receipt -> safe refusal; explicit owner override works.
            c4 = base / "case4"
            lid = make_state(c4, op="git_commit")
            try:
                release_lease(
                    c4, lease_id=lid, reason="self-test case4-safe",
                    terminate_owned=False, kill_after_timeout=False,
                    allow_stale_nonjournal_ops=False,
                )
                raise AssertionError("unsafe stale mutation receipt was accepted without owner override")
            except RecoveryError as exc:
                assert "stale non-journal" in str(exc).lower()
            out = release_lease(
                c4, lease_id=lid, reason="self-test case4-break-glass",
                terminate_owned=False, kill_after_timeout=False,
                allow_stale_nonjournal_ops=True,
            )
            assert out["released"] is True

            # CASE 5: expired active record -> persist expired, no release capability needed.
            c5 = base / "case5"
            lid = make_state(c5, expired=True)
            out = release_lease(
                c5, lease_id=lid, reason="self-test case5",
                terminate_owned=False, kill_after_timeout=False,
                allow_stale_nonjournal_ops=False,
            )
            assert out["expired"] is True
            assert read_json(c5 / "leases" / "active.json")["status"] == "expired"

            # Local-process ownership identity is recognized without display-name killing.
            proc = subprocess.Popen(["/bin/sleep", "2"], start_new_session=True)
            try:
                time.sleep(0.1)
                local_record = {
                    "pid": proc.pid,
                    "process_start_identity": process_start(proc.pid),
                    "command_class": "local-process",
                    "resolved_executable": "/bin/sleep",
                }
                assert process_record_live(local_record) is True
            finally:
                try:
                    os.killpg(proc.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                proc.wait(timeout=3)

            # Multiple backups for the same lease must never collide.
            assert len(list(BACKUP_DIR.iterdir())) >= 4
    finally:
        BACKUP_DIR, AUDIT_DIR = old_backup, old_audit
        globals()["executor_pids"] = old_executor_pids
        globals()["listener_pids"] = old_listener_pids

    print("MCP OWNER RECOVERY SELF-TEST: PASS")
    print("case1_clean_release=PASS")
    print("case2_stale_validation_reconcile_release=PASS")
    print("case3_incomplete_journal_refusal=PASS")
    print("case4_stale_mutation_receipt_safe_refusal_and_owner_override=PASS")
    print("case5_expiry_persistence=PASS")
    print("local_process_identity=PASS")
    print("backup_collision_resistance=PASS")

def main() -> int:
    ap = argparse.ArgumentParser(description="Local-only owner/admin recovery for LedgerForge MCP leases.")
    ap.add_argument(
        "--state-root",
        help="Exact production .executor-runs-v2_1-production-* root under ~/ledgerforge-mcp-prototype; "
             "used only if the pointer file is unavailable or the owner deliberately targets a known production root.",
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("status")
    sub.add_parser("self-test")

    stop = sub.add_parser("stop-executor")
    stop.add_argument("--kill-after-timeout", action="store_true")
    stop.add_argument("--all-exact-executors", action="store_true")

    rel = sub.add_parser("release-lease")
    rel.add_argument("--lease-id", required=True)
    rel.add_argument("--reason", default="local owner recovery")
    rel.add_argument("--terminate-owned", action="store_true")
    rel.add_argument("--kill-after-timeout", action="store_true")
    rel.add_argument("--all-exact-executors", action="store_true")
    rel.add_argument("--allow-stale-nonjournal-ops", action="store_true")
    rel.add_argument("--yes", action="store_true")

    rec = sub.add_parser("recover-current")
    rec.add_argument("--reason", default="local owner recovery")
    rec.add_argument("--terminate-owned", action="store_true")
    rec.add_argument("--kill-after-timeout", action="store_true")
    rec.add_argument("--all-exact-executors", action="store_true")
    rec.add_argument("--allow-stale-nonjournal-ops", action="store_true")
    rec.add_argument("--restart", action="store_true")
    rec.add_argument("--yes", action="store_true")

    args = ap.parse_args()

    if args.cmd == "self-test":
        self_test()
        return 0

    sr = state_root(args.state_root)

    if args.cmd == "status":
        print(json.dumps(scan_state(sr), indent=2, sort_keys=True))
        return 0

    lock_handle = lock_admin()
    try:
        if args.cmd == "stop-executor":
            print(json.dumps(stop_executor(
                kill_after_timeout=args.kill_after_timeout,
                all_exact=args.all_exact_executors,
            ), indent=2, sort_keys=True))
            return 0

        if args.cmd in {"release-lease", "recover-current"}:
            current = scan_state(sr)
            lease = current.get("lease")
            if not isinstance(lease, dict) or not lease.get("lease_id"):
                print(json.dumps({"released": False, "already_inactive": True, "reason": "no durable lease"}, indent=2))
                return 0
            lease_id = args.lease_id if args.cmd == "release-lease" else str(lease["lease_id"])
            if not args.yes:
                print("OWNER RECOVERY WILL CHANGE MCP LEASE/RECOVERY STATE ONLY.")
                print("It will NOT edit the LedgerForge repository.")
                print(f"State root: {sr}")
                print(f"Lease ID  : {lease_id}")
                print(f"Lease     : active={lease.get('active')} status={lease.get('status')}")
                typed = input(f"Type the full lease ID to continue:\n{lease_id}\n> ").strip()
                if typed != lease_id:
                    raise RecoveryError("Confirmation mismatch; no recovery performed.")

            stop_result = stop_executor(
                kill_after_timeout=args.kill_after_timeout,
                all_exact=args.all_exact_executors,
            )
            result = release_lease(
                sr,
                lease_id=lease_id,
                reason=args.reason,
                terminate_owned=args.terminate_owned,
                kill_after_timeout=args.kill_after_timeout,
                allow_stale_nonjournal_ops=args.allow_stale_nonjournal_ops,
            )
            result["executor_stop"] = stop_result
            if args.cmd == "recover-current" and args.restart:
                result["executor_restart"] = restart_executor()
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0

        raise RecoveryError(f"Unhandled command: {args.cmd}")
    finally:
        fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)
        lock_handle.close()

if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RecoveryError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(2)
