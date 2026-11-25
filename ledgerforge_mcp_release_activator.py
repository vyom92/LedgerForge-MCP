#!/usr/bin/env python3
from __future__ import annotations
import fcntl, hashlib, json, os, re, shutil, stat, subprocess, sys, tempfile, time, uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ACTIVATOR_VERSION = "mcp-release-activator-2.0"
RELEASE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,119}$")
REQUIRED_ROLES = {
    "executor", "static_qualifier", "isolated_qualifier", "release_qualifier",
    "main_launcher", "owner_admin", "owner_version",
    "release_activator", "release_version",
}
ROOT = Path(os.environ.get("LEDGERFORGE_MCP_ACTIVATOR_ROOT", str(Path(__file__).resolve().parent))).expanduser().resolve()
DESKTOP = Path(os.environ.get("LEDGERFORGE_MCP_ACTIVATOR_DESKTOP", str(ROOT))).expanduser().resolve()
PYTHON = Path(os.environ.get("LEDGERFORGE_MCP_ACTIVATOR_PYTHON", str(ROOT / ".venv/bin/python"))).expanduser()
_port_file = ROOT / ".mcp-maintenance/service-ports.json"
PORT = int(os.environ.get("LEDGERFORGE_MCP_ACTIVATOR_PORT") or (json.loads(_port_file.read_text())["executor"] if _port_file.is_file() else 8768))
MAINT = ROOT / ".mcp-maintenance"
ARMED = MAINT / "armed-release.json"
DEPLOYMENTS = MAINT / "deployments"
BACKUPS = ROOT / "mcp-activation-backups"
LOCK = MAINT / "activation.lock"
ROLE_TARGETS = {
    "executor": ROOT / "executor_v2_1.py",
    "static_qualifier": ROOT / "qualify_executor_current_static.py",
    "isolated_qualifier": ROOT / "qualify_executor_current_isolated.py",
    "release_qualifier": ROOT / "qualify_release.py",
    "main_launcher": DESKTOP / "mcp_control.py",
    "owner_admin": ROOT / "ledgerforge_mcp_owner_admin.py",
    "owner_wrapper": DESKTOP / "LedgerForge MCP Owner Recovery.command",
    "owner_version": ROOT / ".mcp-owner-recovery-version",
    "release_activator": ROOT / "ledgerforge_mcp_release_activator.py",
    "release_version": ROOT / ".mcp-release-version",
}
LEGACY_OWNER_WRAPPER = DESKTOP / "LedgerForge MCP Owner Recovery.command"

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def sha_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def sha_file(path: Path) -> str:
    h=hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda:f.read(1024*1024), b""): h.update(chunk)
    return h.hexdigest()

def read_json(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file(): raise RuntimeError(f"required ordinary file missing: {path}")
    obj=json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(obj,dict): raise RuntimeError(f"JSON object required: {path}")
    return obj

def atomic_bytes(path: Path, data: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink(): raise RuntimeError(f"refusing symlink target: {path}")
    tmp=path.with_name(f".{path.name}.tmp-{uuid.uuid4().hex}")
    fd=os.open(tmp, os.O_WRONLY|os.O_CREAT|os.O_EXCL, mode)
    try:
        with os.fdopen(fd,"wb") as f:
            f.write(data); f.flush(); os.fsync(f.fileno())
        os.chmod(tmp,mode); os.replace(tmp,path)
        dfd=os.open(path.parent,os.O_RDONLY)
        try: os.fsync(dfd)
        finally: os.close(dfd)
    finally:
        try: tmp.unlink()
        except FileNotFoundError: pass

def atomic_json(path: Path, obj: dict[str, Any], mode: int=0o600) -> None:
    atomic_bytes(path,(json.dumps(obj,indent=2,sort_keys=True)+"\n").encode(),mode)

def run(cmd: list[str], timeout: int=180, check: bool=True) -> subprocess.CompletedProcess[str]:
    p=subprocess.run(cmd,capture_output=True,text=True,check=False,timeout=timeout)
    if check and p.returncode!=0:
        raise RuntimeError("command failed: "+" ".join(cmd)+"\n"+(p.stdout or "")[-6000:]+"\n"+(p.stderr or "")[-6000:])
    return p

def owner_status(owner_admin: Path) -> dict[str, Any]:
    p=run([str(PYTHON),str(owner_admin),"status"],timeout=60)
    try: obj=json.loads(p.stdout)
    except Exception as exc: raise RuntimeError("Owner Recovery status was not valid JSON") from exc
    if not isinstance(obj,dict): raise RuntimeError("Owner Recovery status must be an object")
    return obj

def require_quiescent(owner_admin: Path, *, require_executor_running: bool) -> dict[str, Any]:
    s=owner_status(owner_admin)
    if s.get("busy_projects"): raise RuntimeError("Other projects have active work.")
    lease=s.get("lease") or {}
    problems=[]
    if s.get("lease_error"): problems.append("lease_error")
    if isinstance(lease,dict) and lease.get("active"): problems.append("active_lease")
    if s.get("incomplete_journals"): problems.append("incomplete_journal")
    if s.get("running_operations"): problems.append("running_operation")
    if s.get("running_validations"): problems.append("active_validation")
    if s.get("process_records"): problems.append("active_generic_process")
    ep=s.get("executor_pids") or []
    lp=s.get("listener_pids") or []
    if require_executor_running:
        if len(ep)!=1 or len(lp)!=1 or int(ep[0])!=int(lp[0]): problems.append("executor_identity")
    else:
        if ep or lp: problems.append("executor_not_stopped")
    if problems: raise RuntimeError("activation quiescence refusal: "+", ".join(problems))
    return s

def component_target(role: str) -> Path:
    if role not in ROLE_TARGETS: raise RuntimeError(f"unsupported component role: {role}")
    return ROLE_TARGETS[role]

def validate_release(release_id: str) -> tuple[dict[str,Any],dict[str,Any],Path]:
    if not RELEASE_ID_RE.fullmatch(release_id): raise RuntimeError("invalid release id")
    armed=read_json(ARMED)
    if armed.get("release_id")!=release_id: raise RuntimeError("armed release id mismatch")
    root=Path(str(armed.get("prepared_root") or "")).expanduser().resolve()
    expected_root=(MAINT/"prepared-releases"/release_id).resolve()
    if root!=expected_root: raise RuntimeError("armed prepared root mismatch")
    state=read_json(root/"release-state.json")
    if state.get("release_id")!=release_id or state.get("status")!="armed": raise RuntimeError("release is not durably armed")
    if state.get("release_digest")!=armed.get("release_digest"): raise RuntimeError("release digest mismatch")
    comps=state.get("components")
    if not isinstance(comps,dict): raise RuntimeError("component map missing")
    identity={"release_id":state.get("release_id"),"target_version":state.get("target_version"),"expected_current_source_sha256":state.get("expected_current_source_sha256"),"expected_current_launcher_sha256":state.get("expected_current_launcher_sha256"),"components":comps}
    recomputed=sha_bytes(json.dumps(identity,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode())
    if recomputed!=state.get("release_digest"): raise RuntimeError("release identity digest mismatch")
    missing=sorted(REQUIRED_ROLES-set(comps))
    extra=sorted(set(comps)-set(ROLE_TARGETS))
    if missing or extra: raise RuntimeError(f"activation component set mismatch missing={missing} extra={extra}")
    for role,row in comps.items():
        if not isinstance(row,dict): raise RuntimeError(f"invalid component row: {role}")
        expected_filename = {
            "executor": "executor_v2_1.py", "static_qualifier": "qualify_executor_current_static.py", "isolated_qualifier": "qualify_executor_current_isolated.py", "release_qualifier": "qualify_release.py", "main_launcher": "mcp_control.py", "owner_admin": "ledgerforge_mcp_owner_admin.py", "owner_wrapper": "LedgerForge MCP Owner Recovery.command", "owner_version": ".mcp-owner-recovery-version", "release_activator": "ledgerforge_mcp_release_activator.py", "release_version": ".mcp-release-version",
        }[role]
        if row.get("filename") != expected_filename: raise RuntimeError(f"prepared component filename mismatch: {role}")
        p=root/expected_filename
        if p.is_symlink() or not p.is_file(): raise RuntimeError(f"prepared component missing: {role}")
        if p.stat().st_size!=int(row.get("size") or -1) or sha_file(p)!=row.get("sha256"):
            raise RuntimeError(f"prepared component identity changed: {role}")
        expected_mode = 0o700 if role not in {"owner_version", "release_version"} else 0o600
        if stat.S_IMODE(p.stat().st_mode) != expected_mode: raise RuntimeError(f"prepared component mode mismatch: {role}")
    live_source=component_target("executor"); live_launcher=component_target("main_launcher")
    if live_source.is_symlink() or not live_source.is_file() or sha_file(live_source)!=state.get("expected_current_source_sha256"):
        raise RuntimeError("current executor source identity mismatch")
    if live_launcher.is_symlink() or not live_launcher.is_file() or sha_file(live_launcher)!=state.get("expected_current_launcher_sha256"):
        raise RuntimeError("current launcher identity mismatch")
    return armed,state,root

def make_backup(release_id: str, state: dict[str,Any]) -> tuple[Path,dict[str,Any]]:
    stamp=datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    bdir=BACKUPS/f"{stamp}-{release_id}"
    bdir.mkdir(parents=True,mode=0o700)
    records={}
    for role in sorted(REQUIRED_ROLES):
        target=component_target(role)
        if target.is_symlink(): raise RuntimeError(f"refusing symlink live target: {role}")
        if target.exists() and not target.is_file(): raise RuntimeError(f"live target is not file: {role}")
        rec={"target":str(target),"existed":target.is_file()}
        if target.is_file():
            data=target.read_bytes(); name=f"{role}.backup"; bp=bdir/name
            bp.write_bytes(data); os.chmod(bp,0o600)
            rec.update({"backup":name,"sha256":sha_bytes(data),"size":len(data),"mode":stat.S_IMODE(target.stat().st_mode)})
        records[role]=rec
    legacy=LEGACY_OWNER_WRAPPER
    if legacy.is_symlink(): raise RuntimeError("refusing symlink legacy owner wrapper")
    if legacy.exists() and not legacy.is_file(): raise RuntimeError("legacy owner wrapper is not a file")
    rec={"target":str(legacy),"existed":legacy.is_file()}
    if legacy.is_file():
        data=legacy.read_bytes(); name="legacy_owner_wrapper.backup"; bp=bdir/name
        bp.write_bytes(data); os.chmod(bp,0o600)
        rec.update({"backup":name,"sha256":sha_bytes(data),"size":len(data),"mode":stat.S_IMODE(legacy.stat().st_mode)})
    records["legacy_owner_wrapper"]=rec
    manifest={"activator_version":ACTIVATOR_VERSION,"release_id":release_id,"created_at":now_iso(),"expected_current_source_sha256":state.get("expected_current_source_sha256"),"expected_current_launcher_sha256":state.get("expected_current_launcher_sha256"),"files":records}
    atomic_json(bdir/"rollback-manifest.json",manifest)
    return bdir,manifest

def restore_backup(bdir: Path, manifest: dict[str,Any]) -> None:
    for role,rec in manifest["files"].items():
        target = LEGACY_OWNER_WRAPPER if role == "legacy_owner_wrapper" else component_target(role)
        if rec.get("backup") and (Path(rec["backup"]).name!=rec["backup"] or (bdir/rec["backup"]).is_symlink()):
            raise RuntimeError("Unsafe rollback record")
        if target.is_symlink(): raise RuntimeError(f"rollback target became symlink: {role}")
        if rec["existed"]:
            bp=bdir/rec["backup"]; data=bp.read_bytes()
            if sha_bytes(data)!=rec["sha256"] or len(data)!=rec["size"]: raise RuntimeError(f"rollback backup corrupted: {role}")
            atomic_bytes(target,data,int(rec["mode"]))
        elif target.exists():
            if not target.is_file(): raise RuntimeError(f"rollback cannot remove non-file: {role}")
            target.unlink()
    for role,rec in manifest["files"].items():
        target = LEGACY_OWNER_WRAPPER if role == "legacy_owner_wrapper" else component_target(role)
        if rec.get("backup") and (Path(rec["backup"]).name!=rec["backup"] or (bdir/rec["backup"]).is_symlink()):
            raise RuntimeError("Unsafe rollback record")
        if rec["existed"]:
            if target.is_symlink() or not target.is_file() or sha_file(target)!=rec["sha256"] or target.stat().st_size!=rec["size"] or stat.S_IMODE(target.stat().st_mode)!=int(rec["mode"]):
                raise RuntimeError(f"rollback verification failed: {role}")
        elif target.exists():
            raise RuntimeError(f"rollback absent-target verification failed: {role}")
    if sha_file(component_target("executor"))!=manifest["expected_current_source_sha256"]: raise RuntimeError("rollback executor verification failed")
    if sha_file(component_target("main_launcher"))!=manifest["expected_current_launcher_sha256"]: raise RuntimeError("rollback launcher verification failed")

def write_integrity_manifest():
    names = [p for r,p in ROLE_TARGETS.items() if r in REQUIRED_ROLES and not r.endswith("version")]
    atomic_json(MAINT/"installed-files.json", {p.name:sha_file(p) for p in names if p.is_file()})

def install_release(root: Path, state: dict[str,Any]) -> None:
    comps=state["components"]
    order=[r for r in sorted(REQUIRED_ROLES) if r not in {"main_launcher"}] + ["main_launcher"]
    for role in order:
        row=comps[role]; src=root/row["filename"]; data=src.read_bytes(); mode=int(row.get("mode") or (0o700 if role not in {"owner_version","release_version"} else 0o600))
        if sha_bytes(data)!=row["sha256"] or len(data)!=row["size"]: raise RuntimeError(f"prepared component changed during install: {role}")
        atomic_bytes(component_target(role),data,mode)
    for role,row in comps.items():
        p=component_target(role)
        if sha_file(p)!=row["sha256"] or p.stat().st_size!=row["size"]: raise RuntimeError(f"installed component verification failed: {role}")
    if LEGACY_OWNER_WRAPPER.exists():
        if LEGACY_OWNER_WRAPPER.is_symlink() or not LEGACY_OWNER_WRAPPER.is_file(): raise RuntimeError("legacy owner wrapper removal target is unsafe")
        LEGACY_OWNER_WRAPPER.unlink()
    if LEGACY_OWNER_WRAPPER.exists(): raise RuntimeError("legacy owner wrapper still present after unified-launcher install")


def qualify_live(state: dict[str,Any]) -> None:
    if PYTHON.is_symlink() and not PYTHON.exists(): raise RuntimeError(f"configured MCP Python interpreter is a broken symlink: {PYTHON}")
    if not PYTHON.is_file() or not os.access(PYTHON, os.X_OK): raise RuntimeError(f"configured MCP Python interpreter is not executable: {PYTHON}")
    q=component_target("isolated_qualifier"); source=component_target("executor"); sh=sha_file(source)
    run([str(PYTHON),str(q),"--port",str(PORT),"--schema-only-live","--expected-source-sha",sh],timeout=180)
    run([str(PYTHON),str(q),"--port",str(PORT),"--live-smoke","--expected-source-sha",sh],timeout=240)
    run([str(PYTHON),str(q),"--port",str(PORT),"--admin-smoke-live","--expected-source-sha",sh],timeout=240)
    run([str(PYTHON),str(component_target("owner_admin")),"self-test"],timeout=240)

def receipt_path(prefix: str, release_id: str) -> Path:
    DEPLOYMENTS.mkdir(parents=True,exist_ok=True,mode=0o700)
    stamp=datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    return DEPLOYMENTS/f"{stamp}-{release_id}-{prefix}.json"

def activate(release_id: str) -> int:
    MAINT.mkdir(parents=True,exist_ok=True,mode=0o700); BACKUPS.mkdir(parents=True,exist_ok=True,mode=0o700)
    lock=open(LOCK,"a+"); fcntl.flock(lock.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
    armed,state,prepared=validate_release(release_id)
    old_owner=component_target("owner_admin"); require_quiescent(old_owner,require_executor_running=True)
    bdir,manifest=make_backup(release_id,state)
    stopped=False
    try:
        run([str(component_target("main_launcher")),"stop","executor"],timeout=120); stopped=True
        require_quiescent(old_owner,require_executor_running=False)
        install_release(prepared,state)
        write_integrity_manifest()
        if os.environ.get("LEDGERFORGE_MCP_ACTIVATOR_FAIL_AFTER_INSTALL")=="1": raise RuntimeError("synthetic failure injection after install")
        run([str(component_target("main_launcher")),"start","executor"],timeout=180)
        qualify_live(state)
        state["status"]="deployed"; state["deployed_at"]=now_iso(); state["deployment_rollback_root"]=str(bdir)
        receipt={"activator_version":ACTIVATOR_VERSION,"release_id":release_id,"release_digest":state.get("release_digest"),"target_version":state.get("target_version"),"result":"deployed","deployed_at":state["deployed_at"],"source_sha256":sha_file(component_target("executor")),"launcher_sha256":sha_file(component_target("main_launcher")),"rollback_root":str(bdir),"single_desktop_launcher":not LEGACY_OWNER_WRAPPER.exists()}
        rp=receipt_path("deployed",release_id); receipt["receipt_path"]=str(rp); atomic_json(rp,receipt); state["deployment_receipt"]=str(rp); atomic_json(prepared/"release-state.json",state)
        try: ARMED.unlink()
        except FileNotFoundError: pass
        print(json.dumps(receipt,indent=2,sort_keys=True)); return 0
    except Exception as exc:
        rollback_error=None
        try:
            if stopped:
                run([str(component_target("main_launcher")),"stop","executor"],timeout=120,check=False)
            restore_backup(bdir,manifest)
            write_integrity_manifest()
            run([str(component_target("main_launcher")),"start","executor"],timeout=180)
            run([str(component_target("main_launcher")),"verify"],timeout=240)
        except Exception as rex: rollback_error=str(rex)
        failure={"activator_version":ACTIVATOR_VERSION,"release_id":release_id,"result":"activation_failed","error":str(exc),"rollback_restored":rollback_error is None,"rollback_error":rollback_error,"rollback_root":str(bdir),"failed_at":now_iso()}
        rp=receipt_path("failed",release_id); failure["receipt_path"]=str(rp); atomic_json(rp,failure)
        try:
            state["status"]="activation_failed_rolled_back" if rollback_error is None else "activation_failed_rollback_failed"; state["activation_failure_receipt"]=str(rp); atomic_json(prepared/"release-state.json",state)
        except Exception: pass
        print(json.dumps(failure,indent=2,sort_keys=True),file=sys.stderr)
        if rollback_error is not None: return 3
        return 2
    finally:
        fcntl.flock(lock.fileno(),fcntl.LOCK_UN); lock.close()

def rollback_candidate(receipt_file):
    """Bind a complete relocated rollback copy to the exact deployment currently installed."""
    receipt=read_json(receipt_file)
    rid=receipt.get("release_id","")
    if not RELEASE_ID_RE.fullmatch(rid) or receipt.get("result")!="deployed":
        raise RuntimeError("Historical deployment record.")
    prepared=MAINT/"prepared-releases"/rid
    state=read_json(prepared/"release-state.json")
    if state.get("status")!="deployed" or state.get("release_digest")!=receipt.get("release_digest"):
        raise RuntimeError("This release is no longer the deployed release.")
    for role in REQUIRED_ROLES:
        target=component_target(role)
        if target.is_symlink() or not target.is_file() or sha_file(target)!=state["components"][role]["sha256"]:
            raise RuntimeError("This receipt belongs to an earlier installation.")
    bdir=Path(receipt["rollback_root"])
    if bdir.parent!=BACKUPS or bdir.resolve()!=bdir:
        raise RuntimeError("This backup predates the current installation path.")
    manifest=read_json(bdir/"rollback-manifest.json")
    if manifest.get("release_id")!=rid or set(manifest["files"])!=REQUIRED_ROLES|{"legacy_owner_wrapper"}:
        raise RuntimeError("The rollback manifest is incomplete.")
    for role,row in manifest["files"].items():
        target=LEGACY_OWNER_WRAPPER if role=="legacy_owner_wrapper" else component_target(role)
        if row["target"]!=str(target): raise RuntimeError("Rollback target belongs to a different installation.")
        if row["existed"]:
            item=bdir/(role+".backup")
            if row["backup"]!=item.name or item.is_symlink() or not item.is_file() or item.stat().st_size!=row["size"] or sha_file(item)!=row["sha256"]:
                raise RuntimeError("Rollback content fails its recorded identity.")
    for role,prop in [("executor","expected_current_source_sha256"),("main_launcher","expected_current_launcher_sha256")]:
        if manifest["files"][role].get("sha256")!=state.get(prop) or manifest.get(prop)!=state.get(prop):
            raise RuntimeError("Rollback content differs from the deployment precondition.")
    return receipt,state,bdir,manifest

def rollback(receipt_name):
    if Path(receipt_name).name!=receipt_name or not receipt_name.endswith("-deployed.json"):
        raise ValueError("Select a deployment receipt.")
    with LOCK.open("a+") as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        receipt,state,bdir,manifest=rollback_candidate(DEPLOYMENTS/receipt_name)
        require_quiescent(component_target("owner_admin"),require_executor_running=True)
        prior={"expected_current_source_sha256":sha_file(component_target("executor")),
               "expected_current_launcher_sha256":sha_file(component_target("main_launcher"))}
        rid=state["release_id"]
        safety,back=make_backup(rid,prior)
        ctl=str(component_target("main_launcher"))
        run([ctl,"stop","executor"],timeout=120)
        try:
            require_quiescent(component_target("owner_admin"),require_executor_running=False)
            restore_backup(bdir,manifest)
            write_integrity_manifest()
            run([ctl,"start","executor"],timeout=180)
            verified=json.loads(run([ctl,"verify"],timeout=180).stdout)
            if sha_file(component_target("executor"))!=manifest["expected_current_source_sha256"]:
                raise RuntimeError("Restored source differs after restart.")
        except Exception:
            run([ctl,"stop","executor"],timeout=120,check=False)
            restore_backup(safety,back)
            write_integrity_manifest()
            run([ctl,"start","executor"],timeout=180)
            run([ctl,"verify"],timeout=180)
            raise
        result={"release_id":rid,"result":"rolled_back","verified":verified,"rollback_root":str(bdir),
                "replaced_installation_backup":str(safety),"restored_at":now_iso()}
        atomic_json(receipt_path("rollback",rid),result)
        state["status"]="rolled_back"
        atomic_json(MAINT/"prepared-releases"/rid/"release-state.json",state)
        print(json.dumps(result))
        return 0


def main() -> int:
    if len(sys.argv)==3 and sys.argv[1]=="rollback": return rollback(sys.argv[2])
    if len(sys.argv)!=2: print("usage: ledgerforge_mcp_release_activator.py RELEASE_ID",file=sys.stderr); return 64
    return activate(sys.argv[1])

if __name__=="__main__": raise SystemExit(main())
