#!/usr/bin/python3
"""Local catalogue for the native control window. Uses the installed owner and release mechanisms."""
from __future__ import annotations
import argparse
import contextlib
import datetime as dt
import fcntl
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import time
import uuid
from pathlib import Path

def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    loaded=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded

def read(path):
    if path.is_symlink() or not path.is_file(): raise ValueError("Record missing or linked: "+path.name)
    value=json.loads(path.read_text())
    if not isinstance(value,dict): raise ValueError("Unreadable record: "+path.name)
    return value

def hash_value(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,default=str).encode()).hexdigest()

def item(kind,key,title,state,*,project="",path=None,details=(),ops=(),identity=None,log=None):
    return dict(kind=kind,id=key,title=str(title),status=str(state),project=project,
        path=str(path) if path else None,details=[str(x) for x in details if x],actions=list(ops),
        identity=hash_value([key,state,identity]),log=str(log) if log else None)

def option(name,label,impact):
    return dict(name=name,label=label,impact=impact)

def git(path,*args):
    env=dict(os.environ,GIT_OPTIONAL_LOCKS="0",GIT_TERMINAL_PROMPT="0")
    return subprocess.run(["/usr/bin/git","-c","core.fsmonitor=false","-C",str(path),*args],text=True,capture_output=True,env=env,timeout=15)

def projects(selected):
    ws=ctl.WS
    if not ws.is_dir(): raise ValueError("Workspace is unavailable.")
    def fail(error): raise error
    for base,dirs,files in os.walk(ws,followlinks=False,onerror=fail):
        path=Path(base)
        marker=".git" in dirs or ".git" in files
        if path!=ws and (path.parent==ws or marker):
            key=path.relative_to(ws).as_posix()
            if selected is None or key==selected:
                stat=path.stat(); state="Repository" if marker else "Directory"
                details=[str(path)]; identity=[stat.st_dev,stat.st_ino]
                if marker:
                    chk=git(path,"rev-parse","--path-format=absolute","--show-toplevel","--absolute-git-dir","--git-common-dir")
                    lines=chk.stdout.splitlines()
                    valid=chk.returncode==0 and len(lines)==3 and Path(lines[0]).resolve()==path and all(Path(l).resolve().is_relative_to(ws) for l in lines)
                    if not valid: state="Git link unavailable"
                    elif selected:
                        head=git(path,"rev-parse","--verify","HEAD").stdout.strip()
                        branch=git(path,"symbolic-ref","--short","HEAD").stdout.strip() or "Detached HEAD"
                        changes=git(path,"status","--porcelain=v1","-z","--untracked-files=normal")
                        if changes.returncode: raise RuntimeError("Git could not read this working tree.")
                        rows=[s for s in changes.stdout.split("\0") if s]
                        details.extend(["Branch · "+branch,"HEAD · "+(head or "No commits"),"Working tree · "+(str(len(rows))+" changed entries" if rows else "Clean")])
                        identity.extend([head,hash_value(rows)])
                if selected:
                    states=dict(owner.all_states())
                    if key in states:
                        lease=states[key]/"leases/active.json"
                        details.append("Execution lease · "+(read(lease).get("status","Unknown") if lease.exists() else "None"))
                    else: details.append("No recorded execution state")
                yield item("projects",key,path.name,state,project=key,path=path,details=details,identity=identity)
        dirs[:]=[] if path==ctl.ROOT else sorted(d for d in dirs if d not in {".git",".build",".venv","node_modules","DerivedData","__pycache__"} and not (path/d).is_symlink())

def owner_rows():
    status=ctl.owner_status()
    return {"LedgerForge":status,**status.get("project_states",{})}

def leases(selected):
    rows=owner_rows()
    live=ctl.component_status("executor")["healthy"]
    for project,row in rows.items():
        if row.get("lease_error"): raise RuntimeError(project+" · "+row["lease_error"])
        root=Path(row["state_root"]);summary=row.get("lease") or {}
        key=summary.get("lease_id")
        if not key or selected and selected!=key: continue
        raw=read(root/"leases/active.json")
        info=ctl.lease_summary(row,live) if hasattr(ctl,"lease_summary") else {"stale":raw["status"]=="active" and not summary["active"]}
        state="Stale" if info["stale"] else str(raw["status"]).replace("_"," ").capitalize()
        details=[f"Project · {project}","Owner · "+str(raw.get("owner_label") or "Unlabelled"),"Purpose · "+str(raw.get("provenance_label") or "Unspecified")]
        for k,title in [("acquired_at","Acquired"),("heartbeat_at","Last heartbeat"),("expires_at","Expires"),("released_at","Released")]:
            if raw.get(k):details.append(title+" · "+raw[k])
        details.append("Incomplete journals · "+(", ".join(row["incomplete_journals"]) or "None"))
        for k,label,field in [("running_operations","Operations","operation_id"),("running_validations","Validations","run_id"),("process_records","Owned processes","run_id")]:
            current=[str(v.get(field)) for v in row[k] if v.get("lease_id",key)==key]
            details.append(label+" · "+(", ".join(current) if current else "None running"))
        if selected:
            associated=[]
            for f in (root/"operations").glob("*.json"):
                obj=read(f)
                if obj.get("lease_id")==key: associated.append((obj.get("started_at",""),obj.get("action","Operation"),obj.get("status","")))
            if associated:
                details.append("Recent associated operations")
                details.extend("  "+str(action)+" · "+str(status) for _,action,status in sorted(associated,reverse=True)[:6])
        ops=[]
        if raw["status"]=="active":
            other=any(owner.busy(other) for other_name,other in rows.items() if other_name!=project)
            if other: details.append("Recovery unavailable while another project has active work.")
            elif row["incomplete_journals"] and summary["active"]: details.append("Resolve the incomplete file journal before releasing this lease.")
            else:
                impact="The local owner helper stops the Shared Tunnel and preserves a recovery backup and audit. Both connection profiles stay running. Other projects must be idle."
                if info["stale"]: ops.append(option("recover-stale","Recover stale lease",impact))
                ops.append(option("force-release","Force-release lease",impact))
        yield item("leases",key,raw.get("owner_label") or project,state,project=project,path=root/"leases/active.json",details=details,ops=ops,identity=[raw,row["incomplete_journals"],row["running_operations"],row["running_validations"],row["process_records"],info["stale"]])

def work(selected):
    rows=[]
    for project,root in owner.all_states():
        for folder,kind in [(root/"local-processes","Process"),(root,"Validation")]:
            if not folder.is_dir(): raise RuntimeError(project+" · "+folder.name+" is inaccessible.")
            for path in folder.glob("*.json"):
                if selected and path.stem!=selected: continue
                try: uuid.UUID(path.stem)
                except ValueError: continue
                v=read(path)
                if not v.get("run_id"): continue
                if selected and v["run_id"]!=selected: continue
                state=v.get("status","Unknown"); key=v["run_id"]
                private=bool(v.get("private_context_configured") or v.get("private_context") or v.get("secret_refs"))
                label=v.get("operation") or (Path(v.get("resolved_executable","")).name if kind=="Process" else None) or kind
                if selected:
                    reg=root/"processes"/(key+".json")
                    owned=owner.process_record_live(read(reg)) if reg.is_file() and state=="running" else False
                    details=["Type · "+kind,"Project · "+project,"Purpose · "+str(v.get("provenance_label") or label),
                        "Started · "+str(v.get("started_at","Unknown")),"Finished · "+str(v.get("completed_at") or "In progress"),
                        "Owner · "+str(v.get("lease_id") or "Executor scratch workspace")]
                    if v.get("duration_seconds") is not None: details.append("Elapsed · "+str(v["duration_seconds"])+" seconds")
                    elif v.get("started_at"):
                        with contextlib.suppress(ValueError):
                            elapsed=dt.datetime.now(dt.timezone.utc)-dt.datetime.fromisoformat(v["started_at"].replace("Z","+00:00"))
                            details.append("Elapsed · "+str(int(elapsed.total_seconds()))+" seconds")
                    for field,name in [("exit_code","Exit code"),("classification","Result"),("failure_classification","Classification"),("safe_test_summary","Test result")]:
                        if v.get(field) is not None:details.append(name+" · "+str(v[field])[:600])
                    ops=[]
                    if state=="running":
                        if owned and kind=="Process" and v.get("execution_class")!="repository" and not v.get("lease_id") and ctl.component_status("executor")["healthy"]:
                            ops.append(option("cancel","Cancel process","Stops this executor-owned scratch process group and verifies its final state. Other runs continue."))
                        else: details.append("Cancellation requires the owning execution lease. Inspect that lease in Maintenance & Recovery.")
                    log=root/"local-process-output"/(key+".stdout") if kind=="Process" else root/(key+".log")
                    if kind=="Process" and (root/"local-process-output"/(key+".stderr")).is_file():
                        details+=["Standard error",*ctl.tail(root/"local-process-output"/(key+".stderr"),14)] if not private else []
                    if private: details.append("Private validation · use the recorded result summary.");log=None
                    if log and not log.is_file(): log=None
                else: details=[];ops=[];log=None
                record=item("work",key,label,state.capitalize(),project=project,path=path,details=details,ops=ops,identity=[v.get("pid"),v.get("process_start_identity"),v.get("operation_id"),v.get("completed_at")],log=log)
                rows.append((state=="running",v.get("started_at",""),record))
    rows.sort(key=lambda r:(r[0],r[1]),reverse=True)
    for i,(_,_,row) in enumerate(rows):
        if i<40 or row["status"]=="Running" or selected: yield row

def releases(selected):
    folder=ctl.MAINT/"prepared-releases"
    if not folder.is_dir(): raise RuntimeError("Prepared releases cannot be inspected.")
    for f in sorted(folder.glob("*/release-state.json"),key=lambda p:p.stat().st_mtime,reverse=True):
        if selected and f.parent.name!=selected:continue
        st=read(f);rid=st["release_id"];status=st["status"];qual=st.get("qualification") or {}
        ready=st.get("expected_current_source_sha256")==ctl.digest(ctl.SOURCE) and st.get("expected_current_launcher_sha256")==ctl.digest(ctl.ROOT/"mcp_control.py") if ctl.SOURCE.is_file() else False
        details=["Version · "+st["target_version"],"Qualification · "+("Passed" if qual.get("passed") else "Failed" if "passed" in qual else "Pending"),"Staged · "+str(st.get("staged_at","Unknown"))]
        if not ready and status in {"qualified","staged","armed"}: details.append("The installed source or controller differs from this candidate’s staging baseline.")
        ops=[]
        if selected:
            local=ctl.component_status("executor")["healthy"]
            if local and status in {"staged","qualification_failed"}:ops.append(option("qualify","Qualify release","Runs the prepared candidate in its isolated qualification environment."))
            if local and status=="qualified" and ready and qual.get("passed") and act.REQUIRED_ROLES.issubset(st.get("components",{})) and not ctl.busy(ctl.owner_status()) and not act.ARMED.exists():
                ops.append(option("arm","Arm release","Records this qualified release as the next eligible activation. Services continue running."))
            if status=="armed" and ready and act.ARMED.is_file() and read(act.ARMED).get("release_id")==rid and local and not ctl.busy(ctl.owner_status()):
                ops.append(option("activate","Activate release","Installs the verified component set and restarts the Shared Tunnel after checking for active work. Both profile processes stay running."))
            if status in {"qualification_failed","staged","qualified"} and local:
                ops.append(option("discard","Discard release","Permanently removes this prepared candidate. The deployed installation and its rollback copy stay available."))
            if set(st.get("components",{}))-act.REQUIRED_ROLES:
                ops=[];details.append("This candidate uses retired component roles. Verified superseded candidates can be reviewed in Cleanup.")
            if not local: details.append("Start the Shared Tunnel to perform release actions. Local evidence is available.")
        log=f.parent/"qualification.log"
        yield item("releases",rid,rid,status.replace("_"," ").capitalize(),path=f.parent,details=details,ops=ops,identity=[st.get("release_digest"),qual.get("passed"),ready],log=log if selected and log.is_file() else None)

def rollbacks(selected):
    folder=ctl.MAINT/"deployments"
    if not folder.is_dir(): raise ValueError("Deployment receipts are unavailable.")
    for f in sorted(folder.glob("*-deployed.json"),reverse=True):
        if selected and f.name!=selected: continue
        r=read(f);ops=[];details=["Release · "+str(r.get("release_id"))];state="Historical";path=f
        try:
            if not hasattr(act,"rollback_candidate"): raise ValueError("Rollback selection requires the updated local activator.")
            _,_,path,m=act.rollback_candidate(f)
            state="Verified";details.extend(["Backup hashes and restore targets verified.","Created · "+str(m["created_at"])])
            if selected and ctl.component_status("executor")["healthy"] and not ctl.busy(ctl.owner_status()):
                ops=[option("rollback","Restore verified backup","Restores the previous deployed components and verifies the restarted Shared Tunnel. Current components are backed up first. Connection profiles stay running.")]
        except (ValueError,KeyError,RuntimeError,OSError) as e: details.append(str(e))
        yield item("rollback",f.name,r.get("release_id") or f.name,state,path=path,details=details,ops=ops,identity=[r.get("release_digest"),r.get("launcher_sha256"),str(path)])

def tree_info(p):
    h=hashlib.sha256();total=0;allocated=0
    def fail(error):raise error
    def visit(x):
        nonlocal total,allocated
        s=x.lstat();total+=s.st_size if x.is_file() and not x.is_symlink() else 0; allocated+=s.st_blocks*512
        h.update(os.fsencode(str(x.relative_to(p)))+str((s.st_ino,s.st_mtime_ns,s.st_size,s.st_mode)).encode())
    visit(p)
    if p.is_dir() and not p.is_symlink():
        for base,dirs,names in os.walk(p,onerror=fail,followlinks=False):
            dirs.sort()
            for n in sorted([*dirs,*names]):visit(Path(base)/n)
    return total,allocated,h.hexdigest()

def superseded_failure(folder):
    st=read(folder/"release-state.json");rid=st.get("release_id","")
    if not ctl.RELEASE_ID.fullmatch(rid) or rid!=folder.name or st.get("status")!="qualification_failed":return False
    if folder.is_symlink() or folder.resolve()!=folder:return False
    rows=[read(p) for p in (ctl.MAINT/"deployments").glob("*-deployed.json")]
    if not any(d.get("target_version")==st.get("target_version") for d in rows) or any(d.get("release_id")==rid for d in rows):return False
    if act.ARMED.exists() and read(act.ARMED).get("release_id")==rid:return False
    comps=st.get("components",{})
    if not comps or set(comps)-act.REQUIRED_ROLES-{"owner_wrapper"}:return False
    identity={k:st.get(k) for k in ("release_id","target_version","expected_current_source_sha256","expected_current_launcher_sha256","components")}
    if hashlib.sha256(json.dumps(identity,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()).hexdigest()!=st.get("release_digest"):return False
    for entry in comps.values():
        name=entry.get("filename","")
        if not name or Path(name).name!=name:return False
        f=folder/name
        if f.is_symlink() or not f.is_file() or f.stat().st_size!=entry.get("size") or ctl.digest(f)!=entry.get("sha256"):return False
    expected={e["filename"] for e in comps.values()} | {
        "release-state.json","qualification-result.json","qualification-exit.json","qualification.log",
        "qualification.sb","qualification-runner.py","isolated-process-diagnostic.json","qualification-mcp-bare.git"}
    for p in folder.iterdir():
        if p.name not in expected or p.is_symlink():return False
        if p.name=="qualification-mcp-bare.git":
            if not p.is_dir() or git(p,"rev-parse","--is-bare-repository").stdout.strip()!="true":return False
        elif not p.is_file():return False
    return True

def retain_failure(folder):
    target=ctl.MAINT/"deployments"/"retired-candidates"/folder.name
    target.mkdir(parents=True,exist_ok=True,mode=0o700)
    if target.resolve()!=target:raise RuntimeError("Failure record archive has an unexpected location.")
    for n in ("release-state.json","qualification-result.json","qualification-exit.json","qualification.log","isolated-process-diagnostic.json"):
        f=folder/n
        if f.is_file() and not f.is_symlink():
            dst=target/n
            if dst.is_symlink() or dst.exists() and ctl.digest(f)!=ctl.digest(dst):raise ValueError("A different archived failure already exists.")
            if not dst.exists():shutil.copy2(f,dst)
            if ctl.digest(dst)!=ctl.digest(f):raise RuntimeError("Failure evidence copy could not be verified.")
    return tree_info(target)[:2]


def cleanup(selected):
    root=ctl.ROOT
    candidates=[]
    for name in ["2.6.1","2.6.2","2.6.3"]:
        p=root/name
        if not p.is_dir():continue
        clean=git(root,"diff","--quiet","HEAD","--",name).returncode==0
        tracked=git(root,"ls-files","--",name).stdout.splitlines()
        actual={str(x.relative_to(root)) for x in p.rglob("*") if (x.is_file() or x.is_symlink()) and x.name!=".DS_Store"}
        extra=actual-set(tracked)
        manifest=p/"MANIFEST.sha256"
        markers={name+"/release/.mcp-release-version",name+"/release/.mcp-owner-recovery-version"}
        version=name
        markers_ok=all((root/f).read_text().strip() in {version,"mcp-"+version+"-owner-recovery-r1"} for f in extra) if extra<=markers else False
        history=clean and bool(tracked) and set(tracked)<=actual and (not extra or markers_ok)
        candidates.append((p,history,"Superseded release copy preserved in Git" if history else "Contains material without an identical Git copy"))
    for p in [root/"__pycache__",*sorted(root.glob("mcp2.*-backups")),root/"mcp-releases"]:
        if p.name=="__pycache__" and p.is_dir() and not p.is_symlink() and all(x.is_file() and x.suffix==".pyc" and not x.is_symlink() for x in p.iterdir()):
            candidates.append((p,True,"Generated Python bytecode; recreated on demand"))
        elif p.is_symlink(): candidates.append((p,not p.exists(),"Obsolete dangling compatibility link" if not p.exists() else "Link to a retained rollback store"))
    # Only explicitly terminal qualification peers, whose durable state has no owner or work, are removable.
    for p in root.glob(".executor-runs-v2_1-qualification-universal-workspace-*"):
        slot=ctl.MAINT/"prepared-releases"/p.name.split("qualification-",1)[1]/"release-state.json"
        if not slot.is_file() or p.is_symlink():continue
        if read(slot).get("status") not in {"deployed","rolled_back"}:continue
        if owner.busy(owner.scan_state(p)):continue
        candidates.append((p,True,"Finished migration qualification peer; deployment receipt and prepared evidence retained"))
    current=ctl.state_root()
    bootstrap=root/"mcp-activation-backups"/"workspace-relocation-20261125-original"
    legacy=root/"LedgerForge MCP.command"
    if legacy.is_file() and (bootstrap/legacy.name).is_file():
        same=ctl.digest(legacy)==ctl.digest(bootstrap/legacy.name)
        candidates.append((legacy,same,"Superseded Terminal launcher; identical bytes in the original rollback bundle" if same else "Different from the archived launcher"))
    for name in ("server.py","test_client.py"):
        p=root/name
        if p.is_file():
            tracked=git(root,"show","HEAD:"+name)
            same=tracked.returncode==0 and tracked.stdout.encode()==p.read_bytes()
            candidates.append((p,same,"Retired prototype; exact file preserved in Git" if same else "Uncommitted prototype changes"))
    for p in sorted(root.glob(".executor-runs-v2_1*")):
        if p==current or p.is_symlink() or not p.is_dir():continue
        if p.name.startswith(".executor-runs-v2_1-qualification-universal-"):continue
        paths=[f for f in p.rglob("*") if f.is_file() or f.is_symlink()]
        if paths and all(f.name in {"boot.json",".DS_Store"} and not f.is_symlink() for f in paths):
            candidates.append((p,True,"Unused state root containing only a boot marker; no leases, runs, journals or process records"))
    # Qualification sandboxes are disposable products of a finished runner. Result/exit records and immutable staged components are retained.
    slots=ctl.MAINT/"prepared-releases"
    for f in slots.glob("*/release-state.json"):
        rec=read(f);rid=rec.get("release_id")
        if rec.get("status")=="qualification_failed" and (selected is None or selected==str(f.parent.relative_to(root))) and superseded_failure(f.parent):
            candidates.append((f.parent,True,"Superseded failed candidate. The deployed successor exists and every recorded byte matches; failure evidence will be retained."))
        if rec.get("status") not in {"deployed","rolled_back","qualification_failed","activation_failed_rollback_failed","activation_failed_rolled_back"}:continue
        if not (f.parent/"qualification-exit.json").is_file():continue
        for n in ("qualification-bare.git","qualification-bridge","qualification-desktop","qualification-home","qualification-repo","qualification-tunnel-config","tmp","__pycache__"):
            p=f.parent/n
            if p.is_dir() and not p.is_symlink():candidates.append((p,True,"Completed release-qualification sandbox; immutable payloads, exit record and result retained"))
    # A finalized upload is redundant only when the prepared component exists and both files match its recorded hash.
    for f in (ctl.MAINT/"blobs").glob("*/blob-manifest.json"):
        manifest=read(f); rid=manifest.get("release_id",""); role=manifest.get("component_role")
        if not ctl.RELEASE_ID.fullmatch(rid) or manifest.get("finalized") is not True:continue
        sf=slots/rid/"release-state.json"
        if not sf.is_file():continue
        rec=read(sf);component=(rec.get("components") or {}).get(role,{})
        if rec.get("status") not in {"deployed","rolled_back","qualification_failed","activation_failed_rolled_back","activation_failed_rollback_failed"}:continue
        sha=component.get("sha256")
        filename=component.get("filename","")
        if not filename or Path(filename).name!=filename:continue
        payload=sf.parent/filename;blob=f.parent/"blob.bin"
        if not payload.is_file() or not blob.is_file() or payload.is_symlink() or blob.is_symlink():continue
        if sha and sha==manifest.get("final_sha256") and ctl.digest(payload)==sha and ctl.digest(blob)==sha:
            candidates.append((f.parent,True,"Finalized upload duplicated byte-for-byte by a terminal prepared component"))


    for p,eligible,reason in candidates:
        key=str(p.relative_to(root))
        if selected and key!=selected:continue
        size,allocated,identity=tree_info(p)
        ops=[option("remove","Remove permanently","Permanently removes this verified obsolete MCP item. Active services, state and rollback material are preserved.")] if eligible else []
        yield item("cleanup",key,p.name,"Eligible" if eligible else "Retained",path=p,details=[reason,f"File bytes · {size:,}",f"Allocated bytes · {allocated:,}","References · "+("No current runtime dependency" if eligible else "Historical or unverified")],ops=ops,identity=identity)

CATALOG={"projects":projects,"leases":leases,"work":work,"releases":releases,"rollback":rollbacks,"cleanup":cleanup}

def selected_item(kind,key):
    rows=list(CATALOG[kind](key))
    if len(rows)!=1: raise ValueError("Selection changed or unavailable. Refresh the list and select the current record.")
    row=rows[0]
    if row["log"]:row["details"]+=["Recent log",*ctl.tail(Path(row["log"]),18)]
    return row

def execute(kind,key,expected,op,flags):
    row=selected_item(kind,key)
    if row["identity"]!=expected or not any(a["name"]==op for a in row["actions"]):
        raise ValueError("Selection changed. The action was cancelled. Refresh and review the current record.")
    if kind=="leases":
        reply=ctl.action(op,row["project"],key,flags)
        return "Lease verified · "+reply["verified_state"].replace("_"," ")
    if kind=="work":
        ctl.live_rpc("process_cancel",{"project":row["project"],"run_id":key,"operation_id":str(uuid.uuid4())})
        for _ in range(30):
            after=selected_item(kind,key)
            if after["status"]!="Running": return "Process verified · "+after["status"]
            time.sleep(.3)
        raise RuntimeError("Cancellation requested. The process has not yet reported a final state.")
    if op=="rollback":
        reply=ctl.shell([ctl.PYTHON,ctl.ROOT/"ledgerforge_mcp_release_activator.py","rollback",key],600)
        if reply.returncode:raise RuntimeError(ctl.safe_text(reply.stderr[-900:]))
        return "Restored and verified · "+str(json.loads(reply.stdout)["verified"]["version"])
    if kind=="releases":
        folder=ctl.MAINT/"prepared-releases"/key
        if op=="activate":
            reply=ctl.action(op,key,key)
            if reply.get("result")!="deployed" or read(folder/"release-state.json")["status"]!="deployed": raise RuntimeError("Deployment could not be verified.")
            return "Deployed and verified · "+key
        args=dict(release_id=key,action=op,operation_id=str(uuid.uuid4()),expected_release_digest=read(folder/"release-state.json")["release_digest"],dry_run=False)
        ctl.live_rpc("maintenance_release",args,admin=True)
        if op=="discard" and not folder.exists():return "Removal verified · "+key
        if op=="qualify":
            for _ in range(360):
                result=ctl.live_rpc("maintenance_release",dict(operation_id=str(uuid.uuid4()),action="status",release_id=key),admin=True)
                if result.get("status")!="qualifying":break
                time.sleep(1)
            if result.get("status")=="qualified":return "Qualification passed · "+key
            raise RuntimeError("Qualification "+str(result.get("status"))+". Inspect the release log.")
        if op=="arm" and read(act.ARMED).get("release_id")==key and read(folder/"release-state.json")["status"]=="armed":
            return "Armed release verified · "+key
        raise RuntimeError("Release postcondition could not be verified.")
    if kind=="cleanup":
        ctl.require_idle(); path=Path(row["path"])
        if not path.parent.resolve().is_relative_to(ctl.ROOT) or path.parent.resolve()!=path.parent or selected_item(kind,key)["identity"]!=expected:raise RuntimeError("Cleanup selection changed.")
        size,allocated,_=tree_info(path)
        if path.parent==ctl.MAINT/"prepared-releases" and superseded_failure(path):
            retained_size,retained_allocation=retain_failure(path)
            size-=retained_size;allocated-=retained_allocation
        if path.is_symlink() or path.is_file():path.unlink()
        else:shutil.rmtree(path)
        if os.path.lexists(path):raise RuntimeError("Removal could not be verified.")
        receipt={"path":key,"bytes":size,"allocated_bytes":allocated,"removed_at":dt.datetime.now().astimezone().isoformat()}
        with (ctl.MAINT/"cleanup-receipts.jsonl").open("a") as out:out.write(json.dumps(receipt)+"\n")
        return f"Removal verified · {key} · {allocated:,} allocated bytes"
    raise ValueError("This object has no matching action.")

FEATURE_DEFAULTS={"core":True,"evidence":True,"optional":True,"ci_status_inspection":False}
def feature_settings():
    path=ctl.ROOT/".executor-v2.1-features.json"
    raw=read(path) if path.exists() else {}
    if any(type(raw[k]) is not bool for k in raw.keys() & FEATURE_DEFAULTS.keys()):
        raise ValueError("The installed feature configuration contains a non-boolean value.")
    return {"flags":{k:raw.get(k,v) for k,v in FEATURE_DEFAULTS.items()},"identity":hash_value(raw)}

def change_features(supplied,expected):
    values=json.loads(supplied)
    if set(values)!=set(FEATURE_DEFAULTS) or any(type(v) is not bool for v in values.values()):raise ValueError("Select the supported capability flags.")
    with (ctl.MAINT/"service-control.lock").open("a") as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        if feature_settings()["identity"]!=expected:raise ValueError("Feature configuration changed. Refresh Settings.")
        path=ctl.ROOT/".executor-v2.1-features.json"
        before=read(path) if path.exists() else {};combined=dict(before,**values)
        ctl.atomic_private(path,(json.dumps(combined,indent=2,sort_keys=True)+"\n").encode())
        if feature_settings()["flags"]!=values:raise RuntimeError("Feature settings could not be verified.")
        return {"verified":"Capability settings saved and verified on disk."}


def main():
    global ctl,owner,act
    root=Path(sys.argv[1]).resolve(strict=True)
    ctl=module("installed_control",root/"mcp_control.py")
    owner=module("installed_owner",root/"ledgerforge_mcp_owner_admin.py")
    act=module("installed_activator",root/"ledgerforge_mcp_release_activator.py")
    cmd,kind,*args=sys.argv[2:]
    if cmd=="preferences" and kind=="features":return feature_settings()
    if cmd=="preferences" and kind=="save":return change_features(*args)
    if kind not in CATALOG:raise ValueError("Unknown section")
    if cmd=="catalog":return list(CATALOG[kind](None))
    if cmd=="inspect":return selected_item(kind,args[0])
    if cmd!="apply":raise ValueError("Unknown action")
    key,expected,op,*flags=args
    # Activation and rollback call the service controller recursively. Their existing activation lock serializes them.
    lock_name="native-maintenance.lock" if op in {"activate","rollback"} else "service-control.lock"
    with (ctl.MAINT/lock_name).open("a") as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        message=execute(kind,key,expected,op,flags)
        with (ctl.MAINT/"control.log").open("a") as log:log.write(dt.datetime.now().astimezone().isoformat(timespec="seconds")+"  "+message+"\n")
        return {"verified":message}

if __name__=="__main__":
    try:print(json.dumps(main()))
    except Exception as error:
        print(json.dumps({"error":str(error)}));sys.exit(1)
