#!/usr/bin/python3
"""Local service control for the native ChatGPT MCP app. All data returned to it is JSON."""
from __future__ import annotations
import argparse
import contextlib
import datetime
import fcntl
import hashlib
import json
import os
import re
import signal
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent
WS = Path(os.environ.get("CHATGPT_MCP_WORKSPACE", ROOT.parent)).resolve()
CFG = Path(os.environ.get("LEDGERFORGE_EXECUTOR_MAINTENANCE_TUNNEL_CONFIG", Path.home()/".config/tunnel-client"))
MAINT = ROOT/".mcp-maintenance"
SOURCE = ROOT/"executor_v2_1.py"
PYTHON = ROOT/".venv/bin/python"
OWNER = ROOT/"ledgerforge_mcp_owner_admin.py"
TUNNEL = Path("/opt/homebrew/bin/tunnel-client")
PORT = int(os.environ.get("LEDGERFORGE_EXECUTOR_PORT","8768"))
PROFILES = {"executor-tunnel":("ledgerforge-recovery",8080), "admin-tunnel":("ledgerforge-recovery-admin",8081)}
COMPONENTS = ("executor", *PROFILES)
PRIVATE_FILES = (ROOT/".executor-token", ROOT/".executor-admin-token", ROOT/".executor-path", ROOT/".mcp-path")
RELEASE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{2,119}\Z")

PORT_KEYS=("executor","executor-tunnel","admin-tunnel")
PORT_DEFAULTS=dict(zip(PORT_KEYS,(8768,8080,8081)))
PORT_FILE=MAINT/"service-ports.json"
PORT_JOURNAL=MAINT/"port-change"
def stored_ports():
    if not PORT_FILE.exists(): return dict(PORT_DEFAULTS)
    if PORT_FILE.is_symlink(): raise ValueError("Shared Tunnel port settings are linked.")
    return validate_ports(json.loads(PORT_FILE.read_text()))

def validate_ports(values):
    if set(values)!=set(PORT_KEYS) or any(type(p)!=int or not 1024<=p<=65535 for p in values.values()) or len(set(values.values()))!=3:
        raise ValueError("Choose three distinct local ports from 1024 to 65535.")
    return values

def atomic_private(path,body,mode=0o600):
    if path.is_symlink():raise ValueError("Refusing to replace a linked setting.")
    import tempfile
    fd,name=tempfile.mkstemp(dir=path.parent,prefix="."+path.name+".")
    try:
        with os.fdopen(fd,"wb") as out:
            out.write(body);out.flush();os.fsync(out.fileno())
        os.chmod(name,mode);os.replace(name,path)
    finally:
        if os.path.exists(name):os.unlink(name)

def use_ports(values):
    global PORT,PROFILES
    PORT=values["executor"]
    PROFILES={name:(profile,values[name]) for name,(profile,_) in PROFILES.items()}

def mapped_profile(data,old,new,name):
    for field,old_port,new_port in [("url",old["executor"],new["executor"]),("listen_addr",old[name],new[name])]:
        pattern=rb"(?m)^([ \t]*"+field.encode()+rb":[ \t]*['\"]?(?:https?://)?(?:localhost|127\.0\.0\.1):)"+str(old_port).encode()+rb"(?=[/'\"\s]|$)"
        data,count=re.subn(pattern,lambda m:m.group(1)+str(new_port).encode(),data)
        if count!=1:raise ValueError("The "+name+" profile contains a different or ambiguous "+field+". Review it in Finder.")
    return data

def port_configuration():
    values=stored_ports()
    facts=[]
    for name,(profile,_) in PROFILES.items():
        p=CFG/(profile+".yaml")
        if p.is_symlink() or not p.is_file():raise ValueError("Missing exact profile: "+profile)
        data=p.read_bytes();mapped_profile(data,values,values,name);facts.append(hashlib.sha256(data).hexdigest())
    return {"ports":values,"identity":hashlib.sha256(json.dumps([values,facts]).encode()).hexdigest(),"pending":PORT_JOURNAL.exists()}

def restore_ports():
    import shutil
    journal=json.loads((PORT_JOURNAL/"transaction.json").read_text());old=journal["old"];new=journal["new"]
    affected=journal["affected"];running=journal["running"]
    if "executor" in affected:require_idle()
    for n in reversed(affected):
        if process_ids(n):stop_one(n)
    for n,(profile,_) in PROFILES.items():
        if n in affected:
            p=CFG/(profile+".yaml")
            atomic_private(p,(PORT_JOURNAL/(n+".yaml")).read_bytes(),journal["modes"][n])
    if journal["had_settings"]:atomic_private(PORT_FILE,json.dumps(old).encode())
    elif PORT_FILE.exists():PORT_FILE.unlink()
    use_ports(old)
    for n in affected:
        if n in running:repair(n)
    if port_configuration()["ports"]!=old or any(not component_status(n)["healthy"] for n in affected if n in running):
        raise RuntimeError("Original ports could not be verified. Inspect the port change in Settings.")
    shutil.rmtree(PORT_JOURNAL)
    return {"verified":"Restored the previous ports and verified the services."}

def configure_ports(value,expected):
    import shutil,stat,tempfile
    if PORT_JOURNAL.exists(): raise RuntimeError("Finish the interrupted port change in Settings first.")
    current=port_configuration();old=current["ports"];new=validate_ports(json.loads(value))
    if current["identity"]!=expected: raise ValueError("Port configuration changed. Refresh Settings before applying.")
    if old==new:return {"verified":"Port settings already match."}
    changed=[n for n in PORT_KEYS if old[n]!=new[n]]
    for n in changed:
        if new[n] in old.values() or listener(new[n]):raise ValueError("Port "+str(new[n])+" is already in use. Choose a free local port.")
        with socket.socket() as sock:
            # A just-stopped health endpoint can have ordinary TIME_WAIT connections.
            # The real listener check above still excludes any service owning the port.
            sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
            sock.bind(("127.0.0.1",new[n]))
    affected=list(PORT_KEYS) if "executor" in changed else changed
    states={n:component_status(n) for n in PORT_KEYS}
    if any(s["pids"]!=s["listeners"] or len(s["pids"])>1 for s in states.values()):raise RuntimeError("Resolve the current service ownership conflict first.")
    running=[n for n in PORT_KEYS if states[n]["pids"]]
    if "executor" in affected: require_idle()
    prepared={};modes={};temp=Path(tempfile.mkdtemp(prefix=".port-change-",dir=MAINT))
    try:
        for n,(profile,_) in PROFILES.items():
            if n not in affected:continue
            p=CFG/(profile+".yaml");data=p.read_bytes()
            prepared[n]=mapped_profile(data,old,new,n);modes[n]=stat.S_IMODE(p.stat().st_mode)
            atomic_private(temp/(n+".yaml"),data)
        atomic_private(temp/"transaction.json",json.dumps(dict(old=old,new=new,affected=affected,running=running,modes=modes,had_settings=PORT_FILE.exists())).encode())
        os.rename(temp,PORT_JOURNAL)
    finally:
        if temp.exists():shutil.rmtree(temp)
    try:
        for n in reversed(affected):
            if n in running: stop_one(n)
        for n,data in prepared.items():atomic_private(CFG/(PROFILES[n][0]+".yaml"),data,modes[n])
        atomic_private(PORT_FILE,json.dumps(new,sort_keys=True).encode())
        use_ports(new)
        for n in affected:
            if n in running: repair(n)
        if port_configuration()["ports"]!=new:raise RuntimeError("New ports did not match the profile settings.")
        for n in PORT_KEYS:
            after=component_status(n)
            if (n in running and not after["healthy"]) or (n not in affected and after["pids"]!=states[n]["pids"]):
                raise RuntimeError("Service state changed unexpectedly during the port update.")
        if "executor" in running and "executor" in affected:verify()
    except Exception as exc:
        restore_ports()
        raise RuntimeError("The proposed change failed. Previous ports restored. "+str(exc)) from exc
    shutil.rmtree(PORT_JOURNAL)
    return {"verified":"Port settings and affected listeners verified."}


try:
    use_ports(stored_ports())
except (OSError,ValueError):
    pass  # Readiness reports the damaged configuration to the local application.
if os.environ.get("LEDGERFORGE_EXECUTOR_PORT"):PORT=int(os.environ["LEDGERFORGE_EXECUTOR_PORT"])

def shell(argv, timeout=30):
    return subprocess.run([str(x) for x in argv], capture_output=True, text=True, timeout=timeout)

def safe_text(text):
    for p in PRIVATE_FILES:
        if p.is_file():
            value=p.read_text().strip()
            if value: text=text.replace(value,"[REDACTED]")
    text = re.sub(r"/mcp_[A-Za-z0-9_-]{16,}","/[REDACTED]",text)
    text = re.sub(r"(?i)(bearer\s+|(?:api[_-]?key|authorization|token|pass(?:word|phrase))\s*[:=]\s*)[^\s,}]+", r"\1[REDACTED]",text)
    return text

def digest(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()

def state_root():
    pointer = ROOT/".executor-v2.1-state-root"
    path = (ROOT/pointer.read_text().strip()).resolve(strict=True)
    if path.parent != ROOT or not path.name.startswith(".executor-runs-v2_1-production-"):
        raise ValueError("Runtime pointer does not identify this installation's production state.")
    return path

def health_url(port, path):
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/{path}",timeout=2) as response:
            return response.status == 200
    except OSError:
        return False

def listener(port):
    result = shell(["/usr/sbin/lsof","-nP",f"-iTCP:{port}","-sTCP:LISTEN","-Fp"])
    return sorted({int(x[1:]) for x in result.stdout.splitlines() if x.startswith("p") and x[1:].isdigit()})

def process_ids(component):
    rows = shell(["/bin/ps","-ww","-axo","pid=,command="]).stdout.splitlines()
    ids=[]
    for line in rows:
        parts=line.strip().split(None,1)
        if len(parts)!=2 or not parts[0].isdigit(): continue
        command = parts[1].strip()
        if component=="executor":
            # ps on Darwin renders argv joined by spaces. Match the whole script suffix, including spaces.
            if not command.endswith(" "+str(SOURCE)): continue
            exe = command[:-(len(str(SOURCE))+1)]
            if not Path(exe).name.lower().startswith("python"): continue
        else:
            profile,_=PROFILES[component]
            if not re.fullmatch(r"\S*/tunnel-client run --profile "+re.escape(profile),command): continue
        ids.append(int(parts[0]))
    return ids

def component_status(name):
    port=PORT if name=="executor" else PROFILES[name][1]
    pids=process_ids(name)
    listeners=listener(port)
    matched=len(pids)==1 and pids==listeners
    healthy=matched and (name=="executor" or (health_url(port,"healthz") and health_url(port,"readyz")))
    return {"name":name,"port":port,"pid":pids[0] if len(pids)==1 else None, "pids":pids,
            "listeners":listeners, "healthy":healthy, "state":"Ready" if healthy else
            "Ownership conflict" if listeners and not matched or len(pids)>1 else "Unavailable"}

def live_rpc(tool, args=None, admin=False, port=None):
    route=(ROOT/".executor-path").read_text().strip()
    token=(ROOT/(".executor-admin-token" if admin else ".executor-token")).read_text().strip()
    if not re.fullmatch(r"/mcp_[A-Za-z0-9_-]+",route): raise ValueError("Invalid endpoint configuration")
    headers={"Content-Type":"application/json","Accept":"application/json, text/event-stream","Authorization":"Bearer "+token}
    def send(method, params, seq=None):
        packet={"jsonrpc":"2.0","method":method,"params":params}
        if seq is not None: packet["id"]=seq
        req=urllib.request.Request("http://127.0.0.1:"+str(port or PORT)+route, data=json.dumps(packet).encode(), headers=headers)
        with urllib.request.urlopen(req,timeout=12) as reply:
            sid=reply.headers.get("Mcp-Session-Id")
            if sid: headers["Mcp-Session-Id"]=sid
            raw=reply.read()
        if not raw.strip(): return {}
        if raw.startswith(b"event:") or raw.startswith(b"data:"):
            raw=next(line[5:].strip() for line in raw.splitlines() if line.startswith(b"data:"))
        value=json.loads(raw)
        if "error" in value: raise RuntimeError("The live MCP server rejected "+method)
        return value.get("result",{})
    init=send("initialize",{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"ChatGPT MCP Control","version":"1"}},1)
    headers["MCP-Protocol-Version"]=init["protocolVersion"]
    try:
        send("notifications/initialized",{})
        if tool=="tools/list": return send("tools/list",{},2)
        result=send("tools/call",{"name":tool,"arguments":args or {}},2)
        if result.get("isError"): raise RuntimeError("MCP rejected "+tool)
        return result.get("structuredContent") or json.loads(result["content"][0]["text"])
    finally:
        if "Mcp-Session-Id" in headers:
            with contextlib.suppress(OSError):
                with urllib.request.urlopen(urllib.request.Request("http://127.0.0.1:"+str(port or PORT)+route,headers=headers,method="DELETE"),timeout=2): pass

def installation_issues():
    issues=[]
    try: port_configuration()
    except (ValueError,OSError) as error: issues.append("Port configuration · "+str(error))
    for p in (SOURCE, OWNER,ROOT/"ledgerforge_mcp_release_activator.py",ROOT/"qualify_executor_current_static.py",ROOT/"qualify_executor_current_isolated.py",ROOT/"qualify_release.py"):
        if not p.is_file() or p.is_symlink(): issues.append("Missing source · "+p.name)
    if not WS.is_dir() or not os.access(WS,os.R_OK|os.X_OK): issues.append("Workspace is missing or inaccessible.")
    try:
        sr=state_root()
        for name in ("leases","operations","journals","processes","boot.json","local-processes","evidence"):
            if not (sr/name).exists(): issues.append("Missing runtime state · "+name)
    except (ValueError,OSError): issues.append("Runtime-state pointer is missing or inaccessible.")
    try:
        check=shell([PYTHON,"-IB","-c","import sys,mcp,uvicorn,httpx2; from mcp.server import MCPServer; from mcp.server.transport_security import TransportSecuritySettings; print(sys.prefix)"])
        if check.returncode or Path(check.stdout.strip()).resolve()!=(ROOT/".venv").resolve(): raise ValueError()
    except (OSError,ValueError,subprocess.SubprocessError): issues.append("Invalid Python environment · verify the installed MCP dependencies.")
    for p in PRIVATE_FILES[:3]:
        if not p.is_file() or p.is_symlink() or p.stat().st_mode & 0o077: issues.append("Credential configuration unavailable · "+p.name)
    for profile,_ in PROFILES.values():
        file=CFG/(profile+".yaml")
        if not file.is_file() or file.is_symlink():
            issues.append("Missing tunnel profile · "+profile)
            continue
        for reference in re.findall(r"(/[^\s'\"}]+(?:auth-header|runtime-key))",file.read_text()):
            if not Path(reference).is_file(): issues.append("Missing credential reference · "+profile)
    if (MAINT/"installed-files.json").exists():
        try:
            for name,sha in json.loads((MAINT/"installed-files.json").read_text()).items():
                p=ROOT/name
                if p.parent!=ROOT or not p.is_file() or digest(p)!=sha: issues.append("Installed component differs · "+name)
        except (OSError,ValueError): issues.append("Installed release manifest is unreadable.")
    return issues

def backend_issues():
    # The shared listener can start when an independent tunnel profile is damaged.
    issues=installation_issues()
    profile_messages=("Missing tunnel profile","Missing credential reference","Port configuration · Missing exact profile","Port configuration · The executor-tunnel profile","Port configuration · The admin-tunnel profile")
    return [message for message in issues if not message.startswith(profile_messages)]

def owner_status():
    reply=shell([sys.executable,OWNER,"status"],timeout=40)
    if reply.returncode: raise RuntimeError("Owner recovery could not inspect production state. "+safe_text(reply.stderr[-500:]))
    return json.loads(reply.stdout)

def busy(s):
    return bool((s.get("lease") or {}).get("active") or s.get("lease_error") or s.get("busy_projects") or any(s.get(k) for k in ("incomplete_journals","running_operations","running_validations","process_records")))

def require_idle():
    if busy(owner_status()): raise RuntimeError("The executor has a lease, active work, or unresolved recovery records.")

def log_file(component):
    name="ledgerforge-executor" if component=="executor" else PROFILES[component][0]
    return CFG/(name+".log")

def tail(path,limit=12,raw=False):
    if not path.is_file() or path.is_symlink(): return []
    with path.open("rb") as stream:
        stream.seek(max(0,path.stat().st_size-18000)); chunk=stream.read()
    lines=chunk.decode(errors="replace").splitlines()[-limit:]
    return lines if raw else [safe_text(line)[:800] for line in lines]

def release_list():
    result=[]
    for file in sorted((MAINT/"prepared-releases").glob("*/release-state.json")):
        try:
            st=json.loads(file.read_text())
            result.append({"id":file.parent.name,"version":st.get("target_version",""),"status":st.get("status","unknown")})
        except (OSError,ValueError): result.append({"id":file.parent.name,"version":"","status":"unreadable"})
    return result

def set_manifest():
    names=("executor_v2_1.py","mcp_control.py","ledgerforge_mcp_owner_admin.py","ledgerforge_mcp_release_activator.py","qualify_executor_current_static.py","qualify_executor_current_isolated.py","qualify_release.py")
    expected={n:digest(ROOT/n) for n in names}
    path=MAINT/"installed-files.json"
    tmp=path.with_suffix(".tmp"); tmp.write_text(json.dumps(expected,sort_keys=True));tmp.chmod(0o600);os.replace(tmp,path)

def connection_diagnostics(name):
    if name not in PROFILES: raise ValueError("Select MCP Executor or MCP Admin.")
    profile,port=PROFILES[name]; tunnel=component_status(name); server=component_status("executor")
    report={"connection":"MCP Admin" if name=="admin-tunnel" else "MCP Executor",
            "profile":profile,"port":port,"pid":tunnel["pid"],"listener_owners":tunnel["listeners"],
            "exact_profile_processes":tunnel["pids"],"healthz":health_url(port,"healthz"),
            "readyz":health_url(port,"readyz"),"profile_readable":os.access(CFG/(profile+".yaml"),os.R_OK),
            "shared_executor":server["state"],"local_scope_verified":False,"log":tail(log_file(name),30,raw=True)}
    if server["healthy"]:
        try:
            if name=="admin-tunnel":
                report["local_scope_verified"]=bool(live_rpc("maintenance_status",{"max_bytes":120000},admin=True).get("admin_scope_verified"))
            else:
                report["local_scope_verified"]=bool(live_rpc("executor_capabilities").get("schema_contract_sha256"))
        except Exception as exc: report["local_error"]=safe_text(str(exc))
    return report

def connection_action(op,name):
    if name not in PROFILES: raise ValueError("Select a registered connection.")
    if op=="diagnose-connection": return connection_diagnostics(name)
    if op=="stop-connection":
        stop_one(name)
        after=component_status(name)
        if after["pids"] or after["listeners"]: raise RuntimeError("The selected listener is still active.")
        return {"stopped":name,"verified":True}
    if op=="restart-connection": stop_one(name)
    repair("executor")
    result=repair(name)
    if not component_status(name)["healthy"]: raise RuntimeError("The selected connection is still unavailable.")
    return {name:result,"verified":True}

def lease_summary(row,executor_ready):
    lease=row.get("lease") or {}
    raw_active=lease.get("status")=="active"
    try: boot=json.loads((Path(row["state_root"])/"boot.json").read_text()).get("boot_id")
    except (OSError,ValueError,KeyError): boot=None
    stale=raw_active and (not lease.get("active") or not executor_ready or bool(boot and lease.get("executor_boot_id")!=boot))
    return {"lease":lease.get("lease_id") if raw_active else None,"stale":stale,
            "operations":len(row.get("running_operations",[])),"journals":len(row.get("incomplete_journals",[])),
            "owned":len(row.get("process_records",[])),"status":lease.get("status","idle")}

def service_identity(target=None, rows=None):
    rows=rows if rows is not None else [component_status(n) for n in COMPONENTS]
    facts=[(r["name"],r["pids"],r["listeners"],r["healthy"]) for r in rows if target is None or r["name"]==target]
    return hashlib.sha256(json.dumps(facts).encode()).hexdigest()

def snapshot():
    issues=installation_issues()
    components=[component_status(n) for n in COMPONENTS]
    caps={};projects=[]; recovery={}; recovery_required=False
    if components[0]["healthy"]:
        try:
            caps=live_rpc("executor_capabilities")
            if not SOURCE.is_file() or caps.get("source_sha256")!=digest(SOURCE) or caps.get("loaded_source_sha256")!=digest(SOURCE) or caps.get("workspace_root")!=str(WS) or caps.get("state_root")!=str(state_root()):
                issues.append("The responding executor does not match this installation.")
            if caps.get("project_routing"): projects=live_rpc("workspace_projects").get("projects",[])
        except Exception as exc: issues.append("Live MCP verification failed · "+safe_text(str(exc))[:180])
    try:
        rec=owner_status(); project_states={"LedgerForge":rec,**rec.get("project_states",{})}
        recovery={k:lease_summary(v,components[0]["healthy"]) for k,v in project_states.items()}
        recovery_required=any(v["stale"] for v in recovery.values()) or any(v.get("lease_error") or v.get("incomplete_journals") or any(not r.get("alive_and_owned") for r in v.get("process_records",[])) for v in project_states.values())
    except Exception: issues.append("Recovery state cannot be inspected.")
    overall="Recovery required" if recovery_required else ("Responding · degraded installation" if components[0]["healthy"] else "Installation needs repair") if issues else "Fully operational" if all(c["healthy"] for c in components) else "Services need attention"
    if not issues and not recovery_required and all(not c["pids"] and not c["listeners"] for c in components):
        overall="Stopped"
    for row in components: row["identity"]=service_identity(row["name"],components)
    return {"service_identity":service_identity(rows=components),"overall":overall,"issues":issues,"workspace":str(WS),"installation":str(ROOT),"components":components,
            "version":caps.get("executor_version"),"schema":caps.get("schema_contract_sha256"),"source":caps.get("source_sha256"),
            "projects":projects,"recovery":recovery,"releases":release_list(),"activity":tail(MAINT/"control.log",6),
            "log_paths":{n:str(log_file(n)) for n in COMPONENTS},"logs":{n:tail(log_file(n),70,raw=True) for n in COMPONENTS}}

def identity(pid):
    return shell(["/bin/ps","-p",str(pid),"-o","lstart="]).stdout.strip()

def stop_one(name):
    st=component_status(name); ids=st["pids"]
    if len(ids)>1 or set(st["listeners"])-set(ids): raise RuntimeError("Ambiguous ownership for "+name)
    if not ids: return
    if name=="executor": require_idle()
    pid=ids[0]; started=identity(pid)
    if not started or pid not in process_ids(name) or identity(pid)!=started: raise RuntimeError("Process identity changed.")
    os.kill(pid,signal.SIGTERM)
    for _ in range(60):
        if pid not in process_ids(name): return
        time.sleep(0.15)
    raise RuntimeError("Timed out stopping "+name+"; inspect its log.")

def launch(name):
    if listener(PORT if name=="executor" else PROFILES[name][1]) or process_ids(name):
        raise RuntimeError("Refusing to start over an existing listener or process.")
    env={k:v for k,v in os.environ.items() if not k.startswith(("LEDGERFORGE_PRIVATE_","LEDGERFORGE_AXIS_CARD_PRIVATE_","LEDGERFORGE_EXECUTOR_"))}
    if name=="executor":
        issues=backend_issues()
        if issues: raise RuntimeError(" · ".join(issues))
        env.update(LEDGERFORGE_EXECUTOR_MCP_PATH=(ROOT/".executor-path").read_text().strip(),
                   LEDGERFORGE_EXECUTOR_BEARER_TOKEN=(ROOT/".executor-token").read_text().strip(),
                   LEDGERFORGE_EXECUTOR_ADMIN_BEARER_TOKEN=(ROOT/".executor-admin-token").read_text().strip(),
                   LEDGERFORGE_EXECUTOR_STATE_ROOT=str(state_root()),LEDGERFORGE_EXECUTOR_BRIDGE_ROOT=str(ROOT),
                   LEDGERFORGE_EXECUTOR_REPO_ROOT=str(WS/"LedgerForge"), CHATGPT_MCP_WORKSPACE=str(WS),
                   LEDGERFORGE_EXECUTOR_PUBLIC_URL=f"https://localhost:{PORT}",LEDGERFORGE_EXECUTOR_PORT=str(PORT),
                   LEDGERFORGE_EXECUTOR_MAINTENANCE_DESKTOP=str(ROOT),LEDGERFORGE_EXECUTOR_MAINTENANCE_TUNNEL_CONFIG=str(CFG),
                   LEDGERFORGE_EXECUTOR_MCP_HOST="127.0.0.1",PYTHONDONTWRITEBYTECODE="1")
        argv=[PYTHON,SOURCE]
    else:
        profile,_=PROFILES[name]
        if not (CFG/(profile+".yaml")).is_file(): raise RuntimeError("Missing tunnel configuration for "+profile)
        argv=[TUNNEL,"run","--profile",profile]
    with log_file(name).open("ab") as out:
        proc=subprocess.Popen([str(v) for v in argv],cwd=ROOT,env=env,stdin=subprocess.DEVNULL,stdout=out,stderr=out,start_new_session=True)
    pname="ledgerforge-executor" if name=="executor" else PROFILES[name][0]
    (CFG/(pname+".pid")).write_text(str(proc.pid)+"\n")
    for _ in range(85):
        if proc.poll() is not None: raise RuntimeError(name+" exited. "+ " ".join(tail(log_file(name),2)))
        if component_status(name)["healthy"]: return
        time.sleep(.3)
    if proc.poll() is None and not listener(PORT if name=="executor" else PROFILES[name][1]):
        proc.terminate()
        try: proc.wait(5)
        except subprocess.TimeoutExpired:
            if proc.poll() is None: proc.kill();proc.wait(5)
    raise RuntimeError(name+" has not reported ready. Inspect the component log.")

def repair(name):
    st=component_status(name)
    if st["healthy"]:
        if name!="executor": return "Healthy component preserved"
        issues=backend_issues()
        if issues: raise RuntimeError(" · ".join(issues))
        caps=live_rpc("executor_capabilities")
        if caps.get("loaded_source_sha256",caps.get("source_sha256"))==digest(SOURCE) and (caps.get("workspace_root")==str(WS) or caps.get("executor_version")=="2.6.4" and caps.get("source_sha256")==digest(SOURCE)):
            return "Healthy component preserved"
    if name=="executor": require_idle()
    stop_one(name);launch(name)
    return "Started "+name

def verify_live_contract(listing,caps):
    """Independently compare tools/list and the published contract with the installed source."""
    import ast
    required={"TOOL_ANNOTATION_CONTRACT","SCHEMA_CONTRACT_REVISION","TOOLSET_REVISION","CORE_FEATURES","EVIDENCE_FEATURES","OPTIONAL_FEATURES","ALLOWED_VALIDATIONS","PRIVATE_CONTEXTS"}
    values={}
    for stmt in ast.parse(SOURCE.read_bytes()).body:
        target=stmt.target if isinstance(stmt,ast.AnnAssign) else stmt.targets[0] if isinstance(stmt,ast.Assign) and len(stmt.targets)==1 else None
        if isinstance(target,ast.Name) and target.id in required:values[target.id]=ast.literal_eval(stmt.value)
    if set(values)!=required:raise ValueError("Installed source contract is incomplete.")
    contract=values["TOOL_ANNOTATION_CONTRACT"]
    tools={t["name"]:t for t in listing["tools"]}
    if set(tools)!=set(contract) or len(tools)!=len(listing["tools"]):raise ValueError("Live tool names differ from the installed source.")
    mapping={"read_only":"readOnlyHint","destructive":"destructiveHint","idempotent":"idempotentHint","open_world":"openWorldHint"}
    for name,row in contract.items():
        if any(tools[name].get("annotations",{}).get(hint)!=row[key] for key,hint in mapping.items()):
            raise ValueError("Live annotation differs for "+name)
    payload={"revision":values["SCHEMA_CONTRACT_REVISION"],"toolset_revision":values["TOOLSET_REVISION"],"annotations":contract,
             "core_features":sorted(values["CORE_FEATURES"]),"evidence_features":sorted(values["EVIDENCE_FEATURES"]),
             "optional_features":sorted(values["OPTIONAL_FEATURES"]),"validations":sorted(values["ALLOWED_VALIDATIONS"]),
             "private_contexts":sorted(values["PRIVATE_CONTEXTS"])}
    sha=hashlib.sha256(json.dumps(payload,sort_keys=True,separators=(",",":")).encode()).hexdigest()
    if caps.get("schema_contract_sha256")!=sha:raise RuntimeError("The live schema identity differs from installed source.")


def verify():
    caps=live_rpc("executor_capabilities")
    listing=live_rpc("tools/list")
    verify_live_contract(listing,caps)
    count=len(listing.get("tools",[]))
    if caps.get("annotation_contract_count")!=count or caps.get("source_sha256")!=digest(SOURCE):
        raise RuntimeError("Live source or tool count differs from disk.")
    if not live_rpc("maintenance_status",{"max_bytes":120000},admin=True).get("admin_scope_verified"):
        raise RuntimeError("Admin scope verification failed.")
    return {"version":caps["executor_version"],"schema":caps["schema_contract_sha256"],"tools":count}

def action(op,value,confirm,recovery_options=()):
    if op=="ports":return port_configuration()
    if op=="configure-ports":return configure_ports(value,confirm)
    if op=="restore-ports":return restore_ports()
    if op.endswith("-connection"): return connection_action(op,value)
    if op=="status": return snapshot()
    if op=="verify": return verify()
    if op=="recovery": return owner_status()
    if op=="releases": return release_list()
    if op=="self-test":
        test=shell([sys.executable,OWNER,"self-test"],120)
        if test.returncode: raise RuntimeError(safe_text(test.stderr[-600:]))
        return {"owner_self_test":"passed"}
    if op=="activate":
        if not value or not RELEASE_ID.fullmatch(value) or confirm!=value: raise ValueError("Confirm the exact armed release ID.")
        require_idle()
        reply=shell([sys.executable,ROOT/"ledgerforge_mcp_release_activator.py",value],600)
        if reply.returncode: raise RuntimeError(safe_text(reply.stderr[-1200:]))
        return json.loads(reply.stdout)
    if op in ("recover-stale","force-release","release-lease"):
        st=owner_status(); records={"LedgerForge":st,**st.get("project_states",{})}
        row=records.get(value,{})
        if not confirm or confirm!=(row.get("lease") or {}).get("lease_id") or (row.get("lease") or {}).get("status")!="active":
            raise ValueError("Confirm the active lease ID for the selected project.")
        if op=="recover-stale" and not lease_summary(row,component_status("executor")["healthy"])["stale"]:
            raise ValueError("This lease is current. Review force-release if the owner intends to interrupt it.")
        options=[x for x in recovery_options if x!="--restart"]
        result=shell([sys.executable,OWNER,"--state-root",row["state_root"],"release-lease","--lease-id",confirm,"--yes",*options],120)
        if result.returncode: raise RuntimeError(safe_text(result.stderr[-1000:]))
        reply=json.loads(result.stdout)
        durable=json.loads((Path(row["state_root"])/"leases/active.json").read_text())
        if durable.get("lease_id")!=confirm or durable.get("status") not in {"owner_released","expired"}:
            raise RuntimeError("The selected lease did not reach a verified final state: "+str(durable.get("status")))
        if "--restart" in recovery_options: reply["restart"]=repair("executor")
        reply["verified_state"]=durable["status"]
        return reply
    target=[value] if value in COMPONENTS else list(COMPONENTS) if value is None else []
    if not target: raise ValueError("Unknown service component")
    if op in ("stop","restart"):
        if "executor" in target: require_idle()
        for n in reversed(target): stop_one(n)
    if op in ("start","restart","repair"):
        result={n:repair(n) for n in target}
        if not all(component_status(n)["healthy"] for n in target): raise RuntimeError("A selected service did not become ready.")
        return result
    if op=="stop":
        if any(component_status(n)["pids"] or component_status(n)["listeners"] for n in target):
            raise RuntimeError("A selected service is still listening.")
        return {"stopped":target,"verified":True}
    raise ValueError("Unknown control action")

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("operation",choices=["ports","configure-ports","restore-ports","status","verify","recovery","releases","self-test","activate","release-lease","recover-stale","force-release","repair","start","restart","stop","start-connection","stop-connection","restart-connection","repair-connection","diagnose-connection"])
    parser.add_argument("value",nargs="?");parser.add_argument("--confirm");parser.add_argument("--expected-services")
    flags=("--terminate-owned","--kill-after-timeout","--all-exact-executors","--allow-stale-nonjournal-ops","--restart")
    for flag in flags: parser.add_argument(flag,action="store_true")
    args=parser.parse_args()
    recovery_options=[flag for flag in flags if getattr(args,flag[2:].replace("-","_"))]
    try:
        if args.operation in ("ports","status","verify","releases","recovery","self-test","activate","diagnose-connection"):
            value=action(args.operation,args.value,args.confirm,recovery_options)
        else:
            with (MAINT/"service-control.lock").open("a") as lock:
                fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
                if args.expected_services:
                    if service_identity(args.value if args.value in COMPONENTS else None)!=args.expected_services:
                        raise RuntimeError("Service state changed since selection. Refresh and review the current services.")
                value=action(args.operation,args.value,args.confirm,recovery_options)
        if args.operation not in ("ports","status","recovery","releases","diagnose-connection"):
            with (MAINT/"control.log").open("a") as fh: fh.write(datetime.datetime.now().astimezone().isoformat(timespec="seconds")+"  "+args.operation+"  "+(args.value or "")+"  completed\n")
        print(json.dumps(value,sort_keys=True));return 0
    except Exception as e:
        print(json.dumps({"error":safe_text(str(e)) or type(e).__name__}));return 1

if __name__=="__main__":
    sys.exit(main())
