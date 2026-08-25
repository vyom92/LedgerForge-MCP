#!/usr/bin/env python3
from __future__ import annotations
import argparse, asyncio, base64, hashlib, inspect, json, os, secrets, shutil, socket, subprocess, sys, tempfile, time, uuid
from contextlib import asynccontextmanager
from pathlib import Path

EXPECTED_TOOLS={
"executor_capabilities","host_status","workspace_state","execution_lease_status","executor_recovery_status","execution_snapshot",
"acquire_execution_lease","heartbeat_execution_lease","resume_execution_lease","release_execution_lease","list_files","read_file","search_files","artifact_inspect","git_inspect","evidence_batch",
"apply_file_ops","git_fetch_origin","git_stage","precommit_privacy_scan","git_commit","git_push","run_repo_task","start_validation","validation_status","validation_result","validation_wait_result","cancel_validation",
"test_discovery","documentation_sync_preflight","cycle_close_evidence","runtime_launch","runtime_status","runtime_logs","runtime_stop","test_impact_advisor","performance_probe","swift_xcode_audit","repository_recovery_analysis","fixture_provenance_inspect","run_regression_campaign","private_context_matrix","ci_status_inspection",
"local_fs_inspect","local_fs_mutate","task_workspace","process_start","process_status","process_wait","process_cancel","process_result","executor_help","maintenance_status","maintenance_file_inspect","maintenance_release"}

try:
    from mcp import ClientSession
except ImportError:
    from mcp.client.session import ClientSession
try:
    from mcp.client.streamable_http import streamablehttp_client
except ImportError:
    from mcp.client.streamable_http import streamable_http_client as streamablehttp_client

ROOT=(Path.home()/"ledgerforge-mcp-prototype").resolve()

def sha(data:bytes)->str: return hashlib.sha256(data).hexdigest()
def fsha(p:Path)->str: return sha(p.read_bytes())
def run(cmd,cwd=None,timeout=120,env=None):
    p=subprocess.run(cmd,cwd=cwd,capture_output=True,text=True,check=False,timeout=timeout,env=env)
    if p.returncode!=0: raise RuntimeError("command failed: "+" ".join(map(str,cmd))+"\n"+(p.stdout or "")[-8000:]+"\n"+(p.stderr or "")[-8000:])
    return p

def model_dict(v):
    if hasattr(v,"model_dump"): return v.model_dump(by_alias=True)
    if hasattr(v,"dict"): return v.dict(by_alias=True)
    return v

def parse_result(result):
    raw=model_dict(result)
    if isinstance(raw,dict):
        is_error=bool(raw.get("isError",raw.get("is_error",False))); structured=raw.get("structuredContent",raw.get("structured_content")); content=raw.get("content",[])
    else:
        is_error=bool(getattr(result,"isError",getattr(result,"is_error",False))); structured=getattr(result,"structuredContent",getattr(result,"structured_content",None)); content=getattr(result,"content",[])
    if isinstance(structured,dict):
        if is_error: raise RuntimeError(json.dumps(structured,sort_keys=True))
        return structured
    text=[]
    for item in content or []:
        row=model_dict(item); t=row.get("text") if isinstance(row,dict) else getattr(item,"text",None)
        if isinstance(t,str): text.append(t)
    joined="\n".join(text).strip()
    if is_error: raise RuntimeError(joined or "MCP tool returned error")
    if joined:
        try:
            obj=json.loads(joined)
            if isinstance(obj,dict): return obj
        except Exception: pass
        return {"text":joined}
    return {}

async def call(session,name,args): return parse_result(await session.call_tool(name,args))
async def expect_error(session,name,args):
    try: await call(session,name,args)
    except Exception: return True
    return False

@asynccontextmanager
async def open_session(port:int,path:str,token:str|None):
    url=f"http://127.0.0.1:{port}{path}"; headers={"Authorization":f"Bearer {token}"} if token else {}
    params=inspect.signature(streamablehttp_client).parameters
    if "headers" in params:
        kw={"headers":headers}
        if "timeout" in params: kw["timeout"]=120.0
        async with streamablehttp_client(url,**kw) as streams:
            async with ClientSession(streams[0],streams[1]) as session:
                await session.initialize(); yield session
        return
    import httpx2
    async with httpx2.AsyncClient(headers=headers,follow_redirects=True,timeout=120.0) as client:
        async with streamablehttp_client(url,http_client=client) as streams:
            async with ClientSession(streams[0],streams[1]) as session:
                await session.initialize(); yield session

async def session_denied(port,path,token):
    try:
        async with open_session(port,path,token): return False
    except Exception: return True

async def assert_schema(session,expected_sha):
    listed=await session.list_tools(); tools=getattr(listed,"tools",[]); names={getattr(t,"name",None) or model_dict(t).get("name") for t in tools}
    if names!=EXPECTED_TOOLS: raise RuntimeError(f"tool mismatch missing={sorted(EXPECTED_TOOLS-names)} extra={sorted(names-EXPECTED_TOOLS)}")
    caps=await call(session,"executor_capabilities",{})
    if (caps.get("executor_version"),caps.get("toolset_revision"),caps.get("schema_contract_revision"))!=("2.6.1",8,"2.6.1"): raise RuntimeError(f"identity mismatch: {caps}")
    if caps.get("source_sha256")!=expected_sha or caps.get("annotation_contract_count")!=55: raise RuntimeError("source/tool annotation identity mismatch")
    fp=caps.get("fingerprint_contract") or {}
    if fp.get("worktree_revision")!="2" or fp.get("index_revision")!="1": raise RuntimeError("fingerprint revision metadata missing")
    return caps

def init_repo(repo:Path,bare:Path):
    repo.mkdir(parents=True); (repo/"README.md").write_text("MCP 2.6.1 isolated qualification\n"); (repo/"SyntheticTests.swift").write_text("import Testing\n@Test func smoke() { #expect(true) }\n")
    script_dir=repo/"script"; script_dir.mkdir(); validate=script_dir/"validate.sh"; validate.write_text("#!/bin/sh\nset -eu\nexit 0\n"); validate.chmod(0o700)
    run(["git","init","-b","main"],repo); run(["git","config","user.name","MCP Qualification"],repo); run(["git","config","user.email","mcp-qualification@example.invalid"],repo); run(["git","add","."],repo); run(["git","commit","-m","Synthetic baseline"],repo)
    run(["git","init","--bare",str(bare)]); run(["git","remote","add","origin",str(bare)],repo); run(["git","push","-u","origin","main"],repo); run(["git","fetch","origin"],repo)

def free_port():
    s=socket.socket(); s.bind(("127.0.0.1",0)); p=s.getsockname()[1]; s.close(); return p

async def isolated_calls(port,path,normal,admin,expected_sha,state_root,desktop):
    async with open_session(port,path,normal) as s:
        caps=await assert_schema(s,expected_sha)
        isolated_root=state_root.parent.parent.resolve()
        roots=caps.get("evidence_roots") or {}
        for root_name in ("repo","originals","derived_data","executor_artifacts","ledgerforge_logs","task_scratch"):
            resolved=(roots.get(root_name) or {}).get("resolved_path")
            if not resolved: raise RuntimeError(f"isolated evidence root missing: {root_name}")
            try: Path(resolved).resolve().relative_to(isolated_root)
            except ValueError as exc: raise RuntimeError(f"isolated evidence root escaped temp root: {root_name}={resolved}") from exc
        helpv=await call(s,"executor_help",{"topic":"maintenance"}); rendered=json.dumps(helpv,sort_keys=True)
        if len(rendered.encode())>160000 or normal in rendered or admin in rendered: raise RuntimeError("executor_help boundedness/secret failure")
        if not await expect_error(s,"maintenance_status",{}): raise RuntimeError("normal token obtained admin authority")
        await call(s,"workspace_state",{}); snap=await call(s,"execution_snapshot",{"max_bytes":120000})
        if "processes" not in snap or "task_workspaces" not in snap or "cleanup_safe" not in snap: raise RuntimeError("snapshot owned-resource grouping missing")
        disc=await call(s,"test_discovery",{"max_results":50,"max_bytes":80000}); sc=disc.get("selector_capabilities") or {}
        if sc.get("zero_test_result_is_acceptance") is not False or "swift_testing_method_selector" not in sc: raise RuntimeError("selector metadata missing")
        wid=str(uuid.uuid4()); await call(s,"task_workspace",{"operation_id":str(uuid.uuid4()),"workspace_id":wid,"action":"create","task_label":"mcp261-http-close"})
        args={"operation_id":str(uuid.uuid4()),"workspace_id":wid,"argv":["/bin/sleep","120"],"cwd_path":"work","execution_class":"scratch","timeout_seconds":180,"expected_exit_codes":[0],"output_paths":[],"dry_run":True}
        plan=await call(s,"process_start",args); digest=plan.get("process_plan_digest")
        args["operation_id"]=str(uuid.uuid4()); args["dry_run"]=False; args["reviewed_plan_digest"]=digest; started=await call(s,"process_start",args)
        run_id=started.get("run_id")
        if not run_id: raise RuntimeError("process_start did not return run_id")
        terminal=None
        try:
            running=None
            for _ in range(100):
                running=await call(s,"process_status",{"run_id":run_id})
                if running.get("status")!="running": raise RuntimeError(f"process stopped before close probe: {running.get('status')}")
                if running.get("pid"):
                    break
                await asyncio.sleep(0.05)
            else:
                raise RuntimeError("process did not publish a PID before close probe")
            blocked=await call(s,"task_workspace",{"operation_id":str(uuid.uuid4()),"workspace_id":wid,"action":"close","wait_seconds":0})
            if blocked.get("closed") is not False or blocked.get("cleanup_safe") is not False or blocked.get("exists_after") is not True: raise RuntimeError("workspace close did not refuse while busy")
            cancelled=await call(s,"process_cancel",{"run_id":run_id,"operation_id":str(uuid.uuid4())})
            if cancelled.get("cancelled") is not True: raise RuntimeError("scratch process cancellation was not accepted")
            terminal=await call(s,"process_wait",{"run_id":run_id,"wait_seconds":10})
            if terminal.get("status")!="cancelled": raise RuntimeError(f"scratch process did not reach cancelled state: {terminal.get('status')}")
        finally:
            try:
                current=await call(s,"process_status",{"run_id":run_id})
                if current.get("status")=="running":
                    await call(s,"process_cancel",{"run_id":run_id,"operation_id":str(uuid.uuid4())})
                    await call(s,"process_wait",{"run_id":run_id,"wait_seconds":10})
            except Exception:
                pass
        closed=await call(s,"task_workspace",{"operation_id":str(uuid.uuid4()),"workspace_id":wid,"action":"close","wait_seconds":5})
        if closed.get("closed") is not True or closed.get("exists_after") is not False: raise RuntimeError("bounded workspace close failed after cancellation")
        rid=str(uuid.uuid4()); rp=state_root/f"{rid}.json"; rp.write_text(json.dumps({"run_id":rid,"status":"running","operation":"test-full","selectors":[],"safe_test_summary":{},"xcresult_evidence":{}})+"\n")
        vr=await call(s,"validation_wait_result",{"run_id":rid,"wait_seconds":0,"detail":"summary","max_bytes":80000})
        if vr.get("status")!="running" or vr.get("result_ready") is not False or vr.get("retry_safe") is not True: raise RuntimeError("validation wait running semantics failed")
        rp.write_text(json.dumps({"run_id":rid,"status":"completed","operation":"test-full","selectors":[],"exit_code":0,"repository_mutated":False,"safe_test_summary":{"totalTestCount":1},"xcresult_evidence":{}})+"\n")
        vt=await call(s,"validation_wait_result",{"run_id":rid,"wait_seconds":0,"detail":"summary","max_bytes":80000})
        if vt.get("status")!="completed" or vt.get("result_ready") is not True or vt.get("retry_safe") is not True: raise RuntimeError("validation wait terminal semantics failed")
    if not await session_denied(port,path,"invalid-"+secrets.token_urlsafe(40)): raise RuntimeError("invalid token was accepted")
    if not await session_denied(port,path,None): raise RuntimeError("missing token was accepted")
    small={"executor":b"x","static_qualifier":b"y","release_qualifier":b"z"}; comps=[{"role":r,"sha256":sha(b),"content_base64":base64.b64encode(b).decode()} for r,b in small.items()]
    launcher_sha=fsha(desktop/"LedgerForge MCP.command"); release_id="http-reconnect-test"
    async with open_session(port,path,admin) as a:
        await assert_schema(a,expected_sha); ms=await call(a,"maintenance_status",{}); txt=json.dumps(ms,sort_keys=True)
        if ms.get("admin_scope_verified") is not True or normal in txt or admin in txt: raise RuntimeError("admin status secret/scope failure")
        fi=await call(a,"maintenance_file_inspect",{"target":"executor_source","action":"hash"})
        if fi.get("sha256")!=expected_sha: raise RuntimeError("admin control-file hash mismatch")
        if not await expect_error(a,"maintenance_file_inspect",{"target":"../../.ssh","action":"stat"}): raise RuntimeError("maintenance target allowlist bypass")
        if not await expect_error(a,"maintenance_release",{"operation_id":str(uuid.uuid4()),"release_id":"bad","action":"activate","dry_run":True}): raise RuntimeError("remote activate action exists")
        plan=await call(a,"maintenance_release",{"operation_id":str(uuid.uuid4()),"release_id":release_id,"action":"stage","target_version":"9.9.9","expected_current_source_sha256":expected_sha,"expected_current_launcher_sha256":launcher_sha,"components":comps,"dry_run":True})
        staged=await call(a,"maintenance_release",{"operation_id":str(uuid.uuid4()),"release_id":release_id,"action":"stage","target_version":"9.9.9","expected_current_source_sha256":expected_sha,"expected_current_launcher_sha256":launcher_sha,"components":comps,"dry_run":False,"reviewed_plan_digest":plan["reviewed_plan_digest"]}); release_digest=staged["release_digest"]
    async with open_session(port,path,admin) as a2:
        ms2=await call(a2,"maintenance_status",{})
        if release_id not in [r.get("release_id") for r in ms2.get("prepared_releases",[])]: raise RuntimeError("prepared release did not survive reconnect")
        status=await call(a2,"maintenance_release",{"operation_id":str(uuid.uuid4()),"release_id":release_id,"action":"status","dry_run":True})
        if status.get("release_digest")!=release_digest: raise RuntimeError("reconnected release digest changed")
        disc=await call(a2,"maintenance_release",{"operation_id":str(uuid.uuid4()),"release_id":release_id,"action":"discard","expected_release_digest":release_digest,"dry_run":False})
        if disc.get("discarded") is not True: raise RuntimeError("synthetic release discard failed")
    return {"tool_count":55,"normal_admin_separation":"PASS","invalid_token_denied":"PASS","workspace_close":"PASS","validation_wait_result":"PASS","snapshot_grouping":"PASS","selector_metadata":"PASS","admin_reconnect_persistence":"PASS","remote_activate_absent":"PASS"}

def launch_isolated(candidate:Path,expected_sha:str):
    if fsha(candidate)!=expected_sha: raise RuntimeError("candidate hash mismatch before isolated launch")
    work=Path(tempfile.mkdtemp(prefix="mcp261-isolated-",dir=str(candidate.parent))).resolve(); bridge=work/"bridge"; desktop=work/"Desktop"; tunnel=work/"tunnel"; repo=work/"repo"; bare=work/"remote.git"; home=work/"home"; tmp=work/"tmp"
    for d in (bridge,desktop,tunnel,home,tmp,home/"Documents"/"Ledger Forge"/"Originals",home/"Library"/"Developer"/"Xcode"/"DerivedData",home/".config"/"tunnel-client"): d.mkdir(parents=True,exist_ok=True)
    init_repo(repo,bare)
    state=bridge/(".executor-runs-v2_1-qualification-"+uuid.uuid4().hex); state.mkdir(); shutil.copy2(candidate,bridge/"executor_v2_1.py"); (desktop/"LedgerForge MCP.command").write_text("#!/bin/zsh\nexit 0\n"); (desktop/"LedgerForge MCP.command").chmod(0o700)
    normal=secrets.token_urlsafe(48); admin=secrets.token_urlsafe(48)
    while admin==normal: admin=secrets.token_urlsafe(48)
    path="/mcp_qualification_261_"+uuid.uuid4().hex; port=free_port()
    env={"HOME":str(home),"TMPDIR":str(tmp),"PATH":"/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin","USER":os.environ.get("USER",""),"LOGNAME":os.environ.get("LOGNAME",""),"LANG":os.environ.get("LANG","en_US.UTF-8")}
    for k in ("LC_ALL","DEVELOPER_DIR","SDKROOT","TOOLCHAINS","TERM"):
        if os.environ.get(k): env[k]=os.environ[k]
    env.update({"LEDGERFORGE_EXECUTOR_BRIDGE_ROOT":str(bridge),"LEDGERFORGE_EXECUTOR_MAINTENANCE_DESKTOP":str(desktop),"LEDGERFORGE_EXECUTOR_MAINTENANCE_TUNNEL_CONFIG":str(tunnel),"LEDGERFORGE_EXECUTOR_REPO_ROOT":str(repo),"LEDGERFORGE_EXECUTOR_EXPECTED_REMOTE_URL":str(bare),"LEDGERFORGE_EXECUTOR_STATE_ROOT":str(state),"LEDGERFORGE_EXECUTOR_MCP_PATH":path,"LEDGERFORGE_EXECUTOR_MCP_HOST":"127.0.0.1","LEDGERFORGE_EXECUTOR_BEARER_TOKEN":normal,"LEDGERFORGE_EXECUTOR_ADMIN_BEARER_TOKEN":admin,"LEDGERFORGE_EXECUTOR_PUBLIC_URL":f"https://localhost:{port}","LEDGERFORGE_EXECUTOR_PORT":str(port)})
    cmd=[sys.executable,str(candidate)]
    proc=subprocess.Popen(cmd,cwd=work,env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,start_new_session=True)
    try:
        deadline=time.monotonic()+30
        while time.monotonic()<deadline:
            s=socket.socket(); s.settimeout(.2)
            try:
                if s.connect_ex(("127.0.0.1",port))==0: break
            finally: s.close()
            if proc.poll() is not None: raise RuntimeError("isolated executor exited:\n"+(proc.stdout.read() if proc.stdout else ""))
            time.sleep(.2)
        else: raise RuntimeError("isolated executor did not listen")
        result=asyncio.run(isolated_calls(port,path,normal,admin,expected_sha,state,desktop)); print("MCP 2.6.1 ISOLATED HTTP QUALIFICATION: PASS"); print(json.dumps(result,sort_keys=True))
    finally:
        try: os.killpg(proc.pid,15)
        except Exception: pass
        try: proc.wait(timeout=5)
        except Exception:
            try: os.killpg(proc.pid,9)
            except Exception: pass
        shutil.rmtree(work,ignore_errors=True)

def persisted_identity(admin=False):
    path_file=ROOT/".executor-path"
    if not path_file.is_file(): path_file=ROOT/".mcp-path"
    token_file=ROOT/(".executor-admin-token" if admin else ".executor-token")
    return path_file.read_text().strip(),token_file.read_text().strip()

async def live_schema(port,expected_sha,admin=False,smoke=False):
    path,token=persisted_identity(admin)
    async with open_session(port,path,token) as s:
        caps=await assert_schema(s,expected_sha)
        if admin:
            ms=await call(s,"maintenance_status",{})
            if ms.get("admin_scope_verified") is not True: raise RuntimeError("live admin scope failed")
        if smoke:
            h=await call(s,"executor_help",{"topic":"overview"}); snap=await call(s,"execution_snapshot",{"max_bytes":120000})
            if h.get("executor_version")!="2.6.1" or "cleanup_safe" not in snap: raise RuntimeError("live smoke failed")
        return caps

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--candidate"); ap.add_argument("--expected-source-sha",required=True); ap.add_argument("--port",type=int,default=8768); ap.add_argument("--schema-only-live",action="store_true"); ap.add_argument("--live-smoke",action="store_true"); ap.add_argument("--admin-smoke-live",action="store_true"); ap.add_argument("--recovery-status-live",action="store_true"); a=ap.parse_args()
    if a.schema_only_live:
        c=asyncio.run(live_schema(a.port,a.expected_source_sha)); print("MCP 2.6.1 LIVE SCHEMA QUALIFICATION: PASS"); print(json.dumps(c,sort_keys=True)); return
    if a.live_smoke:
        c=asyncio.run(live_schema(a.port,a.expected_source_sha,smoke=True)); print("MCP 2.6.1 LIVE SMOKE: PASS"); print(json.dumps(c,sort_keys=True)); return
    if a.admin_smoke_live:
        c=asyncio.run(live_schema(a.port,a.expected_source_sha,admin=True,smoke=True)); print("MCP 2.6.1 LIVE ADMIN SMOKE: PASS"); print(json.dumps(c,sort_keys=True)); return
    if a.recovery_status_live:
        path,token=persisted_identity(False)
        async def r():
            async with open_session(a.port,path,token) as s: return await call(s,"executor_recovery_status",{})
        print(json.dumps(asyncio.run(r()),indent=2,sort_keys=True)); return
    if not a.candidate: raise SystemExit("--candidate is required for isolated qualification")
    launch_isolated(Path(a.candidate).resolve(),a.expected_source_sha)

if __name__=="__main__": main()
