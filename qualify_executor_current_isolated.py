#!/usr/bin/env python3
from __future__ import annotations
import argparse, asyncio, base64, hashlib, inspect, json, os, secrets, shutil, socket, subprocess, sys, tempfile, time, uuid
from contextlib import asynccontextmanager
from pathlib import Path

EXPECTED_TOOLS={
"workspace_projects","executor_capabilities","host_status","workspace_state","execution_lease_status","executor_recovery_status","execution_snapshot",
"acquire_execution_lease","heartbeat_execution_lease","resume_execution_lease","release_execution_lease","list_files","read_file","search_files","artifact_inspect","git_inspect","evidence_batch",
"apply_file_ops","git_fetch_origin","git_stage","precommit_privacy_scan","git_commit","adopt_publication_candidate","git_push","run_repo_task","start_validation","validation_status","validation_result","validation_wait_result","cancel_validation",
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

ROOT=Path(__file__).resolve().parent
PROJECT="repo"

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

async def call(session,name,args):
    if name not in {"workspace_projects","executor_capabilities","executor_help","host_status","maintenance_status","maintenance_file_inspect","maintenance_release"}:
        args={"project":PROJECT, **args}
    return parse_result(await session.call_tool(name,args))
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
    if (caps.get("executor_version"),caps.get("toolset_revision"),caps.get("schema_contract_revision"))!=("3.0.0",11,"3.0.0"): raise RuntimeError(f"identity mismatch: {caps}")
    if caps.get("source_sha256")!=expected_sha or caps.get("annotation_contract_count")!=57: raise RuntimeError("source/tool annotation identity mismatch")
    fp=caps.get("fingerprint_contract") or {}
    if fp.get("worktree_revision")!="2" or fp.get("index_revision")!="1": raise RuntimeError("fingerprint revision metadata missing")
    return caps

def init_repo(repo:Path,bare:Path):
    repo.mkdir(parents=True); (repo/"README.md").write_text("MCP 3.0.0 isolated qualification\n"); (repo/"SyntheticTests.swift").write_text("import Testing\n@Test func smoke() { #expect(true) }\n")
    script_dir=repo/"script"; script_dir.mkdir(); validate=script_dir/"validate.sh"; validate.write_text("#!/bin/sh\nset -eu\nexit 0\n"); validate.chmod(0o700)
    run(["git","init","-b","main"],repo); run(["git","config","user.name","MCP Qualification"],repo); run(["git","config","user.email","mcp-qualification@example.invalid"],repo); run(["git","add","."],repo); run(["git","commit","-m","Synthetic baseline"],repo)
    run(["git","init","--bare",str(bare)]); run(["git","remote","add","origin",str(bare)],repo); run(["git","push","-u","origin","main"],repo); run(["git","fetch","origin"],repo)

def free_port():
    s=socket.socket(); s.bind(("127.0.0.1",0)); p=s.getsockname()[1]; s.close(); return p

def _write_json(path: Path, value: dict) -> None:
    temp = path.with_name(path.name + ".tmp")
    temp.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temp.chmod(0o600)
    os.replace(temp, path)


async def _wait_validation(session, *, expected_head: str, lease_id: str, lease_token: str, state_root: Path) -> dict:
    """Bind deterministic successful test evidence without requiring Xcode."""
    lease = await call(session, "execution_lease_status", {})
    if lease.get("lease_id") != lease_id or not lease.get("execution_id"):
        raise RuntimeError(f"synthetic lease identity unavailable: {lease}")
    snapshot = await call(session, "workspace_state", {})
    run_id = str(uuid.uuid4())
    state = {
        "run_id": run_id,
        "lease_id": lease_id,
        "execution_id": lease["execution_id"],
        "status": "completed",
        "operation": "test-focused",
        "selectors": ["SyntheticTests/smoke"],
        "validation_intent": "execute_tests",
        "exit_code": 0,
        "repository_mutated": False,
        "publication_eligible": True,
        "ending_head": expected_head,
        "ending_worktree_fingerprint": snapshot["worktree_fingerprint"],
        "ending_index_fingerprint": snapshot["index_fingerprint"],
        "safe_test_summary": {"totalTestCount": 1, "synthetic": True},
        "xcresult_evidence": {"available": False, "synthetic": True},
        "failure_classification": None,
    }
    # The HTTP qualification focuses on recovery semantics; this durable state
    # is explicitly synthetic and does not claim a product/Xcode test result.
    _write_json(state_root / f"{run_id}.json", state)
    lease_path = state_root / "leases" / "active.json"
    durable_lease = json.loads(lease_path.read_text(encoding="utf-8"))
    if durable_lease.get("lease_id") != lease_id:
        raise RuntimeError("synthetic validation lease changed before binding")
    durable_lease["validated_state"] = {
        "run_id": run_id,
        "head": expected_head,
        "worktree_fingerprint": state["ending_worktree_fingerprint"],
        "index_fingerprint": state["ending_index_fingerprint"],
        "exit_code": 0,
        "repository_mutated": False,
        "failure_classification": None,
        "operation": "test-focused",
        "validation_intent": "execute_tests",
        "publication_eligible": True,
        "bound_at": state.get("completed_at"),
    }
    durable_lease["active_validation_run_id"] = None
    _write_json(lease_path, durable_lease)
    return {
        "run_id": run_id,
        "lease_id": lease_id,
        "execution_id": lease["execution_id"],
        "status": "completed",
        "operation": "test-focused",
        "selectors": state["selectors"],
        "validation_intent": "execute_tests",
        "starting_head": expected_head,
        "ending_head": expected_head,
        "ending_worktree_fingerprint": state["ending_worktree_fingerprint"],
        "ending_index_fingerprint": state["ending_index_fingerprint"],
        "exit_code": 0,
        "failure_classification": None,
        "repository_mutated": False,
        "safe_test_summary": state["safe_test_summary"],
        "xcresult_evidence": state["xcresult_evidence"],
        "validation_binding_failed": False,
        "provenance_label": None,
        "private_result_contract": None,
        "private_result_captured": False,
    }


async def _publication_adoption_flow(session, repo: Path, bare: Path, state_root: Path) -> dict:
    """Prove interrupted commit recovery through explicit adoption and managed push."""
    before = await call(session, "workspace_state", {})
    head_a = before.get("head")
    if not head_a or before.get("main") != head_a or before.get("origin_main") != head_a:
        raise RuntimeError(f"synthetic baseline is not converged: {before}")

    # A disposable harness mutation stands in for the approved file-operation path;
    # all Git writes below still go through the managed MCP capabilities.
    readme = repo / "README.md"
    readme.write_text(readme.read_text(encoding="utf-8") + "interrupted publication adoption\n", encoding="utf-8")
    changed = await call(session, "workspace_state", {})
    lease_a = await call(session, "acquire_execution_lease", {
        "operation_id": str(uuid.uuid4()),
        "expected_head": head_a,
        "expected_worktree_fingerprint": changed["worktree_fingerprint"],
        "authorization_digest": "a" * 64,
        "owner_label": "isolated-publication-lease-a",
    })
    lease_a_id, lease_a_token = lease_a["lease_id"], lease_a["lease_token"]
    validated_a = await _wait_validation(session, expected_head=head_a, lease_id=lease_a_id, lease_token=lease_a_token, state_root=state_root)
    index_before_stage = (await call(session, "workspace_state", {}))["index_fingerprint"]
    staged = await call(session, "git_stage", {
        "operation_id": str(uuid.uuid4()),
        "expected_head": head_a,
        "expected_worktree_fingerprint": validated_a["ending_worktree_fingerprint"],
        "expected_index_fingerprint": index_before_stage,
        "lease_id": lease_a_id,
        "lease_token": lease_a_token,
        "paths": ["README.md"],
        "dry_run": False,
    })
    head_a_after_stage = staged.get("head")
    if head_a_after_stage != head_a or staged.get("staged_paths") != ["README.md"]:
        raise RuntimeError(f"managed stage did not bind expected path: {staged}")
    index_after_stage = staged["index_fingerprint_after"]
    committed = await call(session, "git_commit", {
        "operation_id": str(uuid.uuid4()),
        "expected_head": head_a,
        "expected_index_fingerprint": index_after_stage,
        "expected_staged_paths": ["README.md"],
        "lease_id": lease_a_id,
        "lease_token": lease_a_token,
        "message": "Synthetic interrupted publication candidate",
        "dry_run": False,
    })
    head_b = committed.get("head")
    if not head_b or head_b == head_a or committed.get("remaining_staged_paths"):
        raise RuntimeError(f"managed commit did not produce clean B: {committed}")
    after_commit = await call(session, "workspace_state", {})
    if after_commit.get("origin_main") != head_a or after_commit.get("head") != head_b:
        raise RuntimeError(f"synthetic commit relationship is not A->B: {after_commit}")

    # Simulate interruption/lease loss before publication. A fresh lease must not
    # inherit the old lease's publication candidate implicitly.
    await call(session, "release_execution_lease", {
        "operation_id": str(uuid.uuid4()),
        "lease_id": lease_a_id,
        "lease_token": lease_a_token,
    })
    resumed_state = await call(session, "workspace_state", {})
    lease_b = await call(session, "acquire_execution_lease", {
        "operation_id": str(uuid.uuid4()),
        "expected_head": head_b,
        "expected_worktree_fingerprint": resumed_state["worktree_fingerprint"],
        "authorization_digest": "b" * 64,
        "owner_label": "isolated-publication-lease-b",
    })
    lease_b_id, lease_b_token = lease_b["lease_id"], lease_b["lease_token"]
    validated_b = await _wait_validation(session, expected_head=head_b, lease_id=lease_b_id, lease_token=lease_b_token, state_root=state_root)
    fetched = await call(session, "git_fetch_origin", {
        "operation_id": str(uuid.uuid4()),
        "expected_head": head_b,
        "lease_id": lease_b_id,
        "lease_token": lease_b_token,
    })
    if fetched.get("origin_main_after") != head_a:
        raise RuntimeError(f"fresh origin fetch unexpectedly changed synthetic baseline: {fetched}")

    expected_wt = validated_b["ending_worktree_fingerprint"]
    expected_index = validated_b["ending_index_fingerprint"]
    push_args = {
        "expected_head": head_b,
        "expected_origin_main": head_a,
        "lease_id": lease_b_id,
        "lease_token": lease_b_token,
    }
    dry_before = await call(session, "git_push", {"operation_id": str(uuid.uuid4()), **push_args, "dry_run": True})
    if dry_before.get("publication_candidate_present") is not False:
        raise RuntimeError(f"fresh lease unexpectedly inherited publication candidate: {dry_before}")
    if not await expect_error(session, "git_push", {"operation_id": str(uuid.uuid4()), **push_args, "dry_run": False}):
        raise RuntimeError("managed push accepted a validated existing commit before adoption")

    state_before_adoption = await call(session, "workspace_state", {})
    adoption_args = {
        "expected_head": head_b,
        "expected_worktree_fingerprint": expected_wt,
        "expected_index_fingerprint": expected_index,
        "expected_origin_main": head_a,
        "lease_id": lease_b_id,
        "lease_token": lease_b_token,
    }
    adoption_plan = await call(session, "adopt_publication_candidate", {
        "operation_id": str(uuid.uuid4()), **adoption_args, "dry_run": True,
    })
    if adoption_plan.get("dry_run") is not True:
        raise RuntimeError(f"adoption dry-run did not remain non-mutating: {adoption_plan}")
    adopted = await call(session, "adopt_publication_candidate", {
        "operation_id": str(uuid.uuid4()), **adoption_args, "dry_run": False,
    })
    candidate = adopted.get("publication_candidate") if isinstance(adopted.get("publication_candidate"), dict) else adopted
    if candidate.get("commit_head") != head_b:
        raise RuntimeError(f"adopted candidate is not bound to B: {adopted}")
    if candidate.get("expected_origin_main", candidate.get("previous_head")) != head_a:
        raise RuntimeError(f"adopted candidate lost expected origin A: {adopted}")
    if candidate.get("source") != "adopted-existing-commit":
        raise RuntimeError(f"adoption provenance missing: {adopted}")
    if candidate.get("validation_run_id") != validated_b.get("run_id"):
        raise RuntimeError(f"adoption validation binding missing: {adopted}")
    if candidate.get("validated_head") != head_b:
        raise RuntimeError(f"adoption validated HEAD binding missing: {adopted}")
    if candidate.get("validated_worktree_fingerprint") not in {None, expected_wt}:
        raise RuntimeError(f"adoption worktree binding changed: {adopted}")
    if candidate.get("validated_index_fingerprint") not in {None, expected_index}:
        raise RuntimeError(f"adoption index binding changed: {adopted}")
    state_after_adoption = await call(session, "workspace_state", {})
    for key in ("head", "main", "origin_main", "worktree_fingerprint", "index_fingerprint", "staged_files", "conflicted_files", "active_git_operation"):
        if state_after_adoption.get(key) != state_before_adoption.get(key):
            raise RuntimeError(f"adoption mutated repository state {key}: before={state_before_adoption.get(key)!r} after={state_after_adoption.get(key)!r}")

    dry_after = await call(session, "git_push", {"operation_id": str(uuid.uuid4()), **push_args, "dry_run": True})
    if dry_after.get("publication_candidate_present") is not True:
        raise RuntimeError(f"managed push did not observe adopted candidate: {dry_after}")
    pushed = await call(session, "git_push", {"operation_id": str(uuid.uuid4()), **push_args, "dry_run": False})
    if pushed.get("post_push_converged") is not True or pushed.get("origin_main") != head_b:
        raise RuntimeError(f"managed push failed to converge after adoption: {pushed}")
    final_state = await call(session, "workspace_state", {})
    if not (final_state.get("head") == final_state.get("main") == final_state.get("origin_main") == head_b):
        raise RuntimeError(f"post-adoption convergence failed: {final_state}")
    if final_state.get("main_ahead_of_origin_main") != 0 or final_state.get("main_behind_origin_main") != 0:
        raise RuntimeError(f"post-adoption ahead/behind not zero: {final_state}")
    remote_head = run(["git", "--git-dir", str(bare), "rev-parse", "refs/heads/main"]).stdout.strip()
    if remote_head != head_b:
        raise RuntimeError(f"bare origin did not converge to B: {remote_head} != {head_b}")
    return {
        "interrupted_commit_head": head_b,
        "origin_before": head_a,
        "validation_run_id": validated_b.get("run_id"),
        "adoption_source": candidate.get("source"),
        "candidate_committed_paths": candidate.get("committed_paths", []),
        "post_push_converged": True,
        "repository_unchanged_during_adoption": True,
    }


async def qualify_project_routing(s, root, http_only):
    """Exercise the same authenticated transport used by the registered clients."""
    def nonce(): return str(uuid.uuid4())
    base=root/"routing"
    nested=base/"nested"; bare=root/"routing-origin.git"
    init_repo(base,bare)
    init_repo(nested,root/"nested-origin.git")
    (base/"script/test.sh").write_text("#!/bin/sh\ntest -s README.md\n")
    # Rename the publication branch to exercise an actual non-main fast-forward.
    run(["git","branch","-m","trunk"],nested)
    run(["git","push","-u","origin","trunk"],nested)
    (nested/"script/test.sh").write_text("#!/bin/sh\ntest -s README.md\n")
    run(["git","add","script/test.sh"],nested);run(["git","commit","-m","Test entry point"],nested);run(["git","push","origin","trunk"],nested)
    first,second = await asyncio.gather(call(s,"workspace_state",{"project":"routing"}),call(s,"workspace_state",{"project":"routing/nested"}))
    assert first["project"]=="routing" and second["project"]=="routing/nested" and second["publication_branch"]=="trunk"
    assert first["worktree_fingerprint"]!=second["worktree_fingerprint"]
    direct=await s.call_tool("workspace_state",{}); assert getattr(direct,"is_error",False) or getattr(direct,"isError",False)
    options=await call(s,"workspace_projects",{})
    assert {"routing","routing/nested"}<=set(r["project"] for r in options["projects"])
    (root/"new-project").mkdir()
    options=await call(s,"workspace_projects",{})
    assert "new-project" in {r["project"] for r in options["projects"]}
    for invalid in ("../x",str(nested),"routing/../routing","routing/.git"):
        assert await expect_error(s,"workspace_state",{"project":invalid})
    assert await expect_error(s,"read_file",{"project":"routing","path":"nested/README.md"})
    assert await expect_error(s,"test_discovery",{"project":"routing"})
    assert await expect_error(s,"read_file",{"project":"routing","root_id":"workspace","path":"bridge/.executor-admin-token"})
    listing=await call(s,"list_files",{"project":"routing","root_id":"workspace","path":"routing","glob":"*/README.md"})
    assert "routing/nested/README.md" in listing["files"]
    scope={"project":"routing/nested"}
    lease=await call(s,"acquire_execution_lease",{**scope,"operation_id":nonce(),"authorization_digest":"e"*64,"expected_head":second["head"],"expected_worktree_fingerprint":second["worktree_fingerprint"]})
    capability={k:lease[k] for k in ("lease_id","lease_token")}
    assert await expect_error(s,"heartbeat_execution_lease",{"project":"routing",**capability,"operation_id":nonce()})
    content="project isolation test\n"
    changes=[{"op":"create","path":"routing-check.txt","content":content}]
    request={**scope,**capability,"expected_head":second["head"],"expected_worktree_fingerprint":second["worktree_fingerprint"],"operations":changes}
    plan=await call(s,"apply_file_ops",{**request,"operation_id":nonce(),"dry_run":True})
    await call(s,"apply_file_ops",{**request,"operation_id":nonce(),"dry_run":False,"reviewed_plan_digest":plan["patch_plan_digest"]})
    assert (nested/"routing-check.txt").read_text()==content and not (base/"routing-check.txt").exists()
    if not http_only:
        validation=await call(s,"start_validation",{**scope,**capability,"operation":"test-full","expected_head":second["head"],"operation_id":nonce()})
        await call(s,"validation_wait_result",{**scope,"run_id":validation["run_id"],"wait_seconds":30})
        done=await call(s,"validation_status",{**scope,"run_id":validation["run_id"]})
        assert done.get("exit_code")==0 and done.get("repository_mutated") is False, {k:done.get(k) for k in ["exit_code","status","error_message"]}
        assert await expect_error(s,"validation_status",{"project":"routing","run_id":validation["run_id"]})
        snap=await call(s,"workspace_state",scope)
        await call(s,"git_stage",{**scope,**capability,"operation_id":nonce(),"paths":["routing-check.txt"],"dry_run":False,"expected_head":second["head"],"expected_worktree_fingerprint":snap["worktree_fingerprint"],"expected_index_fingerprint":snap["index_fingerprint"]})
        staged=await call(s,"workspace_state",scope)
        await call(s,"git_commit",{**scope,**capability,"operation_id":nonce(),"expected_head":second["head"],"expected_index_fingerprint":staged["index_fingerprint"],"expected_staged_paths":["routing-check.txt"],"message":"Check nested project routing","dry_run":False})
        committed=await call(s,"workspace_state",scope)
        await call(s,"git_push",{**scope,**capability,"operation_id":nonce(),"expected_head":committed["head"],"expected_origin_main":second["head"],"dry_run":False})
        assert run(["git","--git-dir",str(root/"nested-origin.git"),"rev-parse","trunk"]).stdout.strip()==committed["head"]
    await call(s,"release_execution_lease",{**scope,**capability,"operation_id":nonce()})
    return {"per_call_selection":True,"nested":True,"new_directory":True,"cross_project_lease_refused":True,
            "mutation":True,"generic_validation_and_publication":not http_only}


async def isolated_calls(port,path,normal,admin,expected_sha,state_root,desktop,repo,bare,http_only=False):
    async with open_session(port,path,normal) as s:
        caps=await assert_schema(s,expected_sha)
        isolated_root=state_root.parent.parent.resolve()
        roots=caps.get("evidence_roots") or {}
        for root_name in ("repo","workspace","derived_data","executor_artifacts","ledgerforge_logs","task_scratch"):
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
        # A full standalone run is mandatory before activation; the outer sandbox runs HTTP-only.
        if not http_only:
            wid=str(uuid.uuid4()); await call(s,"task_workspace",{"operation_id":str(uuid.uuid4()),"workspace_id":wid,"action":"create","task_label":"mcp264-http-close"})
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
                    if running.get("status")!="running":
                        detail=await call(s,"process_result",{"run_id":run_id,"max_bytes":12000})
                        fields={key:detail.get(key) for key in ("status","classification","error_type","error_message","exit_code","stderr")}
                        raise RuntimeError("process stopped before close probe: " + json.dumps(fields,sort_keys=True))
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
        adoption_result = await _publication_adoption_flow(s, repo, bare, state_root)
    if not await session_denied(port,path,"invalid-"+secrets.token_urlsafe(40)): raise RuntimeError("invalid token was accepted")
    if not await session_denied(port,path,None): raise RuntimeError("missing token was accepted")
    small={"executor":b"x","static_qualifier":b"y","release_qualifier":b"z"}; comps=[{"role":r,"sha256":sha(b),"content_base64":base64.b64encode(b).decode()} for r,b in small.items()]
    launcher_sha=fsha(desktop/"mcp_control.py"); release_id="http-reconnect-test"
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
    async with open_session(port,path,normal) as routed:
        routing=await qualify_project_routing(routed,repo.parent,http_only)
    return {"candidate_source_sha256":expected_sha,"routing":routing,"process_lifecycle_mode":"http-only" if http_only else "standalone","tool_count":57,"normal_admin_separation":"PASS","invalid_token_denied":"PASS","workspace_close":"REQUIRES_STANDALONE" if http_only else "PASS","validation_wait_result":"PASS","snapshot_grouping":"PASS","selector_metadata":"PASS","admin_reconnect_persistence":"PASS","remote_activate_absent":"PASS","publication_adoption":adoption_result}

def launch_isolated(candidate:Path,expected_sha:str,http_only=False):
    if fsha(candidate)!=expected_sha: raise RuntimeError("candidate hash mismatch before isolated launch")
    work=Path(tempfile.mkdtemp(prefix="mcp264-isolated-",dir=str(candidate.parent))).resolve(); bridge=work/"bridge"; desktop=work/"Desktop"; tunnel=work/"tunnel"; repo=work/"repo"; bare=work/"remote.git"; home=work/"home"; tmp=work/"tmp"
    for d in (bridge,desktop,tunnel,home,tmp,home/"Library"/"Developer"/"Xcode"/"DerivedData",home/".config"/"tunnel-client"): d.mkdir(parents=True,exist_ok=True)
    init_repo(repo,bare)
    state=bridge/(".executor-runs-v2_1-qualification-"+uuid.uuid4().hex); state.mkdir(); shutil.copy2(candidate,bridge/"executor_v2_1.py"); (desktop/"mcp_control.py").write_text("#!/bin/zsh\nexit 0\n"); (desktop/"mcp_control.py").chmod(0o700)
    normal=secrets.token_urlsafe(48); admin=secrets.token_urlsafe(48)
    while admin==normal: admin=secrets.token_urlsafe(48)
    path="/mcp_qualification_264_"+uuid.uuid4().hex; port=free_port()
    env={"HOME":str(home),"TMPDIR":str(tmp),"PATH":"/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin","USER":os.environ.get("USER",""),"LOGNAME":os.environ.get("LOGNAME",""),"LANG":os.environ.get("LANG","en_US.UTF-8")}
    for k in ("LC_ALL","DEVELOPER_DIR","SDKROOT","TOOLCHAINS","TERM"):
        if os.environ.get(k): env[k]=os.environ[k]
    env.update({"LEDGERFORGE_EXECUTOR_BRIDGE_ROOT":str(bridge),"LEDGERFORGE_EXECUTOR_MAINTENANCE_DESKTOP":str(desktop),"LEDGERFORGE_EXECUTOR_MAINTENANCE_TUNNEL_CONFIG":str(tunnel),"LEDGERFORGE_EXECUTOR_REPO_ROOT":str(repo),"LEDGERFORGE_EXECUTOR_EXPECTED_REMOTE_URL":str(bare),"LEDGERFORGE_EXECUTOR_STATE_ROOT":str(state),"LEDGERFORGE_EXECUTOR_MCP_PATH":path,"LEDGERFORGE_EXECUTOR_MCP_HOST":"127.0.0.1","LEDGERFORGE_EXECUTOR_BEARER_TOKEN":normal,"LEDGERFORGE_EXECUTOR_ADMIN_BEARER_TOKEN":admin,"LEDGERFORGE_EXECUTOR_PUBLIC_URL":f"https://localhost:{port}","LEDGERFORGE_EXECUTOR_PORT":str(port)})
    env.update({"GIT_CONFIG_NOSYSTEM":"1","GIT_CONFIG_GLOBAL":"/dev/null","GIT_CONFIG_SYSTEM":"/dev/null","GIT_TERMINAL_PROMPT":"0"})
    cmd=[sys.executable,str(candidate)]
    proc=subprocess.Popen(cmd,cwd=work,env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,start_new_session=True)
    import signal
    def terminate_qualification(signum, frame):
        raise SystemExit(128 + signum)
    previous_sigterm=signal.signal(signal.SIGTERM,terminate_qualification)
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
        result=asyncio.run(isolated_calls(port,path,normal,admin,expected_sha,state,desktop,repo,bare,http_only=http_only)); print("MCP 3.0.0 ISOLATED HTTP QUALIFICATION: PASS"); print(json.dumps(result,sort_keys=True))
    finally:
        try: os.killpg(proc.pid,15)
        except Exception: pass
        try: proc.wait(timeout=5)
        except Exception:
            try: os.killpg(proc.pid,9)
            except Exception: pass
        shutil.rmtree(work,ignore_errors=True)
        signal.signal(signal.SIGTERM,previous_sigterm)

def persisted_identity(admin=False):
    path_file=ROOT/".executor-path"
    if not path_file.is_file(): path_file=ROOT/".mcp-path"
    token_file=ROOT/(".executor-admin-token" if admin else ".executor-token")
    return path_file.read_text().strip(),token_file.read_text().strip()

async def live_schema(port,expected_sha,admin=False,smoke=False):
    global PROJECT
    PROJECT="LedgerForge"
    path,token=persisted_identity(admin)
    async with open_session(port,path,token) as s:
        caps=await assert_schema(s,expected_sha)
        if admin:
            ms=await call(s,"maintenance_status",{})
            if ms.get("admin_scope_verified") is not True: raise RuntimeError("live admin scope failed")
        if smoke:
            h=await call(s,"executor_help",{"topic":"overview"}); snap=await call(s,"execution_snapshot",{"max_bytes":120000})
            if h.get("executor_version")!="3.0.0" or "cleanup_safe" not in snap: raise RuntimeError("live smoke failed")
        return caps

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--candidate"); ap.add_argument("--http-only",action="store_true",help="HTTP-only peer under maintenance sandbox; never substitutes for standalone lifecycle qualification"); ap.add_argument("--expected-source-sha",required=True); ap.add_argument("--port",type=int,default=8768); ap.add_argument("--schema-only-live",action="store_true"); ap.add_argument("--live-smoke",action="store_true"); ap.add_argument("--admin-smoke-live",action="store_true"); ap.add_argument("--recovery-status-live",action="store_true"); a=ap.parse_args()
    if a.schema_only_live:
        c=asyncio.run(live_schema(a.port,a.expected_source_sha)); print("MCP 3.0.0 LIVE SCHEMA QUALIFICATION: PASS"); print(json.dumps(c,sort_keys=True)); return
    if a.live_smoke:
        c=asyncio.run(live_schema(a.port,a.expected_source_sha,smoke=True)); print("MCP 3.0.0 LIVE SMOKE: PASS"); print(json.dumps(c,sort_keys=True)); return
    if a.admin_smoke_live:
        c=asyncio.run(live_schema(a.port,a.expected_source_sha,admin=True,smoke=True)); print("MCP 3.0.0 LIVE ADMIN SMOKE: PASS"); print(json.dumps(c,sort_keys=True)); return
    if a.recovery_status_live:
        path,token=persisted_identity(False)
        async def r():
            async with open_session(a.port,path,token) as s: return await call(s,"executor_recovery_status",{})
        print(json.dumps(asyncio.run(r()),indent=2,sort_keys=True)); return
    if not a.candidate: raise SystemExit("--candidate is required for isolated qualification")
    launch_isolated(Path(a.candidate).resolve(),a.expected_source_sha,http_only=a.http_only)

if __name__=="__main__": main()
