#!/usr/bin/env python3
from __future__ import annotations
import argparse, asyncio, hashlib, importlib.util, json, os, shutil, subprocess, sys, uuid
from pathlib import Path

EXPECTED_TOOLS = 55
NORMAL = "mcp261-normal-qualification-token-000000000000000000000001"
ADMIN = "mcp261-admin-qualification-token-000000000000000000000002"

def run(cmd, cwd=None):
    p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, check=False, timeout=60)
    if p.returncode != 0:
        raise RuntimeError("command failed: " + " ".join(map(str, cmd)) + "\n" + p.stdout[-4000:] + "\n" + p.stderr[-4000:])
    return p

def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

def init_repo(repo: Path, bare: Path) -> None:
    repo.mkdir(parents=True, exist_ok=True)
    (repo / "README.md").write_text("MCP 2.6.1 synthetic qualification\n", encoding="utf-8")
    script_dir = repo / "script"
    script_dir.mkdir()
    validate = script_dir / "validate.sh"
    validate.write_text("#!/bin/sh\nset -eu\nexit 0\n", encoding="utf-8")
    validate.chmod(0o700)
    run(["git", "init", "-b", "main"], repo)
    run(["git", "config", "user.name", "MCP Qualification"], repo)
    run(["git", "config", "user.email", "mcp-qualification@example.invalid"], repo)
    run(["git", "add", "README.md", "script/validate.sh"], repo)
    run(["git", "commit", "-m", "Synthetic baseline"], repo)
    run(["git", "init", "--bare", str(bare)])
    run(["git", "remote", "add", "origin", str(bare)], repo)
    run(["git", "push", "-u", "origin", "main"], repo)
    run(["git", "fetch", "origin"], repo)

def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--prepared-slot", required=True)
    a = ap.parse_args()
    slot = Path(a.prepared_slot).resolve()
    result_path = slot / "qualification-result.json"
    try:
        candidate = slot / "executor_v2_1.py"
        staticq = slot / "qualify_executor_current_static.py"
        assert candidate.is_file() and not candidate.is_symlink()
        assert staticq.is_file() and not staticq.is_symlink()
        candidate_sha = sha(candidate)
        repo = slot / "qualification-repo"
        bare = slot / "qualification-bare.git"
        bridge = slot / "qualification-bridge"
        desktop = slot / "qualification-desktop"
        tunnel_cfg = slot / "qualification-tunnel-config"
        for p in (repo, bare, bridge, desktop, tunnel_cfg):
            if p.exists(): shutil.rmtree(p)
        bridge.mkdir(mode=0o700)
        desktop.mkdir(mode=0o700)
        tunnel_cfg.mkdir(mode=0o700)
        init_repo(repo, bare)
        state = bridge / ".executor-runs-v2_1-qualification-261"
        state.mkdir(mode=0o700)
        admin_file = bridge / ".executor-admin-token"
        admin_file.write_text(ADMIN + "\n", encoding="utf-8")
        admin_file.chmod(0o600)
        assert (admin_file.stat().st_mode & 0o077) == 0
        admin_from_file = admin_file.read_text(encoding="utf-8").strip()
        assert admin_from_file == ADMIN
        os.environ.update({
            "LEDGERFORGE_EXECUTOR_BRIDGE_ROOT": str(bridge),
            "LEDGERFORGE_EXECUTOR_MAINTENANCE_DESKTOP": str(desktop),
            "LEDGERFORGE_EXECUTOR_MAINTENANCE_TUNNEL_CONFIG": str(tunnel_cfg),
            "LEDGERFORGE_EXECUTOR_REPO_ROOT": str(repo),
            "LEDGERFORGE_EXECUTOR_EXPECTED_REMOTE_URL": str(bare),
            "LEDGERFORGE_EXECUTOR_STATE_ROOT": str(state),
            "LEDGERFORGE_EXECUTOR_MCP_PATH": "/mcp_qualification_261",
            "LEDGERFORGE_EXECUTOR_MCP_HOST": "127.0.0.1",
            "LEDGERFORGE_EXECUTOR_BEARER_TOKEN": NORMAL,
            "LEDGERFORGE_EXECUTOR_ADMIN_BEARER_TOKEN": admin_from_file,
            "LEDGERFORGE_EXECUTOR_PUBLIC_URL": "https://localhost:8999",
            "LEDGERFORGE_EXECUTOR_PORT": "8999",
        })
        static_run = subprocess.run([sys.executable, str(staticq), str(candidate)], cwd=slot, capture_output=True, text=True, check=False, timeout=120)
        if static_run.returncode != 0:
            raise RuntimeError("prepared static qualifier failed: " + static_run.stdout[-4000:] + static_run.stderr[-4000:])
        spec = importlib.util.spec_from_file_location("mcp261_candidate", candidate)
        if spec is None or spec.loader is None: raise RuntimeError("candidate import spec failed")
        mod = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = mod
        spec.loader.exec_module(mod)
        assert mod.EXECUTOR_VERSION == "2.6.1"
        assert mod.TOOLSET_REVISION == 8
        assert mod.SCHEMA_CONTRACT_REVISION == "2.6.1"
        assert len(mod.TOOL_ANNOTATION_CONTRACT) == EXPECTED_TOOLS
        assert mod.ADMIN_BEARER_TOKEN == ADMIN
        caps = mod.executor_capabilities()
        assert caps["executor_version"] == "2.6.1" and caps["toolset_revision"] == 8
        fingerprint = caps["fingerprint_contract"]
        assert fingerprint["worktree_revision"] == "2"
        assert fingerprint["index_revision"] == "1"
        assert caps["admin_maintenance"]["configured"] is True
        verifier = mod.StaticBearerVerifier(NORMAL, ADMIN)
        normal_access = asyncio.run(verifier.verify_token(NORMAL))
        admin_access = asyncio.run(verifier.verify_token(ADMIN))
        bad_access = asyncio.run(verifier.verify_token("x" * 64))
        assert normal_access is not None and normal_access.scopes == ["ledgerforge:execute"]
        assert admin_access is not None and set(admin_access.scopes) == {"ledgerforge:execute", "ledgerforge:admin"}
        assert bad_access is None
        mod.get_access_token = lambda: normal_access
        try:
            mod.maintenance_status()
        except PermissionError:
            pass
        else:
            raise RuntimeError("normal token obtained admin maintenance authority")
        mod.get_access_token = lambda: admin_access
        mstatus = mod.maintenance_status()
        assert mstatus["admin_scope_verified"] is True
        assert mstatus["cross_chat_resume"]["supported"] is True
        assert mstatus["cross_chat_resume"]["conversation_id_required"] is False
        assert mstatus["credential_values_exposed"] is False
        (tunnel_cfg / "ledgerforge-executor.log").write_text("diag-token=" + ADMIN + "\n", encoding="utf-8")
        try:
            mod.maintenance_file_inspect("executor_log", "read_bytes")
        except PermissionError:
            pass
        else:
            raise RuntimeError("raw maintenance log bytes were exposed")
        redacted_log = mod.maintenance_file_inspect("executor_log", "read_text")
        assert redacted_log["credential_values_exposed"] is False and ADMIN not in redacted_log.get("text", "")
        help_result = mod.executor_help("maintenance")
        assert help_result["executor_version"] == "2.6.1"
        discovered = mod.test_discovery(max_results=50)
        assert discovered["selector_capabilities"]["zero_test_result_is_acceptance"] is False
        assert "swift_testing_method_selector" in discovered["selector_capabilities"]
        wid = str(uuid.uuid4())
        mod.task_workspace(str(uuid.uuid4()), wid, "create", task_label="mcp261-release-qualification")
        fake_run = str(uuid.uuid4())
        fake_state = mod.LOCAL_PROCESS_STATES / f"{fake_run}.json"
        mod.atomic_write_json(fake_state, {"run_id": fake_run, "workspace_id": wid, "status": "running"})
        blocked = mod.task_workspace(str(uuid.uuid4()), wid, "close", wait_seconds=0)
        assert blocked["closed"] is False and blocked["cleanup_safe"] is False and blocked["exists_after"] is True
        mod.atomic_write_json(fake_state, {"run_id": fake_run, "workspace_id": wid, "status": "completed"})
        closed = mod.task_workspace(str(uuid.uuid4()), wid, "close", wait_seconds=0)
        assert closed["closed"] is True and closed["cleaned"] is True and closed["exists_after"] is False
        baseline_snap = mod.execution_snapshot(max_bytes=120000)
        assert baseline_snap["snapshot_schema_revision"] == "execution-snapshot-v2"
        assert "processes" in baseline_snap and "task_workspaces" in baseline_snap and "cleanup_safe" in baseline_snap
        snapshot_fingerprint = baseline_snap["executor"]["fingerprint_contract"]
        assert snapshot_fingerprint["worktree_revision"] == "2"
        assert snapshot_fingerprint["index_revision"] == "1"
        baseline_machine_digest = baseline_snap["machine_state_digest"]
        baseline_continuation_digest = baseline_snap["continuation_digest"]

        stress_state_paths = []
        stress_workspace_ids = []
        active_wid = str(uuid.uuid4())
        mod.task_workspace(str(uuid.uuid4()), active_wid, "create", task_label="snapshot-stress-active")
        stress_workspace_ids.append(active_wid)
        for _ in range(40):
            rid = str(uuid.uuid4())
            path = mod.LOCAL_PROCESS_STATES / f"{rid}.json"
            mod.atomic_write_json(path, {"run_id":rid,"operation_id":str(uuid.uuid4()),"workspace_id":active_wid,"status":"completed","classification":"expected_exit","started_at":mod.now_iso(),"completed_at":mod.now_iso()})
            stress_state_paths.append(path)
        for wi in range(48):
            swid = str(uuid.uuid4())
            mod.task_workspace(str(uuid.uuid4()), swid, "create", task_label=f"snapshot-stress-idle-{wi:02d}")
            stress_workspace_ids.append(swid)
            for _ in range(24):
                rid = str(uuid.uuid4())
                path = mod.LOCAL_PROCESS_STATES / f"{rid}.json"
                mod.atomic_write_json(path, {"run_id":rid,"operation_id":str(uuid.uuid4()),"workspace_id":swid,"status":"completed","classification":"expected_exit","started_at":mod.now_iso(),"completed_at":mod.now_iso()})
                stress_state_paths.append(path)

        history_snap = mod.execution_snapshot(max_bytes=120000)
        assert history_snap["machine_state_digest"] == baseline_machine_digest
        assert history_snap["continuation_digest"] == baseline_continuation_digest
        assert history_snap["processes"]["history_truncated"] is True
        assert history_snap["processes"]["total_count"] >= 1192
        assert history_snap["task_workspace_presentation"]["history_truncated"] is True
        assert history_snap["task_workspace_presentation"]["total_count"] >= 49

        running_id = str(uuid.uuid4())
        running_path = mod.LOCAL_PROCESS_STATES / f"{running_id}.json"
        mod.atomic_write_json(running_path, {"run_id":running_id,"operation_id":str(uuid.uuid4()),"workspace_id":active_wid,"status":"running","classification":None,"started_at":mod.now_iso(),"completed_at":None})
        stress_state_paths.append(running_path)
        snap = mod.execution_snapshot(max_bytes=120000)
        rendered_snapshot_bytes = len(json.dumps(snap, sort_keys=True, separators=(",", ":")).encode("utf-8"))
        assert rendered_snapshot_bytes <= 120000
        assert snap["cleanup_safe"] is False
        assert snap["processes"]["running_count"] >= 1
        assert any(row.get("run_id") == running_id for row in snap["processes"]["running"])
        assert any(row.get("run_id") == running_id for row in snap["processes"]["owned"])
        active_rows = [row for row in snap["task_workspaces"] if row.get("workspace_id") == active_wid]
        assert len(active_rows) == 1
        assert running_id in active_rows[0]["running_process_ids"]
        assert running_id in active_rows[0]["owned_process_ids"]
        assert active_rows[0]["owned_process_count"] >= 41
        assert active_rows[0]["owned_process_ids_truncated"] is True

        for path in stress_state_paths:
            path.unlink(missing_ok=True)
        for swid in stress_workspace_ids:
            shutil.rmtree(mod.TASK_WORKSPACE_ROOT / swid, ignore_errors=True)
        post_stress_snap = mod.execution_snapshot(max_bytes=120000)
        assert post_stress_snap["machine_state_digest"] == baseline_machine_digest
        assert post_stress_snap["continuation_digest"] == baseline_continuation_digest
        lease = mod.execution_lease_status()
        assert "safe_to_release" in lease and "associated_live_processes" in lease
        live_source = bridge / "executor_v2_1.py"
        live_launcher = desktop / "LedgerForge MCP.command"
        live_source.write_bytes(candidate.read_bytes())
        live_launcher.write_text("#!/bin/zsh\nexit 0\n", encoding="utf-8")
        incomplete_id = "qual-incomplete"
        releaseq = slot / "qualify_release.py"
        assert releaseq.is_file() and not releaseq.is_symlink()
        b64 = __import__("base64").b64encode
        incomplete_components = [
            {"role":"executor","sha256":candidate_sha,"content_base64":b64(candidate.read_bytes()).decode("ascii")},
            {"role":"static_qualifier","sha256":sha(staticq),"content_base64":b64(staticq.read_bytes()).decode("ascii")},
            {"role":"release_qualifier","sha256":sha(releaseq),"content_base64":b64(releaseq.read_bytes()).decode("ascii")},
        ]
        stage_plan = mod.maintenance_release(str(uuid.uuid4()), incomplete_id, "stage", target_version="2.6.1", expected_current_source_sha256=sha(live_source), expected_current_launcher_sha256=sha(live_launcher), components=incomplete_components, dry_run=True)
        staged = mod.maintenance_release(str(uuid.uuid4()), incomplete_id, "stage", target_version="2.6.1", expected_current_source_sha256=sha(live_source), expected_current_launcher_sha256=sha(live_launcher), components=incomplete_components, dry_run=False, reviewed_plan_digest=stage_plan["reviewed_plan_digest"])
        state_path = mod._maintenance_release_state_path(incomplete_id)
        state = json.loads(state_path.read_text(encoding="utf-8")); state["status"]="qualified"; state["qualification"]={"passed":True}; mod.atomic_write_json(state_path,state)
        arm_plan = mod.maintenance_release(str(uuid.uuid4()), incomplete_id, "arm", expected_release_digest=staged["release_digest"], dry_run=True)
        expected_missing = ["isolated_qualifier", "main_launcher", "owner_admin", "owner_version", "owner_wrapper", "release_activator", "release_version"]
        assert arm_plan["complete_component_set"] is False and arm_plan["would_arm"] is False
        assert arm_plan["missing_activation_roles"] == expected_missing
        try:
            mod.maintenance_release(str(uuid.uuid4()), incomplete_id, "arm", expected_release_digest=staged["release_digest"], dry_run=False)
        except RuntimeError as exc:
            assert "complete activation component set" in str(exc)
        else:
            raise RuntimeError("incomplete activation component set was armed")
        secrets_rendered = json.dumps({"caps": caps, "status": mstatus, "snapshot": snap, "redacted_log": redacted_log}, sort_keys=True)
        assert NORMAL not in secrets_rendered and ADMIN not in secrets_rendered
        result = {
            "qualification": "PASS",
            "candidate_sha256": candidate_sha,
            "candidate_source_sha256": candidate_sha,
            "tool_count": EXPECTED_TOOLS,
            "identity": {"version": "2.6.1", "toolset_revision": 8, "schema_revision": "2.6.1"},
            "file_backed_admin_token": "PASS",
            "snapshot_large_history_bounded": "PASS",
            "snapshot_running_evidence_preserved": "PASS",
            "snapshot_digest_history_independence": "PASS",
            "file_to_environment_admin_token": "PASS",
            "normal_admin_scope_separation": "PASS",
            "redacted_log_read": "PASS",
            "incomplete_arm_rejection": "PASS",
            "cross_chat_maintenance_state": "PASS",
            "workspace_close": "PASS",
            "owned_resource_snapshot": "PASS",
            "selector_capability_metadata": "PASS",
            "fingerprint_revision_metadata": "PASS",
            "network_used": False,
            "product_repo_used": False,
        }
        result_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print("MCP 2.6.1 PREPARED-SLOT QUALIFICATION: PASS")
        print(json.dumps(result, sort_keys=True))
    except Exception as exc:
        fail = {"qualification": "FAIL", "error_type": type(exc).__name__, "error": str(exc)}
        try: result_path.write_text(json.dumps(fail, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        except Exception: pass
        raise

if __name__ == "__main__": main()
