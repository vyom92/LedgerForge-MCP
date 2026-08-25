#!/usr/bin/env python3
from __future__ import annotations
import ast, hashlib, sys
from pathlib import Path

EXPECTED = {
    "executor_capabilities","host_status","workspace_state","execution_lease_status","executor_recovery_status","execution_snapshot",
    "acquire_execution_lease","heartbeat_execution_lease","resume_execution_lease","release_execution_lease",
    "list_files","read_file","search_files","artifact_inspect","git_inspect","evidence_batch",
    "apply_file_ops","git_fetch_origin","git_stage","precommit_privacy_scan","git_commit","git_push","run_repo_task",
    "start_validation","validation_status","validation_result","cancel_validation","test_discovery","documentation_sync_preflight",
    "cycle_close_evidence","runtime_launch","runtime_status","runtime_logs","runtime_stop","test_impact_advisor","performance_probe",
    "swift_xcode_audit","repository_recovery_analysis","fixture_provenance_inspect","run_regression_campaign","private_context_matrix",
    "ci_status_inspection","executor_help","validation_wait_result","maintenance_status","maintenance_file_inspect","maintenance_release","local_fs_inspect","local_fs_mutate","task_workspace","process_start","process_status","process_wait","process_cancel","process_result",
}

def literal(tree,name):
    for n in tree.body:
        if isinstance(n,(ast.Assign,ast.AnnAssign)):
            targets=n.targets if isinstance(n,ast.Assign) else [n.target]
            if any(isinstance(t,ast.Name) and t.id==name for t in targets): return ast.literal_eval(n.value)
    raise AssertionError(name)

def tools(tree):
    out=set()
    for n in tree.body:
        if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)):
            for d in n.decorator_list:
                if isinstance(d,ast.Call) and isinstance(d.func,ast.Name) and d.func.id=="tool": out.add(n.name)
    return out

source=Path(sys.argv[1]).resolve(); data=source.read_bytes(); text=data.decode("utf-8"); tree=ast.parse(text,filename=str(source))
assert literal(tree,"EXECUTOR_VERSION")=="2.6.1"
assert literal(tree,"TOOLSET_REVISION")==8
assert literal(tree,"SCHEMA_CONTRACT_REVISION")=="2.6.1"
assert tools(tree)==EXPECTED,(sorted(EXPECTED-tools(tree)),sorted(tools(tree)-EXPECTED))
contract=literal(tree,"TOOL_ANNOTATION_CONTRACT")
assert set(contract)==EXPECTED
assert len(contract)==55
for name in ("local_fs_inspect","process_status","process_wait","process_result","executor_help","validation_wait_result","maintenance_status","maintenance_file_inspect"):
    assert contract[name]["read_only"] is True
for name in ("local_fs_mutate","task_workspace","process_start","process_cancel","maintenance_release"):
    assert contract[name]["read_only"] is False
assert "LEDGERFORGE_EXECUTOR_REPO_ROOT" in text
assert "LEDGERFORGE_EXECUTOR_EXPECTED_REMOTE_URL" in text
assert "GENERIC_FS_PLAN_VERSION" in text and "PROCESS_PLAN_VERSION" in text
assert 'Generic process execution requires /usr/bin/sandbox-exec' in text
assert 'credential-redaction-only-bounded-json' in text
assert 'Evidence batch requires no active mutable execution lease.' not in text
assert 'same_owner_active_lease' in text
assert 'binary-safe-filesystem' in text
assert 'task-workspaces' in text
assert 'reviewed-local-process' in text
assert 'binary_metadata' in text
assert 'deleted binary file sha256' not in text
assert 'repository-with-lease-excluding-dotgit' in text
assert 'snapshot-copied into task workspace' in text
assert 'deny file-read* (subpath' in text
assert 'deny file-write* (subpath' in text and '.git' in text
assert 'local-process' in text
assert 'cwd_root' in text and '${input:' in text

assert 'bind_validated_state(lease_id, lease_token, run_id, state)\n        except Exception:\n            state["validation_binding_failed"] = True\n        write_state(run_id, state)' in text
assert 'write_state(run_id, state)\n        try:\n            bind_validated_state(lease_id, lease_token, run_id, state)' not in text

assert 'def git_worktree_status_raw() -> str:' in text
assert '["git", "-C", str(REPO), "status", "--porcelain=v2", "--untracked-files=all", "-z"]' in text
assert '"ending_worktree_fingerprint": ending_worktree_fingerprint' in text
assert '"ending_index_fingerprint": ending_index_fingerprint' in text
assert 'state.get("ending_worktree_fingerprint") or worktree_fingerprint()' in text
assert 'bound_fingerprint=' in text and 'current_fingerprint=' in text

assert 'def current_path_identity(relative: str) -> str:' in text
assert 'payload.append(current_path_identity(relative))' in text
assert '"CHANGED_PATHS=" + json.dumps(changed' in text
assert 'changed = sorted(set(changed_tracked_paths()) | set(untracked_paths()) | set(conflicted_paths()))' in text
assert '"TRACKED=" + json.dumps(tracked' not in text
assert '"UNTRACKED=" + json.dumps(untracked' not in text
assert '"CONFLICTED=" + json.dumps(conflicted' not in text
assert 'payload: list[str] = [f"HEAD={resolve_ref(\'HEAD\')}", git_worktree_status_raw()]' not in text
assert 'ending_worktree_fingerprint != state.get("starting_worktree_fingerprint")' in text
assert 'ending_index_fingerprint != state.get("starting_index_fingerprint")' in text

# 2.6.1 lifecycle/admin maintenance invariants.
assert 'Literal["create", "status", "cleanup", "close"]' in text
assert 'def validation_wait_result(' in text and 'result_ready' in text and 'retry_safe' in text
assert 'selector_capabilities' in text and 'zero_test_result_is_acceptance' in text
assert 'associated_live_processes' in text and 'safe_to_release' in text
assert '"task_workspaces": task_workspaces' in text and '"cleanup_safe":' in text
assert 'SNAPSHOT_SCHEMA_REVISION = "execution-snapshot-v2"' in text
assert 'SNAPSHOT_TERMINAL_PROCESS_HISTORY_LIMIT = 32' in text
assert 'SNAPSHOT_IDLE_WORKSPACE_HISTORY_LIMIT = 24' in text
assert 'SNAPSHOT_WORKSPACE_TERMINAL_PROCESS_ID_LIMIT = 16' in text
assert '"owned_process_ids_truncated": len(terminal) > len(terminal_presented)' in text
assert '"task_workspace_presentation": {' in text
assert '"history_truncated": len(terminal_processes) > len(presented_terminal_processes)' in text
assert '"cleanup_safe": not running_processes and active_validation is None' in text
assert 'WORKTREE_FINGERPRINT_REVISION = "2"' in text
assert 'INDEX_FINGERPRINT_REVISION = "1"' in text
assert 'MaintenanceReleaseAction = Literal["stage", "qualify", "status", "arm", "discard"]' in text
assert 'ledgerforge:admin' in text and 'def require_admin_scope()' in text
assert 'scopes=["ledgerforge:execute"]' in text
assert 'scopes=["ledgerforge:execute", "ledgerforge:admin"]' in text
assert 'ADMIN_BEARER_TOKEN_ENV = "LEDGERFORGE_EXECUTOR_ADMIN_BEARER_TOKEN"' in text
assert 'ADMIN_BEARER_TOKEN = os.environ.get(ADMIN_BEARER_TOKEN_ENV, "").strip()' in text
assert 'if ADMIN_BEARER_TOKEN and len(ADMIN_BEARER_TOKEN) < 32:' in text
assert 'if ADMIN_BEARER_TOKEN and hmac.compare_digest(ADMIN_BEARER_TOKEN, BEARER_TOKEN):' in text
assert 'live self-overwrite during MCP request' in text
assert 'generic admin shell' in text and 'arbitrary home-directory admin access' in text
assert 'conversation_id_bound' in text and 'manual_activation_required' in text
assert 'activation_via_mcp' in text
assert 'action: MaintenanceReleaseAction' in text
assert 'MaintenanceInspectAction = Literal["stat", "hash", "read_bytes", "read_text"]' in text
assert '_MAINTENANCE_REQUIRED_ARM_ROLES = {' in text
assert 'Prepared release lacks the complete activation component set:' in text
assert 'venv = Path(sys.prefix).resolve()' in text
assert 'Raw maintenance log bytes are not exposed; use read_text for credential-redacted diagnostics.' in text
assert '(allow network-bind (local ip "localhost:*"))' in text
assert '(allow network-outbound (remote ip "localhost:*"))' in text

compile(text,str(source),"exec")
print("MCP 2.6.1 STATIC QUALIFICATION: PASS")
print("source_sha256="+hashlib.sha256(data).hexdigest())
print("tool_count=55")
print("binary_filesystem_contract=PASS")
print("task_workspace_contract=PASS")
print("reviewed_process_contract=PASS")
print("same_owner_evidence_contract=PASS")
print("secret_reference_contract=PASS")

print("lifecycle_consolidation_contract=PASS")
print("admin_maintenance_contract=PASS")
print("cross_chat_release_state_contract=PASS")
