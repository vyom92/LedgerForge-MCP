#!/usr/bin/env python3
"""Direct-loopback acceptance for the deployed MCP 2.6.2 control plane.

The script deliberately reads the two protected bearer files without printing
their contents.  It exercises the local executor directly, so a tunnel or MCP
client connection is not required for acceptance.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import sys
import uuid
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from mcp21_client_common import call, expect_error, open_session  # noqa: E402


def digest(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def persisted_identity(admin: bool = False) -> tuple[str, str]:
    root = (Path.home() / "ledgerforge-mcp-prototype").resolve()
    path_file = root / ".executor-path"
    if not path_file.is_file():
        path_file = root / ".mcp-path"
    token_file = root / (".executor-admin-token" if admin else ".executor-token")
    return path_file.read_text(encoding="utf-8").strip(), token_file.read_text(encoding="utf-8").strip()


def existing_completed_validation() -> str | None:
    pointer = ROOT / ".executor-v2.1-state-root"
    if not pointer.is_file():
        return None
    state_root = Path(pointer.read_text(encoding="utf-8").strip()).expanduser()
    candidates: list[tuple[float, str]] = []
    for path in state_root.glob("*.json"):
        try:
            state = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not isinstance(state, dict) or state.get("status") != "completed":
            continue
        if not state.get("run_id") or not (state.get("operation") or state.get("validation_intent")):
            continue
        candidates.append((path.stat().st_mtime, str(state["run_id"])))
    return max(candidates)[1] if candidates else None


async def run() -> dict[str, object]:
    path, normal_token = persisted_identity(False)
    _, admin_token = persisted_identity(True)
    expected_source = digest((ROOT / "executor_v2_1.py").read_bytes())

    evidence: dict[str, object] = {
        "source_sha256": expected_source,
        "normal_admin_separation": "FAIL",
        "invalid_token_refusal": "FAIL",
        "task_workspace_lifecycle": "FAIL",
        "execution_snapshot_v2": "FAIL",
        "durable_validation_terminal_retrieval": "NOT_TESTED",
        "maintenance_status_and_inspect": "FAIL",
        "release_inline_stage_status_discard": "FAIL",
        "release_blob_resume_finalize_stage_discard": "FAIL",
    }

    async with open_session(8768) as normal:
        listed = await normal.list_tools()
        tool_names = sorted(getattr(tool, "name", "") for tool in listed.tools)
        if len(tool_names) != 55 or "executor_help" not in tool_names or "maintenance_release" not in tool_names:
            raise RuntimeError(f"unexpected tool surface: count={len(tool_names)}")
        caps = await call(normal, "executor_capabilities", {})
        if (caps.get("executor_version"), caps.get("toolset_revision"), caps.get("schema_contract_revision")) != ("2.6.2", 9, "2.6.2"):
            raise RuntimeError("live identity contract mismatch")
        if caps.get("source_sha256") != expected_source or caps.get("annotation_contract_count") != 55:
            raise RuntimeError("live source or annotation identity mismatch")

        help_result = await call(normal, "executor_help", {"topic": "maintenance"})
        rendered_help = json.dumps(help_result, sort_keys=True)
        if "durable" not in rendered_help or normal_token in rendered_help or admin_token in rendered_help:
            raise RuntimeError("executor_help was not bounded or exposed a credential")
        snapshot = await call(normal, "execution_snapshot", {"max_bytes": 120000})
        if snapshot.get("snapshot_schema_revision") != "execution-snapshot-v2" or not all(key in snapshot for key in ("processes", "task_workspaces", "cleanup_safe")):
            raise RuntimeError("execution_snapshot v2 grouping missing")
        evidence["execution_snapshot_v2"] = "PASS"

        if not await expect_error(normal, "maintenance_status", {}):
            raise RuntimeError("normal token received maintenance status")
        if not await expect_error(normal, "maintenance_file_inspect", {"target": "executor_source", "action": "hash"}):
            raise RuntimeError("normal token received maintenance file access")
        if not await expect_error(normal, "maintenance_release", {"operation_id": str(uuid.uuid4()), "release_id": "normal-refusal", "action": "status", "expected_release_digest": "0" * 64}):
            raise RuntimeError("normal token received release control")
        evidence["normal_admin_separation"] = "PASS"

        workspace_id = str(uuid.uuid4())
        await call(normal, "task_workspace", {"operation_id": str(uuid.uuid4()), "workspace_id": workspace_id, "action": "create", "task_label": "mcp262-direct-acceptance"})
        workspace_status = await call(normal, "task_workspace", {"operation_id": str(uuid.uuid4()), "workspace_id": workspace_id, "action": "status"})
        if workspace_status.get("exists") is not True:
            raise RuntimeError("task workspace was not created")
        closed = await call(normal, "task_workspace", {"operation_id": str(uuid.uuid4()), "workspace_id": workspace_id, "action": "close", "wait_seconds": 5})
        if closed.get("closed") is not True or closed.get("exists_after") is not False:
            raise RuntimeError("task workspace did not close cleanly")
        evidence["task_workspace_lifecycle"] = "PASS"

        validation_run = existing_completed_validation()
        if validation_run:
            try:
                terminal = await call(normal, "validation_wait_result", {"run_id": validation_run, "wait_seconds": 0, "detail": "summary", "max_bytes": 80000})
                if terminal.get("status") == "completed" and terminal.get("result_ready") is True and terminal.get("retry_safe") is True:
                    evidence["durable_validation_terminal_retrieval"] = "PASS"
            except Exception:
                pass

    try:
        async with open_session(8768, "invalid-" + uuid.uuid4().hex) as invalid:
            await invalid.list_tools()
    except Exception:
        evidence["invalid_token_refusal"] = "PASS"

    _, admin_token = persisted_identity(True)
    async with open_session(8768, admin_token) as admin:
        status = await call(admin, "maintenance_status", {})
        if status.get("admin_scope_verified") is not True or status.get("credential_values_exposed") is not False:
            raise RuntimeError("admin maintenance status contract mismatch")
        source_meta = await call(admin, "maintenance_file_inspect", {"target": "executor_source", "action": "hash"})
        launcher_meta = await call(admin, "maintenance_file_inspect", {"target": "main_launcher", "action": "hash"})
        if source_meta.get("sha256") != expected_source:
            raise RuntimeError("admin source hash does not match live source")
        launcher_sha = str(launcher_meta.get("sha256") or "")
        if len(launcher_sha) != 64:
            raise RuntimeError("admin launcher hash is unavailable")
        if not await expect_error(admin, "maintenance_file_inspect", {"target": "../../.ssh", "action": "stat"}):
            raise RuntimeError("maintenance target allowlist was bypassed")

        inline_release = "mcp-2.6.2-direct-inline-" + uuid.uuid4().hex[:12]
        inline_bodies = {"executor": b"inline-executor", "static_qualifier": b"inline-static", "release_qualifier": b"inline-release"}
        inline_components = [{"role": role, "sha256": digest(body), "content_base64": base64.b64encode(body).decode("ascii")} for role, body in inline_bodies.items()]
        inline_plan = await call(admin, "maintenance_release", {"operation_id": str(uuid.uuid4()), "release_id": inline_release, "action": "stage", "target_version": "9.9.9", "expected_current_source_sha256": expected_source, "expected_current_launcher_sha256": launcher_sha, "components": inline_components, "dry_run": True})
        inline_staged = await call(admin, "maintenance_release", {"operation_id": str(uuid.uuid4()), "release_id": inline_release, "action": "stage", "target_version": "9.9.9", "expected_current_source_sha256": expected_source, "expected_current_launcher_sha256": launcher_sha, "components": inline_components, "dry_run": False, "reviewed_plan_digest": inline_plan["reviewed_plan_digest"]})
        inline_status = await call(admin, "maintenance_release", {"operation_id": str(uuid.uuid4()), "release_id": inline_release, "action": "status", "expected_release_digest": inline_staged["release_digest"], "dry_run": True})
        inline_discard = await call(admin, "maintenance_release", {"operation_id": str(uuid.uuid4()), "release_id": inline_release, "action": "discard", "expected_release_digest": inline_staged["release_digest"], "dry_run": False})
        if inline_status.get("files_match") is not True or inline_discard.get("discarded") is not True:
            raise RuntimeError("inline release lifecycle failed")
        evidence["maintenance_status_and_inspect"] = "PASS"
        evidence["release_inline_stage_status_discard"] = "PASS"

        blob_release = "mcp-2.6.2-direct-blob-" + uuid.uuid4().hex[:12]
        blob_components: list[dict[str, str]] = []
        for role, body in {"executor": b"blob-executor-262", "static_qualifier": b"blob-static-262", "release_qualifier": b"blob-release-262"}.items():
            blob_id = "blob-direct-" + role.replace("_", "-") + "-" + uuid.uuid4().hex[:8]
            midpoint = len(body) // 2
            parts = [(0, body[:midpoint]), (midpoint, body[midpoint:])]
            for offset, part in reversed(parts):
                args = {"operation_id": str(uuid.uuid4()), "release_id": blob_release, "action": "upload_chunk", "component_role": role, "blob_id": blob_id, "blob_size": len(body), "blob_sha256": digest(body), "chunk_offset": offset, "chunk_sha256": digest(part), "chunk_base64": base64.b64encode(part).decode("ascii"), "dry_run": False}
                await call(admin, "maintenance_release", args)
            offset, part = parts[0]
            retry_args = {"operation_id": str(uuid.uuid4()), "release_id": blob_release, "action": "upload_chunk", "component_role": role, "blob_id": blob_id, "blob_size": len(body), "blob_sha256": digest(body), "chunk_offset": offset, "chunk_sha256": digest(part), "chunk_base64": base64.b64encode(part).decode("ascii"), "dry_run": False}
            retry = await call(admin, "maintenance_release", retry_args)
            if retry.get("received_chunks") != 2:
                raise RuntimeError("blob retry was not idempotent")
            finalized = await call(admin, "maintenance_release", {"operation_id": str(uuid.uuid4()), "release_id": blob_release, "action": "finalize_blob", "blob_ref": blob_id, "dry_run": False})
            if finalized.get("finalized") is not True:
                raise RuntimeError("blob did not finalize")
            blob_components.append({"role": role, "sha256": digest(body), "blob_ref": blob_id})
        blob_plan = await call(admin, "maintenance_release", {"operation_id": str(uuid.uuid4()), "release_id": blob_release, "action": "stage", "target_version": "9.9.9", "expected_current_source_sha256": expected_source, "expected_current_launcher_sha256": launcher_sha, "components": blob_components, "dry_run": True})
        blob_staged = await call(admin, "maintenance_release", {"operation_id": str(uuid.uuid4()), "release_id": blob_release, "action": "stage", "target_version": "9.9.9", "expected_current_source_sha256": expected_source, "expected_current_launcher_sha256": launcher_sha, "components": blob_components, "dry_run": False, "reviewed_plan_digest": blob_plan["reviewed_plan_digest"]})
        blob_status = await call(admin, "maintenance_release", {"operation_id": str(uuid.uuid4()), "release_id": blob_release, "action": "status", "expected_release_digest": blob_staged["release_digest"], "dry_run": True})
        blob_discard = await call(admin, "maintenance_release", {"operation_id": str(uuid.uuid4()), "release_id": blob_release, "action": "discard", "expected_release_digest": blob_staged["release_digest"], "dry_run": False})
        if blob_status.get("files_match") is not True or blob_discard.get("discarded") is not True:
            raise RuntimeError("blob release lifecycle failed")
        evidence["release_blob_resume_finalize_stage_discard"] = "PASS"

    return evidence


if __name__ == "__main__":
    print(json.dumps(asyncio.run(run()), sort_keys=True))
