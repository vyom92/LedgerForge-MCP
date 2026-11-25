#!/usr/bin/env python3
from __future__ import annotations
import argparse, asyncio, base64, hashlib, importlib.util, json, os, shutil, subprocess, sys, tempfile, time, uuid
from pathlib import Path

EXPECTED_TOOLS = 57
NORMAL = "mcp264-normal-qualification-token-000000000000000000000001"
ADMIN = "mcp264-admin-qualification-token-000000000000000000000002"

def run(cmd, cwd=None, env=None):
    p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, check=False, timeout=60, env=env)
    if p.returncode != 0:
        raise RuntimeError("command failed: " + " ".join(map(str, cmd)) + "\n" + p.stdout[-4000:] + "\n" + p.stderr[-4000:])
    return p

def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

def git_env(home: Path) -> dict[str, str]:
    env = os.environ.copy()
    env.update({
        "HOME": str(home),
        "XDG_CONFIG_HOME": str(home / ".config"),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_AUTHOR_NAME": "MCP Qualification",
        "GIT_AUTHOR_EMAIL": "mcp-qualification@example.invalid",
        "GIT_COMMITTER_NAME": "MCP Qualification",
        "GIT_COMMITTER_EMAIL": "mcp-qualification@example.invalid",
    })
    return env


def init_repo(repo: Path, bare: Path, home: Path) -> str:
    # The qualification repository is real and disposable. It lives entirely in the
    # prepared slot, has deterministic identity/configuration, and never consults the
    # operator's product checkout or global Git configuration.
    repo.mkdir(parents=True, exist_ok=True)
    (home / ".config").mkdir(parents=True, exist_ok=True, mode=0o700)
    (repo / "README.md").write_text("MCP 3.0.0 disposable qualification repository\n", encoding="utf-8")
    script_dir = repo / "script"
    script_dir.mkdir()
    validate = script_dir / "validate.sh"
    validate.write_text("#!/bin/sh\nset -eu\nexit 0\n", encoding="utf-8")
    validate.chmod(0o700)
    env = git_env(home)
    run(["git", "init", "-b", "main"], repo, env=env)
    run(["git", "config", "--local", "user.name", "MCP Qualification"], repo, env=env)
    run(["git", "config", "--local", "user.email", "mcp-qualification@example.invalid"], repo, env=env)
    run(["git", "add", "--all"], repo, env=env)
    run(["git", "commit", "--no-gpg-sign", "-m", "Deterministic MCP qualification baseline"], repo, env=env)
    head = run(["git", "rev-parse", "HEAD"], repo, env=env).stdout.strip()
    run(["git", "init", "--bare", str(bare)], cwd=repo.parent, env=env)
    run(["git", "remote", "add", "origin", str(bare)], repo, env=env)
    run(["git", "push", "-u", "origin", "main"], repo, env=env)
    run(["git", "fetch", "origin"], repo, env=env)
    run(["git", "symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/main"], repo, env=env)
    assert run(["git", "rev-parse", "--show-toplevel"], repo, env=env).stdout.strip() == str(repo.resolve())
    assert run(["git", "rev-parse", "origin/main"], repo, env=env).stdout.strip() == head
    return head


def _wait_validation(mod, *, expected_head: str, lease_id: str, lease_token: str) -> dict:
    """Bind deterministic successful test evidence without requiring Xcode."""
    lease = mod.read_active_lease_raw()
    if not lease or lease.get("lease_id") != lease_id:
        raise RuntimeError("synthetic validation lease changed before binding")
    run_id = str(uuid.uuid4())
    worktree = mod.worktree_fingerprint()
    index = mod.index_fingerprint()
    state = {
        "run_id": run_id,
        "lease_id": lease_id,
        "execution_id": lease.get("execution_id"),
        "status": "completed",
        "operation": "test-focused",
        "selectors": ["SyntheticTests/smoke"],
        "validation_intent": "execute_tests",
        "exit_code": 0,
        "repository_mutated": False,
        "publication_eligible": True,
        "ending_head": expected_head,
        "ending_worktree_fingerprint": worktree,
        "ending_index_fingerprint": index,
        "safe_test_summary": {"totalTestCount": 1, "synthetic": True},
        "xcresult_evidence": {"available": False, "synthetic": True},
        "failure_classification": None,
    }
    # This release qualifier proves the recovery/Git boundary in a disposable
    # repository. It deliberately labels the validation evidence synthetic and
    # does not claim a product/Xcode test run.
    mod.write_state(run_id, state)
    mod.bind_validated_state(lease_id, lease_token, run_id, state)
    return {
        "run_id": run_id,
        "lease_id": lease_id,
        "execution_id": lease.get("execution_id"),
        "status": "completed",
        "operation": "test-focused",
        "selectors": state["selectors"],
        "validation_intent": "execute_tests",
        "starting_head": expected_head,
        "ending_head": expected_head,
        "ending_worktree_fingerprint": worktree,
        "ending_index_fingerprint": index,
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


def _expect_failure(fn, label: str) -> None:
    try:
        fn()
    except Exception:
        return
    raise RuntimeError(f"negative qualification unexpectedly succeeded: {label}")


def qualify_documentation_static_publication(mod, repo: Path, bare: Path) -> dict[str, object]:
    baseline = mod.workspace_snapshot(); head = baseline["head"]
    if not head or baseline["main"] != head or baseline["origin_main"] != head:
        raise RuntimeError(f"documentation-static baseline not converged: {baseline}")
    readme = repo / "README.md"
    readme.write_text(readme.read_text(encoding="utf-8") + "Markdown hard break  \ncontinued\n", encoding="utf-8")
    changed = mod.workspace_snapshot()
    lease = mod.acquire_execution_lease(operation_id=str(uuid.uuid4()), expected_head=head, expected_worktree_fingerprint=changed["worktree_fingerprint"], authorization_digest="d"*64, owner_label="qualification-documentation-static")
    lid, token = lease["lease_id"], lease["lease_token"]
    index_before = changed["index_fingerprint"]
    args = {"expected_head":head,"expected_worktree_fingerprint":changed["worktree_fingerprint"],"expected_index_fingerprint":index_before,"lease_id":lid,"lease_token":token,"paths":["README.md"]}
    dry = mod.git_stage(operation_id=str(uuid.uuid4()), **args, dry_run=True)
    if not (dry.get("candidate_class") == "documentation_static" and dry.get("validation_class") == "documentation_static" and dry.get("required_class") == "documentation_static" and dry.get("publication_eligible") is True):
        raise RuntimeError(f"documentation-static dry-run policy mismatch: {dry}")
    static = dry.get("static_evidence") or {}
    if static.get("pass") is not True or not any(x.get("category") == "markdown-hard-break-two-spaces" for x in static.get("semantic_exceptions", [])):
        raise RuntimeError(f"documentation static evidence missing Markdown hard-break exception: {static}")
    staged = mod.git_stage(operation_id=str(uuid.uuid4()), **args, dry_run=False)
    for key in ("candidate_class","validation_class","required_class","publication_eligible","policy_revision"):
        if staged.get(key) != dry.get(key): raise RuntimeError(f"dry-run/actual-stage eligibility disagreement for {key}: {dry.get(key)} != {staged.get(key)}")
    scan = mod.precommit_privacy_scan()
    if scan.get("pass") is not True or not any(x.get("category") == "markdown-hard-break-two-spaces" for x in scan.get("semantic_exceptions", [])):
        raise RuntimeError(f"staged Markdown hygiene scan mismatch: {scan}")
    commit_args={"expected_head":head,"expected_index_fingerprint":staged["index_fingerprint_after"],"expected_staged_paths":["README.md"],"lease_id":lid,"lease_token":token,"message":"Synthetic documentation-static publication"}
    commit_plan=mod.git_commit(operation_id=str(uuid.uuid4()),**commit_args,dry_run=True)
    if commit_plan.get("validation_run_id") is not None or commit_plan.get("validation_class") != "documentation_static":
        raise RuntimeError(f"documentation-static commit plan unexpectedly required validation run: {commit_plan}")
    committed=mod.git_commit(operation_id=str(uuid.uuid4()),**commit_args,dry_run=False)
    new_head=committed.get("head")
    if not new_head or new_head == head: raise RuntimeError(f"documentation-static commit missing: {committed}")
    push_args={"expected_head":new_head,"expected_origin_main":head,"lease_id":lid,"lease_token":token}
    push_plan=mod.git_push(operation_id=str(uuid.uuid4()),**push_args,dry_run=True)
    if push_plan.get("publication_candidate_present") is not True: raise RuntimeError(f"static publication candidate missing before push: {push_plan}")
    pushed=mod.git_push(operation_id=str(uuid.uuid4()),**push_args,dry_run=False)
    if pushed.get("post_push_converged") is not True: raise RuntimeError(f"documentation-static push failed: {pushed}")
    mod.release_execution_lease(operation_id=str(uuid.uuid4()),lease_id=lid,lease_token=token)
    remote_head=run(["git","--git-dir",str(bare),"rev-parse","refs/heads/main"],env=git_env(repo.parent/"qualification-home")).stdout.strip()
    if remote_head != new_head: raise RuntimeError("documentation-static bare origin did not converge")
    return {"previous_head":head,"published_head":new_head,"validation_run_id":None,"candidate_class":"documentation_static","validation_class":"documentation_static","dry_actual_agree":True,"markdown_hard_break_exception":True,"post_push_converged":True}


def qualify_project_integrity_publication(mod, repo: Path, bare: Path) -> dict[str, object]:
    """Prove containment-only project metadata can publish with compile+bundle evidence and no XCTest."""
    env = git_env(repo.parent / "qualification-home")
    baseline = mod.workspace_snapshot()
    if not (baseline.get("head") == baseline.get("main") == baseline.get("origin_main")):
        raise RuntimeError(f"project-integrity baseline not converged: {baseline}")
    project_dir = repo / "Demo.xcodeproj"
    project_dir.mkdir(exist_ok=True)
    resource = repo / "Demo.json"
    resource.write_text('{"synthetic":true}\n', encoding="utf-8")
    pbx = project_dir / "project.pbxproj"
    pbx.write_text('// !$*UTF8*$!\n{\n"archiveVersion" = "1";\n"classes" = {\n};\n"objectVersion" = "56";\n"objects" = {\n"000000000000000000000001" = {\n"isa" = "PBXProject";\n"mainGroup" = "000000000000000000000002";\n"targets" = (\n"000000000000000000000003",\n);\n"projectDirPath" = "";\n"projectRoot" = "";\n};\n"000000000000000000000002" = {\n"isa" = "PBXGroup";\n"children" = (\n"CCCCCCCCCCCCCCCCCCCCCCCC",\n);\n"sourceTree" = "<group>";\n};\n"000000000000000000000003" = {\n"isa" = "PBXNativeTarget";\n"buildPhases" = (\n"000000000000000000000005",\n"000000000000000000000004",\n);\n"name" = "LedgerForge";\n"productName" = "LedgerForge";\n"productType" = "com.apple.product-type.application";\n};\n"000000000000000000000004" = {\n"isa" = "PBXResourcesBuildPhase";\n"buildActionMask" = "2147483647";\n"files" = (\n);\n"runOnlyForDeploymentPostprocessing" = "0";\n};\n"000000000000000000000005" = {\n"isa" = "PBXSourcesBuildPhase";\n"buildActionMask" = "2147483647";\n"files" = (\n"DDDDDDDDDDDDDDDDDDDDDDDD",\n);\n"runOnlyForDeploymentPostprocessing" = "0";\n};\n"CCCCCCCCCCCCCCCCCCCCCCCC" = {\n"isa" = "PBXFileReference";\n"path" = "App.swift";\n"sourceTree" = "<group>";\n"lastKnownFileType" = "sourcecode.swift";\n};\n"DDDDDDDDDDDDDDDDDDDDDDDD" = {\n"isa" = "PBXBuildFile";\n"fileRef" = "CCCCCCCCCCCCCCCCCCCCCCCC";\n};\n};\n"rootObject" = "000000000000000000000001";\n}\n', encoding="utf-8")
    run(["git","add","Demo.json","Demo.xcodeproj/project.pbxproj"], repo, env=env)
    run(["git","commit","--no-gpg-sign","-m","Synthetic project-integrity baseline"], repo, env=env)
    run(["git","push","origin","main:main"], repo, env=env)
    run(["git","fetch","origin"], repo, env=env)
    head = run(["git","rev-parse","HEAD"], repo, env=env).stdout.strip()
    if run(["git","rev-parse","origin/main"], repo, env=env).stdout.strip() != head:
        raise RuntimeError("project-integrity setup did not converge")
    pbx.write_text('// !$*UTF8*$!\n{\n"archiveVersion" = "1";\n"classes" = {\n};\n"objectVersion" = "56";\n"objects" = {\n"000000000000000000000001" = {\n"isa" = "PBXProject";\n"mainGroup" = "000000000000000000000002";\n"targets" = (\n"000000000000000000000003",\n);\n"projectDirPath" = "";\n"projectRoot" = "";\n};\n"000000000000000000000002" = {\n"isa" = "PBXGroup";\n"children" = (\n"CCCCCCCCCCCCCCCCCCCCCCCC",\n"BBBBBBBBBBBBBBBBBBBBBBBB",\n);\n"sourceTree" = "<group>";\n};\n"000000000000000000000003" = {\n"isa" = "PBXNativeTarget";\n"buildPhases" = (\n"000000000000000000000005",\n"000000000000000000000004",\n);\n"name" = "LedgerForge";\n"productName" = "LedgerForge";\n"productType" = "com.apple.product-type.application";\n};\n"000000000000000000000004" = {\n"isa" = "PBXResourcesBuildPhase";\n"buildActionMask" = "2147483647";\n"files" = (\n"AAAAAAAAAAAAAAAAAAAAAAAA",\n);\n"runOnlyForDeploymentPostprocessing" = "0";\n};\n"000000000000000000000005" = {\n"isa" = "PBXSourcesBuildPhase";\n"buildActionMask" = "2147483647";\n"files" = (\n"DDDDDDDDDDDDDDDDDDDDDDDD",\n);\n"runOnlyForDeploymentPostprocessing" = "0";\n};\n"CCCCCCCCCCCCCCCCCCCCCCCC" = {\n"isa" = "PBXFileReference";\n"path" = "App.swift";\n"sourceTree" = "<group>";\n"lastKnownFileType" = "sourcecode.swift";\n};\n"DDDDDDDDDDDDDDDDDDDDDDDD" = {\n"isa" = "PBXBuildFile";\n"fileRef" = "CCCCCCCCCCCCCCCCCCCCCCCC";\n};\n"BBBBBBBBBBBBBBBBBBBBBBBB" = {\n"isa" = "PBXFileReference";\n"path" = "Demo.json";\n"sourceTree" = "<group>";\n"lastKnownFileType" = "text.json";\n};\n"AAAAAAAAAAAAAAAAAAAAAAAA" = {\n"isa" = "PBXBuildFile";\n"fileRef" = "BBBBBBBBBBBBBBBBBBBBBBBB";\n};\n};\n"rootObject" = "000000000000000000000001";\n}\n', encoding="utf-8")
    changed = mod.workspace_snapshot()
    temp_root = Path(tempfile.mkdtemp(prefix="mcp264-build-evidence-"))
    try:
        derived = temp_root / "DerivedData"
        app = derived / "Build" / "Products" / "Debug" / "LedgerForge.app"
        executable = app / "Contents" / "MacOS" / "LedgerForge"
        resources = app / "Contents" / "Resources"
        executable.parent.mkdir(parents=True, exist_ok=True)
        resources.mkdir(parents=True, exist_ok=True)
        executable.write_bytes(b"synthetic-ledgerforge-executable-264\n")
        (resources / "Demo.json").write_bytes(resource.read_bytes())
        build_evidence = mod._build_artifact_evidence("build-debug", f"Operation: build-debug\nDerivedData: {derived}\n")
        if not isinstance(build_evidence, dict) or build_evidence.get("pass") is not True or build_evidence.get("resource_paths") != ["Demo.json"]:
            raise RuntimeError(f"synthetic build artifact evidence failed: {build_evidence}")
        lease = mod.acquire_execution_lease(operation_id=str(uuid.uuid4()), expected_head=head, expected_worktree_fingerprint=changed["worktree_fingerprint"], authorization_digest="c"*64, owner_label="qualification-project-integrity-compile")
        lid, token = lease["lease_id"], lease["lease_token"]
        run_id = str(uuid.uuid4())
        state = {
            "run_id": run_id, "lease_id": lid, "execution_id": lease.get("execution_id"), "status": "completed",
            "operation": "build-debug", "selectors": [], "validation_intent": "compile_only", "exit_code": 0,
            "repository_mutated": False, "publication_eligible": True, "ending_head": head,
            "ending_worktree_fingerprint": changed["worktree_fingerprint"], "ending_index_fingerprint": changed["index_fingerprint"],
            "safe_test_summary": {"synthetic_compile": True, "executed_tests": 0, "build_artifact_evidence": build_evidence},
            "xcresult_evidence": {"available": False}, "failure_classification": None,
        }
        mod.write_state(run_id, state); mod.bind_validated_state(lid, token, run_id, state)
        args={"expected_head":head,"expected_worktree_fingerprint":changed["worktree_fingerprint"],"expected_index_fingerprint":changed["index_fingerprint"],"lease_id":lid,"lease_token":token,"paths":["Demo.xcodeproj/project.pbxproj"]}
        dry=mod.git_stage(operation_id=str(uuid.uuid4()),**args,dry_run=True)
        proof=dry.get("project_integrity_evidence") or {}
        if not (dry.get("candidate_class")=="project_integrity_compile" and dry.get("validation_class")=="project_integrity_compile" and dry.get("required_class")=="project_integrity_compile" and dry.get("publication_eligible") is True and proof.get("pass") is True):
            raise RuntimeError(f"project-integrity dry-run policy mismatch: {dry}")
        staged=mod.git_stage(operation_id=str(uuid.uuid4()),**args,dry_run=False)
        for key in ("candidate_class","validation_class","required_class","publication_eligible","policy_revision"):
            if staged.get(key)!=dry.get(key): raise RuntimeError(f"project dry-run/actual disagreement: {key}")
        if (staged.get("project_integrity_evidence") or {}).get("evidence_digest") != proof.get("evidence_digest"):
            raise RuntimeError("project integrity evidence changed between dry-run and stage")
        commit_args={"expected_head":head,"expected_index_fingerprint":staged["index_fingerprint_after"],"expected_staged_paths":["Demo.xcodeproj/project.pbxproj"],"lease_id":lid,"lease_token":token,"message":"Synthetic containment-only project publication"}
        committed=mod.git_commit(operation_id=str(uuid.uuid4()),**commit_args,dry_run=False)
        new_head=committed.get("head")
        if not new_head or new_head==head: raise RuntimeError("project-integrity commit missing")
        pushed=mod.git_push(operation_id=str(uuid.uuid4()),expected_head=new_head,expected_origin_main=head,lease_id=lid,lease_token=token,dry_run=False)
        if pushed.get("post_push_converged") is not True: raise RuntimeError(f"project-integrity push failed: {pushed}")
        mod.release_execution_lease(operation_id=str(uuid.uuid4()),lease_id=lid,lease_token=token)
        # Negative: build-setting/project-behaviour change must escalate despite compile evidence.
        pbx.write_text(pbx.read_text(encoding="utf-8") + "SWIFT_VERSION = 6.0;\n", encoding="utf-8")
        negative = mod.workspace_snapshot(); neg_head=negative["head"]
        lease2=mod.acquire_execution_lease(operation_id=str(uuid.uuid4()),expected_head=neg_head,expected_worktree_fingerprint=negative["worktree_fingerprint"],authorization_digest="e"*64,owner_label="qualification-project-build-setting-negative")
        lid2,token2=lease2["lease_id"],lease2["lease_token"]
        run2=str(uuid.uuid4())
        state2={"run_id":run2,"lease_id":lid2,"execution_id":lease2.get("execution_id"),"status":"completed","operation":"build-debug","selectors":[],"validation_intent":"compile_only","exit_code":0,"repository_mutated":False,"publication_eligible":True,"ending_head":neg_head,"ending_worktree_fingerprint":negative["worktree_fingerprint"],"ending_index_fingerprint":negative["index_fingerprint"],"safe_test_summary":{"synthetic_compile":True,"executed_tests":0,"build_artifact_evidence":build_evidence},"xcresult_evidence":{"available":False},"failure_classification":None}
        mod.write_state(run2,state2); mod.bind_validated_state(lid2,token2,run2,state2)
        negargs={"expected_head":neg_head,"expected_worktree_fingerprint":negative["worktree_fingerprint"],"expected_index_fingerprint":negative["index_fingerprint"],"lease_id":lid2,"lease_token":token2,"paths":["Demo.xcodeproj/project.pbxproj"]}
        negdry=mod.git_stage(operation_id=str(uuid.uuid4()),**negargs,dry_run=True)
        if not (negdry.get("required_class")=="test_executing" and negdry.get("publication_eligible") is False):
            raise RuntimeError(f"build-setting compile-only change did not escalate: {negdry}")
        _expect_failure(lambda: mod.git_stage(operation_id=str(uuid.uuid4()),**negargs,dry_run=False),"build-setting-compile-only-stage")
        mod.release_execution_lease(operation_id=str(uuid.uuid4()),lease_id=lid2,lease_token=token2)
        run(["git","checkout","--","Demo.xcodeproj/project.pbxproj"], repo, env=env)
        return {"published_head":new_head,"validation_run_id":run_id,"validation_intent":"compile_only","executed_tests":0,"bundle_manifest_sha256":build_evidence.get("resource_manifest_sha256"),"project_integrity_evidence_digest":proof.get("evidence_digest"),"dry_actual_agree":True,"build_setting_compile_only_rejected":True,"post_push_converged":True}
    finally:
        shutil.rmtree(temp_root, ignore_errors=True)


def qualify_publication_adoption(mod, repo: Path, bare: Path) -> dict[str, object]:
    """Qualify Lease-A commit interruption, Lease-B adoption, and managed push.

    This is deliberately a real disposable Git A->B repository. It never reads or
    writes the LedgerForge product checkout; all mutation capability calls target
    ``mod.REPO`` bound to ``repo`` by the caller's prepared-slot environment.
    """
    baseline = mod.workspace_snapshot()
    head_a = baseline["head"]
    if not head_a or baseline["main"] != head_a or baseline["origin_main"] != head_a:
        raise RuntimeError(f"synthetic baseline is not converged: {baseline}")
    readme = repo / "README.md"
    readme.write_text(readme.read_text(encoding="utf-8") + "interrupted publication adoption\n", encoding="utf-8")
    changed = mod.workspace_snapshot()
    lease_a = mod.acquire_execution_lease(
        operation_id=str(uuid.uuid4()), expected_head=head_a,
        expected_worktree_fingerprint=changed["worktree_fingerprint"],
        authorization_digest="a" * 64, owner_label="qualification-lease-a",
    )
    lease_a_id, lease_a_token = lease_a["lease_id"], lease_a["lease_token"]
    validated_a = _wait_validation(mod, expected_head=head_a, lease_id=lease_a_id, lease_token=lease_a_token)
    before_index = mod.index_fingerprint()
    staged = mod.git_stage(
        operation_id=str(uuid.uuid4()), expected_head=head_a,
        expected_worktree_fingerprint=validated_a["ending_worktree_fingerprint"],
        expected_index_fingerprint=before_index, lease_id=lease_a_id,
        lease_token=lease_a_token, paths=["README.md"], dry_run=False,
    )
    if staged.get("staged_paths") != ["README.md"]:
        raise RuntimeError(f"synthetic stage path binding failed: {staged}")
    committed = mod.git_commit(
        operation_id=str(uuid.uuid4()), expected_head=head_a,
        expected_index_fingerprint=staged["index_fingerprint_after"],
        expected_staged_paths=["README.md"], lease_id=lease_a_id,
        lease_token=lease_a_token, message="Synthetic interrupted publication candidate", dry_run=False,
    )
    head_b = committed.get("head")
    if not head_b or head_b == head_a or committed.get("remaining_staged_paths"):
        raise RuntimeError(f"synthetic commit did not produce clean B: {committed}")
    after_commit = mod.workspace_snapshot()
    if after_commit["origin_main"] != head_a or after_commit["head"] != head_b:
        raise RuntimeError(f"synthetic commit is not A->B: {after_commit}")

    # Drop Lease A to model interruption. Acquire Lease B against exact committed state.
    mod.release_execution_lease(
        operation_id=str(uuid.uuid4()), lease_id=lease_a_id, lease_token=lease_a_token,
    )
    resumed = mod.workspace_snapshot()
    lease_b = mod.acquire_execution_lease(
        operation_id=str(uuid.uuid4()), expected_head=head_b,
        expected_worktree_fingerprint=resumed["worktree_fingerprint"],
        authorization_digest="b" * 64, owner_label="qualification-lease-b",
    )
    lease_b_id, lease_b_token = lease_b["lease_id"], lease_b["lease_token"]
    validated_b = _wait_validation(mod, expected_head=head_b, lease_id=lease_b_id, lease_token=lease_b_token)
    fetched = mod.git_fetch_origin(
        operation_id=str(uuid.uuid4()), expected_head=head_b,
        lease_id=lease_b_id, lease_token=lease_b_token,
    )
    if fetched.get("origin_main_after") != head_a:
        raise RuntimeError(f"fresh fetch unexpectedly moved synthetic origin: {fetched}")
    common_push = {
        "expected_head": head_b, "expected_origin_main": head_a,
        "lease_id": lease_b_id, "lease_token": lease_b_token,
    }
    dry_before = mod.git_push(operation_id=str(uuid.uuid4()), **common_push, dry_run=True)
    if dry_before.get("publication_candidate_present") is not False:
        raise RuntimeError(f"fresh Lease B inherited candidate: {dry_before}")
    _expect_failure(lambda: mod.git_push(operation_id=str(uuid.uuid4()), **common_push, dry_run=False), "push-before-adoption")

    state_before = mod.workspace_snapshot()
    adoption_args = {
        "expected_head": head_b,
        "expected_worktree_fingerprint": validated_b["ending_worktree_fingerprint"],
        "expected_index_fingerprint": validated_b["ending_index_fingerprint"],
        "expected_origin_main": head_a,
        "lease_id": lease_b_id,
        "lease_token": lease_b_token,
    }
    dry_adoption = mod.adopt_publication_candidate(operation_id=str(uuid.uuid4()), **adoption_args, dry_run=True)
    if dry_adoption.get("dry_run") is not True:
        raise RuntimeError(f"adoption dry-run reported a mutation: {dry_adoption}")
    adopted = mod.adopt_publication_candidate(operation_id=str(uuid.uuid4()), **adoption_args, dry_run=False)
    candidate = adopted.get("publication_candidate") if isinstance(adopted.get("publication_candidate"), dict) else adopted
    if candidate.get("commit_head") != head_b:
        raise RuntimeError(f"adopted candidate is not B: {adopted}")
    if candidate.get("expected_origin_main", candidate.get("previous_head")) != head_a:
        raise RuntimeError(f"adopted candidate expected origin is not A: {adopted}")
    if candidate.get("source") != "adopted-existing-commit":
        raise RuntimeError(f"adoption provenance is not explicit: {adopted}")
    if candidate.get("validation_run_id") != validated_b.get("run_id"):
        raise RuntimeError(f"adoption validation binding is missing: {adopted}")
    if candidate.get("validated_head") != head_b:
        raise RuntimeError(f"adoption validated HEAD binding is missing: {adopted}")
    if candidate.get("validated_worktree_fingerprint") not in {None, adoption_args["expected_worktree_fingerprint"]}:
        raise RuntimeError(f"adoption changed worktree binding: {adopted}")
    if candidate.get("validated_index_fingerprint") not in {None, adoption_args["expected_index_fingerprint"]}:
        raise RuntimeError(f"adoption changed index binding: {adopted}")
    state_after = mod.workspace_snapshot()
    for key in ("head", "main", "origin_main", "worktree_fingerprint", "index_fingerprint", "staged_files", "conflicted_files", "active_git_operation"):
        if state_before.get(key) != state_after.get(key):
            raise RuntimeError(f"adoption mutated repository state {key}: {state_before.get(key)!r} -> {state_after.get(key)!r}")
    dry_after = mod.git_push(operation_id=str(uuid.uuid4()), **common_push, dry_run=True)
    if dry_after.get("publication_candidate_present") is not True:
        raise RuntimeError(f"push did not observe adopted candidate: {dry_after}")
    pushed = mod.git_push(operation_id=str(uuid.uuid4()), **common_push, dry_run=False)
    if pushed.get("post_push_converged") is not True:
        raise RuntimeError(f"managed push did not converge: {pushed}")
    final = mod.workspace_snapshot()
    if not (final["head"] == final["main"] == final["origin_main"] == head_b):
        raise RuntimeError(f"post-push convergence failed: {final}")
    if final.get("main_ahead_of_origin_main") != 0 or final.get("main_behind_origin_main") != 0:
        raise RuntimeError(f"post-push ahead/behind not zero: {final}")
    remote_head = run(["git", "--git-dir", str(bare), "rev-parse", "refs/heads/main"], env=git_env(repo.parent / "qualification-home")).stdout.strip()
    if remote_head != head_b:
        raise RuntimeError(f"bare origin did not converge: {remote_head} != {head_b}")
    return {
        "lease_a_commit_head": head_b,
        "lease_a_origin_head": head_a,
        "lease_b_validation_run_id": validated_b.get("run_id"),
        "candidate_source": candidate.get("source"),
        "candidate_committed_paths": candidate.get("committed_paths", []),
        "pre_adoption_push_refused": True,
        "repository_unchanged_during_adoption": True,
        "post_push_converged": True,
    }

def _qualify_r4_acceptance_gaps(mod):
    import copy
    import hashlib
    import json
    from pathlib import Path

    P='000000000000000000000001'
    G='000000000000000000000002'
    T='000000000000000000000003'
    R='000000000000000000000004'
    S='000000000000000000000005'
    F='BBBBBBBBBBBBBBBBBBBBBBBB'
    B='AAAAAAAAAAAAAAAAAAAAAAAA'
    SF='CCCCCCCCCCCCCCCCCCCCCCCC'
    SB='DDDDDDDDDDDDDDDDDDDDDDDD'

    def fixture(resource=False):
        objects={
            P:{'isa':'PBXProject','mainGroup':G,'targets':[T],'projectDirPath':'','projectRoot':''},
            G:{'isa':'PBXGroup','children':[SF],'sourceTree':'<group>'},
            T:{'isa':'PBXNativeTarget','buildPhases':[S,R],'name':'LedgerForge','productName':'LedgerForge','productType':'com.apple.product-type.application'},
            R:{'isa':'PBXResourcesBuildPhase','buildActionMask':'2147483647','files':[],'runOnlyForDeploymentPostprocessing':'0'},
            S:{'isa':'PBXSourcesBuildPhase','buildActionMask':'2147483647','files':[SB],'runOnlyForDeploymentPostprocessing':'0'},
            SF:{'isa':'PBXFileReference','path':'App.swift','sourceTree':'<group>','lastKnownFileType':'sourcecode.swift'},
            SB:{'isa':'PBXBuildFile','fileRef':SF}
        }
        if resource:
            objects[F]={'isa':'PBXFileReference','path':'Demo.json','sourceTree':'<group>','lastKnownFileType':'text.json'}
            objects[B]={'isa':'PBXBuildFile','fileRef':F}
            objects[G]['children'].append(F)
            objects[R]['files'].append(B)
        return {'archiveVersion':'1','classes':{},'objectVersion':'56','objects':objects,'rootObject':P}

    def serialize(value):
        if isinstance(value,dict): return '{\n'+''.join(json.dumps(k)+' = '+serialize(v)+';\n' for k,v in value.items())+'}'
        if isinstance(value,list): return '(\n'+''.join(serialize(v)+',\n' for v in value)+')'
        return json.dumps(value)

    def project_bytes(resource=False):
        return ('// !$*UTF8*$!\n'+serialize(fixture(resource))+'\n').encode()

    def run_acceptance(mod):
        tests=[]
        def record(name,ok,details=None):
            tests.append({'case':name,'pass':bool(ok),**({'details':details} if details is not None else {})})
        markdown=[
            ('paragraph_hard_break',b'foo  \nbar\n',True),
            ('one_space',b'foo \nbar\n',False),
            ('three_spaces',b'foo   \nbar\n',False),
            ('trailing_tab',b'foo\t\nbar\n',False),
            ('mixed_tab_space',b'foo\t \nbar\n',False),
            ('fenced_code_not_hard_break',b'```python\nx = 1  \n```\n',False),
            ('tilde_fence',b'~~~\nx  \ny\n~~~\n',False),
            ('blank_line_not_hard_break',b'foo\n  \nbar\n',False),
            ('heading_not_hard_break',b'# foo  \nbar\n',False),
            ('end_of_paragraph',b'foo  \n\nbar\n',False),
            ('eof_newline',b'foo  \n',False),
            ('eof_no_newline',b'foo  ',False),
            ('inline_code',b'`foo  \nbar`\n',False),
            ('indented_code',b'    foo  \n    bar\n',False),
            ('html_tag',b'<a href="foo  \nbar">x</a>\n',False),
            ('html_block',b'<div>\nfoo  \nbar\n</div>\n',False),
            ('emphasis',b'*foo  \nbar*\n',True),
            ('list_continuation',b'- foo  \n  bar\n',True),
            ('list_boundary',b'- foo  \n- bar\n',False),
            ('blockquote',b'> foo  \n> bar\n',True),
            ('crlf',b'foo  \r\nbar\r\n',True),
            ('multiline_setext',b'foo  \nbar\n===\n',True),
            ('before_heading',b'foo  \n# bar\n',False),
            ('image_alt',b'![foo  \nbar](example.png)\n',False),
            ('invalid_utf8',b'foo  \n\xff\n',False),
        ]
        for name,body,expected in markdown:
            result=mod._whitespace_semantics('README.md',body)
            accepted=not result['violations'] and not result.get('ambiguous')
            record(name,accepted==expected,result if accepted!=expected else None)
        for path in ('test.swift','migration.sql','a.unknown'):
            result=mod._whitespace_semantics(path,b'foo  \nbar\n')
            record('non_markdown_'+path,bool(result['violations']) or result.get('ambiguous'))
        left,right=project_bytes(False),project_bytes(True)
        proof=mod._pbx_resource_delta(left,right,'Demo.xcodeproj/project.pbxproj')
        record('full_graph_resource_positive',proof['pass'] and proof['resources_added']==['Demo.json'])
        record('full_graph_resource_removed',mod._pbx_resource_delta(right,left,'Demo.xcodeproj/project.pbxproj')['resources_removed']==['Demo.json'])
        cases=[]
        obj=fixture(True); obj['objects'][S]['files']=[]; cases.append(('resource_with_source_membership_change',project_bytes(False),serialize(obj).encode()))
        obj=fixture(True); obj['objects'][B]['settings']={'ATTRIBUTES':['CodeSignOnCopy']}; cases.append(('resource_buildfile_settings_addition',left,serialize(obj).encode()))
        cases.append(('resource_buildfile_settings_change',right,serialize(obj).encode()))
        obj=fixture(True); obj['objects'][T]['buildSettings']={'SWIFT_VERSION':'6.0'}; cases.append(('build_settings',left,serialize(obj).encode()))
        obj=fixture(True); obj['objects'][T]['packageProductDependencies']=['Dependency']; cases.append(('dependency',left,serialize(obj).encode()))
        obj=fixture(True); obj['objects'][F]['path']='../Demo.json'; cases.append(('parent_path',left,serialize(obj).encode()))
        obj=fixture(True); obj['objects'][F]['path']='/tmp/Demo.json'; cases.append(('absolute_path',left,serialize(obj).encode()))
        obj=fixture(True); obj['objects'][S]['files'].append(B); cases.append(('resource_in_source_phase',left,serialize(obj).encode()))
        obj=fixture(True); obj['objects'][R]['files'].append(B); cases.append(('duplicate_membership',left,serialize(obj).encode()))
        obj=fixture(True); obj['objects'][F]['lastKnownFileType']='sourcecode.swift'; cases.append(('spoofed_file_type',left,serialize(obj).encode()))
        obj=fixture(True); obj['objects'][G]['path']='Other'; cases.append(('group_path_change',left,serialize(obj).encode()))
        cases.append(('duplicate_plist_key',left,right.replace(b'"archiveVersion" = "1";',b'"archiveVersion" = "1"; "archiveVersion" = "2";')))
        cases.append(('trailing_tokens',left,right+b'SWIFT_VERSION=6.0;'))
        for name,a,b in cases:
            try: result=mod._pbx_resource_delta(a,b,'Demo.xcodeproj/project.pbxproj')
            except (ValueError,KeyError,TypeError): result={'pass':False}
            record(name,result.get('pass') is not True,result if result.get('pass') else None)
        if hasattr(mod,'evaluate_publication_eligibility'):
            compile_only={'exit_code':0,'repository_mutated':False,'validation_intent':'compile_only','operation':'build-debug'}
            for name,paths in [('swift',['App.swift']),('migration',['Migrations/V17.sql']),('mixed',['README.md','App.swift']),('test',['Tests.swift']),('dependency',['Package.resolved'])]:
                verdict=mod.evaluate_publication_eligibility(paths,compile_only)
                record(name+'_compile_only_denied',verdict['required_class']=='test_executing' and verdict['publication_eligible'] is False)
        failures=[t for t in tests if not t['pass']]
        report={'schema':'mcp264-acceptance-gap-regressions-v2','pass':not failures,'case_count':len(tests),'passed':len(tests)-len(failures),'failed':len(failures),'cases':tests}
        return report


    return run_acceptance(mod)

import contextlib
import hashlib
import io
import json
import os
import signal
import stat
import subprocess
import sys
import tempfile
import time
import types
from pathlib import Path


def _r4_sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def qualify_control(launcher):
    spec=importlib.util.spec_from_file_location("qualified_control",launcher)
    ctl=importlib.util.module_from_spec(spec);spec.loader.exec_module(ctl)
    from unittest.mock import patch
    events=[]
    good=lambda name: {"healthy":True,"pids":[100],"listeners":[100]}
    with patch.object(ctl,"component_status",good), patch.object(ctl,"launch",side_effect=AssertionError), patch.object(ctl,"stop_one",side_effect=AssertionError):
        for name in ctl.PROFILES: assert ctl.repair(name)=="Healthy component preserved"
    for name in ctl.PROFILES:
        with patch.object(ctl,"component_status",return_value={"healthy":False}), patch.object(ctl,"stop_one",side_effect=lambda n:events.append(("stop",n))), patch.object(ctl,"launch",side_effect=lambda n:events.append(("start",n))):
            ctl.repair(name);assert events[-2:]==[("stop",name),("start",name)]
    with patch.object(ctl,"component_status",return_value={"healthy":False}),patch.object(ctl,"owner_status",return_value={"lease":{"active":True}}):
        try: ctl.repair("executor")
        except RuntimeError: pass
        else: raise AssertionError("active lease allowed executor repair")
    return {"pass":True,"tested":["preserve healthy tunnel","independent normal repair","independent admin repair","active lease restart guard"]}


def _r4_activator_module(source, root):
    module=types.ModuleType('r4_activation_'+root.name)
    module.__file__=str(source)
    exec(compile(Path(source).read_bytes(),str(source),'exec'),module.__dict__)
    module.ROOT=root/'bridge'; module.DESKTOP=root/'Desktop'
    module.MAINT=module.ROOT/'.mcp-maintenance'
    module.ARMED=module.MAINT/'armed-release.json'
    module.DEPLOYMENTS=module.MAINT/'deployments'
    module.BACKUPS=module.ROOT/'mcp-activation-backups'
    module.LOCK=module.MAINT/'activation.lock'
    module.PYTHON=Path(sys.executable)
    module.ROLE_TARGETS={r:(module.DESKTOP if r in {'main_launcher','owner_wrapper'} else module.ROOT)/p.name for r,p in module.ROLE_TARGETS.items()}
    module.LEGACY_OWNER_WRAPPER=module.DESKTOP/'LedgerForge MCP Owner Recovery.command'
    return module


def qualify_r4_activation_transactions(activator, bootstrap_source, launcher, parent):
    """Actual immutable files/receipts/rollback; server processes replaced by deterministic doubles."""
    cases=[]
    for label,source in [('installed-activator',activator)]:
        for failure in ('none','after-install','after-start','active-lease','corrupt-payload'):
            with tempfile.TemporaryDirectory(prefix='r4-activation-',dir=parent) as td:
                root=Path(td); mod=_r4_activator_module(source,root)
                mod.ROOT.mkdir(); mod.DESKTOP.mkdir()
                rid='r4-transaction-fixture'
                prepared=mod.MAINT/'prepared-releases'/rid; prepared.mkdir(parents=True)
                originals={}; comps={}
                for role in mod.REQUIRED_ROLES|{'owner_wrapper'}:
                    path=mod.component_target(role)
                    body=('old-synthetic-'+role+'\n').encode()
                    mode=0o600 if role in {'owner_version','release_version'} else 0o700
                    path.write_bytes(body); path.chmod(mode)
                    originals[role]=(body,mode)
                for role in mod.REQUIRED_ROLES:
                    path=mod.component_target(role)
                    body=originals[role][0] if role=='owner_wrapper' else Path(launcher).read_bytes() if role=='main_launcher' else ('new-synthetic-'+role+'\n').encode()
                    mode=originals[role][1]
                    (prepared/path.name).write_bytes(body); (prepared/path.name).chmod(mode)
                    comps[role]={'filename':path.name,'size':len(body),'sha256':hashlib.sha256(body).hexdigest(),'mode':mode,'role':role,'transport':'synthetic'}
                identity={'release_id':rid,'target_version':'3.0.0','expected_current_source_sha256':_r4_sha(mod.component_target('executor')),'expected_current_launcher_sha256':_r4_sha(mod.component_target('main_launcher')),'components':comps}
                digest=hashlib.sha256(json.dumps(identity,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()
                state={**identity,'release_digest':digest,'status':'armed','qualification':{'passed':True,'synthetic':True}}
                mod.atomic_json(prepared/'release-state.json',state)
                mod.atomic_json(mod.ARMED,{'release_id':rid,'release_digest':digest,'prepared_root':str(prepared)})
                running=[True]
                def owner_status(_):
                    return {'lease':{'active':failure=='active-lease'},'lease_error':None,'incomplete_journals':[],'running_operations':[],'running_validations':[],'process_records':[],'executor_pids':[919191] if running[0] else [],'listener_pids':[919191] if running[0] else []}
                mod.owner_status=owner_status
                def fake_run(cmd,timeout=180,check=True):
                    if cmd[0]!=str(mod.component_target('main_launcher')) or len(cmd) not in {2,3} or (len(cmd)==3 and cmd[2]!='executor') or cmd[1] not in {'start','stop','verify'}:
                        raise RuntimeError('unexpected-activation-process')
                    if cmd[1]=='stop': running[0]=False
                    if cmd[1]=='start':
                        running[0]=True
                    return subprocess.CompletedProcess(cmd,0,'','')
                mod.run=fake_run
                def qualify(_):
                    if failure=='after-start': raise RuntimeError('synthetic failure after launcher retirement')
                    if mod.LEGACY_OWNER_WRAPPER.exists(): raise RuntimeError('legacy launcher retained')
                    for role,row in comps.items():
                        if role!='owner_wrapper' and _r4_sha(mod.component_target(role))!=row['sha256']:
                            raise RuntimeError('installed-file-mismatch')
                mod.qualify_live=qualify
                key='LEDGERFORGE_MCP_ACTIVATOR_FAIL_AFTER_INSTALL'
                old=os.environ.get(key)
                if failure=='after-install': os.environ[key]='1'
                else: os.environ.pop(key,None)
                if failure=='corrupt-payload': (prepared/comps['executor']['filename']).write_bytes(b'corrupt')
                result=None
                try:
                    with contextlib.redirect_stdout(io.StringIO()),contextlib.redirect_stderr(io.StringIO()):
                        try: result=mod.activate(rid)
                        except RuntimeError:
                            if failure not in {'active-lease','corrupt-payload'}: raise
                            result='refused'
                finally:
                    if old is None: os.environ.pop(key,None)
                    else: os.environ[key]=old
                if failure=='none':
                    assert result==0 and not mod.LEGACY_OWNER_WRAPPER.exists() and not mod.ARMED.exists()
                    assert len(list(mod.DESKTOP.iterdir()))==1
                else:
                    assert result==('refused' if failure in {'active-lease','corrupt-payload'} else 2), (label,failure,result)
                    for role,(body,mode) in originals.items():
                        path=mod.component_target(role)
                        assert path.read_bytes()==body and stat.S_IMODE(path.stat().st_mode)==mode, (label,failure,role)
                    if result==2:
                        receipt=json.loads(next(mod.DEPLOYMENTS.glob('*-failed.json')).read_text())
                        assert receipt['rollback_restored'] is True
                cases.append({'activator':label,'case':failure,'pass':True})
    return {'pass':True,'case_count':len(cases),'cases':cases,'mode':'real backup/install/restore and receipts; executor lifecycle simulated','product_repo_used':False}

def _qualify_r4_runtime(slot):
    with tempfile.TemporaryDirectory(dir=slot) as td:
        launcher=slot/"mcp_control.py"
        return {"control":qualify_control(launcher),
                "activation":qualify_r4_activation_transactions(slot/"ledgerforge_mcp_release_activator.py",None,launcher,Path(td))}

def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--prepared-slot", required=True)
    a = ap.parse_args()
    slot = Path(a.prepared_slot).resolve()
    # Qualification must not consult the operator home. The maintenance sandbox deliberately denies it.
    qual_home = slot / "qualification-home"
    qual_home.mkdir(mode=0o700, exist_ok=True)
    qual_config = qual_home / ".config"
    qual_config.mkdir(mode=0o700, exist_ok=True)
    os.environ["HOME"] = str(qual_home)
    os.environ["XDG_CONFIG_HOME"] = str(qual_config)
    os.environ["GIT_CONFIG_NOSYSTEM"] = "1"
    os.environ["GIT_CONFIG_GLOBAL"] = "/dev/null"
    os.environ["GIT_CONFIG_SYSTEM"] = "/dev/null"
    os.environ["GIT_TERMINAL_PROMPT"] = "0"
    os.environ["GIT_AUTHOR_NAME"] = "MCP Qualification"
    os.environ["GIT_AUTHOR_EMAIL"] = "mcp-qualification@example.invalid"
    os.environ["GIT_COMMITTER_NAME"] = "MCP Qualification"
    os.environ["GIT_COMMITTER_EMAIL"] = "mcp-qualification@example.invalid"
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
        initial_head = init_repo(repo, bare, qual_home)
        state = bridge / ".executor-runs-v2_1-qualification-264"
        state.mkdir(mode=0o700)
        admin_file = bridge / ".executor-admin-token"
        admin_file.write_text(ADMIN + "\n", encoding="utf-8")
        admin_file.chmod(0o600)
        assert (admin_file.stat().st_mode & 0o077) == 0
        admin_from_file = admin_file.read_text(encoding="utf-8").strip()
        assert admin_from_file == ADMIN
        os.environ.update({
            "CHATGPT_MCP_WORKSPACE": str(slot),
            "LEDGERFORGE_EXECUTOR_BRIDGE_ROOT": str(bridge),
            "LEDGERFORGE_EXECUTOR_MAINTENANCE_DESKTOP": str(desktop),
            "LEDGERFORGE_EXECUTOR_MAINTENANCE_TUNNEL_CONFIG": str(tunnel_cfg),
            "LEDGERFORGE_EXECUTOR_REPO_ROOT": str(repo),
            "LEDGERFORGE_EXECUTOR_EXPECTED_REMOTE_URL": str(bare),
            "LEDGERFORGE_EXECUTOR_STATE_ROOT": str(state),
            "LEDGERFORGE_EXECUTOR_MCP_PATH": "/mcp_qualification_264",
            "LEDGERFORGE_EXECUTOR_MCP_HOST": "127.0.0.1",
            "LEDGERFORGE_EXECUTOR_BEARER_TOKEN": NORMAL,
            "LEDGERFORGE_EXECUTOR_ADMIN_BEARER_TOKEN": admin_from_file,
            "LEDGERFORGE_EXECUTOR_PUBLIC_URL": "https://localhost:8999",
            "LEDGERFORGE_EXECUTOR_PORT": "8999",
        })
        static_run = subprocess.run([sys.executable, str(staticq), str(candidate)], cwd=slot, capture_output=True, text=True, check=False, timeout=120)
        if static_run.returncode != 0:
            raise RuntimeError("prepared static qualifier failed: " + static_run.stdout[-4000:] + static_run.stderr[-4000:])
        spec = importlib.util.spec_from_file_location("mcp264_candidate", candidate)
        if spec is None or spec.loader is None: raise RuntimeError("candidate import spec failed")
        mod = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = mod
        spec.loader.exec_module(mod)
        assert mod.EXECUTOR_VERSION == "3.0.0"
        assert mod.TOOLSET_REVISION == 11
        assert mod.SCHEMA_CONTRACT_REVISION == "3.0.0"
        assert len(mod.TOOL_ANNOTATION_CONTRACT) == EXPECTED_TOOLS
        assert mod.ADMIN_BEARER_TOKEN == ADMIN
        caps = mod.executor_capabilities()
        assert caps["executor_version"] == "3.0.0" and caps["toolset_revision"] == 11
        fingerprint = caps["fingerprint_contract"]
        assert fingerprint["worktree_revision"] == "2"
        assert fingerprint["index_revision"] == "1"
        assert caps["admin_maintenance"]["configured"] is True
        # The candidate's production import invariant has now run against the real
        # disposable repository. Keep those semantics active for the remainder of
        # qualification; synthetic hooks, if any, are restricted to post-import
        # effect-oracle cases and never replace startup validation.
        assert mod.REPO == repo.resolve()
        assert mod.resolve_ref("HEAD") == initial_head
        assert mod.resolve_ref("origin/main") == initial_head
        assert mod.workspace_snapshot()["head"] == initial_head
        assert {"README.md", "script/validate.sh"}.issubset(mod.tracked_paths())
        SYNTH_HEAD = initial_head
        SYNTH_WT = mod.worktree_fingerprint()
        SYNTH_INDEX = mod.index_fingerprint()
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
        assert help_result["executor_version"] == "3.0.0"
        discovered = mod.test_discovery(max_results=50)
        assert discovered["selector_capabilities"]["zero_test_result_is_acceptance"] is False
        assert "swift_testing_method_selector" in discovered["selector_capabilities"]
        wid = str(uuid.uuid4())
        mod.task_workspace(str(uuid.uuid4()), wid, "create", task_label="mcp264-release-qualification")
        fake_run = str(uuid.uuid4())
        fake_state = mod.LOCAL_PROCESS_STATES / f"{fake_run}.json"
        mod.atomic_write_json(fake_state, {"run_id": fake_run, "workspace_id": wid, "status": "running"})
        blocked = mod.task_workspace(str(uuid.uuid4()), wid, "close", wait_seconds=0)
        assert blocked["closed"] is False and blocked["cleanup_safe"] is False and blocked["exists_after"] is True
        mod.atomic_write_json(fake_state, {"run_id": fake_run, "workspace_id": wid, "status": "completed"})
        closed = mod.task_workspace(str(uuid.uuid4()), wid, "close", wait_seconds=0)
        assert closed["closed"] is True and closed["cleaned"] is True and closed["exists_after"] is False

        # 3.0.0 synthetic private-source taint and repository-process effect qualification.
        assert mod.MAX_VALIDATION_STATUS_WAIT_SECONDS == 300
        assert caps["validation_status_wait_max_seconds"] == 300
        assert caps["private_source_taint_policy"]["direct_originals_to_repo_copy"] == "denied"
        assert caps["repository_process_effect_policy"]["expected_changed_paths_required"] is True
        synthetic_originals = slot / "qualification-originals"
        synthetic_originals.mkdir(exist_ok=True)
        private_fixture = synthetic_originals / "private-source.bin"
        private_fixture.write_bytes(b"synthetic-private-source-264\n")
        private_sha = sha(private_fixture)
        private_size = private_fixture.stat().st_size
        base_root_registry = mod.root_registry
        def qualification_root_registry():
            roots = base_root_registry()
            roots["originals"] = synthetic_originals.resolve()
            return roots
        mod.root_registry = qualification_root_registry

        taint_wid = str(uuid.uuid4())
        mod.task_workspace(str(uuid.uuid4()), taint_wid, "create", task_label="taint-qualification")
        scratch_copy_op = {"op":"copy","root_id":"task_scratch","path":f"{taint_wid}/input/private-source.bin","source_root_id":"originals","source_path":"private-source.bin","expected_sha256":private_sha,"expected_size":private_size}
        scratch_copy_plan = mod.local_fs_mutate(str(uuid.uuid4()), [scratch_copy_op], dry_run=True)
        scratch_copy = mod.local_fs_mutate(str(uuid.uuid4()), [scratch_copy_op], dry_run=False, reviewed_plan_digest=scratch_copy_plan["reviewed_plan_digest"])
        assert scratch_copy["reviewed_plan_digest_verified"] is True
        taint_status = mod.task_workspace(str(uuid.uuid4()), taint_wid, "status")
        assert taint_status["private_source_tainted"] is True

        # Taint enforcement through the actual filesystem preflight path, without a Git subprocess.
        leak_op = {"op":"copy","root_id":"repo","path":"private-leak.bin","source_root_id":"originals","source_path":"private-source.bin","expected_sha256":private_sha,"expected_size":private_size}
        try:
            mod._local_fs_preflight([leak_op])
        except PermissionError as exc:
            assert "Private-original-derived data" in str(exc)
        else:
            raise RuntimeError("direct originals-to-repo copy preflight was not denied")
        assert not (repo / "private-leak.bin").exists()
        tainted_leak_op = {"op":"copy","root_id":"repo","path":"tainted-leak.bin","source_root_id":"task_scratch","source_path":f"{taint_wid}/input/private-source.bin","expected_sha256":private_sha,"expected_size":private_size}
        try:
            mod._local_fs_preflight([tainted_leak_op])
        except PermissionError as exc:
            assert "Private-original-derived data" in str(exc)
        else:
            raise RuntimeError("tainted-scratch-to-repo copy preflight was not denied")
        assert not (repo / "tainted-leak.bin").exists()

        process_wid = str(uuid.uuid4())
        mod.task_workspace(str(uuid.uuid4()), process_wid, "create", task_label="effect-qualification")
        def process_plan(workspace_id, *, input_files=None, expected_paths=None, max_count=None):
            return mod._process_plan(
                workspace_id=workspace_id, argv=["/usr/bin/true"],
                cwd_path=".", cwd_root="repo", execution_class="repository", env_additions={},
                stdin_descriptor={"mode":"none"}, input_files=input_files or [],
                expected_changed_paths=expected_paths, max_changed_path_count=max_count,
                timeout_seconds=30, expected_exit_codes=[0], output_paths=[],
                expected_head=SYNTH_HEAD, expected_worktree_fingerprint=SYNTH_WT,
                expected_index_fingerprint=SYNTH_INDEX,
            )
        try:
            process_plan(process_wid, input_files=[{"root_id":"originals","path":"private-source.bin","expected_sha256":private_sha,"expected_size":private_size}], expected_paths=["allowed-effect.txt"], max_count=1)
        except PermissionError as exc:
            assert "Private-original-derived" in str(exc)
        else:
            raise RuntimeError("original-derived repository process plan was not denied")
        try:
            process_plan(taint_wid, expected_paths=["allowed-effect.txt"], max_count=1)
        except PermissionError as exc:
            assert "Private-original-derived" in str(exc)
        else:
            raise RuntimeError("tainted workspace repository process plan was not denied")
        try:
            process_plan(process_wid)
        except ValueError as exc:
            assert "expected_changed_paths" in str(exc)
        else:
            raise RuntimeError("repository process plan without effect allowlist was accepted")
        allowed_plan = process_plan(process_wid, expected_paths=["allowed-effect.txt"], max_count=1)
        assert allowed_plan["expected_changed_paths"] == ["allowed-effect.txt"]
        assert allowed_plan["max_changed_path_count"] == 1
        assert allowed_plan["private_source_tainted"] is False

        verdict = mod._repository_process_effect_verdict
        allowed = verdict({}, {"allowed-effect.txt":"A"}, ["allowed-effect.txt"], 1, SYNTH_HEAD, SYNTH_HEAD, SYNTH_INDEX, SYNTH_INDEX)
        assert allowed["repository_effects_verified"] is True and allowed["repository_effect_paths"] == ["allowed-effect.txt"]
        unexpected = verdict({}, {"unexpected-effect.txt":"A"}, ["allowed-effect.txt"], 1, SYNTH_HEAD, SYNTH_HEAD, SYNTH_INDEX, SYNTH_INDEX)
        assert unexpected["repository_effects_verified"] is False
        assert unexpected["repository_unexpected_effect_paths"] == ["unexpected-effect.txt"]
        assert "unexpected_changed_path" in unexpected["repository_effect_violations"]
        over_count = verdict({}, {"effect-a.txt":"A","effect-b.txt":"B"}, ["effect-a.txt","effect-b.txt"], 1, SYNTH_HEAD, SYNTH_HEAD, SYNTH_INDEX, SYNTH_INDEX)
        assert "changed_path_count_exceeded" in over_count["repository_effect_violations"]
        head_changed = verdict({}, {}, ["allowed-effect.txt"], 1, SYNTH_HEAD, "4"*40, SYNTH_INDEX, SYNTH_INDEX)
        assert "head_changed" in head_changed["repository_effect_violations"]
        index_changed = verdict({}, {}, ["allowed-effect.txt"], 1, SYNTH_HEAD, SYNTH_HEAD, SYNTH_INDEX, "5"*64)
        assert "index_changed" in index_changed["repository_effect_violations"]
        preexisting_changed = verdict({"dirty.txt":"OLD"}, {"dirty.txt":"NEW"}, ["dirty.txt"], 1, SYNTH_HEAD, SYNTH_HEAD, SYNTH_INDEX, SYNTH_INDEX)
        assert preexisting_changed["repository_effect_paths"] == ["dirty.txt"] and preexisting_changed["repository_effects_verified"] is True
        preexisting_same = verdict({"dirty.txt":"SAME"}, {"dirty.txt":"SAME"}, ["dirty.txt"], 1, SYNTH_HEAD, SYNTH_HEAD, SYNTH_INDEX, SYNTH_INDEX)
        assert preexisting_same["repository_effect_paths"] == [] and preexisting_same["repository_effects_verified"] is True

        normalized, limit = mod._normalize_repository_process_effect_bounds("repository", ["b.txt","a.txt"], 1)
        assert normalized == ["a.txt","b.txt"] and limit == 1
        try:
            mod._normalize_repository_process_effect_bounds("repository", [".git/config"], 1)
        except PermissionError:
            pass
        else:
            raise RuntimeError("repository process effect allowlist accepted .git path")

        mod.task_workspace(str(uuid.uuid4()), taint_wid, "close", wait_seconds=5)
        mod.task_workspace(str(uuid.uuid4()), process_wid, "close", wait_seconds=5)
        mod.root_registry = base_root_registry
        shutil.rmtree(synthetic_originals)

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
        live_launcher = desktop / "mcp_control.py"
        live_source.write_bytes(candidate.read_bytes())
        live_launcher.write_text("#!/bin/zsh\nexit 0\n", encoding="utf-8")
        releaseq = slot / "qualify_release.py"
        assert releaseq.is_file() and not releaseq.is_symlink()
        # Exercise the durable release transport with real candidate bytes. Chunks are
        # uploaded out of order, one is retried idempotently, and stage consumes only
        # the finalized blob references (never an arbitrary caller path).
        blob_release_id = "blob-stage-" + uuid.uuid4().hex[:12]
        blob_components = []
        for role, source_path in (("executor", candidate), ("static_qualifier", staticq), ("release_qualifier", releaseq)):
            data = source_path.read_bytes()
            blob_id = "blob-" + role.replace("_", "-") + "-" + uuid.uuid4().hex[:10]
            parts = [(offset, data[offset:offset + 200_000]) for offset in range(0, len(data), 200_000)]
            for offset, part in reversed(parts):
                args = {
                    "operation_id": str(uuid.uuid4()), "release_id": blob_release_id, "action": "upload_chunk",
                    "component_role": role, "blob_id": blob_id, "blob_size": len(data), "blob_sha256": sha(source_path),
                    "chunk_offset": offset, "chunk_sha256": hashlib.sha256(part).hexdigest(),
                    "chunk_base64": base64.b64encode(part).decode("ascii"), "dry_run": False,
                }
                uploaded = mod.maintenance_release(**args)
                assert uploaded["blob_id"] == blob_id and uploaded["live_files_mutated"] is False
            first_offset, first_part = parts[0]
            retry = mod.maintenance_release(
                operation_id=str(uuid.uuid4()), release_id=blob_release_id, action="upload_chunk",
                component_role=role, blob_id=blob_id, blob_size=len(data), blob_sha256=sha(source_path),
                chunk_offset=first_offset, chunk_sha256=hashlib.sha256(first_part).hexdigest(),
                chunk_base64=base64.b64encode(first_part).decode("ascii"), dry_run=False,
            )
            assert retry["received_chunks"] == len(parts)
            finalized = mod.maintenance_release(
                operation_id=str(uuid.uuid4()), release_id=blob_release_id, action="finalize_blob",
                blob_ref=blob_id, dry_run=False,
            )
            assert finalized["finalized"] is True and finalized["blob_ref"] == blob_id
            blob_components.append({"role": role, "sha256": sha(source_path), "blob_ref": blob_id})
        blob_stage_plan = mod.maintenance_release(
            operation_id=str(uuid.uuid4()), release_id=blob_release_id, action="stage", target_version="3.0.0",
            expected_current_source_sha256=sha(live_source), expected_current_launcher_sha256=sha(live_launcher),
            components=blob_components, dry_run=True,
        )
        blob_staged = mod.maintenance_release(
            operation_id=str(uuid.uuid4()), release_id=blob_release_id, action="stage", target_version="3.0.0",
            expected_current_source_sha256=sha(live_source), expected_current_launcher_sha256=sha(live_launcher),
            components=blob_components, dry_run=False, reviewed_plan_digest=blob_stage_plan["reviewed_plan_digest"],
        )
        assert blob_staged["release_digest"] == blob_stage_plan["release_digest"]
        blob_status = mod.maintenance_release(
            operation_id=str(uuid.uuid4()), release_id=blob_release_id, action="status", dry_run=True,
        )
        assert blob_status["files_match"] is True
        discarded_blob_stage = mod.maintenance_release(
            operation_id=str(uuid.uuid4()), release_id=blob_release_id, action="discard",
            expected_release_digest=blob_staged["release_digest"], dry_run=False,
        )
        assert discarded_blob_stage["discarded"] is True
        incomplete_id = "qual-incomplete"
        b64 = __import__("base64").b64encode
        incomplete_components = [
            {"role":"executor","sha256":candidate_sha,"content_base64":b64(candidate.read_bytes()).decode("ascii")},
            {"role":"static_qualifier","sha256":sha(staticq),"content_base64":b64(staticq.read_bytes()).decode("ascii")},
            {"role":"release_qualifier","sha256":sha(releaseq),"content_base64":b64(releaseq.read_bytes()).decode("ascii")},
        ]
        stage_plan = mod.maintenance_release(str(uuid.uuid4()), incomplete_id, "stage", target_version="3.0.0", expected_current_source_sha256=sha(live_source), expected_current_launcher_sha256=sha(live_launcher), components=incomplete_components, dry_run=True)
        staged = mod.maintenance_release(str(uuid.uuid4()), incomplete_id, "stage", target_version="3.0.0", expected_current_source_sha256=sha(live_source), expected_current_launcher_sha256=sha(live_launcher), components=incomplete_components, dry_run=False, reviewed_plan_digest=stage_plan["reviewed_plan_digest"])
        state_path = mod._maintenance_release_state_path(incomplete_id)
        state = json.loads(state_path.read_text(encoding="utf-8")); state["status"]="qualified"; state["qualification"]={"passed":True}; mod.atomic_write_json(state_path,state)
        arm_plan = mod.maintenance_release(str(uuid.uuid4()), incomplete_id, "arm", expected_release_digest=staged["release_digest"], dry_run=True)
        expected_missing = ["isolated_qualifier", "main_launcher", "owner_admin", "owner_version", "release_activator", "release_version"]
        assert arm_plan["complete_component_set"] is False and arm_plan["would_arm"] is False
        assert arm_plan["missing_activation_roles"] == expected_missing
        try:
            mod.maintenance_release(str(uuid.uuid4()), incomplete_id, "arm", expected_release_digest=staged["release_digest"], dry_run=False)
        except RuntimeError as exc:
            assert "complete activation component set" in str(exc)
        else:
            raise RuntimeError("incomplete activation component set was armed")
        # 3.0.0 effect-aware publication, whitespace, and unified-launcher qualification.
        compile_bound = {"exit_code":0,"repository_mutated":False,"validation_intent":"compile_only","operation":"build-debug"}
        test_bound = {"exit_code":0,"repository_mutated":False,"validation_intent":"execute_tests","operation":"test-focused"}
        docs_policy = mod.evaluate_publication_eligibility(["README.md"], None, static_evidence={"pass":True,"state_bound":True})
        assert docs_policy["candidate_class"] == "documentation_static" and docs_policy["validation_class"] == "documentation_static" and docs_policy["required_class"] == "documentation_static" and docs_policy["publication_eligible"] is True
        for changed in (["Sources/App.swift"], ["Migrations/V17.sql"], ["README.md", "Sources/App.swift"], ["LedgerForge.xcodeproj/project.pbxproj"]):
            pol = mod.evaluate_publication_eligibility(changed, compile_bound)
            if changed == ["LedgerForge.xcodeproj/project.pbxproj"]:
                assert pol["required_class"] in {"project_integrity_compile", "test_executing"}
            else:
                assert pol["required_class"] == "test_executing" and pol["publication_eligible"] is False
        assert mod.evaluate_publication_eligibility(["Sources/App.swift"], test_bound)["publication_eligible"] is True
        for payload, accepted, category in [(b"hard break  \nnext\n",True,"markdown-hard-break-two-spaces"),(b"tab\t\n",False,"trailing-tab"),(b"one \n",False,"trailing-space-one"),(b"three   \n",False,"trailing-spaces-excess")]:
            verdict=mod._whitespace_semantics("README.md",payload)
            if accepted: assert not verdict["violations"] and verdict["semantic_exceptions"][0]["category"]==category
            else: assert verdict["violations"][0]["category"]==category
        assert mod._whitespace_semantics("Sources/App.swift",b"let x = 1 \n")["violations"][0]["category"]=="trailing-space-one"
        acceptance_gaps = _qualify_r4_acceptance_gaps(mod)
        if acceptance_gaps["pass"] is not True:
            raise RuntimeError("r4 acceptance-gap regressions failed: " + json.dumps(acceptance_gaps, sort_keys=True))
        runtime_gates = _qualify_r4_runtime(slot)
        documentation_static_publication = qualify_documentation_static_publication(mod, repo, bare)
        project_integrity_compile_publication = qualify_project_integrity_publication(mod, repo, bare)
        publication_adoption = qualify_publication_adoption(mod, repo, bare)
        isolated = subprocess.run([sys.executable, str(slot / "qualify_executor_current_isolated.py"), "--candidate", str(candidate), "--expected-source-sha", candidate_sha, "--http-only"], cwd=slot, capture_output=True, text=True, check=False, timeout=300)
        if isolated.returncode != 0 or "ISOLATED HTTP QUALIFICATION: PASS" not in isolated.stdout:
            raise RuntimeError("isolated HTTP qualification failed: " + (isolated.stdout + isolated.stderr)[-6000:])
        isolated_result=json.loads(isolated.stdout.strip().splitlines()[-1])
        assert isolated_result.get("candidate_source_sha256")==candidate_sha
        assert isolated_result.get("process_lifecycle_mode")=="http-only" and isolated_result.get("workspace_close")=="REQUIRES_STANDALONE"
        secrets_rendered = json.dumps({"caps": caps, "status": mstatus, "snapshot": snap, "redacted_log": redacted_log}, sort_keys=True)
        assert NORMAL not in secrets_rendered and ADMIN not in secrets_rendered
        result = {
            "qualification": "PASS",
            "independent_acceptance_gap_regressions": acceptance_gaps,
            "runtime_regression_gates": runtime_gates,
            "schema_contract_sha256": caps["schema_contract_sha256"],
            "candidate_sha256": candidate_sha,
            "candidate_source_sha256": candidate_sha,
            "tool_count": EXPECTED_TOOLS,
            "identity": {"version": "3.0.0", "toolset_revision": 11, "schema_revision": "3.0.0"},
            "file_backed_admin_token": "PASS",
            "snapshot_large_history_bounded": "PASS",
            "snapshot_running_evidence_preserved": "PASS",
            "snapshot_digest_history_independence": "PASS",
            "file_to_environment_admin_token": "PASS",
            "normal_admin_scope_separation": "PASS",
            "redacted_log_read": "PASS",
            "incomplete_arm_rejection": "PASS",
            "release_blob_transport": "PASS",
            "publication_adoption": publication_adoption,
            "documentation_static_publication": documentation_static_publication,
            "project_integrity_compile_publication": project_integrity_compile_publication,
            "publication_effect_classes": "PASS",
            "publication_compile_only_rejections": "PASS",
            "markdown_whitespace_semantics": "PASS",
            "component_control": runtime_gates["control"],
            "publication_adoption_negative_precondition": "PASS",
            "cross_chat_maintenance_state": "PASS",
            "workspace_close": "PASS",
            "owned_resource_snapshot": "PASS",
            "selector_capability_metadata": "PASS",
            "fingerprint_revision_metadata": "PASS",
            "private_source_taint_enforcement": "PASS",
            "repository_process_effect_bounds": "PASS",
            "repository_effect_test_mode": "deterministic-helper-plus-process-plan-no-git-subprocess",
            "formal_qualification_git_subprocess_used": True,
            "extended_wait_contract": "PASS",
            "network_used": True,
            "external_network_used": False,
            "isolated_http_qualification": "PASS",
            "isolated_http_scope": "http-only-under-maintenance-sandbox",
            "standalone_process_lifecycle_required": True,
            "isolated_http_log_sha256": hashlib.sha256(isolated.stdout.encode()).hexdigest(),
            "product_repo_used": False,
        }
        result_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print("MCP 3.0.0 PREPARED-SLOT QUALIFICATION: PASS")
        print(json.dumps(result, sort_keys=True))
    except Exception as exc:
        fail = {"qualification": "FAIL", "error_type": type(exc).__name__, "error": str(exc)}
        try: result_path.write_text(json.dumps(fail, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        except Exception: pass
        raise

if __name__ == "__main__": main()
