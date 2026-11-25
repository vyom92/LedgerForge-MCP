"""Synthetic qualification for MCP 2.6.3 publication-candidate adoption.

The tests deliberately import the candidate executor against a fresh disposable
Git worktree and bare origin.  They never touch the LedgerForge product
checkout.  The important boundary is that a commit made under Lease A can be
validated again under Lease B and published only after an explicit adoption
operation; validation alone never grants push authority.
"""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
from pathlib import Path
from typing import Any, Callable
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
EXECUTOR = ROOT / "executor_v2_1.py"


def _run(cmd: list[str], cwd: Path | None = None, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True, check=False, timeout=120)
    if result.returncode != 0:
        raise AssertionError(
            "command failed: " + " ".join(cmd) + "\n" + (result.stdout or "")[-4000:] + "\n" + (result.stderr or "")[-4000:]
        )
    return result


def _init_repo(root: Path) -> tuple[Path, Path, str]:
    """Create a real A/origin-main disposable repository before executor import."""
    home = root / "home"
    repo = root / "repo"
    bare = root / "remote.git"
    repo.mkdir(parents=True)
    (home / ".config").mkdir(parents=True)
    (repo / "README.md").write_text("MCP 2.6.3 synthetic qualification\n", encoding="utf-8")
    script = repo / "script" / "validate.sh"
    script.parent.mkdir()
    script.write_text("#!/bin/sh\nset -eu\nexit 0\n", encoding="utf-8")
    script.chmod(0o700)
    env = os.environ.copy()
    env.update(
        {
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
        }
    )
    _run(["git", "init", "-b", "main"], repo, env)
    _run(["git", "config", "user.name", "MCP Qualification"], repo, env)
    _run(["git", "config", "user.email", "mcp-qualification@example.invalid"], repo, env)
    _run(["git", "add", "--all"], repo, env)
    _run(["git", "commit", "--no-gpg-sign", "-m", "Synthetic baseline A"], repo, env)
    head = _run(["git", "rev-parse", "HEAD"], repo, env).stdout.strip()
    _run(["git", "init", "--bare", str(bare)], root, env)
    _run(["git", "remote", "add", "origin", str(bare)], repo, env)
    _run(["git", "push", "-u", "origin", "main"], repo, env)
    _run(["git", "fetch", "origin"], repo, env)
    _run(["git", "symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/main"], repo, env)
    return repo, bare, head


class PublicationAdoptionQualification(unittest.TestCase):
    def setUp(self) -> None:
        self._saved_env = os.environ.copy()
        self.temp = Path(tempfile.mkdtemp(prefix="mcp263-publication-test-"))
        self.repo, self.bare, self.initial_head = _init_repo(self.temp)
        home = self.temp / "home"
        bridge = self.temp / "bridge"
        bridge.mkdir()
        derived = home / "Library" / "Developer" / "Xcode" / "DerivedData"
        logs = home / ".config" / "tunnel-client"
        for path in (derived, logs):
            path.mkdir(parents=True, exist_ok=True)
        state = bridge / (".executor-runs-v2_1-qualification-" + uuid.uuid4().hex)
        module_name = "mcp263_test_executor_" + uuid.uuid4().hex
        normal = "mcp263-test-normal-token-" + "n" * 48
        admin = "mcp263-test-admin-token-" + "a" * 48
        env = {
            "HOME": str(home),
            "TMPDIR": str(self.temp / "tmp"),
            "XDG_CONFIG_HOME": str(home / ".config"),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_SYSTEM": "/dev/null",
            "GIT_TERMINAL_PROMPT": "0",
            "LEDGERFORGE_EXECUTOR_REPO_ROOT": str(self.repo),
            "LEDGERFORGE_EXECUTOR_EXPECTED_REMOTE_URL": str(self.bare),
            "LEDGERFORGE_EXECUTOR_BRIDGE_ROOT": str(bridge),
            "LEDGERFORGE_EXECUTOR_STATE_ROOT": str(state),
            "LEDGERFORGE_EXECUTOR_MCP_PATH": "/mcp_263_test",
            "LEDGERFORGE_EXECUTOR_MCP_HOST": "127.0.0.1",
            "LEDGERFORGE_EXECUTOR_BEARER_TOKEN": normal,
            "LEDGERFORGE_EXECUTOR_ADMIN_BEARER_TOKEN": admin,
            "LEDGERFORGE_EXECUTOR_PUBLIC_URL": "https://localhost:8999",
            "LEDGERFORGE_EXECUTOR_PORT": "8999",
            "GIT_AUTHOR_NAME": "MCP Qualification",
            "GIT_AUTHOR_EMAIL": "mcp-qualification@example.invalid",
            "GIT_COMMITTER_NAME": "MCP Qualification",
            "GIT_COMMITTER_EMAIL": "mcp-qualification@example.invalid",
        }
        (self.temp / "tmp").mkdir()
        os.environ.update(env)
        spec = importlib.util.spec_from_file_location(module_name, EXECUTOR)
        if spec is None or spec.loader is None:
            raise AssertionError("unable to import executor candidate")
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        spec.loader.exec_module(module)
        self.mod = module
        self._module_name = module_name

    def tearDown(self) -> None:
        # Stop any worker left by a failed test before removing its isolated state.
        try:
            active = getattr(self.mod, "_active_validation", None)
            if active:
                getattr(self.mod, "_cancelled_runs", set()).add(active)
        except Exception:
            pass
        sys.modules.pop(getattr(self, "_module_name", ""), None)
        os.environ.clear()
        os.environ.update(self._saved_env)
        shutil.rmtree(self.temp, ignore_errors=True)

    def _validation(self, head: str, lease_id: str, lease_token: str) -> dict[str, Any]:
        # The adoption tests isolate the Git/recovery boundary from Xcode.  Seed
        # the same durable, lease-bound result shape a successful executing-test
        # run would produce; no product validation or private source is used.
        active = self.mod.read_active_lease_raw()
        self.assertIsNotNone(active)
        run_id = str(uuid.uuid4())
        worktree = self.mod.worktree_fingerprint()
        index = self.mod.index_fingerprint()
        state = {
            "run_id": run_id,
            "lease_id": lease_id,
            "execution_id": active["execution_id"],
            "status": "completed",
            "operation": "test-focused",
            "selectors": ["SyntheticTests/smoke"],
            "validation_intent": "execute_tests",
            "exit_code": 0,
            "repository_mutated": False,
            "publication_eligible": True,
            "ending_head": head,
            "ending_worktree_fingerprint": worktree,
            "ending_index_fingerprint": index,
            "safe_test_summary": {"totalTestCount": 1, "synthetic": True},
            "xcresult_evidence": {"available": False, "synthetic": True},
            "failure_classification": None,
        }
        self.mod.write_state(run_id, state)
        self.mod.bind_validated_state(lease_id, lease_token, run_id, state)
        result = self.mod.validation_result(run_id, detail="summary")
        self.assertEqual(result.get("exit_code"), 0, result)
        self.assertFalse(result.get("repository_mutated"), result)
        self.assertIsNot(result.get("publication_eligible"), False, result)
        return result

    def _acquire(self, head: str, digest: str = "a" * 64) -> dict[str, Any]:
        snap = self.mod.workspace_snapshot()
        return self.mod.acquire_execution_lease(
            operation_id=str(uuid.uuid4()),
            expected_head=head,
            expected_worktree_fingerprint=snap["worktree_fingerprint"],
            authorization_digest=digest,
            owner_label="mcp263-publication-test",
        )

    def _prepare_lease_b(self) -> dict[str, Any]:
        """Make B under Lease A, lose it, then validate B under fresh Lease B."""
        readme = self.repo / "README.md"
        readme.write_text(readme.read_text(encoding="utf-8") + "commit B\n", encoding="utf-8")
        lease_a = self._acquire(self.initial_head)
        lease_a_id, lease_a_token = lease_a["lease_id"], lease_a["lease_token"]
        validated_a = self._validation(self.initial_head, lease_a_id, lease_a_token)
        staged = self.mod.git_stage(
            operation_id=str(uuid.uuid4()),
            expected_head=self.initial_head,
            expected_worktree_fingerprint=validated_a["ending_worktree_fingerprint"],
            expected_index_fingerprint=validated_a["ending_index_fingerprint"],
            lease_id=lease_a_id,
            lease_token=lease_a_token,
            paths=["README.md"],
            dry_run=False,
        )
        committed = self.mod.git_commit(
            operation_id=str(uuid.uuid4()),
            expected_head=self.initial_head,
            expected_index_fingerprint=staged["index_fingerprint_after"],
            expected_staged_paths=["README.md"],
            lease_id=lease_a_id,
            lease_token=lease_a_token,
            message="Synthetic interrupted publication candidate B",
            dry_run=False,
        )
        head_b = committed["head"]
        self.assertNotEqual(head_b, self.initial_head)
        self.assertEqual(self.mod.resolve_ref("origin/main"), self.initial_head)
        self.mod.release_execution_lease(
            operation_id=str(uuid.uuid4()), lease_id=lease_a_id, lease_token=lease_a_token
        )
        lease_b = self._acquire(head_b, "b" * 64)
        lease_b_id, lease_b_token = lease_b["lease_id"], lease_b["lease_token"]
        validated_b = self._validation(head_b, lease_b_id, lease_b_token)
        fetched = self.mod.git_fetch_origin(
            operation_id=str(uuid.uuid4()), expected_head=head_b,
            lease_id=lease_b_id, lease_token=lease_b_token,
        )
        self.assertEqual(fetched["origin_main_after"], self.initial_head)
        return {
            "head": head_b,
            "origin": self.initial_head,
            "lease": lease_b,
            "validated": validated_b,
            "lease_id": lease_b_id,
            "lease_token": lease_b_token,
        }

    def _adoption_args(self, flow: dict[str, Any]) -> dict[str, Any]:
        validated = flow["validated"]
        return {
            "expected_head": flow["head"],
            "expected_worktree_fingerprint": validated["ending_worktree_fingerprint"],
            "expected_index_fingerprint": validated["ending_index_fingerprint"],
            "expected_origin_main": flow["origin"],
            "lease_id": flow["lease_id"],
            "lease_token": flow["lease_token"],
        }

    def test_interrupted_publication_requires_adoption_and_converges(self) -> None:
        flow = self._prepare_lease_b()
        push_args = {
            "expected_head": flow["head"],
            "expected_origin_main": flow["origin"],
            "lease_id": flow["lease_id"],
            "lease_token": flow["lease_token"],
        }
        pre = self.mod.git_push(operation_id=str(uuid.uuid4()), **push_args, dry_run=True)
        self.assertFalse(pre["publication_candidate_present"], pre)
        with self.assertRaises(Exception):
            self.mod.git_push(operation_id=str(uuid.uuid4()), **push_args, dry_run=False)

        before = self.mod.workspace_snapshot()
        adoption_args = self._adoption_args(flow)
        plan = self.mod.adopt_publication_candidate(
            operation_id=str(uuid.uuid4()), **adoption_args, dry_run=True
        )
        self.assertTrue(plan.get("dry_run"), plan)
        adopted = self.mod.adopt_publication_candidate(
            operation_id=str(uuid.uuid4()), **adoption_args, dry_run=False
        )
        candidate = adopted.get("publication_candidate") if isinstance(adopted.get("publication_candidate"), dict) else adopted
        self.assertEqual(candidate.get("source"), "adopted-existing-commit", adopted)
        self.assertEqual(candidate.get("commit_head"), flow["head"], adopted)
        self.assertEqual(candidate.get("expected_origin_main", candidate.get("previous_head")), flow["origin"], adopted)
        self.assertEqual(candidate.get("validation_run_id"), flow["validated"]["run_id"], adopted)
        self.assertEqual(candidate.get("validated_head"), flow["head"], adopted)
        self.assertFalse(adopted.get("push_performed"), adopted)
        self.assertTrue(candidate.get("committed_paths"), adopted)
        after = self.mod.workspace_snapshot()
        for key in ("head", "main", "origin_main", "worktree_fingerprint", "index_fingerprint", "staged_files", "conflicted_files", "active_git_operation"):
            self.assertEqual(before.get(key), after.get(key), key)
        self.assertEqual(_run(["git", "--git-dir", str(self.bare), "rev-parse", "refs/heads/main"], env=os.environ.copy()).stdout.strip(), flow["origin"])

        post_dry = self.mod.git_push(operation_id=str(uuid.uuid4()), **push_args, dry_run=True)
        self.assertTrue(post_dry["publication_candidate_present"], post_dry)
        pushed = self.mod.git_push(operation_id=str(uuid.uuid4()), **push_args, dry_run=False)
        self.assertTrue(pushed.get("post_push_converged"), pushed)
        final = self.mod.workspace_snapshot()
        self.assertEqual(final["head"], flow["head"])
        self.assertEqual(final["main"], flow["head"])
        self.assertEqual(final["origin_main"], flow["head"])
        self.assertEqual(final["main_ahead_of_origin_main"], 0)
        self.assertEqual(final["main_behind_origin_main"], 0)
        self.assertFalse(final["staged_files"])

        # A later validation invalidation must remove the adopted capability;
        # push cannot reuse the stale candidate even though Git is converged.
        self.mod.invalidate_lease_validation_binding(
            self.mod.read_active_lease_raw(), "synthetic post-adoption invalidation"
        )
        with self.assertRaises(Exception):
            self.mod.git_push(operation_id=str(uuid.uuid4()), **push_args, dry_run=False)

    def test_adoption_can_rebind_explicit_durable_validation_after_lease_loss(self) -> None:
        flow = self._prepare_lease_b()
        run_id = flow["validated"]["run_id"]
        # Simulate the original lease having been released after validation:
        # the durable successful run remains available, but the fresh Lease B
        # has no local validation binding yet.
        self.mod.invalidate_lease_validation_binding(
            self.mod.read_active_lease_raw(), "synthetic lease interruption"
        )
        args = self._adoption_args(flow)
        adopted = self.mod.adopt_publication_candidate(
            operation_id=str(uuid.uuid4()),
            **args,
            validation_run_id=run_id,
            dry_run=False,
        )
        candidate = adopted.get("publication_candidate") if isinstance(adopted.get("publication_candidate"), dict) else adopted
        self.assertEqual(candidate.get("source"), "adopted-existing-commit", adopted)
        self.assertEqual(candidate.get("validation_run_id"), run_id, adopted)
        self.assertEqual(candidate.get("validation_binding_source"), "explicit-durable-validation-run", adopted)
        self.assertTrue(adopted.get("repository_state_unchanged"), adopted)
        lease = self.mod.read_active_lease_raw()
        self.assertEqual((lease or {}).get("validated_state", {}).get("run_id"), run_id)

    def test_same_lease_commit_push_regression_requires_no_adoption(self) -> None:
        readme = self.repo / "README.md"
        readme.write_text(readme.read_text(encoding="utf-8") + "same lease\n", encoding="utf-8")
        lease = self._acquire(self.initial_head)
        validated = self._validation(self.initial_head, lease["lease_id"], lease["lease_token"])
        staged = self.mod.git_stage(
            operation_id=str(uuid.uuid4()), expected_head=self.initial_head,
            expected_worktree_fingerprint=validated["ending_worktree_fingerprint"],
            expected_index_fingerprint=validated["ending_index_fingerprint"],
            lease_id=lease["lease_id"], lease_token=lease["lease_token"], paths=["README.md"], dry_run=False,
        )
        committed = self.mod.git_commit(
            operation_id=str(uuid.uuid4()), expected_head=self.initial_head,
            expected_index_fingerprint=staged["index_fingerprint_after"], expected_staged_paths=["README.md"],
            lease_id=lease["lease_id"], lease_token=lease["lease_token"], message="Same lease publication", dry_run=False,
        )
        push = self.mod.git_push(
            operation_id=str(uuid.uuid4()), expected_head=committed["head"], expected_origin_main=self.initial_head,
            lease_id=lease["lease_id"], lease_token=lease["lease_token"], dry_run=False,
        )
        self.assertTrue(push.get("post_push_converged"), push)
        self.assertEqual(self.mod.resolve_ref("origin/main"), committed["head"])

    def test_representative_adoption_negative_preconditions(self) -> None:
        # No active lease and wrong token are refused before any candidate can be minted.
        with self.assertRaises(Exception):
            self.mod.adopt_publication_candidate(
                operation_id=str(uuid.uuid4()), expected_head=self.initial_head,
                expected_worktree_fingerprint=self.mod.worktree_fingerprint(), expected_index_fingerprint=self.mod.index_fingerprint(),
                expected_origin_main=self.initial_head, lease_id=str(uuid.uuid4()), lease_token="wrong", dry_run=False,
            )
        flow = self._prepare_lease_b()
        args = self._adoption_args(flow)
        with self.assertRaises(Exception):
            self.mod.adopt_publication_candidate(operation_id=str(uuid.uuid4()), **{**args, "lease_token": "x" * 96}, dry_run=False)

        # Every mutation below is made in the disposable fixture and must invalidate
        # the exact Lease-B validation binding.
        lease_state_path = self.mod.LEASE_FILE
        original_lease = json.loads(lease_state_path.read_text(encoding="utf-8"))

        def attempt_with_lease(mutator: Callable[[dict[str, Any]], None]) -> None:
            state = json.loads(lease_state_path.read_text(encoding="utf-8"))
            mutator(state)
            self.mod.atomic_write_json(lease_state_path, state)
            with self.assertRaises(Exception):
                self.mod.adopt_publication_candidate(operation_id=str(uuid.uuid4()), **args, dry_run=False)
            self.mod.atomic_write_json(lease_state_path, original_lease)

        attempt_with_lease(lambda lease: lease.__setitem__("validated_state", None))
        attempt_with_lease(lambda lease: lease["validated_state"].update({"publication_eligible": False, "validation_intent": "compile_only"}))
        attempt_with_lease(lambda lease: lease["validated_state"].update({"exit_code": 1}))
        attempt_with_lease(lambda lease: lease["validated_state"].update({"repository_mutated": True}))

        # HEAD/worktree/index and staged paths are all exact-state guards.
        (self.repo / "untracked.txt").write_text("changed after validation\n", encoding="utf-8")
        with self.assertRaises(Exception):
            self.mod.adopt_publication_candidate(operation_id=str(uuid.uuid4()), **args, dry_run=False)
        (self.repo / "untracked.txt").unlink()
        (self.repo / "staged-after-validation.txt").write_text("staged after validation\n", encoding="utf-8")
        self._run_git_for_test(["git", "add", "staged-after-validation.txt"])
        with self.assertRaises(Exception):
            self.mod.adopt_publication_candidate(operation_id=str(uuid.uuid4()), **args, dry_run=False)
        self._run_git_for_test(["git", "reset", "--quiet", "HEAD", "--", "staged-after-validation.txt"])
        (self.repo / "staged-after-validation.txt").unlink()

        # Caller-supplied SHA must be exactly current HEAD; operation-id reuse with
        # different arguments is fail-closed by the durable receipt layer.
        with self.assertRaises(Exception):
            self.mod.adopt_publication_candidate(operation_id=str(uuid.uuid4()), **{**args, "expected_head": "f" * 40}, dry_run=False)
        operation_id = str(uuid.uuid4())
        self.mod.adopt_publication_candidate(operation_id=operation_id, **args, dry_run=True)
        with self.assertRaises(Exception):
            self.mod.adopt_publication_candidate(operation_id=operation_id, **{**args, "expected_origin_main": "e" * 40}, dry_run=True)

    def test_remaining_adoption_guards_fail_closed(self) -> None:
        """Exercise the non-state branches without touching the product checkout."""
        flow = self._prepare_lease_b()
        args = self._adoption_args(flow)

        def attempt(label: str, **patches: Any) -> None:
            with self.subTest(label=label):
                with mock.patch.multiple(self.mod, **patches):
                    with self.assertRaises(Exception):
                        self.mod.adopt_publication_candidate(
                            operation_id=str(uuid.uuid4()), **args, dry_run=False
                        )

        attempt("conflict", conflicted_paths=mock.Mock(return_value=["conflict.txt"]))
        attempt("active-git-operation", active_git_operation=mock.Mock(return_value="merge"))
        attempt("remote-identity", require_expected_origin_identity=mock.Mock(side_effect=RuntimeError("wrong remote")))
        attempt("privacy-scan", scan_committed_blobs=mock.Mock(return_value={"pass": False}))

        original_run_git = self.mod.run_git

        def non_main(*git_args: Any, **kwargs: Any) -> str:
            if git_args[:2] == ("branch", "--show-current"):
                return "feature"
            return original_run_git(*git_args, **kwargs)

        attempt("branch-not-main", run_git=non_main)

        original_resolve = self.mod.resolve_ref

        def head_not_main(name: str) -> str | None:
            if name == "main":
                return "f" * 40
            return original_resolve(name)

        attempt("head-not-main", resolve_ref=head_not_main)

        origin_calls = 0

        def origin_changed(name: str) -> str | None:
            nonlocal origin_calls
            if name == "origin/main":
                origin_calls += 1
                if origin_calls >= 2:
                    return "f" * 40
            return original_resolve(name)

        attempt("origin-changed-after-fetch", resolve_ref=origin_changed)

        original_relationship = self.mod.publication_relationship
        attempt(
            "origin-ahead",
            publication_relationship=mock.Mock(side_effect=RuntimeError("origin/main is ahead")),
        )
        attempt(
            "history-diverged",
            publication_relationship=mock.Mock(side_effect=RuntimeError("history is not a safe fast-forward")),
        )
        self.assertTrue(callable(original_relationship))

    def _run_git_for_test(self, cmd: list[str]) -> None:
        env = os.environ.copy()
        env.update({"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null"})
        _run(cmd, self.repo, env)


if __name__ == "__main__":
    unittest.main()
