from __future__ import annotations

import ast
import importlib.util
import inspect
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def source(name: str) -> str:
    return (ROOT / name).read_text(encoding="utf-8")


def module_from_file(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / filename)
    if spec is None or spec.loader is None:
        raise AssertionError(f"unable to load {filename}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class MCP262RepairTests(unittest.TestCase):
    def test_executor_imports_sys_and_exposes_current_candidate_contract(self) -> None:
        text = source("executor_v2_1.py")
        tree = ast.parse(text)
        self.assertTrue(any(isinstance(node, ast.Import) and any(alias.name == "sys" for alias in node.names) for node in tree.body))
        self.assertIn('EXECUTOR_VERSION = "3.0.0"', text)
        self.assertIn("TOOLSET_REVISION = 11", text)
        self.assertIn('SCHEMA_CONTRACT_REVISION = "3.0.0"', text)
        self.assertIn('validation_status_wait_max_seconds', text)

    def test_publication_adoption_is_explicit_and_non_pushing(self) -> None:
        text = source("executor_v2_1.py")
        self.assertIn("def adopt_publication_candidate(", text)
        self.assertIn('"source": "adopted-existing-commit"', text)
        self.assertIn('"committed_paths_source": "git-diff-tree"', text)
        self.assertIn('"push_performed": False', text)
        self.assertIn("Publication adoption requires exactly one local commit ahead", text)

    def test_release_blob_transport_is_pathless_and_integrity_bound(self) -> None:
        text = source("executor_v2_1.py")
        self.assertIn('"upload_chunk", "finalize_blob"', text)
        self.assertIn("MAINTENANCE_MAX_BLOB_CHUNK_BYTES", text)
        self.assertIn("whole-file SHA", text)
        self.assertIn("Release blob path escapes the maintenance root", text)
        self.assertIn('"arbitrary_caller_paths": False', text)
        self.assertIn('"cross_chat_resume": True', text)

    def test_qualification_imports_real_git_before_candidate_import(self) -> None:
        text = source("qualify_release.py")
        self.assertIn('run(["git", "init", "-b", "main"]', text)
        self.assertIn('run(["git", "commit", "--no-gpg-sign"', text)
        self.assertIn('"GIT_CONFIG_GLOBAL": "/dev/null"', text)
        self.assertIn('"GIT_CONFIG_NOSYSTEM": "1"', text)
        self.assertLess(text.index("initial_head = init_repo"), text.index("spec.loader.exec_module(mod)"))
        self.assertIn('"repository_effect_test_mode": "deterministic-helper-plus-process-plan-no-git-subprocess"', text)

    def test_qualification_sandbox_allows_metadata_traversal_only(self) -> None:
        text = source("executor_v2_1.py")
        self.assertIn('(allow file-read-metadata)', text)
        self.assertIn('(deny file-read* (subpath', text)
        self.assertIn('sandbox-exec', text)
        self.assertIn('sys.executable', text)
        self.assertIn('(deny network*)', text)

    def test_owner_admin_accepts_only_installed_script(self) -> None:
        owner = module_from_file("mcp262_owner_admin_test", "ledgerforge_mcp_owner_admin.py")
        canonical = str((ROOT / "executor_v2_1.py").resolve())
        compatibility = str(Path.home() / "ledgerforge-mcp-prototype" / "executor_v2_1.py")
        self.assertEqual(owner.executor_script_identity(f"python {canonical}"), canonical)
        self.assertIsNone(owner.executor_script_identity(f"python {compatibility}"))
        self.assertIsNone(owner.executor_script_identity("python /tmp/executor_v2_1.py"))
        self.assertIsNone(owner.executor_script_identity("python -c 'import executor_v2_1'"))
        self.assertIn("signal.SIGTERM", source("ledgerforge_mcp_owner_admin.py"))
        self.assertIn("SIGKILL", source("ledgerforge_mcp_owner_admin.py"))

    def test_supported_client_path_uses_httpx2_and_explicit_token_override(self) -> None:
        text = source("mcp21_client_common.py")
        self.assertRegex(text, r"import httpx2")
        self.assertIn("streamablehttp_client", text)
        helper = module_from_file("mcp262_client_common_test", "mcp21_client_common.py")
        self.assertIn("token", inspect.signature(helper.open_session).parameters)

    def test_release_activator_validates_all_roles_and_preserves_venv_prefix(self) -> None:
        text = source("ledgerforge_mcp_release_activator.py")
        self.assertIn('ACTIVATOR_VERSION = "mcp-release-activator-2.0"', text)
        self.assertIn('"owner_wrapper"', text)
        self.assertIn('"release_version"', text)
        self.assertIn('Path(os.environ.get("LEDGERFORGE_MCP_ACTIVATOR_PYTHON"', text)
        self.assertIn('PYTHON = Path(os.environ.get("LEDGERFORGE_MCP_ACTIVATOR_PYTHON", str(ROOT / ".venv/bin/python"))).expanduser()', text)
        self.assertIn("rollback", text)

    def test_controller_matches_tunnel_profiles_independently(self) -> None:
        from unittest.mock import patch
        from types import SimpleNamespace
        ctl = module_from_file("test_installed_mcp_control", "mcp_control.py")
        ps = SimpleNamespace(stdout="81 /opt/homebrew/bin/tunnel-client run --profile ledgerforge-recovery\n82 /opt/homebrew/bin/tunnel-client run --profile ledgerforge-recovery-admin\n83 /opt/homebrew/bin/tunnel-client run --profile ledgerforge-recovery-old")
        with patch.object(ctl, "shell", return_value=ps):
            self.assertEqual([81], ctl.process_ids("executor-tunnel"))
            self.assertEqual([82], ctl.process_ids("admin-tunnel"))

    def test_live_acceptance_script_never_prints_credentials(self) -> None:
        text = source("tests/live_acceptance_262.py")
        self.assertNotIn("print(normal_token", text)
        self.assertNotIn("print(admin_token", text)
        self.assertIn("normal_token in rendered_help", text)
        self.assertIn("credential_values_exposed", text)


if __name__ == "__main__":
    unittest.main()
