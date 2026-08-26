# LedgerForge MCP Executor

Local MCP execution and evidence infrastructure for LedgerForge.

## Current production baseline

- Executor: 2.6.2
- Toolset revision: 9
- Schema contract revision: 2.6.2
- Snapshot contract: execution-snapshot-v2

Canonical release evidence is under `2.6.2/`. The accepted 2.6.1 package remains
under `2.6.1/` as the verified rollback baseline.

This repository contains the MCP control-plane runtime, qualification harnesses,
release transport and deployment evidence. It does not contain LedgerForge
product source or product data. Release staging uses immutable, hash-verified
blob chunks with resumable cross-chat assembly; callers never provide arbitrary
filesystem paths to the maintenance API.

## Active MCP tool surface — Executor 2.6.2

This is the human-readable catalogue for the **55 active registered tools** in
Toolset Revision 9. The callable names are mechanically checked against
`TOOL_ANNOTATION_CONTRACT` in `executor_v2_1.py`; the live schema remains the
runtime authority for argument shapes.

`Normal` means the ordinary authenticated executor surface. `Admin-only` means
the tool requires the separate `ledgerforge:admin` scope. Admin sessions may
also invoke normal tools.

<!-- ACTIVE_TOOL_CATALOGUE_START -->

| Tool | Description | Access | Effect | Lease | Important boundary |
|---|---|---|---|---|---|
| `executor_capabilities` | Return live executor capability/version information without secret values. | Normal | Read-only | No | Mechanical capability evidence only; it grants no project authorization. |
| `executor_help` | Return a concise usage FAQ for new or resumed Executor chats. | Normal | Read-only | No | Guidance only; it does not authorize mutation. |
| `host_status` | Return bounded non-secret executor and tunnel host health. | Normal | Read-only | No | Reports health/identity without exposing credential values. |
| `workspace_state` | Return complete local LedgerForge Git/worktree safety state. | Normal | Read-only | No | Product repository only; no implicit fetch. |
| `execution_lease_status` | Return writer-lease lifecycle and owned-resource evidence without the capability token. | Normal | Read-only | No | Status is evidence, not mutation authority. |
| `executor_recovery_status` | Return startup recovery, journal, and process evidence without mutation. | Normal | Read-only | No | Recovery evidence only; performs no cleanup. |
| `execution_snapshot` | Return a read-only mechanical continuation snapshot. | Normal | Read-only | No | Snapshot carries no project authorization. |
| `acquire_execution_lease` | Acquire the single LedgerForge mutable execution lease and return its opaque token once. | Normal | Control mutation | Creates lease | Product-repository mutation still requires exact bound state and separate authorization. |
| `resume_execution_lease` | Resume an existing owned execution lease against exact repository state. | Normal | Control mutation | Existing lease | Fails closed on identity/state mismatch. |
| `heartbeat_execution_lease` | Refresh an owned execution lease without persisting its token. | Normal | Control mutation | Yes | Refreshes only the exact owned lease. |
| `release_execution_lease` | Release the writer lease without repository rollback or cleanup. | Normal | Control mutation | Yes | Does not undo repository changes. |
| `list_files` | List files under an approved evidence root, including ignored repo files. | Normal | Read-only | No | Restricted to registered roots; secret-name protections remain. |
| `read_file` | Read bounded sanitized UTF-8 text from an approved evidence root. | Normal | Read-only | No | Registered roots only; bounded output. |
| `search_files` | Search bounded UTF-8 files under an approved evidence root. | Normal | Read-only | No | Registered roots only; bounded result count. |
| `artifact_inspect` | Inspect supported artifacts with bounded/private-safe handling. | Normal | Read-only | No | Supports only registered artifact kinds and roots. |
| `git_inspect` | Inspect bounded Git state, diffs, log, show, or blame without mutation or fetch. | Normal | Read-only | No | Local Git evidence only; remote freshness requires an explicit fetch. |
| `local_fs_inspect` | Inspect registered local roots with binary-safe bounded reads. | Normal | Read-only | No | No arbitrary caller paths; credentials remain blocked. |
| `local_fs_mutate` | Apply a reviewed binary-safe mutation batch to the product repo or an owned task workspace. | Normal | Mutation | Repo: yes; scratch: no | Only `repo` and `task_scratch` roots are mutable; repo changes require exact lease/state. |
| `task_workspace` | Create, inspect, clean up, or safely close one MCP-owned task workspace. | Normal | Mutation | No | Scratch only, outside the LedgerForge product repository. |
| `process_start` | Start one reviewed bounded argv process in an MCP task workspace. | Normal | Mutation | Repo-writing process: yes | Network denied; repository writes are effect-bounded and exclude `.git`. |
| `process_status` | Return durable local-process state without output bodies. | Normal | Read-only | No | Exact executor-owned run only. |
| `process_wait` | Wait boundedly for a durable local process without cancelling it. | Normal | Read-only | No | Waits only; never cancels. |
| `process_cancel` | Cancel only the exact executor-owned generic process group. | Normal | Mutation | If lease-bound run, supply lease | No arbitrary PID/process termination. |
| `process_result` | Return bounded stdout/stderr and artifact references for a completed process. | Normal | Read-only | No | Completed executor-owned run only. |
| `evidence_batch` | Run bounded read-only evidence jobs against one stable repository snapshot. | Normal | Read-only | Optional same-owner lease evidence | Whole-manifest preflight; does not itself authorize mutation. |
| `apply_file_ops` | Create, edit, move, or delete product-worktree text files under one execution lease. | Normal | Mutation | Yes | Exact HEAD/worktree preconditions and reviewed plan required. |
| `git_fetch_origin` | Refresh only origin remote-tracking refs under the active execution lease. | Normal | Network mutation | Yes | Only origin refs; no merge/rebase/worktree mutation. |
| `git_stage` | Stage only explicitly named paths after successful lease-bound validation. | Normal | Mutation | Yes | Exact HEAD/worktree/index binding. |
| `precommit_privacy_scan` | Scan exact staged blobs for prohibited private/residue classes. | Normal | Read-only | No | Privacy/residue check only; not financial-correctness authority. |
| `git_commit` | Commit exactly the validated staged index on `main`. | Normal | Mutation | Yes | Requires exact staged-path/index binding and privacy scan boundary. |
| `git_push` | Push the lease-bound validated commit to `origin/main` and prove convergence. | Normal | Network mutation | Yes | No force push or history rewriting. |
| `run_repo_task` | Run one fixed server-registered repository task. | Normal | Controlled execution | Execution: yes | Only registered tasks; no arbitrary shell. |
| `start_validation` | Start one bounded build/test/cycle-close validation. | Normal | Controlled execution | Yes | Bound to exact HEAD and active execution lease. |
| `validation_status` | Return validation state, optionally waiting boundedly for terminal state. | Normal | Read-only | No | Never cancels a validation. |
| `validation_result` | Return typed retained validation evidence. | Normal | Read-only | No | Credentials redacted; private result content may be returned when authorized. |
| `validation_wait_result` | Wait boundedly for a durable validation and return retained terminal evidence. | Normal | Read-only | No | Durable across chat interruption; never cancels. |
| `cancel_validation` | Terminate only the exact executor-owned validation process group. | Normal | Mutation | Yes | Owned run only; verifies cleanup. |
| `test_discovery` | Discover the current test surface conservatively. | Normal | Read-only | No | Discovery is not acceptance authority. |
| `documentation_sync_preflight` | Collect authority-aware documentation state for Chat-owned synchronization. | Normal | Read-only | No | Evidence only; does not edit documentation. |
| `cycle_close_evidence` | Assemble an immutable-style evidence view from completed validation runs. | Normal | Read-only | No | Only retained completed-run evidence. |
| `runtime_launch` | Launch the repository-owned freshly built LedgerForge runtime through the canonical verifier. | Normal | Controlled execution | Yes | Only the verified repository-owned app/runtime. |
| `runtime_status` | Return the executor-owned LedgerForge runtime identity, if present. | Normal | Read-only | No | Exact owned runtime only. |
| `runtime_logs` | Return privacy-filtered unified logs for the executor-owned LedgerForge PID. | Normal | Read-only | No | Bounded interval and exact owned PID. |
| `runtime_stop` | Stop only the exact LedgerForge PID previously recorded by `runtime_launch`. | Normal | Mutation | Yes | No arbitrary process stop. |
| `test_impact_advisor` | Return conservative test-impact suggestions. | Normal | Read-only | No | Advisory only; never acceptance authority. |
| `performance_probe` | Return bounded engineering performance measurements already observable locally. | Normal | Read-only | No | Only registered probe kinds. |
| `swift_xcode_audit` | Return fixed Swift/Xcode/toolchain and selected build-setting evidence. | Normal | Read-only | No | Evidence only; no build mutation. |
| `repository_recovery_analysis` | Return read-only repository/executor recovery evidence. | Normal | Read-only | No | Never performs cleanup or rollback. |
| `fixture_provenance_inspect` | Inspect Git-safe fixture provenance signals. | Normal | Read-only | No | Does not invent or establish source authority. |
| `run_regression_campaign` | Run one small server-owned engineering regression campaign. | Normal | Controlled execution | Yes | Only registered small campaigns; not a substitute for full acceptance. |
| `private_context_matrix` | Qualify configured private-context availability sequentially. | Normal | Controlled execution | Yes | Availability only; financial tests remain explicit validations. |
| `ci_status_inspection` | Return optional CI/status evidence when dedicated read-only authorization is configured. | Normal | Read-only | No | Currently installed but disabled until dedicated authorization is configured. |
| `maintenance_status` | Return durable MCP control-plane/release handoff status without credential values. | Admin-only | Read-only | No product lease | Admin scope required; no arbitrary home access. |
| `maintenance_file_inspect` | Inspect explicit MCP control-plane files through a bounded target allowlist. | Admin-only | Read-only | No product lease | No arbitrary caller path; credential values remain excluded. |
| `maintenance_release` | Stage, qualify, inspect, arm, or discard immutable prepared MCP releases. | Admin-only | Mutation | No product lease | Admin scope required; never activates a release and exposes no generic admin shell. |
<!-- ACTIVE_TOOL_CATALOGUE_END -->

The table records operational intent, not project authorization. A lease is a
mechanical capability and never substitutes for Chat-approved scope. Tools that
can mutate the LedgerForge product repository continue to require their exact
lease/state preconditions. MCP maintenance tools do not provide an arbitrary
admin shell or arbitrary filesystem access.

## Repository boundary

This repository is separate from the LedgerForge product repository.

- LedgerForge product: `/Users/vyom/Applications/LedgerForge`
- LedgerForge MCP: `/Users/vyom/Applications/LedgerForge-MCP`

MCP runtime state, credentials, task workspaces, rollback stores,
historical build artifacts and private material are intentionally not
version-controlled.

See `MCP_ROOT_RECORD.md`, `2.6.2/RELEASE_RECORD.md` and the historical
`2.6.1/RELEASE_RECORD.md`.
