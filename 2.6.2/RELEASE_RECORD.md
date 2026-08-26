# LedgerForge MCP Executor 2.6.2 release record

Accepted deployment: 2026-08-26T19:05:56.427870+00:00 (UTC)

This record covers the MCP control plane only. The LedgerForge product
repository at `/Users/vyom/Applications/LedgerForge` is outside the release
boundary and was not used as qualification or artifact storage.

## Accepted production identity

- Release ID: `mcp-2.6.2-luna-20260827-final-r3`
- Release digest: `6d030b34da02685d5b78dc5a64e19cc1ff7bd26bcbcf2e4d645d4e33fc0b55c5`
- Executor version: `2.6.2`
- Toolset revision: `9`
- Schema contract revision: `2.6.2`
- Snapshot contract: `execution-snapshot-v2`
- Annotation/tool count: `55`
- Candidate source SHA-256: `e208bece9275d60eac00f164d0f6353f1c10090646ee3350c22febfa3591950c`
- Deployment receipt: `.mcp-maintenance/deployments/20260826T190556.428436Z-mcp-2.6.2-luna-20260827-final-r3-deployed.json`
- Deployment receipt SHA-256: `a79de10111f9918e1703b01d3502acea35655a103ce96841971e0b93a9b29d09`
- Qualification result: `.mcp-maintenance/prepared-releases/mcp-2.6.2-luna-20260827-final-r3/qualification-result.json`
- Qualification result SHA-256: `f645cc53464fd6729c295be85c4effa708962f2934b8df69a51ca9a4df62c08b`
- Qualification log SHA-256: `7130f27f7f3262f451d50656303a90ea9bf60b43250fc4bbbdfc5aff59935356`
- Formal qualification exit code: `0`
- Formal qualification result: `PASS`

## Ten-role immutable component manifest

All ten roles below were staged through the resumable blob transport, qualified
as the exact bytes shown, armed together, and activated as one release.

| Role | File | SHA-256 | Size | Mode |
|---|---|---|---:|---:|
| executor | `executor_v2_1.py` | `e208bece9275d60eac00f164d0f6353f1c10090646ee3350c22febfa3591950c` | 386100 | 0700 |
| static_qualifier | `qualify_executor_current_static.py` | `754fa66c20262773f7351c56901950878e24805045333985bff7ec8859cfb74e` | 10100 | 0700 |
| isolated_qualifier | `qualify_executor_current_isolated.py` | `f43111d29f719b041383b37ebe60925b9a889a9c9040d4885e91b141512c3860` | 20680 | 0700 |
| release_qualifier | `qualify_release.py` | `0effeeefac6f870920794dd75eb734e114cf8d255301cfd5882089560675918a` | 31323 | 0700 |
| main_launcher | `LedgerForge MCP.command` | `382b374681c90eddbb6d6187af33e335c41fe1c9c1f99a71cbd120d415b9ae14` | 18442 | 0700 |
| owner_admin | `ledgerforge_mcp_owner_admin.py` | `2c68d571446af3a99ac21ca30376a56160815e84bf34320a84963ba88fba2e6d` | 36161 | 0700 |
| owner_wrapper | `LedgerForge MCP Owner Recovery.command` | `b3a13035d7494fe2aa1ff2e4ad155cc4988f5772b8f89bc7ba85405952aef1c5` | 1051 | 0700 |
| owner_version | `.mcp-owner-recovery-version` | `894eed305f01e15a5470845796cfc91a05c70529d6e5670dbcb7bf34c31dc508` | 28 | 0600 |
| release_activator | `ledgerforge_mcp_release_activator.py` | `0ab4f5682ee2b85daea210e0b4fd077e36101aaea480c2dd8030477d32819fd7` | 16432 | 0700 |
| release_version | `.mcp-release-version` | `8fde0552368c64879b3f23c72df5308bcee45ab7c4226ad2d18efd12d1f2e960` | 6 | 0600 |

The repository copy of these bytes is under this directory. `MANIFEST.sha256`
is the component manifest; the receipt and qualification-result hashes above
bind the operational evidence to the same release identity.

## 2.6.2 engineering repairs

- Release staging now supports immutable, pathless chunk/blob ingestion with
  per-chunk hashes, ordered offsets, idempotent retries, cross-chat resume and
  whole-file SHA-256/size verification before a blob can be referenced by
  `maintenance_release(stage)`.
- The supported MCP client path uses the installed `httpx2` and SDK
  `streamablehttp_client`; no duplicate HTTP stack was introduced.
- The maintenance qualification path imports `sys` and has an AST regression
  assertion for the import.
- Owner-admin executor identity accepts only the canonical or compatibility
  symlink spelling of the known executor script, verifies listener ownership,
  preserves start identity, uses SIGTERM first and fails closed on ambiguity.
- Generated qualification profiles permit metadata-only traversal needed for
  canonical path resolution while retaining HOME content, network and
  credential restrictions. A real sandbox execution regression exercises the
  intended interpreter.
- Formal qualification creates a disposable real Git repository and isolated
  bare `origin` before importing the candidate, with deterministic local Git
  identity/configuration. The production import-time Git-root invariant remains
  active; synthetic hooks are used only after import for deterministic bounds.
- The launcher matches the normal `ledgerforge-recovery` tunnel profile by an
  exact profile expression, so the admin profile cannot be mistaken for the
  normal tunnel.
- The release activator validates all ten roles, preserves the virtualenv
  interpreter prefix, verifies rollback assets and writes a durable receipt.

## Qualification evidence

| Gate | Result | Evidence |
|---|---|---|
| Python compile/syntax | VERIFIED PASS | All 2.6.2 source, qualification and test Python compiled; launcher passed `zsh -n`. |
| Static qualification | VERIFIED PASS | 2.6.2 static qualifier; source SHA above; 55 tools; taint/effect/wait/admin/blob contracts. |
| Unit/regression tests | VERIFIED PASS | `tests/test_mcp262_repairs.py`: 9 tests passed. |
| Isolated HTTP qualification | VERIFIED PASS | Admin reconnect persistence, invalid-token refusal, normal/Admin separation, snapshot grouping, durable wait and workspace close. |
| Independent hardening oracle | VERIFIED PASS | Deterministic taint, effect-bound, dirty-identity and pre-existing-process checks. |
| Sandbox execution | VERIFIED PASS | Generated profile executed the intended Python interpreter with metadata traversal only. |
| Real Git import qualification | VERIFIED PASS | Disposable Git repo, deterministic commit/main and isolated bare origin existed before candidate import. |
| Release ingestion | VERIFIED PASS | Out-of-order chunk upload, same-offset retry, final whole-file hash and blob-backed stage/status/discard. |
| Owner-admin identity | VERIFIED PASS | Canonical/symlink acceptance, unrelated Python rejection, listener ownership and SIGTERM-first self-test. |
| Formal release qualification | VERIFIED PASS | Exact ten-role r3 bytes; exit `0`; `qualification=PASS`; `files_match=true`; network/product-repo use false. |

## Arm and activation

- Arm evidence: release state recorded all ten roles, exact hashes/sizes/modes,
  release digest, qualification `PASS`, candidate source SHA and no active
  lease, validation, journal or stale process.
- Activation result: `deployed`.
- Activation receipt: `2.6.2-deployment-r3.json` in this directory and the
  durable operational receipt named above.
- Immediate pre-r3 rollback backup root (the accepted r2 2.6.2 bytes):
  `/Users/vyom/Applications/LedgerForge-MCP/mcp-activation-backups/20260826T190545.664252Z-mcp-2.6.2-luna-20260827-final-r3`
- Accepted 2.6.1 rollback root:
  `/Users/vyom/Applications/LedgerForge-MCP/mcp-activation-backups/20260826T184230.036073Z-mcp-2.6.2-luna-20260827-final-r2`
  (its `executor.backup`, `main_launcher.backup`, `owner_admin.backup`,
  `static_qualifier.backup`, `isolated_qualifier.backup` and
  `release_activator.backup` hashes match the accepted 2.6.1 baseline).
- The accepted 2.6.1 package and rollback stores remain available. The first
  two failed activation attempts failed closed and restored 2.6.1; r2 then
  deployed as an intermediate 2.6.2 release, and r3 deployed successfully. No
  partial activation was accepted.

## Live acceptance

Direct loopback acceptance was run against the locally started executor on
`127.0.0.1:8768`, without requiring an MCP application connection. It verified
executor identity `2.6.2`, toolset `9`, schema `2.6.2`, 55 annotations,
`executor_help`, durable terminal validation retrieval, execution snapshot v2,
task-workspace create/status/close, maintenance status/inspect, inline and blob
release lifecycle, invalid-token refusal and normal/Admin separation. No
credential values were printed or persisted in the repository.

Current owner-admin status after activation: lease inactive with status
`owner_released`, one identity-proven executor listener, no incomplete journals,
no running operations and no running validations.

## Explicit limitation

The formal maintenance qualification reports
`repository_effect_test_mode=deterministic-helper-plus-process-plan-no-git-subprocess`.
It proves the repository process-plan/effect-bound oracle and exercises the real
Git repository/import invariant, but it does not claim that a real Git-writing
subprocess was executed inside the formal maintenance sandbox. This is an
intentional bounded 2.6.2 limitation; the independent deterministic oracle and
process-plan checks remain required gates.

## Historical failed prepared releases retained for evidence

- `mcp-2.6.2-hardening-20260826` — staged; digest
  `8afab3677a0fa9f4ad81cba8a5e0f431411eb84335cd0b2e81dc836c336a3baa`.
- `mcp-2.6.2-hardening-sysfix-20260826` — qualification_failed; digest
  `722abc84777feed06ab52a3c828cc418d05318caeee6572bc02b9259050b0cdc`.
- `mcp-2.6.2-hardening-sandboxmeta-20260826` — qualification_failed; digest
  `cdd3ac8bd92183fb1645e7a8b94536b05e2680b4e1058a3e79e44d4682917f06`.
- `mcp-2.6.2-luna-20260826-final` — activation_failed_rolled_back; digest
  `1f35599b9b3c2c775f129d0ebe6287f219b247a275338f33d5cdf127d7c2201e`.
- `mcp-2.6.2-luna-20260827-final` — activation_failed_rolled_back; digest
  `599a6b003f7058e038cf137afd3e59902bcba5dc7124d92fe480cb0b7c5f45a8`.
- `mcp-2.6.2-luna-20260827-final-r2` — accepted intermediate deployment and
  rollback asset; digest
  `04eb31b768ec787831669e234ef25dc9b023eb08ebad8322822b7c2a1521acad`.

These operational records are not copied into the Git release package because
they contain machine-local runtime state. Their paths, digests and failure
causes remain in the local maintenance store and the final acceptance report.
