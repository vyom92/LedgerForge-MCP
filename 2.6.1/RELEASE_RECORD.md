# LedgerForge MCP Executor 2.6.1 release record

Last formalized: 2026-08-25T05:15:36.859923+00:00

## Dedicated MCP root

`/Users/vyom/ledgerforge-mcp-prototype`

This is the dedicated LedgerForge MCP development, release, rollback and runtime root.

**Never place MCP engineering artifacts in the LedgerForge product repository**
`/Users/vyom/Applications/LedgerForge`.

## Production baseline

- Executor version: `2.6.1`
- Toolset revision: `8`
- Schema contract revision: `2.6.1`
- Executor SHA-256: `48666ab8560f3d365a48970a7792814f137916fd861d857dbfa4fe4ff635d292`
- Schema contract SHA-256: `308c76caa85a1200711a349443eff90af55bf3be35f0c9a09b99fb32f75a72a6`
- Snapshot schema: `execution-snapshot-v2`
- Worktree fingerprint revision: `2`
- Index fingerprint revision: `1`
- Annotation contract count: `55`
- Successful cutover receipt: `mcp-releases/2.6.1-deployment-20260825T065141.json`
- Successful cutover receipt SHA-256: `4804e79dec6bef9a872514fc9fe05a1d65fa13c27fddf544394cae3a9f37f70d`
- Final installer SHA-256: `1005982a939c82772ef94731e4fcc7435f36c6e1a255f2b7920cc4b12898fe05`
- Target launcher SHA-256: `969d20ff5cb43cbb3678806324cfd4561f81b346f03553c8988c776a9c9c8c3b`

## Directory policy

Human-managed material is organized under:

- `2.6.1/` — current accepted release package, qualification evidence, receipts and manifest.
- `previous/` — rollback stores and legacy installed sources/qualifiers.
- `archive/` — historical release store, development iterations and owner-recovery audit/backups.

Compatibility symlinks remain at historical hard-coded paths where receipts or runtime tooling use absolute/root-relative locations. They preserve historical provenance while the physical data lives under `previous/` or `archive/`.

## Operational root exceptions

These remain at the MCP root because they are live runtime/control-plane state rather than release-storage folders:

- `.executor-runs`
- `.executor-runs-v2`
- `.executor-runs-v2_1`
- `.executor-runs-v2_1-production-20260821-210426-14614`
- `.executor-runs-v2_1-production-20260821-232139-23689`
- `.executor-runs-v2_1-qualification.D7RALA`
- `.executor-runs-v2_1-qualification.helper.2n4XZl`
- `.executor-runs-v2_1-qualification.helper.hQOeZH`
- `.executor-runs-v2_1-qualification.helper.KuMpaq`
- `.executor-runs-v2_1-qualification.helper.u6sbE7`
- `.executor-task-workspaces`
- `.mcp-maintenance`
- `.venv`

Current installed/runtime files also remain at their established root paths. Canonical release copies are stored under `2.6.1/`.

## Deployment history retained

- First 2.6.1 cutover attempt: rolled back because 2.6.1 did not listen on port 8768.
- r9-era cutover reached live smoke but exposed unbounded snapshot history behavior and rolled back.
- r10 installer failed pre-cutover because its target-source binding still referenced the previous candidate SHA.
- r11 corrected only the installer binding/invariant and successfully cut over 2.6.1.
- Final production snapshot proved bounded history against 357 accumulated process records with no running process hidden by truncation.

Failed installers/candidates required for provenance are archived rather than silently deleted.

## Chat/client loading note

A broad ChatGPT app/tool discovery response may present only 50 tools even when the server contract has 55. After an app refresh, explicitly attaching `@MCP executor` and targeted discovery for the required tool can load the 2.6.1-only schemas.

Verified 2.6.1 additions:
- `executor_help`
- `validation_wait_result`
- `maintenance_status`
- `maintenance_file_inspect`
- `maintenance_release`
- `task_workspace(action="close")`

Do not classify a deployment failure solely from a broad 50-tool discovery result.

## Cleanup actions

- MKDIR 2.6.1/runtime/
- MKDIR 2.6.1/qualification/
- MKDIR 2.6.1/deployment/
- MKDIR 2.6.1/receipts/
- MKDIR previous/legacy-root-files/
- MKDIR previous/rollback-stores/
- MKDIR archive/2.6.1-development-history/root-stale-installers/
- MKDIR archive/2.6.1-development-history/selected-provenance/
- MKDIR archive/owner-recovery-state/
- COPY /Users/vyom/ledgerforge-mcp-prototype/executor_v2_1.py -> /Users/vyom/ledgerforge-mcp-prototype/2.6.1/runtime/executor_v2_1.py
- COPY /Users/vyom/ledgerforge-mcp-prototype/ledgerforge_mcp_owner_admin.py -> /Users/vyom/ledgerforge-mcp-prototype/2.6.1/runtime/ledgerforge_mcp_owner_admin.py
- COPY /Users/vyom/ledgerforge-mcp-prototype/ledgerforge_mcp_release_activator.py -> /Users/vyom/ledgerforge-mcp-prototype/2.6.1/runtime/ledgerforge_mcp_release_activator.py
- COPY /Users/vyom/ledgerforge-mcp-prototype/qualify_executor_current_static.py -> /Users/vyom/ledgerforge-mcp-prototype/2.6.1/qualification/qualify_executor_current_static.py
- COPY /Users/vyom/ledgerforge-mcp-prototype/qualify_executor_current_isolated.py -> /Users/vyom/ledgerforge-mcp-prototype/2.6.1/qualification/qualify_executor_current_isolated.py
- COPY /Users/vyom/ledgerforge-mcp-prototype/qualify_release.py -> /Users/vyom/ledgerforge-mcp-prototype/2.6.1/qualification/qualify_release.py
- COPY /Users/vyom/ledgerforge-mcp-prototype/.executor-task-workspaces/65e755ea-52c7-4995-926e-c8fabac925fa/output/candidate_r10.py -> /Users/vyom/ledgerforge-mcp-prototype/2.6.1/qualification/candidate_r10.py
- COPY /Users/vyom/ledgerforge-mcp-prototype/.executor-task-workspaces/65e755ea-52c7-4995-926e-c8fabac925fa/output/r10_snapshot_stress_oracle.py -> /Users/vyom/ledgerforge-mcp-prototype/2.6.1/qualification/r10_snapshot_stress_oracle.py
- COPY /Users/vyom/ledgerforge-mcp-prototype/.executor-task-workspaces/65e755ea-52c7-4995-926e-c8fabac925fa/output/LedgerForge_MCP_2.6.1_Installer_r11.command -> /Users/vyom/ledgerforge-mcp-prototype/2.6.1/deployment/LedgerForge_MCP_2.6.1_Installer_r11.command
- COPY /Users/vyom/ledgerforge-mcp-prototype/.executor-task-workspaces/65e755ea-52c7-4995-926e-c8fabac925fa/output/target_launcher_261_r9_final.command -> /Users/vyom/ledgerforge-mcp-prototype/2.6.1/deployment/target_launcher_261_r9_final.command
- COPY /Users/vyom/ledgerforge-mcp-prototype/.executor-task-workspaces/65e755ea-52c7-4995-926e-c8fabac925fa/output/LedgerForge_MCP_2.6.1_Installer.command -> /Users/vyom/ledgerforge-mcp-prototype/archive/2.6.1-development-history/selected-provenance/LedgerForge_MCP_2.6.1_Installer.command
- COPY /Users/vyom/ledgerforge-mcp-prototype/.executor-task-workspaces/65e755ea-52c7-4995-926e-c8fabac925fa/output/LedgerForge_MCP_2.6.1_Installer_r2.command -> /Users/vyom/ledgerforge-mcp-prototype/archive/2.6.1-development-history/selected-provenance/LedgerForge_MCP_2.6.1_Installer_r2.command
- COPY /Users/vyom/ledgerforge-mcp-prototype/.executor-task-workspaces/65e755ea-52c7-4995-926e-c8fabac925fa/output/LedgerForge_MCP_2.6.1_Installer_r3.command -> /Users/vyom/ledgerforge-mcp-prototype/archive/2.6.1-development-history/selected-provenance/LedgerForge_MCP_2.6.1_Installer_r3.command
- COPY /Users/vyom/ledgerforge-mcp-prototype/.executor-task-workspaces/65e755ea-52c7-4995-926e-c8fabac925fa/output/LedgerForge_MCP_2.6.1_Installer_r4.command -> /Users/vyom/ledgerforge-mcp-prototype/archive/2.6.1-development-history/selected-provenance/LedgerForge_MCP_2.6.1_Installer_r4.command
- COPY /Users/vyom/ledgerforge-mcp-prototype/.executor-task-workspaces/65e755ea-52c7-4995-926e-c8fabac925fa/output/LedgerForge_MCP_2.6.1_Installer_r5.command -> /Users/vyom/ledgerforge-mcp-prototype/archive/2.6.1-development-history/selected-provenance/LedgerForge_MCP_2.6.1_Installer_r5.command
- COPY /Users/vyom/ledgerforge-mcp-prototype/.executor-task-workspaces/65e755ea-52c7-4995-926e-c8fabac925fa/output/LedgerForge_MCP_2.6.1_Installer_r6.command -> /Users/vyom/ledgerforge-mcp-prototype/archive/2.6.1-development-history/selected-provenance/LedgerForge_MCP_2.6.1_Installer_r6.command
- COPY /Users/vyom/ledgerforge-mcp-prototype/.executor-task-workspaces/65e755ea-52c7-4995-926e-c8fabac925fa/output/LedgerForge_MCP_2.6.1_Installer_r7.command -> /Users/vyom/ledgerforge-mcp-prototype/archive/2.6.1-development-history/selected-provenance/LedgerForge_MCP_2.6.1_Installer_r7.command
- COPY /Users/vyom/ledgerforge-mcp-prototype/.executor-task-workspaces/65e755ea-52c7-4995-926e-c8fabac925fa/output/LedgerForge_MCP_2.6.1_Installer_r8.command -> /Users/vyom/ledgerforge-mcp-prototype/archive/2.6.1-development-history/selected-provenance/LedgerForge_MCP_2.6.1_Installer_r8.command
- COPY /Users/vyom/ledgerforge-mcp-prototype/.executor-task-workspaces/65e755ea-52c7-4995-926e-c8fabac925fa/output/LedgerForge_MCP_2.6.1_Installer_r9.command -> /Users/vyom/ledgerforge-mcp-prototype/archive/2.6.1-development-history/selected-provenance/LedgerForge_MCP_2.6.1_Installer_r9.command
- COPY /Users/vyom/ledgerforge-mcp-prototype/.executor-task-workspaces/65e755ea-52c7-4995-926e-c8fabac925fa/output/LedgerForge_MCP_2.6.1_Installer_r10.command -> /Users/vyom/ledgerforge-mcp-prototype/archive/2.6.1-development-history/selected-provenance/LedgerForge_MCP_2.6.1_Installer_r10.command
- COPY /Users/vyom/ledgerforge-mcp-prototype/.executor-task-workspaces/65e755ea-52c7-4995-926e-c8fabac925fa/output/candidate_final.py -> /Users/vyom/ledgerforge-mcp-prototype/archive/2.6.1-development-history/selected-provenance/candidate_final.py
- COPY /Users/vyom/ledgerforge-mcp-prototype/.executor-task-workspaces/65e755ea-52c7-4995-926e-c8fabac925fa/output/qualify_executor_current_static_final.py -> /Users/vyom/ledgerforge-mcp-prototype/archive/2.6.1-development-history/selected-provenance/qualify_executor_current_static_final.py
- COPY /Users/vyom/ledgerforge-mcp-prototype/.executor-task-workspaces/65e755ea-52c7-4995-926e-c8fabac925fa/output/qualify_release_final5.py -> /Users/vyom/ledgerforge-mcp-prototype/archive/2.6.1-development-history/selected-provenance/qualify_release_final5.py
- MOVE /Users/vyom/ledgerforge-mcp-prototype/executor_v1.pre-auth.py -> /Users/vyom/ledgerforge-mcp-prototype/previous/legacy-root-files/executor_v1.pre-auth.py
- MOVE /Users/vyom/ledgerforge-mcp-prototype/executor_v1.py -> /Users/vyom/ledgerforge-mcp-prototype/previous/legacy-root-files/executor_v1.py
- MOVE /Users/vyom/ledgerforge-mcp-prototype/executor_v2.py -> /Users/vyom/ledgerforge-mcp-prototype/previous/legacy-root-files/executor_v2.py
- MOVE /Users/vyom/ledgerforge-mcp-prototype/LedgerForge MCP.command.v1.backup -> /Users/vyom/ledgerforge-mcp-prototype/previous/legacy-root-files/LedgerForge MCP.command.v1.backup
- MOVE /Users/vyom/ledgerforge-mcp-prototype/qualify_executor_v1.py -> /Users/vyom/ledgerforge-mcp-prototype/previous/legacy-root-files/qualify_executor_v1.py
- MOVE /Users/vyom/ledgerforge-mcp-prototype/qualify_executor_v2_live.py -> /Users/vyom/ledgerforge-mcp-prototype/previous/legacy-root-files/qualify_executor_v2_live.py
- MOVE /Users/vyom/ledgerforge-mcp-prototype/qualify_executor_v2_static.py -> /Users/vyom/ledgerforge-mcp-prototype/previous/legacy-root-files/qualify_executor_v2_static.py
- MOVE /Users/vyom/ledgerforge-mcp-prototype/qualify_executor_v2_1_live.py -> /Users/vyom/ledgerforge-mcp-prototype/previous/legacy-root-files/qualify_executor_v2_1_live.py
- MOVE /Users/vyom/ledgerforge-mcp-prototype/qualify_executor_v2_1_recovery.py -> /Users/vyom/ledgerforge-mcp-prototype/previous/legacy-root-files/qualify_executor_v2_1_recovery.py
- MOVE /Users/vyom/ledgerforge-mcp-prototype/qualify_executor_v2_1_static.py -> /Users/vyom/ledgerforge-mcp-prototype/previous/legacy-root-files/qualify_executor_v2_1_static.py
- MOVE /Users/vyom/ledgerforge-mcp-prototype/qualify_executor_v2_5_live.py -> /Users/vyom/ledgerforge-mcp-prototype/previous/legacy-root-files/qualify_executor_v2_5_live.py
- MOVE /Users/vyom/ledgerforge-mcp-prototype/qualify_executor_v2_5_static.py -> /Users/vyom/ledgerforge-mcp-prototype/previous/legacy-root-files/qualify_executor_v2_5_static.py
- MOVE /Users/vyom/ledgerforge-mcp-prototype/qualify_executor_v2_6_isolated.py -> /Users/vyom/ledgerforge-mcp-prototype/previous/legacy-root-files/qualify_executor_v2_6_isolated.py
- MOVE /Users/vyom/ledgerforge-mcp-prototype/qualify_executor_v2_6_static.py -> /Users/vyom/ledgerforge-mcp-prototype/previous/legacy-root-files/qualify_executor_v2_6_static.py
- MOVE /Users/vyom/ledgerforge-mcp-prototype/qualify_xcode_sync_exception_v2_6.py -> /Users/vyom/ledgerforge-mcp-prototype/previous/legacy-root-files/qualify_xcode_sync_exception_v2_6.py
- MOVE /Users/vyom/ledgerforge-mcp-prototype/LedgerForge_MCP_2.6.1_Installer.command -> /Users/vyom/ledgerforge-mcp-prototype/archive/2.6.1-development-history/root-stale-installers/LedgerForge_MCP_2.6.1_Installer.command
- MOVE /Users/vyom/ledgerforge-mcp-prototype/LedgerForge_MCP_2.6.1_Installer_r2.command -> /Users/vyom/ledgerforge-mcp-prototype/archive/2.6.1-development-history/root-stale-installers/LedgerForge_MCP_2.6.1_Installer_r2.command
- MOVE mcp2.1-backups/ -> previous/rollback-stores/mcp2.1-backups/
- LINK mcp2.1-backups -> previous/rollback-stores/mcp2.1-backups
- MOVE mcp2.3-backups/ -> previous/rollback-stores/mcp2.3-backups/
- LINK mcp2.3-backups -> previous/rollback-stores/mcp2.3-backups
- MOVE mcp2.4-backups/ -> previous/rollback-stores/mcp2.4-backups/
- LINK mcp2.4-backups -> previous/rollback-stores/mcp2.4-backups
- MOVE mcp2.5-backups/ -> previous/rollback-stores/mcp2.5-backups/
- LINK mcp2.5-backups -> previous/rollback-stores/mcp2.5-backups
- MOVE mcp2.5.1-backups/ -> previous/rollback-stores/mcp2.5.1-backups/
- LINK mcp2.5.1-backups -> previous/rollback-stores/mcp2.5.1-backups
- MOVE mcp2.5.2-backups/ -> previous/rollback-stores/mcp2.5.2-backups/
- LINK mcp2.5.2-backups -> previous/rollback-stores/mcp2.5.2-backups
- MOVE mcp2.6-backups/ -> previous/rollback-stores/mcp2.6-backups/
- LINK mcp2.6-backups -> previous/rollback-stores/mcp2.6-backups
- MOVE mcp2.6.1-backups/ -> previous/rollback-stores/mcp2.6.1-backups/
- LINK mcp2.6.1-backups -> previous/rollback-stores/mcp2.6.1-backups
- MOVE mcp-owner-recovery-audit/ -> archive/owner-recovery-state/mcp-owner-recovery-audit/
- LINK mcp-owner-recovery-audit -> archive/owner-recovery-state/mcp-owner-recovery-audit
- MOVE mcp-owner-recovery-backups/ -> archive/owner-recovery-state/mcp-owner-recovery-backups/
- LINK mcp-owner-recovery-backups -> archive/owner-recovery-state/mcp-owner-recovery-backups
- MOVE mcp-owner-recovery-deployment-backups/ -> archive/owner-recovery-state/mcp-owner-recovery-deployment-backups/
- LINK mcp-owner-recovery-deployment-backups -> archive/owner-recovery-state/mcp-owner-recovery-deployment-backups
- MOVE mcp-releases/ -> archive/release-store/
- LINK mcp-releases -> archive/release-store
- DELETE .DS_Store
- DELETE __pycache__/
- DELETE mcp-releases/.DS_Store
- DELETE abandoned release temp 2.5-6aec4a5eba2e5060a98bc0f955ce4a6805492b00884a1654e589026c3fd16331-20260823-063636.tmp/
- DELETE abandoned release temp 2.5-6aec4a5eba2e5060a98bc0f955ce4a6805492b00884a1654e589026c3fd16331-20260823-063926.tmp/
- DELETE abandoned release temp 2.5-aeae0a057a09f8bea8da85ac0d46662fd14e41ea5cc6812d97cafb42ad2a2903-20260823-062319.tmp/
- DELETE abandoned release temp 2.5-aeae0a057a09f8bea8da85ac0d46662fd14e41ea5cc6812d97cafb42ad2a2903-20260823-062559.tmp/
- DELETE abandoned release temp 2.5-aeae0a057a09f8bea8da85ac0d46662fd14e41ea5cc6812d97cafb42ad2a2903-20260823-063215.tmp/
- DELETE mcp2.1-backups/.DS_Store
- DELETE mcp2.3-backups/.DS_Store
- DELETE mcp2.5.1-backups/.DS_Store
- DELETE mcp2.6-backups/.DS_Store
- COPY /Users/vyom/ledgerforge-mcp-prototype/mcp-releases/2.6.1-deployment-20260825T061125.json -> /Users/vyom/ledgerforge-mcp-prototype/2.6.1/receipts/2.6.1-deployment-20260825T061125.json
- COPY /Users/vyom/ledgerforge-mcp-prototype/mcp-releases/2.6.1-deployment-20260825T062341.json -> /Users/vyom/ledgerforge-mcp-prototype/2.6.1/receipts/2.6.1-deployment-20260825T062341.json
- COPY /Users/vyom/ledgerforge-mcp-prototype/mcp-releases/2.6.1-deployment-20260825T065141.json -> /Users/vyom/ledgerforge-mcp-prototype/2.6.1/receipts/2.6.1-deployment-20260825T065141.json

## Safety notes

- Product repository WIP was not touched by this housekeeping.
- Historical receipt paths are preserved through compatibility paths.
- Live state-root and task-workspace directories are not bulk-cleaned by this organizer.
- `.tmp` release staging directories are deleted only after verifying there is no prepared maintenance release.
- Managed Executor task workspaces require lifecycle-aware cleanup; they are not recursively purged here.
