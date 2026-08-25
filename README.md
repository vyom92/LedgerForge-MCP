# LedgerForge MCP Executor

Local MCP execution and evidence infrastructure for LedgerForge.

## Current production baseline

- Executor: 2.6.1
- Toolset revision: 8
- Schema contract revision: 2.6.1
- Snapshot contract: execution-snapshot-v2

Canonical release evidence is under `2.6.1/`.

## Repository boundary

This repository is separate from the LedgerForge product repository.

- LedgerForge product: `/Users/vyom/Applications/LedgerForge`
- LedgerForge MCP: `/Users/vyom/Applications/LedgerForge-MCP`

MCP runtime state, credentials, task workspaces, rollback stores,
historical build artifacts and private material are intentionally not
version-controlled.

See `MCP_ROOT_RECORD.md` and `2.6.1/RELEASE_RECORD.md`.
