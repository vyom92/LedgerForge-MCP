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

## Repository boundary

This repository is separate from the LedgerForge product repository.

- LedgerForge product: `/Users/vyom/Applications/LedgerForge`
- LedgerForge MCP: `/Users/vyom/Applications/LedgerForge-MCP`

MCP runtime state, credentials, task workspaces, rollback stores,
historical build artifacts and private material are intentionally not
version-controlled.

See `MCP_ROOT_RECORD.md`, `2.6.2/RELEASE_RECORD.md` and the historical
`2.6.1/RELEASE_RECORD.md`.
