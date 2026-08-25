# LedgerForge MCP root

Current accepted release: **2.6.1**

Primary record:
`2.6.1/RELEASE_RECORD.md`

Current manifest:
`2.6.1/MANIFEST.sha256`

Organization:
- `2.6.1/` current accepted release
- `previous/` rollback/legacy material
- `archive/` historical development and audit material

Hidden `.executor-*`, `.mcp-maintenance` and `.venv` paths are operational runtime exceptions and must not be reorganized casually.

Never use the LedgerForge product repository as MCP artifact storage.

## Finder presentation

Finder-facing policy for the MCP root:

- Visible: `2.6.1/`, `archive/`, `previous/`, `MCP_ROOT_RECORD.md`.
- Installed runtime files remain at their established root paths but carry the macOS Finder `hidden` flag.
- Historical compatibility symlinks remain at their established root paths but carry the macOS Finder `hidden` flag.
- Hidden flags are presentation metadata only. They do not change pathnames, file contents, symlink targets, hashes, runtime behavior, or historical receipt resolution.
- Do not move or delete hidden compatibility/runtime entries merely because Finder normally suppresses them.


## Canonical physical checkout

As of 2026-08-25:

- Canonical physical MCP root:
  `/Users/vyom/Applications/LedgerForge-MCP`
- Historical compatibility path:
  `/Users/vyom/ledgerforge-mcp-prototype`
- The historical path is a symlink to the canonical physical root.
- Keep the compatibility path throughout the 2.6.1 lifecycle because the accepted launcher, state pointers and historical receipts reference it.
- Do not rewrite historical deployment receipts merely to replace the old pathname.
- LedgerForge product repository remains physically separate at:
  `/Users/vyom/Applications/LedgerForge`
