#!/bin/zsh
set -euo pipefail
ROOT="$HOME/ledgerforge-mcp-prototype"
PYTHON="$ROOT/.venv/bin/python"
ADMIN="$ROOT/ledgerforge_mcp_owner_admin.py"
[[ -x "$PYTHON" ]] || { echo "ERROR: MCP Python venv missing." >&2; exit 1; }
[[ -f "$ADMIN" ]] || { echo "ERROR: Owner Recovery engine missing." >&2; exit 1; }
if [[ $# -gt 0 ]]; then
  exec "$PYTHON" "$ADMIN" "$@"
fi
while true; do
  clear
  echo "LedgerForge MCP Owner Recovery"
  echo "────────────────────────────────"
  "$PYTHON" "$ADMIN" status || true
  echo
  echo "1. Refresh status"
  echo "2. Run recovery self-test"
  echo "3. Recover current lease (interactive confirmation)"
  echo "4. Quit"
  printf "Choose: "
  read choice
  case "$choice" in
    1) ;;
    2) "$PYTHON" "$ADMIN" self-test ; read -k 1 "?Press any key to continue..." ;;
    3) "$PYTHON" "$ADMIN" recover-current --terminate-owned --restart ; read -k 1 "?Press any key to continue..." ;;
    4) exit 0 ;;
    *) echo "Invalid choice."; sleep 1 ;;
  esac
done
