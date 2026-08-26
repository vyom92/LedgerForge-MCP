#!/bin/zsh
set -u

ROOT="$HOME/ledgerforge-mcp-prototype"
CFG="$HOME/.config/tunnel-client"
PYTHON="$ROOT/.venv/bin/python"
VERSION_FILE="$ROOT/.executor-version"
STATE_ROOT_FILE="$ROOT/.executor-v2.1-state-root"
ADMIN_TOKEN_FILE="$ROOT/.executor-admin-token"
CURRENT_STATIC_QUALIFIER="$ROOT/qualify_executor_current_static.py"
CURRENT_ISOLATED_QUALIFIER="$ROOT/qualify_executor_current_isolated.py"
RELEASE_ACTIVATOR="$ROOT/ledgerforge_mcp_release_activator.py"
EXECUTOR_PIDFILE="$CFG/ledgerforge-executor.pid"
TUNNEL_PIDFILE="$CFG/ledgerforge-recovery.pid"
EXECUTOR_LOG="$CFG/ledgerforge-executor.log"
TUNNEL_LOG="$CFG/ledgerforge-recovery.log"
TUNNEL_PROFILE="ledgerforge-recovery"
TUNNEL_BIN="/opt/homebrew/bin/tunnel-client"
PORT=8768

mkdir -p "$CFG"

active_version() {
    local v="v1"
    if [[ -f "$VERSION_FILE" ]]; then
        v="$(/bin/cat "$VERSION_FILE" 2>/dev/null || true)"
    fi
    [[ "$v" == "v1" || "$v" == "v2" || "$v" == "v2.1" ]] || v="v1"
    printf '%s' "$v"
}

executor_file() {
    case "$(active_version)" in
        v2.1) printf '%s' "$ROOT/executor_v2_1.py" ;;
        v2) printf '%s' "$ROOT/executor_v2.py" ;;
        *) printf '%s' "$ROOT/executor_v1.py" ;;
    esac
}

executor_pids() {
    pgrep -f 'python.*executor_v(1|2|2_1)\.py|[/ ]executor_v(1|2|2_1)\.py$' 2>/dev/null || true
}

tunnel_pids() {
    ps -axo pid=,command= 2>/dev/null | awk '$0 ~ /tunnel-client run --profile ledgerforge-recovery([[:space:]]|$)/ {print $1}' || true
}

port_pid() {
    lsof -tiTCP:${PORT} -sTCP:LISTEN 2>/dev/null | head -1
}

one_pid_or_empty() {
    local values="$1"
    local count
    count=$(printf '%s\n' "$values" | sed '/^$/d' | wc -l | tr -d ' ')
    if [[ "$count" -gt 1 ]]; then
        return 2
    fi
    printf '%s' "$(printf '%s\n' "$values" | sed '/^$/d' | head -1)"
}

sha_file() {
    [[ -f "$1" ]] && shasum -a 256 "$1" | awk '{print $1}' || printf 'MISSING'
}

status() {
    local epids tpids epid tpid socketpid erc trc active execfile release
    active="$(active_version)"
    execfile="$(executor_file)"
    release="$(/usr/bin/awk -F '"' '/^EXECUTOR_VERSION[[:space:]]*=/ {print $2; exit}' "$execfile" 2>/dev/null || true)"
    [[ -n "$release" ]] || release="unknown"
    epids="$(executor_pids)"
    tpids="$(tunnel_pids)"
    epid="$(one_pid_or_empty "$epids")"; erc=$?
    tpid="$(one_pid_or_empty "$tpids")"; trc=$?
    socketpid="$(port_pid)"

    echo "LedgerForge MCP Control"
    echo "────────────────────────────────────"
    echo "Release  : MCP $release"
    echo "Engine   : $active (legacy slot name)"
    echo "Source   : $(basename "$execfile")"
    echo "SHA-256  : $(sha_file "$execfile")"
    if [[ $erc -eq 2 ]]; then
        echo "Executor : ⚠ MULTIPLE PROCESSES"
        printf '%s\n' "$epids" | sed 's/^/           PID /'
    elif [[ -n "$epid" ]]; then
        echo "Executor : ✅ RUNNING (PID $epid)"
    else
        echo "Executor : ⛔ STOPPED"
    fi
    if [[ $trc -eq 2 ]]; then
        echo "Tunnel   : ⚠ MULTIPLE PROCESSES"
        printf '%s\n' "$tpids" | sed 's/^/           PID /'
    elif [[ -n "$tpid" ]]; then
        echo "Tunnel   : ✅ RUNNING (PID $tpid)"
    else
        echo "Tunnel   : ⛔ STOPPED"
    fi
    [[ -n "$socketpid" ]] && echo "Port $PORT: ✅ LISTENING (PID $socketpid)" || echo "Port $PORT: ⛔ NOT LISTENING"
    [[ -f "$ROOT/.executor-path" || -f "$ROOT/.mcp-path" ]] && echo "MCP path : ✅ FOUND" || echo "MCP path : ⛔ MISSING"
    [[ -f "$ROOT/.executor-token" ]] && echo "Token    : ✅ FOUND" || echo "Token    : ⛔ MISSING"
    [[ -f "$ADMIN_TOKEN_FILE" ]] && echo "Admin    : ✅ TOKEN FOUND" || echo "Admin    : ⚠ TOKEN MISSING"
    [[ -x "$PYTHON" ]] && echo "Python   : ✅ VENV FOUND" || echo "Python   : ⛔ VENV MISSING"
    [[ -x "$TUNNEL_BIN" ]] && echo "Tunnel   : ✅ BINARY FOUND" || echo "Tunnel   : ⛔ BINARY MISSING"
    if [[ "$active" == "v2.1" ]]; then
        [[ -f "$STATE_ROOT_FILE" ]] && echo "State    : ✅ ISOLATED PRODUCTION ROOT" || echo "State    : ⛔ v2.1 POINTER MISSING"
    fi
    if /usr/bin/curl -fsS --max-time 2 http://127.0.0.1:8080/healthz >/dev/null 2>&1; then
        echo "Health   : ✅ healthz"
    else
        echo "Health   : ⚠ healthz unavailable"
    fi
    if /usr/bin/curl -fsS --max-time 2 http://127.0.0.1:8080/readyz >/dev/null 2>&1; then
        echo "Ready    : ✅ readyz"
    else
        echo "Ready    : ⚠ readyz unavailable"
    fi
}

require_base_config() {
    [[ -d "$ROOT" ]] || { echo "ERROR: $ROOT missing."; return 1; }
    [[ -x "$PYTHON" ]] || { echo "ERROR: MCP Python venv missing."; return 1; }
    [[ -f "$(executor_file)" ]] || { echo "ERROR: $(executor_file) missing."; return 1; }
    [[ -f "$ROOT/.executor-token" ]] || { echo "ERROR: .executor-token missing."; return 1; }
    [[ -f "$ROOT/.executor-path" || -f "$ROOT/.mcp-path" ]] || { echo "ERROR: executor MCP path file missing."; return 1; }
    [[ -x "$TUNNEL_BIN" ]] || { echo "ERROR: tunnel-client missing."; return 1; }
    if [[ "$(active_version)" == "v2.1" ]]; then
        [[ -f "$STATE_ROOT_FILE" ]] || { echo "ERROR: v2.1 state-root pointer missing."; return 1; }
        local sr release
        sr="$(/bin/cat "$STATE_ROOT_FILE" 2>/dev/null || true)"
        [[ -n "$sr" && "$sr" == "$ROOT"/.executor-runs-v2_1-production-* ]] || { echo "ERROR: invalid v2.1 production state root."; return 1; }
        [[ -d "$sr" ]] || { echo "ERROR: v2.1 production state root missing."; return 1; }
        release="$(/usr/bin/awk -F '"' '/^EXECUTOR_VERSION[[:space:]]*=/ {print $2; exit}' "$(executor_file)" 2>/dev/null || true)"
        if [[ "$release" == "2.6.1" || "$release" == "2.6.2" ]]; then
            [[ -f "$ADMIN_TOKEN_FILE" ]] || { echo "ERROR: MCP $release admin token missing."; return 1; }
            [[ -f "$CURRENT_STATIC_QUALIFIER" ]] || { echo "ERROR: MCP $release static qualifier missing."; return 1; }
            [[ -f "$CURRENT_ISOLATED_QUALIFIER" ]] || { echo "ERROR: MCP $release isolated qualifier missing."; return 1; }
            [[ -f "$RELEASE_ACTIVATOR" ]] || { echo "ERROR: MCP $release release activator missing."; return 1; }
        fi
        unset sr release
    fi
}

load_private_environment() {
    export LEDGERFORGE_PRIVATE_AMEX_DIRECTORY="$HOME/Documents/Ledger Forge/Originals/AmericanExpress"
    export LEDGERFORGE_AXIS_CARD_PRIVATE_DIRECTORY="$HOME/Documents/Ledger Forge/Originals/Axis/CreditCard"
    export LEDGERFORGE_PRIVATE_CBQ_TEXT_DIRECTORY="$HOME/Documents/Ledger Forge/Originals/CBQ"
    export LEDGERFORGE_PRIVATE_HDFC_ORIGINALS_ROOT="$HOME/Documents/Ledger Forge/Originals/HDFC"
    unset LEDGERFORGE_AXIS_CARD_PRIVATE_PASSWORD 2>/dev/null || true
    if [[ "$(active_version)" != "v2.1" ]]; then
        local pw
        pw="$(security find-generic-password -s "com.ledgerforge.recovery-executor" -a "axis-private-acceptance" -w 2>/dev/null || true)"
        if [[ -n "$pw" ]]; then
            export LEDGERFORGE_AXIS_CARD_PRIVATE_PASSWORD="$pw"
            unset pw
        fi
    fi
}

mcp_path_value() {
    if [[ -f "$ROOT/.executor-path" ]]; then
        /bin/cat "$ROOT/.executor-path"
    else
        /bin/cat "$ROOT/.mcp-path"
    fi
}

start_executor() {
    require_base_config || return 1
    local existing
    existing="$(executor_pids)"
    [[ -z "$existing" ]] || { echo "Executor already running."; return 0; }

    local mcpvalue tokenvalue admintokenvalue execfile release
    mcpvalue="$(mcp_path_value)"
    tokenvalue="$(/bin/cat "$ROOT/.executor-token")"
    execfile="$(executor_file)"
    release="$(/usr/bin/awk -F '"' '/^EXECUTOR_VERSION[[:space:]]*=/ {print $2; exit}' "$execfile" 2>/dev/null || true)"
    [[ -n "$mcpvalue" && -n "$tokenvalue" ]] || { echo "ERROR: persisted executor identity invalid."; return 1; }

    export LEDGERFORGE_EXECUTOR_MCP_PATH="$mcpvalue"
    export LEDGERFORGE_EXECUTOR_MCP_HOST="127.0.0.1"
    export LEDGERFORGE_EXECUTOR_BEARER_TOKEN="$tokenvalue"
    export LEDGERFORGE_EXECUTOR_PUBLIC_URL="https://localhost:${PORT}"
    export LEDGERFORGE_EXECUTOR_PORT="$PORT"
    if [[ "$(active_version)" == "v2.1" ]]; then
        export LEDGERFORGE_EXECUTOR_STATE_ROOT="$(/bin/cat "$STATE_ROOT_FILE")"
        if [[ "$release" == "2.6.1" || "$release" == "2.6.2" ]]; then
            admintokenvalue="$(/bin/cat "$ADMIN_TOKEN_FILE" 2>/dev/null || true)"
            [[ -n "$admintokenvalue" && "$admintokenvalue" != "$tokenvalue" ]] || { echo "ERROR: persisted admin executor identity invalid."; return 1; }
            export LEDGERFORGE_EXECUTOR_ADMIN_BEARER_TOKEN="$admintokenvalue"
        else
            unset LEDGERFORGE_EXECUTOR_ADMIN_BEARER_TOKEN 2>/dev/null || true
        fi
    else
        unset LEDGERFORGE_EXECUTOR_STATE_ROOT 2>/dev/null || true
        unset LEDGERFORGE_EXECUTOR_ADMIN_BEARER_TOKEN 2>/dev/null || true
    fi
    unset mcpvalue tokenvalue admintokenvalue release
    load_private_environment

    cd "$ROOT" || return 1
    nohup "$PYTHON" "$execfile" >> "$EXECUTOR_LOG" 2>&1 &
    local pid=$!
    echo "$pid" > "$EXECUTOR_PIDFILE"
    sleep 2
    if ! kill -0 "$pid" 2>/dev/null; then
        echo "ERROR: executor exited during startup."
        tail -40 "$EXECUTOR_LOG"
        return 1
    fi
    if [[ "$(port_pid)" != "$pid" ]]; then
        echo "ERROR: executor does not own port ${PORT}."
        return 1
    fi
    echo "Executor $(active_version) started: PID $pid"
}

start_tunnel() {
    local existing
    existing="$(tunnel_pids)"
    [[ -z "$existing" ]] || { echo "Tunnel already running."; return 0; }
    nohup "$TUNNEL_BIN" run --profile "$TUNNEL_PROFILE" >> "$TUNNEL_LOG" 2>&1 &
    local pid=$!
    echo "$pid" > "$TUNNEL_PIDFILE"
    sleep 2
    if ! kill -0 "$pid" 2>/dev/null; then
        echo "ERROR: tunnel exited during startup."
        tail -40 "$TUNNEL_LOG"
        return 1
    fi
    echo "Tunnel started: PID $pid"
}

stop_one() {
    local label="$1" values="$2"
    [[ -n "$values" ]] || { echo "$label already stopped."; return 0; }
    local count pid
    count=$(printf '%s\n' "$values" | sed '/^$/d' | wc -l | tr -d ' ')
    if [[ "$count" -gt 1 ]]; then
        echo "STOP: multiple $label processes detected; refusing automatic termination."
        printf '%s\n' "$values"
        return 1
    fi
    pid="$(printf '%s\n' "$values" | head -1)"
    echo "Stopping $label PID $pid..."
    kill "$pid" 2>/dev/null || true
    for _ in {1..30}; do
        if ! kill -0 "$pid" 2>/dev/null; then
            echo "$label stopped."
            return 0
        fi
        sleep 0.2
    done
    echo "STOP: $label did not terminate normally. No SIGKILL issued."
    return 1
}

stop_all() {
    stop_one "tunnel" "$(tunnel_pids)" || return 1
    stop_one "executor" "$(executor_pids)" || return 1
    rm -f "$TUNNEL_PIDFILE" "$EXECUTOR_PIDFILE"
}

start_all() {
    start_executor || return 1
    start_tunnel || return 1
    sleep 1
    [[ -n "$(executor_pids)" && -n "$(tunnel_pids)" && -n "$(port_pid)" ]] || return 1
}

verify_schema() {
    case "$(active_version)" in
        v2.1)
            local execfile release
            execfile="$(executor_file)"
            release="$(/usr/bin/awk -F '"' '/^EXECUTOR_VERSION[[:space:]]*=/ {print $2; exit}' "$execfile" 2>/dev/null || true)"
            case "$release" in
                2.6.1|2.6.2) "$PYTHON" "$CURRENT_ISOLATED_QUALIFIER" --port "$PORT" --schema-only-live --expected-source-sha "$(sha_file "$execfile")" ;;
                2.6.0) "$PYTHON" "$ROOT/qualify_executor_v2_6_isolated.py" --port "$PORT" --schema-only-live --expected-source-sha "$(sha_file "$execfile")" ;;
                *) "$PYTHON" "$ROOT/qualify_executor_v2_5_live.py" --port "$PORT" --schema-only ;;
            esac ;;
        v2) "$PYTHON" "$ROOT/qualify_executor_v2_live.py" --port "$PORT" --schema-only ;;
        *) echo "Schema qualifier is available for v2/v2.1 only."; return 1 ;;
    esac
}

switch_version() {
    local target="$1" previous targetfile
    [[ "$target" == "v1" || "$target" == "v2" || "$target" == "v2.1" ]] || { echo "Invalid target version."; return 1; }
    case "$target" in
        v2.1) targetfile="$ROOT/executor_v2_1.py" ;;
        v2) targetfile="$ROOT/executor_v2.py" ;;
        *) targetfile="$ROOT/executor_v1.py" ;;
    esac
    [[ -f "$targetfile" ]] || { echo "ERROR: $targetfile missing."; return 1; }
    "$PYTHON" -m py_compile "$targetfile" || return 1
    previous="$(active_version)"
    if [[ "$target" == "$previous" ]]; then
        echo "$target already selected."
        return 0
    fi
    stop_all || return 1
    printf '%s\n' "$target" > "$VERSION_FILE"
    if start_all; then
        if [[ "$target" != "v1" ]] && ! verify_schema; then
            echo "$target schema verification failed; rolling back to $previous."
            stop_all || true
            printf '%s\n' "$previous" > "$VERSION_FILE"
            start_all || true
            return 1
        fi
        echo "Switched to $target successfully."
        return 0
    fi
    echo "Start failed; rolling back to $previous."
    stop_all || true
    printf '%s\n' "$previous" > "$VERSION_FILE"
    start_all || true
    return 1
}

private_status() {
    echo "AMEX source root: $([[ -d "$HOME/Documents/Ledger Forge/Originals/AmericanExpress" ]] && echo FOUND || echo MISSING)"
    echo "Axis source root: $([[ -d "$HOME/Documents/Ledger Forge/Originals/Axis/CreditCard" ]] && echo FOUND || echo MISSING)"
    echo "CBQ source root: $([[ -d "$HOME/Documents/Ledger Forge/Originals/CBQ" ]] && echo FOUND || echo MISSING)"
    echo "HDFC source root: $([[ -d "$HOME/Documents/Ledger Forge/Originals/HDFC" ]] && echo FOUND || echo MISSING)"
    if security find-generic-password -s "com.ledgerforge.recovery-executor" -a "axis-private-acceptance" >/dev/null 2>&1; then
        echo "Axis private credential: FOUND"
    else
        echo "Axis private credential: MISSING"
    fi
    echo "Credential values printed: NO"
}

show_logs() {
    echo "=== EXECUTOR LOG ==="
    tail -80 "$EXECUTOR_LOG" 2>/dev/null || echo "(no executor log)"
    echo
    echo "=== TUNNEL LOG ==="
    tail -80 "$TUNNEL_LOG" 2>/dev/null || echo "(no tunnel log)"
}

open_source() {
    local execfile="$(executor_file)"
    if command -v code >/dev/null 2>&1; then
        code "$execfile"
    else
        open -a TextEdit "$execfile"
    fi
}

case "${1:-}" in
    recover-lease)
        "$PYTHON" "$ROOT/ledgerforge_mcp_owner_admin.py" recover-current --terminate-owned --restart
        exit $? ;;
    owner-recovery-status)
        "$PYTHON" "$ROOT/ledgerforge_mcp_owner_admin.py" status
        exit $? ;;
    status) status; exit $? ;;
    start) start_all; rc=$?; status; exit $rc ;;
    stop) stop_all; rc=$?; status; exit $rc ;;
    restart) stop_all && start_all; rc=$?; status; exit $rc ;;
    verify) verify_schema; exit $? ;;
    switch-v1) switch_version v1; rc=$?; status; exit $rc ;;
    switch-v2) switch_version v2; rc=$?; status; exit $rc ;;
    switch-v2.1) switch_version v2.1; rc=$?; status; exit $rc ;;
    recovery-status)
        if [[ "$(active_version)" == "v2.1" ]]; then
            execfile="$(executor_file)"
            release="$(/usr/bin/awk -F '"' '/^EXECUTOR_VERSION[[:space:]]*=/ {print $2; exit}' "$execfile" 2>/dev/null || true)"
            if [[ "$release" == "2.6.1" || "$release" == "2.6.2" ]]; then
                "$PYTHON" "$CURRENT_ISOLATED_QUALIFIER" --port "$PORT" --recovery-status-live --expected-source-sha "$(sha_file "$execfile")"
            elif [[ "$release" == "2.6.0" ]]; then
                "$PYTHON" "$ROOT/qualify_executor_v2_6_isolated.py" --port "$PORT" --recovery-status-live --expected-source-sha "$(sha_file "$execfile")"
            else
                "$PYTHON" "$ROOT/qualify_executor_v2_5_live.py" --port "$PORT" --recovery-status
            fi
            unset execfile release
        else
            echo "recovery-status requires active v2.1"
        fi
        exit $? ;;
    private-status) private_status; exit $? ;;
    logs) show_logs; exit $? ;;
    activate-release)
        [[ -f "$RELEASE_ACTIVATOR" ]] || { echo "ERROR: release activator missing."; exit 1; }
        "$PYTHON" "$RELEASE_ACTIVATOR" "${2:-}"
        exit $? ;;
esac

while true; do
    clear
    status
    echo
    echo "1. Start / repair active connection"
    echo "2. Stop connection"
    echo "3. Restart active connection"
    echo "4. Verify private validation setup"
    echo "5. Verify live MCP schema"
    echo "6. Switch to v2.1"
    echo "7. Switch to v2"
    echo "8. Switch to v1"
    echo "9. Recovery status"
    echo "10. Show logs"
    echo "11. Open active executor source"
    echo "12. Activate armed prepared release"
    echo "13. Quit"
    echo
    printf "Choose: "
    read choice
    case "$choice" in
        1) start_all ;;
        2) stop_all ;;
        3) stop_all && start_all ;;
        4) private_status ;;
        5) verify_schema ;;
        6) switch_version v2.1 ;;
        7) switch_version v2 ;;
        8) switch_version v1 ;;
        9)
            if [[ "$(active_version)" == "v2.1" ]]; then
                execfile="$(executor_file)"
                release="$(/usr/bin/awk -F '"' '/^EXECUTOR_VERSION[[:space:]]*=/ {print $2; exit}' "$execfile" 2>/dev/null || true)"
                if [[ "$release" == "2.6.1" || "$release" == "2.6.2" ]]; then
                    "$PYTHON" "$CURRENT_ISOLATED_QUALIFIER" --port "$PORT" --recovery-status-live --expected-source-sha "$(sha_file "$execfile")"
                elif [[ "$release" == "2.6.0" ]]; then
                    "$PYTHON" "$ROOT/qualify_executor_v2_6_isolated.py" --port "$PORT" --recovery-status-live --expected-source-sha "$(sha_file "$execfile")"
                else
                    "$PYTHON" "$ROOT/qualify_executor_v2_5_live.py" --port "$PORT" --recovery-status
                fi
                unset execfile release
            else
                echo "recovery-status requires active v2.1"
            fi ;;
        10) show_logs ;;
        11) open_source ;;
        12)
            if [[ -f "$RELEASE_ACTIVATOR" ]]; then
                "$PYTHON" "$RELEASE_ACTIVATOR"
            else
                echo "ERROR: release activator missing."
            fi ;;
        13) exit 0 ;;
        *) echo "Invalid choice." ;;
    esac
    echo
    printf "Press Return to continue..."
    read _
done
