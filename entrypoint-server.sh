#!/usr/bin/env bash
# ── WireGuard Fuzz Server — Container Entrypoint ─────────────────────────────
# Configures a WireGuard interface directly inside the privileged container
# (no inner network namespace needed — the container itself is the namespace).
# Starts wg_monitor, tcpdump, and blocks until SIGTERM.
set -euo pipefail

LOG_DIR="/fuzz-results"
SHARED_DIR="/shared"
WG_IFACE="wg0"
WG_PORT="${WG_PORT:-51820}"
FUZZER_IP="${FUZZER_IP:-172.28.0.20}"
PCAP_FILE="${LOG_DIR}/capture.pcap"
MONITOR_LOG="${LOG_DIR}/monitor.jsonl"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
log()  { echo -e "${GREEN}[server]${NC} $*"; }
warn() { echo -e "${YELLOW}[server]${NC} $*"; }
die()  { echo -e "${RED}[server]${NC} $*" >&2; exit 1; }

mkdir -p "${LOG_DIR}" "${SHARED_DIR}"

# ── 1. Verify WireGuard kernel module ────────────────────────────────────────
log "Checking WireGuard kernel module..."
if ! lsmod 2>/dev/null | grep -q wireguard; then
    # Try to load it (works if host has the module available)
    modprobe wireguard 2>/dev/null || true
fi
if ! lsmod 2>/dev/null | grep -q wireguard; then
    die "wireguard kernel module not loaded. Run: sudo modprobe wireguard on the host."
fi
log "wireguard module: OK"

# ── 2. Generate keypairs ──────────────────────────────────────────────────────
log "Generating WireGuard keypairs..."
SERVER_PRIVKEY=$(wg genkey)
SERVER_PUBKEY=$(echo "${SERVER_PRIVKEY}" | wg pubkey)
CLIENT_PRIVKEY=$(wg genkey)
CLIENT_PUBKEY=$(echo "${CLIENT_PRIVKEY}" | wg pubkey)
log "Server pubkey: ${SERVER_PUBKEY}"

# ── 3. Create WireGuard interface ────────────────────────────────────────────
log "Creating ${WG_IFACE}..."
ip link del "${WG_IFACE}" 2>/dev/null || true
ip link add "${WG_IFACE}" type wireguard
ip addr add "10.100.0.1/24" dev "${WG_IFACE}"

wg set "${WG_IFACE}" \
    listen-port "${WG_PORT}" \
    private-key <(echo "${SERVER_PRIVKEY}") \
    peer "${CLIENT_PUBKEY}" \
        allowed-ips "0.0.0.0/0,::/0"

ip link set "${WG_IFACE}" up
log "WireGuard interface up on :${WG_PORT}"

# ── 4. Kernel instrumentation ─────────────────────────────────────────────────
echo 0    > /proc/sys/kernel/printk_ratelimit        2>/dev/null || true
echo 9999 > /proc/sys/kernel/printk_ratelimit_burst  2>/dev/null || true
INITIAL_TAINT=$(cat /proc/sys/kernel/tainted 2>/dev/null || echo "0")
log "Initial kernel taint: ${INITIAL_TAINT}"

# ── 5. Write fuzzer config to shared volume ───────────────────────────────────
# Use the container's actual IP on the Docker network so the fuzzer
# can reach the WireGuard UDP socket.
CONTAINER_IP=$(ip route get "${FUZZER_IP}" 2>/dev/null \
               | awk '/src/{print $NF; exit}' \
               || hostname -I | awk '{print $1}')

log "Container IP: ${CONTAINER_IP}"

cat > "${SHARED_DIR}/wg_fuzz_config.json" << JSON
{
    "server_ip":          "${CONTAINER_IP}",
    "server_port":        ${WG_PORT},
    "server_pubkey_b64":  "${SERVER_PUBKEY}",
    "client_privkey_b64": "${CLIENT_PRIVKEY}",
    "client_pubkey_b64":  "${CLIENT_PUBKEY}",
    "wg_iface":           "${WG_IFACE}",
    "log_dir":            "${LOG_DIR}",
    "wg_tunnel_server":   "10.100.0.1",
    "wg_tunnel_client":   "10.100.0.2",
    "initial_taint":      ${INITIAL_TAINT}
}
JSON
log "Config written to ${SHARED_DIR}/wg_fuzz_config.json"

# Signal to fuzzer that config is ready
touch "${SHARED_DIR}/.server_ready"

# ── 6. Determine capture interface ───────────────────────────────────────────
# Capture on the main Docker network interface (eth0) so we see all
# WireGuard UDP traffic before it is processed by the kernel module.
CAPTURE_IFACE=$(ip route show default 2>/dev/null \
                | awk '/default/{print $5; exit}' \
                || echo "eth0")
log "Capturing on interface: ${CAPTURE_IFACE}"

# ── 7. Start tcpdump ─────────────────────────────────────────────────────────
tcpdump -i "${CAPTURE_IFACE}" \
        -w "${PCAP_FILE}" \
        -s 0 \
        --immediate-mode \
        "udp port ${WG_PORT}" &
TCPDUMP_PID=$!
log "tcpdump PID: ${TCPDUMP_PID} -> ${PCAP_FILE}"

# ── 8. Start wg_monitor ───────────────────────────────────────────────────────
if [[ -x /harness/wg_monitor ]]; then
    /harness/wg_monitor \
        --port    "${WG_PORT}" \
        --iface   "${CAPTURE_IFACE}" \
        --logfile "${MONITOR_LOG}" \
        --pidfile "${LOG_DIR}/monitor.pid" &
    MONITOR_PID=$!
    log "wg_monitor PID: ${MONITOR_PID} -> ${MONITOR_LOG}"
else
    warn "wg_monitor binary not found — kernel log only"
    MONITOR_PID=""
fi

# ── 9. Watchdog: log taint changes, print wg stats every 10 s ────────────────
watchdog() {
    local prev_taint="${INITIAL_TAINT}"
    while true; do
        sleep 10
        local cur_taint
        cur_taint=$(cat /proc/sys/kernel/tainted 2>/dev/null || echo "0")
        if [[ "${cur_taint}" != "${prev_taint}" ]]; then
            warn "KERNEL TAINT CHANGED: ${prev_taint} -> ${cur_taint}"
            printf '{"ts":"%s","source":"watchdog","event":"taint_change","prev":%s,"now":%s,"ANOMALY":true}\n' \
                "$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)" \
                "${prev_taint}" "${cur_taint}" \
                >> "${LOG_DIR}/watchdog.jsonl"
            prev_taint="${cur_taint}"
        fi
        # Append wg show stats
        if command -v wg &>/dev/null; then
            wg show "${WG_IFACE}" 2>/dev/null \
                | awk -v ts="$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)" \
                    'BEGIN{printf "{\"ts\":\"%s\",\"source\":\"wg_show\"", ts}
                     /latest handshake/{printf ",\"last_handshake\":\"%s %s %s\"", $3,$4,$5}
                     /transfer/{printf ",\"transfer\":\"%s\"", $2}
                     END{print "}"}' \
                >> "${LOG_DIR}/watchdog.jsonl" 2>/dev/null || true
        fi
    done
}
watchdog &
WATCHDOG_PID=$!

# ── 10. Graceful shutdown ─────────────────────────────────────────────────────
cleanup() {
    log "Shutting down..."
    kill "${TCPDUMP_PID}"  2>/dev/null || true
    [[ -n "${MONITOR_PID}" ]] && kill "${MONITOR_PID}" 2>/dev/null || true
    kill "${WATCHDOG_PID}" 2>/dev/null || true
    ip link del "${WG_IFACE}" 2>/dev/null || true
    log "Final kernel taint: $(cat /proc/sys/kernel/tainted 2>/dev/null || echo unknown)"
    log "Logs in ${LOG_DIR}"
}
trap cleanup SIGTERM SIGINT

log "Server ready. Waiting for fuzzer..."
wait
