#!/usr/bin/env bash
# ── WireGuard Fuzz Client — Container Entrypoint ─────────────────────────────
# Waits for the server to write its config, then runs all fuzzing phases,
# copies results to the shared volume, and generates the peer-review report.
set -euo pipefail

SHARED_DIR="/shared"
LOG_DIR="/fuzz-results"
CONFIG_FILE="${SHARED_DIR}/wg_fuzz_config.json"
FUZZER_LOG="${LOG_DIR}/fuzzer.jsonl"

PHASE="${PHASE:-all}"
COUNT="${COUNT:-30}"
DELAY="${DELAY:-0.05}"
SEED="${SEED:-42}"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
log()  { echo -e "${GREEN}[fuzzer]${NC} $*"; }
warn() { echo -e "${YELLOW}[fuzzer]${NC} $*"; }
die()  { echo -e "${RED}[fuzzer]${NC} $*" >&2; exit 1; }

mkdir -p "${LOG_DIR}"

# ── 1. Wait for server to be ready ───────────────────────────────────────────
log "Waiting for server config at ${CONFIG_FILE}..."
WAIT_SECS=0
MAX_WAIT=60
until [[ -f "${SHARED_DIR}/.server_ready" && -f "${CONFIG_FILE}" ]]; do
    if (( WAIT_SECS >= MAX_WAIT )); then
        die "Timed out waiting for server (${MAX_WAIT}s). Is wg-server running?"
    fi
    sleep 1
    (( WAIT_SECS++ )) || true
done
log "Server ready after ${WAIT_SECS}s"

# Give the WireGuard interface a moment to be fully up
sleep 2

# ── 2. Log environment metadata ───────────────────────────────────────────────
SERVER_IP=$(python3 -c "import json; d=json.load(open('${CONFIG_FILE}')); print(d['server_ip'])")
SERVER_PORT=$(python3 -c "import json; d=json.load(open('${CONFIG_FILE}')); print(d['server_port'])")
log "Target: ${SERVER_IP}:${SERVER_PORT}"
log "Phase: ${PHASE}  Count: ${COUNT}  Delay: ${DELAY}  Seed: ${SEED}"

printf '{"ts":"%s","source":"fuzzer","event":"run_start","phase":"%s","count":%s,"delay":%s,"seed":%s,"target":"%s:%s"}\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)" \
    "${PHASE}" "${COUNT}" "${DELAY}" "${SEED}" \
    "${SERVER_IP}" "${SERVER_PORT}" \
    >> "${FUZZER_LOG}"

# ── 3. Run the fuzzer ─────────────────────────────────────────────────────────
log "Starting wg_fuzzer.py..."
python3 /harness/wg_fuzzer.py \
    --config  "${CONFIG_FILE}" \
    --phase   "${PHASE}" \
    --count   "${COUNT}" \
    --delay   "${DELAY}" \
    --seed    "${SEED}" \
    --logfile "${FUZZER_LOG}"

EXIT_CODE=$?
log "wg_fuzzer.py exited with code ${EXIT_CODE}"

# ── 4. Extract anomaly lines into a separate file ────────────────────────────
log "Extracting anomalies..."
grep '"anomaly": true' "${FUZZER_LOG}" > "${LOG_DIR}/anomalies.jsonl" 2>/dev/null || true
ANOMALY_COUNT=$(wc -l < "${LOG_DIR}/anomalies.jsonl" 2>/dev/null || echo "0")
log "Anomalies found: ${ANOMALY_COUNT}"

# ── 5. Generate HTML report ───────────────────────────────────────────────────
log "Generating HTML report..."
python3 /harness/generate_report.py \
    --fuzzer-log  "${FUZZER_LOG}" \
    --monitor-log "${LOG_DIR}/monitor.jsonl" \
    --anomaly-log "${LOG_DIR}/anomalies.jsonl" \
    --config      "${CONFIG_FILE}" \
    --output      "${LOG_DIR}/report.html" \
    || warn "Report generation failed — check generate_report.py"

# ── 6. Write run metadata ─────────────────────────────────────────────────────
cat > "${LOG_DIR}/run_metadata.json" << JSON
{
    "run_ts":       "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "phase":        "${PHASE}",
    "count":        ${COUNT},
    "delay":        ${DELAY},
    "seed":         ${SEED},
    "server_ip":    "${SERVER_IP}",
    "server_port":  ${SERVER_PORT},
    "anomalies":    ${ANOMALY_COUNT},
    "fuzzer_exit":  ${EXIT_CODE},
    "hostname":     "$(hostname)",
    "kernel":       "$(uname -r)"
}
JSON

# Signal server that fuzzing is done so it can flush pcap / logs
touch "${SHARED_DIR}/.fuzzer_done"

printf '{"ts":"%s","source":"fuzzer","event":"run_end","anomalies":%s,"exit":%s}\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)" "${ANOMALY_COUNT}" "${EXIT_CODE}" \
    >> "${FUZZER_LOG}"

log "Done. Results written to ${LOG_DIR}/"
[[ "${ANOMALY_COUNT}" -gt 0 ]] && warn "${ANOMALY_COUNT} anomaly/anomalies detected — review ${LOG_DIR}/anomalies.jsonl"
exit "${EXIT_CODE}"
