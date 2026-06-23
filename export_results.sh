#!/usr/bin/env bash
# ── WireGuard Fuzz Harness — Peer Review Exporter ────────────────────────────
#
# Extracts logs, captures, and metadata from the Docker volumes (or native
# log directory), generates a self-contained HTML report, SHA-256 manifest,
# and packages everything into a timestamped tarball ready for peer review.
#
# Usage:
#   ./export_results.sh                  # Docker mode (default)
#   ./export_results.sh --native         # Native mode (reads wg_fuzz_logs/)
#   ./export_results.sh --out /tmp/peer  # Custom output directory
#   ./export_results.sh --no-stop        # Skip stopping containers
#
# Output:
#   wg_fuzz_export_YYYYMMDD_HHMMSS.tar.gz
# ---------------------------------------------------------------------------
set -euo pipefail

# ── Defaults ──────────────────────────────────────────────────────────────────
MODE="docker"
OUT_DIR=""
STOP_CONTAINERS=true
NATIVE_LOG_DIR="./wg_fuzz_logs"
DOCKER_RESULTS_VOL="wg-fuzz_fuzz-results"
DOCKER_SHARED_VOL="wg-fuzz_shared-config"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
EXPORT_NAME="wg_fuzz_export_${TIMESTAMP}"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; BOLD='\033[1m'; NC='\033[0m'
log()  { echo -e "${GREEN}[export]${NC} $*"; }
warn() { echo -e "${YELLOW}[export]${NC} $*"; }
die()  { echo -e "${RED}[export]${NC} $*" >&2; exit 1; }

# ── Argument parsing ──────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --native)    MODE="native"     ;;
        --no-stop)   STOP_CONTAINERS=false ;;
        --out)       shift; OUT_DIR="$1" ;;
        --out=*)     OUT_DIR="${1#*=}"   ;;
        -h|--help)
            grep '^#' "$0" | sed 's/^# \?//'
            exit 0
            ;;
        *) warn "Unknown argument: $1" ;;
    esac
    shift
done

[[ -z "${OUT_DIR}" ]] && OUT_DIR="${EXPORT_NAME}"

# ── Stop containers gracefully (Docker mode) ──────────────────────────────────
if [[ "${MODE}" == "docker" && "${STOP_CONTAINERS}" == "true" ]]; then
    if command -v docker &>/dev/null && docker compose ps -q 2>/dev/null | grep -q .; then
        log "Stopping containers gracefully..."
        # Give containers 10 s to flush logs before SIGKILL
        docker compose stop --timeout 10 2>/dev/null || true
    fi
fi

# ── Create export directory ───────────────────────────────────────────────────
mkdir -p "${OUT_DIR}"
log "Export directory: ${OUT_DIR}/"

# ── Extract logs ──────────────────────────────────────────────────────────────
if [[ "${MODE}" == "docker" ]]; then
    log "Extracting from Docker volume: ${DOCKER_RESULTS_VOL}"

    # Use a temporary alpine container to copy from named volume
    HELPER="wg-fuzz-exporter-$$"
    docker run --rm --name "${HELPER}" \
        -v "${DOCKER_RESULTS_VOL}:/results:ro" \
        -v "${DOCKER_SHARED_VOL}:/shared:ro" \
        -v "$(realpath "${OUT_DIR}"):/export" \
        alpine:3 sh -c '
            cp -r /results/. /export/ 2>/dev/null || true
            cp /shared/wg_fuzz_config.json /export/ 2>/dev/null || true
        ' 2>/dev/null \
    || { warn "Docker volume extraction failed — trying docker compose cp..."; \
         docker compose cp wg-fuzzer:/fuzz-results/. "${OUT_DIR}/" 2>/dev/null || true; \
         docker compose cp wg-server:/fuzz-results/.  "${OUT_DIR}/" 2>/dev/null || true; }

else
    log "Copying from native log directory: ${NATIVE_LOG_DIR}"
    [[ -d "${NATIVE_LOG_DIR}" ]] || die "Log directory not found: ${NATIVE_LOG_DIR}"
    cp -r "${NATIVE_LOG_DIR}/." "${OUT_DIR}/"
    [[ -f "./wg_fuzz_config.json" ]] && cp ./wg_fuzz_config.json "${OUT_DIR}/" || true
fi

# ── Verify we have something to export ───────────────────────────────────────
JSONL_COUNT=$(find "${OUT_DIR}" -name "*.jsonl" 2>/dev/null | wc -l)
if [[ "${JSONL_COUNT}" -eq 0 ]]; then
    die "No .jsonl files found in ${OUT_DIR}. Did the fuzzer run complete?"
fi
log "Found ${JSONL_COUNT} log file(s)"

# ── Generate HTML report ──────────────────────────────────────────────────────
if command -v python3 &>/dev/null && [[ -f ./generate_report.py ]]; then
    log "Generating HTML report..."
    python3 ./generate_report.py \
        --fuzzer-log  "${OUT_DIR}/fuzzer.jsonl" \
        --monitor-log "${OUT_DIR}/monitor.jsonl" \
        --anomaly-log "${OUT_DIR}/anomalies.jsonl" \
        --config      "${OUT_DIR}/wg_fuzz_config.json" \
        --output      "${OUT_DIR}/report.html" \
    && log "report.html generated" \
    || warn "Report generation failed — HTML report may be missing"
else
    warn "python3 or generate_report.py not found — skipping HTML report"
fi

# ── Filter anomalies if not already present ───────────────────────────────────
if [[ ! -s "${OUT_DIR}/anomalies.jsonl" ]] && [[ -f "${OUT_DIR}/fuzzer.jsonl" ]]; then
    log "Filtering anomalies from fuzzer.jsonl..."
    grep '"anomaly": true' "${OUT_DIR}/fuzzer.jsonl" > "${OUT_DIR}/anomalies.jsonl" 2>/dev/null || true
fi
ANOMALY_COUNT=$(wc -l < "${OUT_DIR}/anomalies.jsonl" 2>/dev/null || echo "0")

# ── Write README_export.txt ───────────────────────────────────────────────────
cat > "${OUT_DIR}/README_export.txt" << TEXT
WireGuard Protocol Fuzz — Peer Review Export
============================================
Generated : $(date -u "+%Y-%m-%d %H:%M:%S UTC")
Host      : $(hostname)
Kernel    : $(uname -r)
Export ID : ${EXPORT_NAME}

Contents
--------
fuzzer.jsonl       All packets sent + server responses + anomaly flags
monitor.jsonl      AF_PACKET captures + /dev/kmsg messages + stats
anomalies.jsonl    Filtered subset: only records where anomaly=true (${ANOMALY_COUNT} events)
capture.pcap       Raw Wireshark-compatible UDP capture (udp.port==51820)
report.html        Self-contained HTML report (open in any browser)
wg_fuzz_config.json Server/client key metadata for the run
manifest.sha256    SHA-256 hashes for all files above

How to Review
-------------
1. Open report.html in any browser — no server needed.
2. Load capture.pcap in Wireshark, filter: udp.port == 51820
3. Verify integrity: sha256sum -c manifest.sha256
4. Reproduce the run with the same seed:
   SEED=$(python3 -c "import json; d=json.load(open('wg_fuzz_config.json')); print(d.get('seed',42))") \
   docker compose up --build

Log Format
----------
Every line is a JSON object. Key fields:
  source   : "fuzzer" | "packet" | "kmsg" | "stats" | "watchdog"
  phase    : "INIT" | "SESSION" | "TEARDOWN"
  anomaly  : true/false  (fuzzer.jsonl only)
  severity : "CRASH" | "WARN"  (kmsg entries only)
  kernel_taint : integer (0 = clean kernel)

Anomaly Triage Guide
--------------------
  RESPONSE to mutated init    -> possible MAC bypass, check noise.c
  Oversized server response   -> possible memory disclosure
  kernel_taint != 0           -> kernel bug triggered; see dmesg
  severity = CRASH            -> BUG/Oops/KASAN/UBSAN; priority review
  RESPONSE to torsion point   -> null-point check failure (ECC-2)

References
----------
  WireGuard whitepaper      https://www.wireguard.com/papers/wireguard.pdf
  Trail of Bits audit 2019  https://www.wireguard.com/papers/wireguard-audit.pdf
  Audit findings            wireguard_length_offset_audit.md
                            wireguard_ecc_encryption_audit.md
TEXT
log "README_export.txt written"

# ── SHA-256 manifest ──────────────────────────────────────────────────────────
log "Computing SHA-256 hashes..."
(
    cd "${OUT_DIR}"
    find . -type f \
        ! -name "manifest.sha256" \
        | sort \
        | xargs sha256sum \
        > manifest.sha256
)
log "manifest.sha256 written ($(wc -l < "${OUT_DIR}/manifest.sha256") files)"

# ── Package into tarball ──────────────────────────────────────────────────────
TARBALL="${EXPORT_NAME}.tar.gz"
log "Creating tarball: ${TARBALL}"
tar -czf "${TARBALL}" "${OUT_DIR}/"
TARBALL_SIZE=$(du -sh "${TARBALL}" | cut -f1)

# ── Print summary ─────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}────────────────────────────────────────────────────────${NC}"
echo -e "${BOLD} Peer Review Export Complete${NC}"
echo -e "${BOLD}────────────────────────────────────────────────────────${NC}"
echo -e "  Archive    : ${GREEN}${TARBALL}${NC}  (${TARBALL_SIZE})"
echo -e "  Directory  : ${OUT_DIR}/"
echo -e "  Anomalies  : $([ "${ANOMALY_COUNT}" -gt 0 ] && echo "${RED}${ANOMALY_COUNT}${NC}" || echo "${GREEN}0${NC}")"
echo -e "  Integrity  : sha256sum -c ${OUT_DIR}/manifest.sha256"
echo ""
echo "  Share the tarball for peer review."
echo "  Reviewer opens: ${OUT_DIR}/report.html"
echo -e "${BOLD}────────────────────────────────────────────────────────${NC}"
