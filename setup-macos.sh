#!/usr/bin/env bash
# =============================================================================
# setup-macos.sh — macOS M4 (Apple Silicon) Prerequisites
#
# Installs or verifies every dependency the WireGuard fuzz harness needs on
# an Apple Silicon Mac, then runs a quick smoke-test to confirm WireGuard
# works inside Docker before the real fuzzing session begins.
#
# Usage:
#   chmod +x setup-macos.sh && ./setup-macos.sh
#
# What it does:
#   1. Checks macOS version and architecture
#   2. Installs Homebrew (if missing)
#   3. Installs Python 3, jq, and Wireshark CLI tools via Homebrew
#   4. Checks for Docker Desktop, OrbStack, or Colima
#   5. Confirms Docker is running and is the arm64 variant
#   6. Installs Python packages (cryptography, scapy)
#   7. Smoke-tests WireGuard inside a privileged Linux container
#   8. Prints a ready-to-run command summary
#
# macOS M4 architecture note:
#   The WireGuard *kernel module* runs inside Docker Desktop's Linux VM
#   (linuxkit), not on macOS itself — macOS has no wireguard.ko. The linuxkit
#   kernel ships with WireGuard compiled in (CONFIG_WIREGUARD=y), so neither
#   'modprobe wireguard' nor 'sudo modprobe' is required. The server container
#   tests this automatically by attempting 'ip link add type wireguard'.
# =============================================================================
set -euo pipefail

BOLD='\033[1m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
log()  { echo -e "${GREEN}[setup]${NC} $*"; }
warn() { echo -e "${YELLOW}[setup]${NC} $*"; }
die()  { echo -e "${RED}[setup]${NC} FATAL: $*" >&2; exit 1; }
step() { echo; echo -e "${BOLD}── $* ──${NC}"; }

# ── 1. Architecture and OS check ─────────────────────────────────────────────
step "System check"

ARCH=$(uname -m)
OS=$(uname -s)
MACOS_VER=$(sw_vers -productVersion 2>/dev/null || echo "unknown")

[[ "${OS}" == "Darwin" ]]  || die "This script is for macOS only (detected: ${OS})"
[[ "${ARCH}" == "arm64" ]] || warn "Expected arm64 (Apple Silicon), got ${ARCH}. Continuing anyway."

log "macOS ${MACOS_VER} on ${ARCH}"

MACOS_MAJOR=$(echo "${MACOS_VER}" | cut -d. -f1)
if (( MACOS_MAJOR < 13 )); then
    warn "macOS ${MACOS_VER} is older than Ventura (13). Docker Desktop may not support Apple Virtualization Framework."
fi

# ── 2. Homebrew ───────────────────────────────────────────────────────────────
step "Homebrew"

if ! command -v brew &>/dev/null; then
    log "Installing Homebrew..."
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    # Add brew to PATH for the rest of this script
    eval "$(/opt/homebrew/bin/brew shellenv)"
else
    log "Homebrew $(brew --version | head -1): OK"
fi

# ── 3. CLI tools ──────────────────────────────────────────────────────────────
step "CLI tools"

BREW_PKGS=()
for pkg in python3 jq; do
    if ! brew list --formula "${pkg}" &>/dev/null 2>&1; then
        BREW_PKGS+=("${pkg}")
    fi
done

# wireshark CLI (tshark) — optional but useful for pcap inspection
if ! command -v tshark &>/dev/null; then
    BREW_PKGS+=("wireshark")
fi

if [[ ${#BREW_PKGS[@]} -gt 0 ]]; then
    log "Installing: ${BREW_PKGS[*]}"
    brew install "${BREW_PKGS[@]}"
else
    log "python3, jq: already installed"
fi

PYTHON=$(command -v python3)
log "Python: $("${PYTHON}" --version)"

# ── 4. Python packages ────────────────────────────────────────────────────────
step "Python packages"

"${PYTHON}" -m pip install --quiet --upgrade pip
"${PYTHON}" -m pip install --quiet cryptography scapy

"${PYTHON}" -c "
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
print('cryptography: OK')
import scapy
print('scapy:', scapy.__version__)
"

# ── 5. Docker runtime ─────────────────────────────────────────────────────────
step "Docker runtime"

DOCKER_RUNTIME=""
DOCKER_HINT=""

if command -v docker &>/dev/null && docker info &>/dev/null 2>&1; then
    DOCKER_RUNTIME=$(docker info --format '{{.OperatingSystem}}' 2>/dev/null || echo "Docker")
    log "Docker running: ${DOCKER_RUNTIME}"

    # Confirm the container platform is linux/arm64
    PLATFORM=$(docker info --format '{{.Architecture}}' 2>/dev/null || echo "unknown")
    log "Container platform: ${PLATFORM}"

    # Check Docker Compose v2
    if docker compose version &>/dev/null 2>&1; then
        log "Docker Compose: $(docker compose version --short 2>/dev/null || echo 'v2')"
    else
        die "Docker Compose v2 not found. Update Docker Desktop to 4.x or later."
    fi

else
    # Docker not running — give installation options
    echo ""
    echo "  Docker is not running. Install one of the following:"
    echo ""
    echo "  Option A — Docker Desktop (official, GUI)"
    echo "    https://www.docker.com/products/docker-desktop/"
    echo "    brew install --cask docker"
    echo "    Then open Docker.app and wait for the whale icon."
    echo ""
    echo "  Option B — OrbStack (faster, recommended for developers)"
    echo "    https://orbstack.dev"
    echo "    brew install --cask orbstack"
    echo ""
    echo "  Option C — Colima (CLI-only, lightweight)"
    echo "    brew install colima docker docker-compose"
    echo "    colima start --arch aarch64 --vm-type vz --vz-rosetta"
    echo ""
    die "Start Docker and re-run this script."
fi

# ── 6. WireGuard smoke-test inside Docker ─────────────────────────────────────
step "WireGuard smoke-test (inside Docker Linux VM)"

log "Pulling alpine (for quick test)..."
docker pull --quiet alpine:3 2>/dev/null || true

log "Testing 'ip link add type wireguard' inside a privileged container..."

WG_TEST_OUTPUT=$(docker run --rm --privileged \
    alpine:3 sh -c '
        apk add --quiet wireguard-tools iproute2 2>/dev/null || true
        ip link add wg_smoke type wireguard 2>&1 && echo OK || echo FAIL
        ip link del wg_smoke 2>/dev/null || true
    ' 2>&1)

if echo "${WG_TEST_OUTPUT}" | grep -q "^OK"; then
    log "WireGuard: works inside Docker  (linuxkit kernel has CONFIG_WIREGUARD=y)"
else
    warn "WireGuard smoke-test output:"
    echo "${WG_TEST_OUTPUT}" | sed 's/^/  /'
    echo ""
    echo "  Possible causes:"
    echo "    - Docker Desktop version is too old (update to 4.x+)"
    echo "    - Docker is using legacy hypervisor (switch to Apple Virtualization Framework)"
    echo "      Docker Desktop → Settings → General → 'Use Virtualization Framework'"
    echo "    - For Colima: colima start --arch aarch64 --vm-type vz"
    echo ""
    warn "WireGuard may not work. Try the fixes above and re-run this script."
fi

# ── 7. Verify harness files are present ───────────────────────────────────────
step "Harness file check"

REQUIRED_FILES=(
    "docker-compose.yml"
    "Dockerfile.server"
    "Dockerfile.fuzzer"
    "entrypoint-server.sh"
    "entrypoint-fuzzer.sh"
    "wg_fuzzer.py"
    "wg_monitor.c"
    "wg_server_harness.sh"
    "generate_report.py"
    "export_results.sh"
    "requirements.txt"
)

MISSING=()
for f in "${REQUIRED_FILES[@]}"; do
    [[ -f "${f}" ]] || MISSING+=("${f}")
done

if [[ ${#MISSING[@]} -gt 0 ]]; then
    warn "Missing files: ${MISSING[*]}"
    warn "Make sure all harness files are in the current directory."
else
    log "All ${#REQUIRED_FILES[@]} harness files present"
fi

# ── 8. Build Docker images ────────────────────────────────────────────────────
step "Docker image build"

log "Building server and fuzzer images (this takes ~2 min on first run)..."
docker compose build 2>&1 | grep -E 'Step|step|--->' | head -30 || \
    docker compose build

log "Images built"

# ── 9. Summary ────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD} macOS M4 setup complete — ready to fuzz${NC}"
echo -e "${BOLD}════════════════════════════════════════════════════════${NC}"
echo ""
echo "  Quick start:"
echo ""
echo -e "    ${GREEN}docker compose up --build${NC}              # run all phases"
echo -e "    ${GREEN}PHASE=1 docker compose up --build${NC}      # init fuzzing only"
echo -e "    ${GREEN}PHASE=2,3 COUNT=100 docker compose up${NC}  # session + teardown"
echo ""
echo "  Live anomaly monitoring (second terminal):"
echo -e "    ${GREEN}docker compose logs -f wg-fuzzer | grep anomaly${NC}"
echo ""
echo "  Export results for peer review:"
echo -e "    ${GREEN}./export_results.sh${NC}"
echo ""
echo "  Note: WireGuard runs inside Docker Desktop's Linux VM."
echo "  No modprobe or sudo is needed on macOS."
echo ""
