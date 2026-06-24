#!/usr/bin/env bash
# =============================================================================
# build.sh — ESPConnect2 Auto-Install & Build Script
# =============================================================================
# Otomatis detect OS, install semua dependency yang kurang, lalu build.
#
# Target build:
#   Linux / macOS (x86_64) : binary native test_e2e
#   Windows (WSL)          : cross-compile .exe via mingw-w64
#   ESP32                  : cek & setup ESP-IDF environment
#
# Usage:
#   ./build.sh              → build untuk host platform (Linux/macOS)
#   ./build.sh --windows    → cross-compile .exe (butuh mingw-w64)
#   ./build.sh --esp32      → build untuk ESP32 via ESP-IDF
#   ./build.sh --clean      → hapus build artifacts
#   ./build.sh --help       → tampilkan bantuan
# =============================================================================

set -euo pipefail

# ─── Warna ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# ─── Banner ───────────────────────────────────────────────────────────────────
print_banner() {
    echo -e "${CYAN}"
    echo "  ███████╗███████╗██████╗  ██████╗ ██████╗ ███╗   ██╗███╗   ██╗███████╗ ██████╗████████╗"
    echo "  ██╔════╝██╔════╝██╔══██╗██╔════╝██╔═══██╗████╗  ██║████╗  ██║██╔════╝██╔════╝╚══██╔══╝"
    echo "  █████╗  ███████╗██████╔╝██║     ██║   ██║██╔██╗ ██║██╔██╗ ██║█████╗  ██║        ██║   "
    echo "  ██╔══╝  ╚════██║██╔═══╝ ██║     ██║   ██║██║╚██╗██║██║╚██╗██║██╔══╝  ██║        ██║   "
    echo "  ███████╗███████║██║     ╚██████╗╚██████╔╝██║ ╚████║██║ ╚████║███████╗╚██████╗   ██║   "
    echo "  ╚══════╝╚══════╝╚═╝      ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝ ╚═════╝   ╚═╝   "
    echo -e "${NC}"
    echo -e "${BOLD}  ESPConnect2 — Auto-Install & Build Script${NC}"
    echo    "  ────────────────────────────────────────────"
    echo
}

# ─── Logging helpers ──────────────────────────────────────────────────────────
log_info()    { echo -e "  ${BLUE}[INFO]${NC}  $*"; }
log_ok()      { echo -e "  ${GREEN}[OK]${NC}    $*"; }
log_warn()    { echo -e "  ${YELLOW}[WARN]${NC}  $*"; }
log_error()   { echo -e "  ${RED}[ERROR]${NC} $*"; }
log_step()    { echo; echo -e "  ${BOLD}${CYAN}▶ $*${NC}"; echo "  ──────────────────────────────────────"; }

# ─── Parse argumen ────────────────────────────────────────────────────────────
BUILD_TARGET="linux"
DO_CLEAN=0

for arg in "$@"; do
    case "$arg" in
        --windows)  BUILD_TARGET="windows" ;;
        --esp32)    BUILD_TARGET="esp32" ;;
        --clean)    DO_CLEAN=1 ;;
        --help|-h)
            echo "Usage: $0 [--windows|--esp32|--clean|--help]"
            echo
            echo "  (kosong)    Build untuk host platform (Linux/macOS)"
            echo "  --windows   Cross-compile .exe via mingw-w64"
            echo "  --esp32     Build ESP32 via ESP-IDF (idf.py build)"
            echo "  --clean     Hapus semua build artifacts"
            exit 0
            ;;
        *)
            log_warn "Argumen tidak dikenal: $arg (diabaikan)"
            ;;
    esac
done

# ─── Detect OS ────────────────────────────────────────────────────────────────
detect_os() {
    case "$(uname -s)" in
        Linux*)
            if grep -qi microsoft /proc/version 2>/dev/null; then
                OS="wsl"
                log_info "Detected: Windows Subsystem for Linux (WSL)"
            else
                OS="linux"
                log_info "Detected: Linux"
            fi
            ;;
        Darwin*)
            OS="macos"
            log_info "Detected: macOS"
            ;;
        CYGWIN*|MINGW*|MSYS*)
            OS="windows_native"
            log_info "Detected: Windows (MSYS2/Cygwin)"
            ;;
        *)
            OS="unknown"
            log_warn "OS tidak dikenal: $(uname -s) — mencoba mode Linux"
            OS="linux"
            ;;
    esac
}

# ─── Detect package manager ───────────────────────────────────────────────────
detect_pkg_manager() {
    if [[ "$OS" == "macos" ]]; then
        if command -v brew &>/dev/null; then
            PKG_MGR="brew"
        else
            PKG_MGR="none_macos"
        fi
    elif command -v apt-get &>/dev/null; then
        PKG_MGR="apt"
    elif command -v dnf &>/dev/null; then
        PKG_MGR="dnf"
    elif command -v yum &>/dev/null; then
        PKG_MGR="yum"
    elif command -v pacman &>/dev/null; then
        PKG_MGR="pacman"
    elif command -v zypper &>/dev/null; then
        PKG_MGR="zypper"
    else
        PKG_MGR="unknown"
        log_warn "Package manager tidak ditemukan. Install dependency secara manual."
    fi
    log_info "Package manager: ${PKG_MGR}"
}

# ─── Install satu package ─────────────────────────────────────────────────────
install_pkg() {
    local pkg="$1"
    local pkg_alt="${2:-$1}"  # nama alternatif untuk distro lain

    log_info "Installing: ${pkg}..."
    case "$PKG_MGR" in
        apt)     sudo apt-get install -y "$pkg" 2>&1 | tail -3 ;;
        dnf)     sudo dnf install -y "$pkg_alt" 2>&1 | tail -3 ;;
        yum)     sudo yum install -y "$pkg_alt" 2>&1 | tail -3 ;;
        pacman)  sudo pacman -S --noconfirm "$pkg_alt" 2>&1 | tail -3 ;;
        zypper)  sudo zypper install -y "$pkg_alt" 2>&1 | tail -3 ;;
        brew)    brew install "$pkg_alt" 2>&1 | tail -3 ;;
        none_macos)
            log_error "Homebrew tidak ditemukan. Install dari https://brew.sh lalu jalankan ulang."
            exit 1
            ;;
        *)
            log_error "Tidak bisa auto-install ${pkg}. Install manual lalu jalankan ulang."
            exit 1
            ;;
    esac
    log_ok "${pkg} installed"
}

# ─── Check & auto-install dependency ─────────────────────────────────────────
check_cmd() {
    local cmd="$1"
    local pkg_apt="${2:-$1}"
    local pkg_alt="${3:-$pkg_apt}"

    if command -v "$cmd" &>/dev/null; then
        log_ok "${cmd} → $(command -v $cmd)"
        return 0
    else
        log_warn "${cmd} tidak ditemukan — menginstall..."
        install_pkg "$pkg_apt" "$pkg_alt"
        # Verifikasi ulang
        if command -v "$cmd" &>/dev/null; then
            log_ok "${cmd} berhasil diinstall"
        else
            log_error "${cmd} masih tidak ditemukan setelah install. Cek error di atas."
            exit 1
        fi
    fi
}

# ─── Check OpenSSL development headers ────────────────────────────────────────
check_openssl_dev() {
    if pkg-config --exists openssl 2>/dev/null; then
        local ver
        ver=$(pkg-config --modversion openssl 2>/dev/null)
        log_ok "OpenSSL dev headers: ${ver}"
        return 0
    fi

    # Fallback: cek file langsung
    local inc_paths=("/usr/include/openssl/ssl.h" "/usr/local/include/openssl/ssl.h" \
                     "/opt/homebrew/include/openssl/ssl.h")
    for p in "${inc_paths[@]}"; do
        if [[ -f "$p" ]]; then
            log_ok "OpenSSL headers: $p"
            return 0
        fi
    done

    log_warn "OpenSSL dev headers tidak ditemukan — menginstall..."
    case "$PKG_MGR" in
        apt)    install_pkg "libssl-dev"  "openssl-devel" ;;
        dnf|yum) install_pkg "openssl-devel" "openssl-devel" ;;
        pacman) install_pkg "openssl" "openssl" ;;
        brew)   install_pkg "openssl" "openssl" ;;
        *)      log_error "Install OpenSSL dev headers secara manual"; exit 1 ;;
    esac
}

# ─── CLEAN ────────────────────────────────────────────────────────────────────
do_clean() {
    log_step "Membersihkan build artifacts"
    local cleaned=0

    if [[ -d "build_x86" ]]; then
        rm -rf build_x86
        log_ok "Hapus build_x86/"
        ((cleaned++)) || true
    fi
    if [[ -f "test/x86/test_build" ]]; then
        rm -f test/x86/test_build test/x86/*.o
        log_ok "Hapus test/x86/test_build"
        ((cleaned++)) || true
    fi
    if [[ -f "espconnect_e2e" ]]; then
        rm -f espconnect_e2e
        log_ok "Hapus espconnect_e2e"
        ((cleaned++)) || true
    fi
    if [[ -d "build" ]]; then
        rm -rf build
        log_ok "Hapus build/ (ESP-IDF)"
        ((cleaned++)) || true
    fi

    [[ $cleaned -eq 0 ]] && log_info "Tidak ada artifacts untuk dihapus."
    log_ok "Clean selesai"
}

# =============================================================================
# BUILD: Linux / macOS (host)
# =============================================================================
build_linux() {
    log_step "Setup dependencies (Linux/macOS)"

    detect_pkg_manager

    # Update package index (apt only, sekali saja)
    if [[ "$PKG_MGR" == "apt" ]]; then
        log_info "Updating apt package index..."
        sudo apt-get update -qq 2>&1 | tail -1
    fi

    # Cek & install tools
    check_cmd "gcc"       "gcc"           "gcc"
    check_cmd "make"      "make"          "make"
    check_cmd "pkg-config" "pkg-config"   "pkgconf"
    check_cmd "git"       "git"           "git"

    # OpenSSL
    check_openssl_dev

    # pthread biasanya sudah ada di libc-dev, tapi pastikan
    if [[ "$OS" == "macos" ]]; then
        # macOS punya pthread built-in
        log_ok "pthread: built-in (macOS)"
    fi

    log_step "Build ESPConnect2 (host: $OS)"

    # Buat build dir
    mkdir -p build_x86
    cd build_x86

    # Determine OpenSSL flags
    if pkg-config --exists openssl 2>/dev/null; then
        OPENSSL_CFLAGS=$(pkg-config --cflags openssl)
        OPENSSL_LIBS=$(pkg-config --libs openssl)
    else
        # macOS Homebrew path
        if [[ -d "/opt/homebrew/opt/openssl" ]]; then
            OPENSSL_CFLAGS="-I/opt/homebrew/opt/openssl/include"
            OPENSSL_LIBS="-L/opt/homebrew/opt/openssl/lib -lssl -lcrypto"
        elif [[ -d "/usr/local/opt/openssl" ]]; then
            OPENSSL_CFLAGS="-I/usr/local/opt/openssl/include"
            OPENSSL_LIBS="-L/usr/local/opt/openssl/lib -lssl -lcrypto"
        else
            OPENSSL_CFLAGS=""
            OPENSSL_LIBS="-lssl -lcrypto"
        fi
    fi

    SRCS=(
        "../src/mercury.c"
        "../src/spclient.c"
        "../src/zeroconf.c"
        "../src/decrypt.c"
        "../src/esp_spotify.c"
        "../src/platform_posix.c"
        "../test/x86/test_e2e.c"
    )

    CFLAGS="-std=c11 -Wall -Wextra -Wno-unused-parameter -O2 -g"
    CFLAGS+=" -D_GNU_SOURCE"
    CFLAGS+=" -I../include -I../include/internal"
    CFLAGS+=" $OPENSSL_CFLAGS"
    LDFLAGS="-lpthread $OPENSSL_LIBS"

    log_info "Compiling..."
    gcc $CFLAGS "${SRCS[@]}" $LDFLAGS -o espconnect_e2e

    cd ..

    log_ok "Build selesai!"
    echo
    echo -e "  ${BOLD}Output:${NC} build_x86/espconnect_e2e"
    echo -e "  ${BOLD}Jalankan:${NC}"
    echo
    echo -e "    ${CYAN}./build_x86/espconnect_e2e <username> <auth_data_b64> <auth_type>${NC}"
    echo -e "    ${CYAN}./build_x86/espconnect_e2e <username> <auth_data_b64> <auth_type> <ap_host> <ap_port>${NC}"
    echo
}

# =============================================================================
# BUILD: Windows (cross-compile via mingw-w64)
# =============================================================================
build_windows() {
    log_step "Setup dependencies (Windows cross-compile)"

    detect_pkg_manager

    if [[ "$PKG_MGR" == "apt" ]]; then
        sudo apt-get update -qq 2>&1 | tail -1
    fi

    # mingw-w64
    if ! command -v x86_64-w64-mingw32-gcc &>/dev/null; then
        log_warn "mingw-w64 tidak ditemukan — menginstall..."
        install_pkg "mingw-w64" "mingw-w64"
        if ! command -v x86_64-w64-mingw32-gcc &>/dev/null; then
            log_error "mingw-w64 GCC tidak ditemukan setelah install."
            exit 1
        fi
    fi
    log_ok "mingw-w64: $(x86_64-w64-mingw32-gcc --version | head -1)"

    # Cek mbedtls cross-compiled
    MBEDTLS_DIR="${MBEDTLS_DIR:-mbedtls-3.6.5}"
    if [[ ! -f "${MBEDTLS_DIR}/library/libmbedcrypto.a" ]]; then
        log_warn "mbedtls cross-compiled tidak ditemukan di ${MBEDTLS_DIR}/"
        log_info "Mendownload & cross-compile mbedtls 3.6.5..."

        check_cmd "wget"  "wget"  "wget"
        check_cmd "make"  "make"  "make"

        if [[ ! -f "mbedtls-3.6.5.tar.gz" ]]; then
            wget -q --show-progress \
                "https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-3.6.5/mbedtls-3.6.5.tar.gz"
        fi

        if [[ ! -d "mbedtls-3.6.5" ]]; then
            log_info "Extracting mbedtls..."
            tar xzf mbedtls-3.6.5.tar.gz
        fi

        log_info "Cross-compiling mbedtls untuk Windows... (ini butuh ~1 menit)"
        cd mbedtls-3.6.5
        CC=x86_64-w64-mingw32-gcc \
        AR=x86_64-w64-mingw32-ar \
        CFLAGS="-O2 -DMBEDTLS_THREADING_C -DMBEDTLS_THREADING_PTHREAD" \
        make -j"$(nproc)" lib 2>&1 | tail -5
        cd ..
        log_ok "mbedtls cross-compiled selesai"
    else
        log_ok "mbedtls: ${MBEDTLS_DIR}/library/libmbedcrypto.a"
    fi

    log_step "Cross-compile ESPConnect2 → Windows .exe"

    GCC="x86_64-w64-mingw32-gcc"
    CFLAGS="-std=gnu11 -O2 -static -Wall"
    CFLAGS+=" -DWIN32_LEAN_AND_MEAN -D_WIN32_WINNT=0x0600"
    CFLAGS+=" -I include -I include/internal -I ${MBEDTLS_DIR}/include"

    SRCS=(
        "src/mercury.c"
        "src/spclient.c"
        "src/zeroconf.c"
        "src/decrypt.c"
        "src/esp_spotify.c"
        "src/platform_windows.c"
        "test/x86/test_e2e.c"
    )

    LIBS=(
        "${MBEDTLS_DIR}/library/libmbedcrypto.a"
        "${MBEDTLS_DIR}/library/libmbedtls.a"
        "${MBEDTLS_DIR}/library/libmbedx509.a"
        "-lws2_32" "-lpthread" "-lbcrypt" "-lshlwapi" "-lm"
    )

    $GCC $CFLAGS "${SRCS[@]}" "${LIBS[@]}" -o espconnect_e2e.exe

    log_ok "Build selesai!"
    echo
    echo -e "  ${BOLD}Output:${NC} espconnect_e2e.exe"
    echo -e "  ${BOLD}Salin ke Windows dan jalankan:${NC}"
    echo
    echo -e "    ${CYAN}espconnect_e2e.exe <username> <auth_data_b64> <auth_type>${NC}"
    echo
    ls -lh espconnect_e2e.exe
}

# =============================================================================
# BUILD: ESP32 via ESP-IDF
# =============================================================================
build_esp32() {
    log_step "Setup ESP-IDF environment"

    # Cek IDF_PATH
    if [[ -z "${IDF_PATH:-}" ]]; then
        log_warn "IDF_PATH tidak di-set."

        # Coba lokasi umum
        local idf_paths=(
            "$HOME/esp/esp-idf"
            "$HOME/esp-idf"
            "/opt/esp-idf"
            "/usr/local/esp-idf"
        )

        local found_idf=""
        for p in "${idf_paths[@]}"; do
            if [[ -f "$p/export.sh" ]]; then
                found_idf="$p"
                break
            fi
        done

        if [[ -n "$found_idf" ]]; then
            log_info "Ditemukan ESP-IDF di: $found_idf"
            export IDF_PATH="$found_idf"
        else
            log_warn "ESP-IDF tidak ditemukan. Menjalankan installer otomatis..."

            check_cmd "git"   "git"   "git"
            check_cmd "python3" "python3" "python3"
            check_cmd "pip3"  "python3-pip" "python3-pip"

            detect_pkg_manager
            if [[ "$PKG_MGR" == "apt" ]]; then
                sudo apt-get update -qq 2>&1 | tail -1
                log_info "Installing ESP-IDF prerequisites..."
                sudo apt-get install -y \
                    git wget flex bison gperf python3 python3-pip python3-venv \
                    cmake ninja-build ccache libffi-dev libssl-dev dfu-util \
                    libusb-1.0-0 2>&1 | tail -5
            fi

            log_info "Cloning ESP-IDF v5.3 ke ~/esp/esp-idf ..."
            mkdir -p "$HOME/esp"
            git clone --recursive --depth 1 --branch v5.3 \
                https://github.com/espressif/esp-idf.git \
                "$HOME/esp/esp-idf" 2>&1 | tail -5

            export IDF_PATH="$HOME/esp/esp-idf"
            log_info "Running install.sh..."
            bash "$IDF_PATH/install.sh" esp32 2>&1 | tail -10
            log_ok "ESP-IDF installed di $IDF_PATH"
        fi
    else
        log_ok "IDF_PATH: $IDF_PATH"
    fi

    # Source environment
    log_info "Sourcing ESP-IDF environment..."
    # shellcheck disable=SC1090
    source "$IDF_PATH/export.sh" 2>&1 | grep -E "(Added|Setting|ESP)" | head -5

    if ! command -v idf.py &>/dev/null; then
        log_error "idf.py tidak ditemukan setelah source. Cek IDF_PATH."
        exit 1
    fi
    log_ok "idf.py: $(idf.py --version 2>&1 | head -1)"

    # Cek contoh project
    if [[ ! -f "examples/basic_pairing/CMakeLists.txt" ]]; then
        log_warn "examples/basic_pairing/CMakeLists.txt tidak ditemukan."
        log_info "Mencoba build dari root sebagai component..."
        TARGET_DIR="."
    else
        TARGET_DIR="examples/basic_pairing"
    fi

    log_step "Build ESP32 target"
    cd "$TARGET_DIR"
    idf.py set-target esp32
    idf.py build 2>&1 | tail -20

    log_ok "ESP32 build selesai!"
    echo
    echo -e "  ${BOLD}Flash ke ESP32:${NC}"
    echo -e "    ${CYAN}idf.py -p /dev/ttyUSB0 flash monitor${NC}"
    echo
}

# =============================================================================
# MAIN
# =============================================================================
main() {
    print_banner
    detect_os

    if [[ $DO_CLEAN -eq 1 ]]; then
        do_clean
        exit 0
    fi

    # Pastikan script dijalankan dari root project
    if [[ ! -f "src/mercury.c" ]]; then
        log_error "Script harus dijalankan dari root direktori ESPConnect2!"
        log_error "Contoh: cd ESPConnect2 && ./build.sh"
        exit 1
    fi

    echo
    log_info "Build target: ${BOLD}${BUILD_TARGET}${NC}"

    case "$BUILD_TARGET" in
        linux)   build_linux   ;;
        windows) build_windows ;;
        esp32)   build_esp32   ;;
    esac

    echo
    echo -e "  ${GREEN}${BOLD}════════════════════════════════════════${NC}"
    echo -e "  ${GREEN}${BOLD}   BUILD SUKSES!                        ${NC}"
    echo -e "  ${GREEN}${BOLD}════════════════════════════════════════${NC}"
    echo
}

main "$@"
