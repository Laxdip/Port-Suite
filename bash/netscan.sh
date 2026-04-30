set -euo pipefail

# ─── ANSI color codes ───────────────────────────────────────────────────────
RED='\033[91m'
GREEN='\033[92m'
YELLOW='\033[93m'
BLUE='\033[94m'
MAGENTA='\033[95m'
CYAN='\033[96m'
WHITE='\033[97m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

# ─── Temp files ─────────────────────────────────────────────────────────────
TMP_HOSTS="/tmp/smartscan_hosts_$$"
TMP_PORTS="/tmp/smartscan_ports_$$"
TMP_LOCK="/tmp/smartscan_lock_$$"

# ─── Cleanup on exit / interrupt ────────────────────────────────────────────
cleanup() {
    rm -f "$TMP_HOSTS" "$TMP_PORTS" "$TMP_LOCK" 2>/dev/null
}
trap cleanup EXIT INT TERM

# ─── Logging helpers ────────────────────────────────────────────────────────
log_info()    { echo -e "${CYAN}[→]${RESET} $*"; }
log_ok()      { echo -e "${GREEN}[✓]${RESET} $*"; }
log_warn()    { echo -e "${YELLOW}[!]${RESET} $*"; }
log_error()   { echo -e "${RED}[✗]${RESET} $*" >&2; }
log_verbose() { [[ "$VERBOSE" == true ]] && echo -e "${DIM}[v] $*${RESET}"; }

# ─── Section headers ─────────────────────────────────────────────────────────
print_section() {
    local title="$1"
    local style="${2:-single}"   # single | double
    local width=100
    local padded
    padded=$(printf "%-$((width - 4))s" "  $title")
    echo -e "${CYAN}"
    if [[ "$style" == "double" ]]; then
        printf '╔'; printf '═%.0s' $(seq 1 $((width - 2))); printf '╗\n'
        echo "║ ${padded} ║"
        printf '╚'; printf '═%.0s' $(seq 1 $((width - 2))); printf '╝\n'
    else
        printf '┌'; printf '─%.0s' $(seq 1 $((width - 2))); printf '┐\n'
        echo "│ ${padded} │"
        printf '└'; printf '─%.0s' $(seq 1 $((width - 2))); printf '┘\n'
    fi
    echo -e "${RESET}"
}

# ─── TTL → OS hint ──────────────────────────────────────────────────────────
ttl_to_os() {
    local ttl="${1:-0}"
    if   (( ttl >= 128 && ttl <= 130 )); then echo "Windows"
    elif (( ttl >= 60  && ttl <= 65  )); then echo "Linux/Unix"
    elif (( ttl >= 250 && ttl <= 255 )); then echo "Cisco/Network"
    else echo "Unknown"
    fi
}

# ─── Port → service name ────────────────────────────────────────────────────
port_to_service() {
    case "$1" in
        21)   echo "FTP" ;;
        22)   echo "SSH" ;;
        23)   echo "Telnet" ;;
        25)   echo "SMTP" ;;
        53)   echo "DNS" ;;
        80)   echo "HTTP" ;;
        110)  echo "POP3" ;;
        135)  echo "RPC" ;;
        139)  echo "NetBIOS" ;;
        143)  echo "IMAP" ;;
        443)  echo "HTTPS" ;;
        445)  echo "SMB" ;;
        3306) echo "MySQL" ;;
        3389) echo "RDP" ;;
        5432) echo "PostgreSQL" ;;
        5900) echo "VNC" ;;
        6379) echo "Redis" ;;
        8080) echo "HTTP-Alt" ;;
        8443) echo "HTTPS-Alt" ;;
        27017)echo "MongoDB" ;;
        *)    echo "Port-$1" ;;
    esac
}

# ─── Results table ───────────────────────────────────────────────────────────
print_results_table() {
    printf "${CYAN}"
    printf '┌──────────────┬──────────────────┬──────────┬──────────────┬──────────────────────────────────────┐\n'
    printf '│   STATUS     │   IP ADDRESS     │  RTT(ms) │     OS HINT  │              HOSTNAME                │\n'
    printf '├──────────────┼──────────────────┼──────────┼──────────────┼──────────────────────────────────────┤\n'
    printf "${RESET}"

    while IFS=$'\t' read -r ip rtt ttl hostname; do
        [[ -z "$ip" ]] && continue
        local os_hint
        os_hint=$(ttl_to_os "$ttl")
        local rtt_disp="${rtt}ms"
        [[ "$rtt" == "N/A" ]] && rtt_disp="N/A    "
        printf "│  ${GREEN}● ALIVE${RESET}     │  ${WHITE}%-16s${RESET}│  ${YELLOW}%-7s${RESET} │  ${MAGENTA}%-12s${RESET}│  ${WHITE}%-38s${RESET}│\n" \
            "$ip" "$rtt_disp" "$os_hint" "$hostname"
    done < "$TMP_HOSTS"

    printf "${CYAN}"
    printf '└──────────────┴──────────────────┴──────────┴──────────────┴──────────────────────────────────────┘\n'
    printf "${RESET}\n"
}

# ─── Ports table ─────────────────────────────────────────────────────────────
print_ports_table() {
    [[ ! -s "$TMP_PORTS" ]] && return

    printf "${CYAN}"
    printf '┌──────────────────┬──────────────────────────────────────┬──────────────────────────────────────┐\n'
    printf '│   IP ADDRESS     │           OPEN PORTS                 │            SERVICES                  │\n'
    printf '├──────────────────┼──────────────────────────────────────┼──────────────────────────────────────┤\n'
    printf "${RESET}"

    while IFS='|' read -r ip ports services; do
        printf "│  ${WHITE}%-16s${RESET}│  ${YELLOW}%-38s${RESET}│  ${GREEN}%-38s${RESET}│\n" "$ip" "$ports" "$services"
    done < "$TMP_PORTS"

    printf "${CYAN}"
    printf '└──────────────────┴──────────────────────────────────────┴──────────────────────────────────────┘\n'
    printf "${RESET}\n"
}

# ─── Summary ─────────────────────────────────────────────────────────────────
print_summary() {
    local total=$1 elapsed=$2 subnet=$3 timeout=$4 jobs=$5
    echo -e "${WHITE}"
    printf "  %-18s : %s\n" "Network subnet"  "$subnet"
    printf "  %-18s : %s\n" "Devices found"   "$total"
    printf "  %-18s : ${elapsed}s\n" "Time taken"
    printf "  %-18s : ${timeout}s\n"  "Timeout"
    printf "  %-18s : %s\n" "Parallel jobs"   "$jobs"
    echo -e "${RESET}"
    echo -e "${CYAN}$(printf '═%.0s' $(seq 1 100))${RESET}"
}

# ─── Ping sweep ─────────────────────────────────────────────────────────────
ping_scan() {
    local subnet="$1" timeout="$2" jobs="$3"
    log_info "Performing ping sweep on ${WHITE}${subnet}${RESET} (${jobs} parallel jobs)"

    local base_ip
    base_ip=$(echo "$subnet" | cut -d'/' -f1 | rev | cut -d'.' -f2- | rev)

    > "$TMP_HOSTS"
    local found=0
    local sem=0

    _probe() {
        local ip="$1"
        local ping_out
        ping_out=$(ping -c 1 -W "$timeout" "$ip" 2>/dev/null) || return

        local rtt ttl hostname

        # Parse RTT
        rtt=$(echo "$ping_out" | grep -oE 'time=[0-9.]+' | head -1 | cut -d= -f2)
        [[ -z "$rtt" ]] && rtt="N/A"

        # Parse TTL
        ttl=$(echo "$ping_out" | grep -oE 'ttl=[0-9]+' | head -1 | cut -d= -f2 | tr '[:upper:]' '[:lower:]')
        ttl=$(echo "$ping_out" | grep -oiE 'ttl=[0-9]+' | head -1 | grep -oE '[0-9]+')
        [[ -z "$ttl" ]] && ttl=0

        # Hostname lookup (skip in quick mode)
        if [[ "$QUICK_MODE" == false ]]; then
            hostname=$(nslookup "$ip" 2>/dev/null \
                | awk -F'name = ' '/name =/{print $2; exit}' \
                | sed 's/\.$//')
        fi
        [[ -z "$hostname" ]] && hostname="Unknown"

        # Atomic write
        (
            flock 200
            echo -e "${ip}\t${rtt}\t${ttl}\t${hostname}" >> "$TMP_HOSTS"
            echo -e "  ${GREEN}●${RESET} ${WHITE}${ip}${RESET}  rtt=${YELLOW}${rtt}ms${RESET}  ttl=${ttl}  → ${WHITE}${hostname}${RESET}"
        ) 200>"$TMP_LOCK"
    }

    for i in $(seq 1 254); do
        _probe "${base_ip}.${i}" &
        (( sem++ ))
        if (( sem >= jobs )); then
            wait -n 2>/dev/null || wait   # wait -n needs bash 4.3+
            (( sem-- ))
        fi
    done
    wait

    found=$(wc -l < "$TMP_HOSTS")
    echo "$found"
}

# ─── ARP scan ────────────────────────────────────────────────────────────────
arp_scan() {
    log_info "Performing ARP scan (requires sudo)"

    > "$TMP_HOSTS"

    if ! command -v arp-scan &>/dev/null; then
        log_warn "arp-scan not found. Falling back to ping scan."
        return 1
    fi

    while IFS=$'\t ' read -r ip mac rest; do
        [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || continue
        local hostname="Unknown"
        if [[ "$QUICK_MODE" == false ]]; then
            hostname=$(nslookup "$ip" 2>/dev/null \
                | awk -F'name = ' '/name =/{print $2; exit}' \
                | sed 's/\.$//')
            [[ -z "$hostname" ]] && hostname="Unknown"
        fi
        echo -e "${ip}\tN/A\t0\t${hostname}" >> "$TMP_HOSTS"
        echo -e "  ${GREEN}●${RESET} ${WHITE}${ip}${RESET} (${YELLOW}${mac}${RESET}) → ${WHITE}${hostname}${RESET}"
    done < <(sudo arp-scan --localnet 2>/dev/null \
        | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+')

    wc -l < "$TMP_HOSTS"
}

# ─── Port scan ───────────────────────────────────────────────────────────────
scan_ports() {
    local ip="$1"
    local port_list="$2"
    local open_ports="" services=""

    for port in $(echo "$port_list" | tr ',' ' '); do
        if timeout 1 bash -c "echo >/dev/tcp/${ip}/${port}" 2>/dev/null; then
            open_ports="${open_ports}${port} "
            services="${services}$(port_to_service "$port") "
            log_verbose "$ip:$port open ($(port_to_service "$port"))"
        fi
    done

    if [[ -n "$open_ports" ]]; then
        (
            flock 201
            echo "${ip}|${open_ports% }|${services% }" >> "$TMP_PORTS"
        ) 201>"${TMP_LOCK}.ports"
    fi
}

# ─── Input validation ────────────────────────────────────────────────────────
validate_subnet() {
    local s="$1"
    if [[ ! "$s" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$ ]]; then
        log_error "Invalid subnet format: $s  (expected x.x.x.x/prefix)"
        exit 1
    fi
}

validate_number() {
    local val="$1" name="$2"
    if [[ ! "$val" =~ ^[0-9]+$ ]]; then
        log_error "$name must be a positive integer, got: $val"
        exit 1
    fi
}

# ─── Auto-detect network ─────────────────────────────────────────────────────
autodetect_network() {
    local net=""
    if command -v ip &>/dev/null; then
        net=$(ip route 2>/dev/null \
            | grep -v default \
            | grep -Eo '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+' \
            | grep -v '127\.' | head -1)
    fi
    if [[ -z "$net" ]] && command -v ifconfig &>/dev/null; then
        local base
        base=$(ifconfig 2>/dev/null \
            | grep -E 'inet [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' \
            | grep -v 127.0.0.1 | head -1 | awk '{print $2}' \
            | rev | cut -d'.' -f2- | rev)
        [[ -n "$base" ]] && net="${base}.0/24"
    fi
    echo "${net:-192.168.1.0/24}"
}

# ─── Save results ────────────────────────────────────────────────────────────
save_results() {
    local file="$1" total="$2" subnet="$3" elapsed="$4"

    # Plain text
    {
        echo "SmartScan Results"
        echo "Generated  : $(date)"
        echo "Network    : $subnet"
        echo "Devices    : $total"
        echo "Duration   : ${elapsed}s"
        echo ""
        printf "%-18s %-10s %-14s %s\n" "IP ADDRESS" "RTT(ms)" "OS HINT" "HOSTNAME"
        printf "%s\n" "$(printf '─%.0s' $(seq 1 72))"
        while IFS=$'\t' read -r ip rtt ttl hostname; do
            local os
            os=$(ttl_to_os "$ttl")
            printf "%-18s %-10s %-14s %s\n" "$ip" "${rtt}ms" "$os" "$hostname"
        done < "$TMP_HOSTS"
    } > "${file}.txt"

    # CSV
    {
        echo "ip,rtt_ms,ttl,os_hint,hostname"
        while IFS=$'\t' read -r ip rtt ttl hostname; do
            echo "${ip},${rtt},${ttl},$(ttl_to_os "$ttl"),${hostname}"
        done < "$TMP_HOSTS"
    } > "${file}.csv"

    log_ok "Results saved → ${WHITE}${file}.txt${RESET}  &  ${WHITE}${file}.csv${RESET}"
}

# ═══════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════
print_banner

# ─── Defaults ────────────────────────────────────────────────────────────────
NETWORK=""
TIMEOUT=1
QUICK_MODE=false
ARP_MODE=false
PORT_SCAN=false
PORT_LIST="21,22,23,25,53,80,110,135,139,143,443,445,3306,3389,5432,5900,6379,8080,8443,27017"
OUTPUT_FILE=""
JOBS=20
VERBOSE=false

# ─── Argument parsing ────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        -n|--network)
            NETWORK="$2"; shift 2 ;;
        -t|--timeout)
            TIMEOUT="$2"; shift 2 ;;
        -p|--ports)
            PORT_SCAN=true
            # Optional custom port list (next arg might be ports or a flag)
            if [[ -n "${2:-}" && "${2:-}" != -* ]]; then
                PORT_LIST="$2"; shift
            fi
            shift ;;
        -j|--jobs)
            JOBS="$2"; shift 2 ;;
        -q|--quick)
            QUICK_MODE=true; shift ;;
        -a|--arp)
            ARP_MODE=true; shift ;;
        -o|--output)
            OUTPUT_FILE="$2"; shift 2 ;;
        -v|--verbose)
            VERBOSE=true; shift ;;
        -h|--help)
            print_help; exit 0 ;;
        *)
            log_warn "Unknown option: $1"; shift ;;
    esac
done

# ─── Validate inputs ─────────────────────────────────────────────────────────
validate_number "$TIMEOUT" "--timeout"
validate_number "$JOBS"    "--jobs"

if [[ -z "$NETWORK" ]]; then
    NETWORK=$(autodetect_network)
    log_info "Auto-detected network: ${WHITE}${NETWORK}${RESET}"
fi
validate_subnet "$NETWORK"

# ─── Print config ────────────────────────────────────────────────────────────
echo ""
log_ok  "Network : ${WHITE}${NETWORK}${RESET}"
log_info "Timeout : ${WHITE}${TIMEOUT}s${RESET}"
log_info "Jobs    : ${WHITE}${JOBS}${RESET}"
log_info "Mode    : ${WHITE}$(
    flags=()
    [[ "$QUICK_MODE" == true ]] && flags+=("quick")
    [[ "$ARP_MODE"   == true ]] && flags+=("arp")
    [[ "$PORT_SCAN"  == true ]] && flags+=("port-scan")
    [[ ${#flags[@]} -eq 0 ]]   && flags+=("standard")
    echo "${flags[*]}"
)${RESET}"
echo ""

# ─── Scan ────────────────────────────────────────────────────────────────────
print_section "SCANNING NETWORK..."

START_TIME=$(date +%s%N)

if [[ "$ARP_MODE" == true ]]; then
    TOTAL=$(arp_scan) || TOTAL=$(ping_scan "$NETWORK" "$TIMEOUT" "$JOBS")
else
    TOTAL=$(ping_scan "$NETWORK" "$TIMEOUT" "$JOBS")
fi

# Port scan
if [[ "$PORT_SCAN" == true && "$QUICK_MODE" == false ]]; then
    echo ""
    log_info "Scanning open ports on discovered hosts..."
    log_info "Ports : ${WHITE}${PORT_LIST}${RESET}"
    > "$TMP_PORTS"
    while IFS=$'\t' read -r ip _rest; do
        [[ -n "$ip" ]] && scan_ports "$ip" "$PORT_LIST" &
    done < "$TMP_HOSTS"
    wait
fi

END_TIME=$(date +%s%N)
ELAPSED=$(awk "BEGIN{printf \"%.2f\", ($END_TIME - $START_TIME)/1000000000}")

# ─── Output ──────────────────────────────────────────────────────────────────
echo ""
print_section "RESULTS" double
print_results_table

if [[ "$PORT_SCAN" == true && "$QUICK_MODE" == false && -s "$TMP_PORTS" ]]; then
    print_section "OPEN PORTS"
    print_ports_table
fi

print_section "SUMMARY" double
print_summary "$TOTAL" "$ELAPSED" "$NETWORK" "$TIMEOUT" "$JOBS"

# ─── Save to file ────────────────────────────────────────────────────────────
if [[ -n "$OUTPUT_FILE" ]]; then
    save_results "$OUTPUT_FILE" "$TOTAL" "$NETWORK" "$ELAPSED"
fi

echo ""
