print_results_header() {
    echo -e "${CYAN}"
    echo '╔════════════════════════════════════════════════════════════════════════════════════════════════════════════════╗'
    echo '║                                                  RESULTS                                                       ║'
    echo '╚════════════════════════════════════════════════════════════════════════════════════════════════════════════════╝'
    echo -e "${RESET}"
}

    
    while IFS= read -r line; do
        ip=$(echo "$line" | awk '{print $1}')
        time=$(echo "$line" | awk '{print $2}')
        hostname=$(echo "$line" | awk '{print $3}')
        
        if [ -n "$ip" ]; then
            if [ "$time" = "N/A" ] || [ -z "$time" ]; then
                echo -e "│  ${GREEN}● ALIVE${RESET}   │  ${WHITE}$(printf '%-32s' "$ip")${RESET}  │  ${YELLOW}N/A${RESET}     │  ${WHITE}$(printf '%-46s' "$hostname")${RESET}  │"
            else
                echo -e "│  ${GREEN}● ALIVE${RESET}   │  ${WHITE}$(printf '%-32s' "$ip")${RESET}  │  ${YELLOW}${time}ms${RESET}   │  ${WHITE}$(printf '%-46s' "$hostname")${RESET}  │"
            fi
        fi
    done < <(cat /tmp/smartscan_hosts 2>/dev/null)
    
    echo -e "${CYAN}"
    echo '└─────────────┴──────────────────────────────────┴────────────┴────────────────────────────────────────────────┘'
    echo -e "${RESET}"
}

print_ports_table() {
    if [ -f /tmp/smartscan_ports ]; then
        echo -e "${CYAN}"
        echo '┌─────────────┬──────────────────────────────────┬────────────────────┬────────────────────────────────────────┐'
        echo '│  IP ADDRESS │              OPEN PORTS          │      SERVICES      │                    INFO                │'
        echo '├─────────────┼──────────────────────────────────┼────────────────────┼────────────────────────────────────────┤'
        echo -e "${RESET}"
        
        while IFS= read -r line; do
            ip=$(echo "$line" | cut -d'|' -f1)
            ports=$(echo "$line" | cut -d'|' -f2)
            services=$(echo "$line" | cut -d'|' -f3)
            
            echo -e "│  ${WHITE}$(printf '%-11s' "$ip")${RESET} │  ${YELLOW}$(printf '%-32s' "$ports")${RESET} │  ${GREEN}$(printf '%-18s' "$services")${RESET} │  ${WHITE}Open ports detected${RESET}          │"
        done < /tmp/smartscan_ports
        
        echo -e "${CYAN}"
        echo '└─────────────┴──────────────────────────────────┴────────────────────┴────────────────────────────────────────┘'
        echo -e "${RESET}"
    fi
}

print_summary_header() {
    echo -e "${CYAN}"
    echo '╔════════════════════════════════════════════════════════════════════════════════════════════════════════════════╗'
    echo '║                                                  SUMMARY                                                       ║'
    echo '╚════════════════════════════════════════════════════════════════════════════════════════════════════════════════╝'
    echo -e "${RESET}"
}

print_summary() {
    local total=$1
    local elapsed=$2
    local subnet=$3
    local timeout=$4
    
    echo -e "${WHITE}"
    echo "  Network subnet : $subnet"
    echo "  Devices found  : $total"
    echo "  Time taken     : ${elapsed} seconds"
    echo "  Timeout        : ${timeout}s"
    echo -e "${RESET}"
    
    echo -e "${CYAN}"
    
    echo -e "${RESET}"
}

ping_scan() {
    local subnet=$1
    local timeout=$2
    
    echo -e "${GREEN}[→] Performing ping sweep on $subnet${RESET}"
    
    # Extract base IP
    local base_ip=$(echo "$subnet" | cut -d'/' -f1 | cut -d'.' -f1-3)
    
    > /tmp/smartscan_hosts
    local found=0
    
    for i in {1..254}; do
        ip="${base_ip}.${i}"
        if ping -c 1 -W "$timeout" "$ip" > /dev/null 2>&1; then
            # Get response time
            local time_ms=$(ping -c 1 -W "$timeout" "$ip" 2>/dev/null | grep 'time=' | head -1 | sed 's/.*time=\([0-9.]*\) ms.*/\1/')
            if [ -z "$time_ms" ]; then
                time_ms="N/A"
            fi
            
            # Get hostname
            local hostname=$(nslookup "$ip" 2>/dev/null | grep 'name =' | head -1 | awk -F'name = ' '{print $2}' | sed 's/\.$//')
            if [ -z "$hostname" ]; then
                hostname="Unknown"
            fi
            
            echo "$ip $time_ms $hostname" >> /tmp/smartscan_hosts
            echo -e "${GREEN}●${RESET} $ip ${YELLOW}[${time_ms}ms]${RESET} → ${WHITE}$hostname${RESET}"
            ((found++))
        fi
    done
    
    echo "$found"
}

arp_scan() {
    echo -e "${GREEN}[→] Performing ARP scan (requires sudo)${RESET}"
    
    > /tmp/smartscan_hosts
    local found=0
    
    if command -v arp-scan &> /dev/null; then
        sudo arp-scan --localnet 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | while read -r ip mac rest; do
            hostname=$(nslookup "$ip" 2>/dev/null | grep 'name =' | head -1 | awk -F'name = ' '{print $2}' | sed 's/\.$//')
            [ -z "$hostname" ] && hostname="Unknown"
            echo "$ip N/A $hostname" >> /tmp/smartscan_hosts
            echo -e "${GREEN}●${RESET} $ip → ${WHITE}$hostname${RESET}"
            ((found++))
        done
    else
        echo -e "${YELLOW}[!] arp-scan not found. Falling back to ping scan...${RESET}"
        return 1
    fi
    
    echo "$found"
}

scan_ports() {
    local ip=$1
    local ports="22,80,443,3306,8080"
    local open_ports=""
    local services=""
    
    for port in $(echo "$ports" | tr ',' ' '); do
        if timeout 1 bash -c "echo >/dev/tcp/$ip/$port" 2>/dev/null; then
            case $port in
                22) services="${services}SSH " ;;
                80) services="${services}HTTP " ;;
                443) services="${services}HTTPS " ;;
                3306) services="${services}MySQL " ;;
                8080) services="${services}HTTP-Alt " ;;
                *) services="${services}Port$port " ;;
            esac
            open_ports="${open_ports}${port} "
        fi
    done
    
    if [ -n "$open_ports" ]; then
        echo "$ip|$open_ports|$services" >> /tmp/smartscan_ports
    fi
}

# Main execution
print_banner

# Parse arguments
NETWORK=""
TIMEOUT=1
QUICK_MODE=false
ARP_MODE=false
PORT_SCAN=false
OUTPUT_FILE=""

while [[ $# -gt 0 ]]; do
    case $1 in
        -n|--network)
            NETWORK="$2"
            shift 2
            ;;
        -t|--timeout)
            TIMEOUT="$2"
            shift 2
            ;;
        -q|--quick)
            QUICK_MODE=true
            shift
            ;;
        -a|--arp)
            ARP_MODE=true
            shift
            ;;
        -p|--ports)
            PORT_SCAN=true
            shift
            ;;
        -o|--output)
            OUTPUT_FILE="$2"
            shift 2
            ;;
        -h|--help)
            print_help
            exit 0
            ;;
        *)
            shift
            ;;
    esac
done

# Auto-detect network if not specified
if [ -z "$NETWORK" ]; then
    if command -v ip &> /dev/null; then
        NETWORK=$(ip route | grep -v default | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+' | head -1 | awk '{print $1}')
    elif command -v ifconfig &> /dev/null; then
        NETWORK=$(ifconfig | grep -E 'inet [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | grep -v 127.0.0.1 | head -1 | awk '{print $2}' | cut -d'.' -f1-3)
        NETWORK="${NETWORK}.0/24"
    else
        NETWORK="192.168.1.0/24"
    fi
fi

echo -e "${CYAN}[✓] Network: ${WHITE}$NETWORK${RESET}"
echo -e "${CYAN}[→] Timeout: ${WHITE}${TIMEOUT}s${RESET}"
echo -e "${CYAN}[→] Quick mode: ${WHITE}$QUICK_MODE${RESET}"
echo -e "${CYAN}[→] ARP mode: ${WHITE}$ARP_MODE${RESET}"
echo ""

print_scanning_header
echo ""

START_TIME=$(date +%s.%N)

if [ "$ARP_MODE" = true ]; then
    TOTAL=$(arp_scan)
    if [ $? -ne 0 ]; then
        TOTAL=$(ping_scan "$NETWORK" "$TIMEOUT")
    fi
else
    TOTAL=$(ping_scan "$NETWORK" "$TIMEOUT")
fi

if [ "$PORT_SCAN" = true ] && [ "$QUICK_MODE" = false ]; then
    echo ""
    echo -e "${GREEN}[→] Scanning for open ports on discovered hosts...${RESET}"
    > /tmp/smartscan_ports
    while IFS= read -r line; do
        ip=$(echo "$line" | awk '{print $1}')
        if [ -n "$ip" ]; then
            scan_ports "$ip" &
        fi
    done < /tmp/smartscan_hosts
    wait
fi

END_TIME=$(date +%s.%N)
ELAPSED=$(echo "$END_TIME - $START_TIME" | bc | cut -c1-4)

echo ""
print_results_header
echo ""
print_results_table

if [ "$PORT_SCAN" = true ] && [ "$QUICK_MODE" = false ] && [ -f /tmp/smartscan_ports ]; then
    echo ""
    print_ports_table
fi

print_summary_header
print_summary "$TOTAL" "$ELAPSED" "$NETWORK" "$TIMEOUT"

# Save to file
if [ -n "$OUTPUT_FILE" ]; then
    {
        echo "SmartScan Results - $(date)"
        echo "Network: $NETWORK"
        echo "Devices found: $TOTAL"
        echo ""
        echo "IP Address          Hostname"
        echo "----------------------------------------"
        while IFS= read -r line; do
            ip=$(echo "$line" | awk '{print $1}')
            hostname=$(echo "$line" | awk '{print $3}')
            echo "$ip     $hostname"
        done < /tmp/smartscan_hosts
    } > "$OUTPUT_FILE"
    echo -e "${GREEN}[✓] Results saved to $OUTPUT_FILE${RESET}"
fi

# Cleanup
rm -f /tmp/smartscan_hosts /tmp/smartscan_ports 2>/dev/null

echo ""
