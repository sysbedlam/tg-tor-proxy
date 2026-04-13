#!/bin/bash
# =============================================================================
# tg-tor-proxy.sh — Route Telegram through Tor for AmneziaWG / Xray VPN clients
# Version: 1.3.0
# =============================================================================
# Usage:
#   ./tg-tor-proxy.sh                    — install / reconfigure
#   ./tg-tor-proxy.sh --install          — same as above
#   ./tg-tor-proxy.sh --remove           — remove everything
#   ./tg-tor-proxy.sh --diagnose         — full diagnostic report
#   ./tg-tor-proxy.sh --check-tor        — test Tor connectivity only
#   ./tg-tor-proxy.sh --add-bridges      — interactively add/replace bridges
#   ./tg-tor-proxy.sh --add-bridges "obfs4 1.2.3.4:1234 FP cert=... iat-mode=0"
#   ./tg-tor-proxy.sh --add-bridges-file /path/to/bridges.txt
# =============================================================================

set -euo pipefail

# ── Constants ────────────────────────────────────────────────────────────────
readonly VERSION="1.3.0"
readonly SCRIPT_NAME="tg-tor-proxy"
readonly CONFIG_DIR="/etc/tg-tor-proxy"
readonly CONFIG_FILE="$CONFIG_DIR/config"
readonly BRIDGES_FILE="$CONFIG_DIR/bridges"
readonly NETWORKS_FILE="$CONFIG_DIR/detected_networks"
readonly ROUTES_SCRIPT="/usr/local/bin/tg-tor-routes.sh"
readonly BOOTSTRAP_SCRIPT="/usr/local/bin/tg-tor-bootstrap.sh"
readonly REDSOCKS_CONF="/etc/redsocks.conf"
readonly TORRC="/etc/tor/torrc"
readonly REDSOCKS_PORT=12345
readonly TOR_PORT=9050
readonly TOR_CONTROL_SOCK="/run/tor/control"
readonly TOR_COOKIE="/run/tor/control.authcookie"
readonly DIRECT_BOOTSTRAP_TIMEOUT=120   # seconds to wait for Tor without bridges
readonly DIRECT_STUCK_THRESHOLD=60      # seconds at same % → switch to bridge mode
readonly BRIDGE_BOOTSTRAP_TIMEOUT=300   # seconds to wait for Tor with bridges
readonly BRIDGE_STUCK_SIGHUP=90         # seconds stuck → send SIGHUP

# ── Colors ───────────────────────────────────────────────────────────────────
if [ -t 1 ]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
    BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; BLUE=''; CYAN=''; BOLD=''; NC=''
fi

# ── Telegram IP ranges ───────────────────────────────────────────────────────
TELEGRAM_NETS=(
    "100.24.0.0/13"   "104.16.0.0/12"   "108.177.0.0/17"  "132.245.0.0/16"
    "142.250.0.0/15"  "146.75.0.0/16"   "149.154.160.0/20" "151.101.0.0/16"
    "170.149.0.0/16"  "172.217.0.0/16"  "172.253.0.0/16"  "172.64.0.0/13"
    "173.194.0.0/16"  "174.143.0.0/16"  "178.128.240.0/20" "18.128.0.0/9"
    "185.76.151.0/24" "188.166.0.0/17"  "192.178.0.0/15"  "199.232.0.0/16"
    "204.212.0.0/14"  "209.85.128.0/17" "209.97.0.0/18"   "213.180.193.0/24"
    "216.58.192.0/19" "34.192.0.0/10"   "34.64.0.0/10"    "35.184.0.0/13"
    "35.224.0.0/12"   "35.240.0.0/13"   "40.96.0.0/12"    "44.192.0.0/10"
    "50.128.0.0/9"    "52.96.0.0/12"    "64.233.160.0/19" "66.102.0.0/20"
    "66.151.176.0/20" "74.125.0.0/16"   "8.0.0.0/13"      "8.32.0.0/11"
    "91.105.192.0/23" "91.108.12.0/22"  "91.108.16.0/22"  "91.108.20.0/22"
    "91.108.4.0/22"   "91.108.56.0/22"  "91.108.8.0/22"   "92.204.208.0/20"
    "95.161.64.0/20"
)

# ── Helpers ──────────────────────────────────────────────────────────────────
log()  { echo -e "${GREEN}[✓]${NC} $*"; }
info() { echo -e "${BLUE}[i]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[✗]${NC} $*" >&2; }
die()  { err "$*"; exit 1; }
hdr()  { echo -e "\n${BOLD}${CYAN}══ $* ══${NC}"; }

require_root() {
    [ "$(id -u)" -eq 0 ] || die "Run as root: sudo $0 $*"
}

iptables_cmd() {
    if command -v iptables-legacy &>/dev/null; then
        iptables-legacy "$@"
    else
        iptables "$@"
    fi
}

# ── Tor control port query ───────────────────────────────────────────────────
tor_query() {
    local cmd="$1"
    python3 -c "
import socket, sys
try:
    with open('$TOR_COOKIE', 'rb') as f:
        cookie = f.read().hex()
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect('$TOR_CONTROL_SOCK')
    s.send(f'AUTHENTICATE {cookie}\r\n'.encode())
    s.recv(200)
    s.send(b'$cmd\r\n')
    resp = b''
    while True:
        chunk = s.recv(4096)
        if not chunk: break
        resp += chunk
        if b'250 OK' in resp or b'5' in resp[:3]: break
    s.close()
    print(resp.decode().strip())
except Exception as e:
    print(f'ERROR: {e}', file=sys.stderr)
    sys.exit(1)
" 2>/dev/null
}

tor_bootstrap_pct() {
    local resp
    resp=$(tor_query "GETINFO status/bootstrap-phase" 2>/dev/null) || true
    echo "$resp" | grep -oP 'PROGRESS=\K\d+' || echo "0"
}

# ─────────────────────────────────────────────────────────────────────────────
# DETECT CONTAINERS
# ─────────────────────────────────────────────────────────────────────────────
detect_vpn_containers() {
    command -v docker &>/dev/null || die "Docker not found. Is Docker installed?"

    local containers=()
    local found_names=()

    # Patterns to match: amnezia, awg, xray, v2ray, sing-box, outline
    while IFS= read -r line; do
        local cid name image
        cid=$(echo "$line" | awk '{print $1}')
        name=$(echo "$line" | awk '{print $2}')
        image=$(echo "$line" | awk '{print $3}')
        local combined="${name,,} ${image,,}"
        if echo "$combined" | grep -qE 'amnezia|awg|xray|v2ray|sing.?box|outline|3proxy|openvpn|wireguard'; then
            containers+=("$cid")
            found_names+=("$name ($image)")
        fi
    done < <(docker ps --format '{{.ID}} {{.Names}} {{.Image}}' 2>/dev/null || true)

    if [ ${#containers[@]} -eq 0 ]; then
        warn "No VPN containers auto-detected."
        info "Searching all running containers..."
        # Fall back: show all containers, let user pick
        docker ps --format '{{.ID}} {{.Names}} {{.Image}}' 2>/dev/null || true
        echo ""
        read -rp "Enter container ID or name (or leave empty to skip): " manual_id
        if [ -n "$manual_id" ]; then
            containers=("$manual_id")
        else
            die "No container selected."
        fi
    else
        log "Detected VPN containers:"
        for n in "${found_names[@]}"; do
            info "  → $n"
        done
    fi

    # Extract docker networks for each container
    local all_networks=()
    for cid in "${containers[@]}"; do
        while IFS= read -r net_cidr; do
            [ -n "$net_cidr" ] && all_networks+=("$net_cidr")
        done < <(docker inspect "$cid" --format \
            '{{range $k, $v := .NetworkSettings.Networks}}{{$v.IPAddress}}/{{(split $v.IPPrefixLen "")}} {{end}}' \
            2>/dev/null | tr ' ' '\n' || true)

        # Better: get the actual network CIDR from docker network inspect
        while IFS= read -r net_name; do
            [ -z "$net_name" ] && continue
            local cidr
            cidr=$(docker network inspect "$net_name" \
                --format '{{range .IPAM.Config}}{{.Subnet}}{{end}}' 2>/dev/null || true)
            [ -n "$cidr" ] && [ "$cidr" != "172.17.0.0/16" ] && all_networks+=("$cidr")
            # Always include the network, even if it's the default bridge
            [ -n "$cidr" ] && all_networks+=("$cidr")
        done < <(docker inspect "$cid" \
            --format '{{range $k, $v := .NetworkSettings.Networks}}{{$k}}{{"\n"}}{{end}}' \
            2>/dev/null || true)
    done

    # Deduplicate and exclude loopback
    local unique_nets=()
    declare -A seen
    for net in "${all_networks[@]}"; do
        [[ "$net" == "127."* ]] && continue
        [[ "$net" == "" ]] && continue
        if [ -z "${seen[$net]+x}" ]; then
            seen[$net]=1
            unique_nets+=("$net")
        fi
    done

    # Fallback: if nothing found, use docker0 default
    if [ ${#unique_nets[@]} -eq 0 ]; then
        warn "Could not detect docker networks, using defaults."
        unique_nets=("172.17.0.0/16" "172.16.0.0/12")
    fi

    # Save to file
    mkdir -p "$CONFIG_DIR"
    printf '%s\n' "${unique_nets[@]}" | sort -u > "$NETWORKS_FILE"

    log "Docker networks to intercept:"
    for n in "${unique_nets[@]}"; do
        info "  → $n"
    done
}

# ─────────────────────────────────────────────────────────────────────────────
# INSTALL PACKAGES
# ─────────────────────────────────────────────────────────────────────────────
install_packages() {
    hdr "Installing packages"
    local pkgs=()
    command -v tor      &>/dev/null || pkgs+=(tor)
    command -v redsocks &>/dev/null || pkgs+=(redsocks)
    command -v obfs4proxy &>/dev/null || pkgs+=(obfs4proxy)

    if [ ${#pkgs[@]} -gt 0 ]; then
        info "Installing: ${pkgs[*]}"
        apt-get update -qq 2>/dev/null
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${pkgs[@]}" 2>/dev/null
        log "Packages installed"
    else
        log "All packages already installed"
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURE REDSOCKS
# ─────────────────────────────────────────────────────────────────────────────
configure_redsocks() {
    hdr "Configuring Redsocks"

    cat > "$REDSOCKS_CONF" << EOF
base {
    log_debug = off;
    log_info = on;
    log = "syslog:daemon";
    daemon = on;
    user = redsocks;
    group = redsocks;
    redirector = iptables;
}

redsocks {
    local_ip = 0.0.0.0;
    local_port = $REDSOCKS_PORT;
    ip = 127.0.0.1;
    port = $TOR_PORT;
    type = socks5;
}
EOF

    systemctl enable redsocks 2>/dev/null || true
    systemctl restart redsocks
    log "Redsocks configured → listening on 0.0.0.0:$REDSOCKS_PORT → Tor :$TOR_PORT"
}

# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURE TOR (no bridges)
# ─────────────────────────────────────────────────────────────────────────────
configure_tor_direct() {
    cat > "$TORRC" << 'TOREOF'
## Managed by tg-tor-proxy
SocksPort 9050
Log notice syslog
# Circuit stability
CircuitBuildTimeout 60
LearnCircuitBuildTimeout 0
MaxCircuitDirtiness 600
NumEntryGuards 4
NewCircuitPeriod 15
MaxClientCircuitsPending 128
KeepalivePeriod 30
TOREOF
    systemctl restart tor@default 2>/dev/null || systemctl restart tor
}

# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURE TOR (with bridges)
# ─────────────────────────────────────────────────────────────────────────────
configure_tor_bridges() {
    local bridges_file="${1:-$BRIDGES_FILE}"

    if [ ! -f "$bridges_file" ] || [ ! -s "$bridges_file" ]; then
        die "No bridges file found. Run: $0 --add-bridges"
    fi

    # Check if obfs4 bridges are provided
    local has_obfs4=false
    grep -q "^Bridge obfs4" "$bridges_file" && has_obfs4=true

    {
        echo "## Managed by tg-tor-proxy (bridge mode)"
        echo "SocksPort $TOR_PORT"
        echo "Log notice syslog"
        if $has_obfs4; then
            echo "ClientTransportPlugin obfs4 exec /usr/bin/obfs4proxy"
        fi
        echo "UseBridges 1"
        grep -v '^#' "$bridges_file" | grep -v '^$' | while read -r line; do
            # Auto-prefix with "Bridge" if not already there
            if echo "$line" | grep -q "^Bridge "; then
                echo "$line"
            else
                echo "Bridge $line"
            fi
        done
        echo "# Circuit stability"
        echo "CircuitBuildTimeout 60"
        echo "LearnCircuitBuildTimeout 0"
        echo "MaxCircuitDirtiness 600"
        echo "NumEntryGuards 4"
        echo "NewCircuitPeriod 15"
        echo "MaxClientCircuitsPending 128"
        echo "KeepalivePeriod 30"
    } > "$TORRC"

    systemctl restart tor@default 2>/dev/null || systemctl restart tor
    log "Tor configured with $(grep -c '^Bridge' "$TORRC" 2>/dev/null || echo '?') bridge(s)"
}

# ─────────────────────────────────────────────────────────────────────────────
# TOR BOOTSTRAP MONITOR
# Returns: 0 if bootstrapped to 100%, 1 if stuck/failed
# ─────────────────────────────────────────────────────────────────────────────
wait_tor_bootstrap() {
    local max_wait="${1:-$DIRECT_BOOTSTRAP_TIMEOUT}"
    local stuck_threshold="${2:-$DIRECT_STUCK_THRESHOLD}"
    local use_sighup="${3:-false}"
    local sighup_threshold="${4:-$BRIDGE_STUCK_SIGHUP}"

    local elapsed=0
    local interval=5
    local last_pct=-1
    local stuck_for=0
    local sighup_for=0
    local tor_pid

    info "Waiting for Tor bootstrap (max ${max_wait}s)..."

    while [ $elapsed -lt $max_wait ]; do
        tor_pid=$(systemctl show tor@default --property=MainPID --value 2>/dev/null || echo "0")
        [ "$tor_pid" = "0" ] && tor_pid=$(pgrep -x tor | head -1 || echo "0")

        if [ "$tor_pid" = "0" ] || ! kill -0 "$tor_pid" 2>/dev/null; then
            warn "Tor not running (${elapsed}s elapsed)"
            sleep $interval
            elapsed=$((elapsed + interval))
            continue
        fi

        local pct
        pct=$(tor_bootstrap_pct 2>/dev/null || echo "0")
        pct=${pct:-0}

        # Progress bar
        local bar_len=30
        local filled=$(( pct * bar_len / 100 ))
        local bar=""
        for ((i=0; i<filled; i++)); do bar+="█"; done
        for ((i=filled; i<bar_len; i++)); do bar+="░"; done
        printf "\r  [%s] %3d%% (%ds)" "$bar" "$pct" "$elapsed"

        if [ "$pct" -eq 100 ]; then
            echo ""
            log "Tor bootstrapped successfully!"
            return 0
        fi

        if [ "$pct" -eq "$last_pct" ]; then
            stuck_for=$((stuck_for + interval))
            sighup_for=$((sighup_for + interval))

            # If stuck for too long in direct mode → give up
            if [ "$stuck_for" -ge "$stuck_threshold" ] && ! $use_sighup; then
                echo ""
                warn "Tor stuck at ${pct}% for ${stuck_for}s"
                return 1
            fi

            # In bridge mode: send SIGHUP if stuck
            if $use_sighup && [ $sighup_for -ge "$sighup_threshold" ]; then
                echo ""
                info "Tor stuck at ${pct}% for ${sighup_for}s — sending SIGHUP to reload consensus from cache"
                kill -HUP "$tor_pid" 2>/dev/null || true
                sighup_for=0
            fi
        else
            stuck_for=0
            sighup_for=0
            last_pct=$pct
        fi

        sleep $interval
        elapsed=$((elapsed + interval))
    done

    echo ""
    warn "Tor bootstrap timed out after ${max_wait}s (at ${last_pct}%)"
    return 1
}

# ─────────────────────────────────────────────────────────────────────────────
# TEST TOR DIRECT (no bridges)
# Returns: 0 if direct works, 1 if needs bridges
# ─────────────────────────────────────────────────────────────────────────────
test_tor_direct() {
    hdr "Testing Tor — direct mode (no bridges)"

    # Quick connectivity test first
    info "Testing raw internet access..."
    if ! curl -s --connect-timeout 5 https://1.1.1.1 -o /dev/null 2>/dev/null; then
        warn "No internet access, skipping direct test"
        return 1
    fi

    configure_tor_direct

    info "Giving Tor time to connect (${DIRECT_BOOTSTRAP_TIMEOUT}s max)..."
    if wait_tor_bootstrap "$DIRECT_BOOTSTRAP_TIMEOUT" "$DIRECT_STUCK_THRESHOLD" false; then
        # Verify actual SOCKS5 works
        info "Verifying Tor SOCKS5 proxy..."
        local tor_ip
        tor_ip=$(curl -s --connect-timeout 10 \
            --socks5-hostname "127.0.0.1:$TOR_PORT" \
            https://check.torproject.org/api/ip 2>/dev/null \
            | grep -oP '"IP":"\K[^"]+' || true)
        if [ -n "$tor_ip" ]; then
            log "Tor working! Exit IP: $tor_ip"
            # Save mode
            mkdir -p "$CONFIG_DIR"
            echo "mode=direct" > "$CONFIG_FILE"
            return 0
        else
            warn "Tor at 100% but SOCKS5 test failed"
        fi
    fi

    warn "Direct Tor not available on this network (likely censored)"
    return 1
}

# ─────────────────────────────────────────────────────────────────────────────
# PROMPT FOR BRIDGES
# ─────────────────────────────────────────────────────────────────────────────
prompt_bridges() {
    local bridges_provided="${1:-}"

    hdr "Bridge configuration"

    if [ -n "$bridges_provided" ]; then
        # Bridges passed as argument
        mkdir -p "$CONFIG_DIR"
        echo "$bridges_provided" > "$BRIDGES_FILE"
        log "Bridges saved from argument"
        return 0
    fi

    echo ""
    echo -e "${CYAN}Tor is blocked on this network. You need obfs4 bridges.${NC}"
    echo ""
    echo "Get bridges from (use a device on another network):"
    echo "  • https://bridges.torproject.org/?transport=obfs4"
    echo "  • Email: bridges@torproject.org  (subject: get transport obfs4)"
    echo "  • Telegram bot: @GetBridgesBot"
    echo ""

    # Check if existing bridges file exists
    if [ -f "$BRIDGES_FILE" ] && [ -s "$BRIDGES_FILE" ]; then
        info "Existing bridges found in $BRIDGES_FILE:"
        grep -v '^#' "$BRIDGES_FILE" | grep -v '^$' | while read -r b; do
            echo "    $b" | cut -c1-80
        done
        echo ""
        read -rp "Use existing bridges? [Y/n]: " ans
        ans=${ans:-Y}
        [[ "${ans^^}" == "Y" ]] && return 0
    fi

    echo "Paste your obfs4 bridge lines (one per line, blank line to finish):"
    echo "Format: obfs4 IP:PORT FINGERPRINT cert=... iat-mode=0"
    echo "Or:     Bridge obfs4 IP:PORT FINGERPRINT cert=... iat-mode=0"
    echo ""

    local bridges=()
    while IFS= read -r line; do
        [ -z "$line" ] && break
        # Strip leading 'Bridge ' if present (we'll add it in configure_tor_bridges)
        line="${line#Bridge }"
        bridges+=("$line")
    done

    if [ ${#bridges[@]} -eq 0 ]; then
        warn "No bridges entered"
        return 1
    fi

    mkdir -p "$CONFIG_DIR"
    printf 'Bridge %s\n' "${bridges[@]}" > "$BRIDGES_FILE"
    log "${#bridges[@]} bridge(s) saved to $BRIDGES_FILE"
    return 0
}

# ─────────────────────────────────────────────────────────────────────────────
# SETUP IPTABLES RULES
# ─────────────────────────────────────────────────────────────────────────────
generate_routes_script() {
    hdr "Generating iptables rules script"

    local networks=()
    if [ -f "$NETWORKS_FILE" ]; then
        while IFS= read -r net; do
            [ -n "$net" ] && networks+=("$net")
        done < "$NETWORKS_FILE"
    fi

    if [ ${#networks[@]} -eq 0 ]; then
        networks=("172.17.0.0/16" "172.29.172.0/24")
        warn "No detected networks, using defaults: ${networks[*]}"
    fi

    cat > "$ROUTES_SCRIPT" << 'HEREDOC'
#!/bin/bash
# Managed by tg-tor-proxy — do not edit manually
REDSOCKS_PORT=REDSOCKS_PORT_PLACEHOLDER

TELEGRAM_NETS="
TELEGRAM_NETS_PLACEHOLDER
"

SOURCE_NETS="
SOURCE_NETS_PLACEHOLDER
"

IPT() { iptables-legacy "$@" 2>/dev/null || iptables "$@" 2>/dev/null; }

flush_rules() {
    IPT -t nat -F TELEGRAM_TOR 2>/dev/null
    IPT -t nat -D PREROUTING -j TELEGRAM_TOR 2>/dev/null
    IPT -t nat -X TELEGRAM_TOR 2>/dev/null
    return 0
}

add_rules() {
    IPT -t nat -N TELEGRAM_TOR 2>/dev/null || true

    # Skip private/bogon destinations (these are routes, not sources)
    for bogon in 0.0.0.0/8 10.0.0.0/8 127.0.0.0/8 169.254.0.0/16 \
                 192.168.0.0/16 224.0.0.0/4 240.0.0.0/4; do
        IPT -t nat -A TELEGRAM_TOR -d "$bogon" -j RETURN
    done

    # Redirect Telegram IPs to Redsocks
    for net in $TELEGRAM_NETS; do
        [ -z "$net" ] && continue
        IPT -t nat -A TELEGRAM_TOR -p tcp -d "$net" -j REDIRECT --to-ports "$REDSOCKS_PORT"
    done

    # Apply to traffic from VPN container networks
    IPT -t nat -I PREROUTING -j TELEGRAM_TOR
}

case "${1:-}" in
    start)
        flush_rules
        add_rules
        echo "Telegram → Tor rules applied"
        ;;
    stop)
        flush_rules
        echo "Telegram → Tor rules removed"
        ;;
    status)
        echo "=== TELEGRAM_TOR chain ==="
        IPT -t nat -L TELEGRAM_TOR -n --line-numbers 2>/dev/null || echo "Chain not found"
        echo ""
        echo "=== PREROUTING ==="
        IPT -t nat -L PREROUTING -n --line-numbers 2>/dev/null | head -5
        ;;
    *)
        echo "Usage: $0 {start|stop|status}"
        exit 1
        ;;
esac
HEREDOC

    # Substitute placeholders
    local tg_nets_str
    tg_nets_str=$(printf '%s\n' "${TELEGRAM_NETS[@]}")
    local src_nets_str
    src_nets_str=$(printf '%s\n' "${networks[@]}")

    sed -i "s|REDSOCKS_PORT_PLACEHOLDER|$REDSOCKS_PORT|g" "$ROUTES_SCRIPT"
    # Use Python for safe multi-line substitution
    python3 - "$ROUTES_SCRIPT" "$tg_nets_str" "$src_nets_str" << 'PYEOF'
import sys
script_path, tg_nets, src_nets = sys.argv[1], sys.argv[2], sys.argv[3]
with open(script_path) as f:
    content = f.read()
content = content.replace('TELEGRAM_NETS_PLACEHOLDER', tg_nets)
content = content.replace('SOURCE_NETS_PLACEHOLDER', src_nets)
with open(script_path, 'w') as f:
    f.write(content)
PYEOF

    chmod +x "$ROUTES_SCRIPT"
    log "Routes script written: $ROUTES_SCRIPT"
}

# ─────────────────────────────────────────────────────────────────────────────
# INSTALL SYSTEMD SERVICES
# ─────────────────────────────────────────────────────────────────────────────
install_systemd_services() {
    hdr "Installing systemd services"

    # Bootstrap watcher (handles stuck Tor)
    cat > "$BOOTSTRAP_SCRIPT" << BSEOF
#!/bin/bash
# Tor bootstrap watcher — sends SIGHUP if stuck, waits for 100%
MAX_WAIT=${BRIDGE_BOOTSTRAP_TIMEOUT}
SIGHUP_AFTER=${BRIDGE_STUCK_SIGHUP}
INTERVAL=5
elapsed=0; last_pct=-1; stuck=0

while [ \$elapsed -lt \$MAX_WAIT ]; do
    pct=\$(python3 -c "
import socket, re
try:
    with open('$TOR_COOKIE','rb') as f: c=f.read().hex()
    s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
    s.settimeout(3); s.connect('$TOR_CONTROL_SOCK')
    s.send(f'AUTHENTICATE {c}\r\n'.encode()); s.recv(200)
    s.send(b'GETINFO status/bootstrap-phase\r\n')
    r=s.recv(500).decode(); s.close()
    m=re.search(r'PROGRESS=(\d+)',r); print(m.group(1) if m else '0')
except: print('0')
" 2>/dev/null || echo 0)

    [ "\$pct" -eq 100 ] && { echo "Tor bootstrapped 100%"; exit 0; }

    if [ "\$pct" -eq "\$last_pct" ]; then
        stuck=\$((stuck+INTERVAL))
        if [ \$stuck -ge \$SIGHUP_AFTER ]; then
            TOR_PID=\$(systemctl show tor@default --property=MainPID --value 2>/dev/null)
            [ -n "\$TOR_PID" ] && [ "\$TOR_PID" != "0" ] && kill -HUP "\$TOR_PID" 2>/dev/null
            echo "SIGHUP sent to Tor (stuck at \${pct}% for \${stuck}s)"
            stuck=0
        fi
    else
        stuck=0; last_pct=\$pct
    fi
    sleep \$INTERVAL
    elapsed=\$((elapsed+INTERVAL))
done
echo "Bootstrap timeout"; exit 1
BSEOF
    chmod +x "$BOOTSTRAP_SCRIPT"

    # Routes service
    cat > /etc/systemd/system/tg-tor-routes.service << EOF
[Unit]
Description=Telegram → Tor iptables routes
After=network.target redsocks.service
Requires=redsocks.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$ROUTES_SCRIPT start
ExecStop=$ROUTES_SCRIPT stop

[Install]
WantedBy=multi-user.target
EOF

    # Bootstrap watcher service
    cat > /etc/systemd/system/tg-tor-bootstrap.service << EOF
[Unit]
Description=Tor bootstrap watcher for tg-tor-proxy
After=tor@default.service tor.service
Wants=tor@default.service

[Service]
Type=oneshot
RemainAfterExit=no
ExecStart=$BOOTSTRAP_SCRIPT
TimeoutStartSec=400
StandardOutput=journal

[Install]
WantedBy=multi-user.target
EOF

    # Main orchestration service
    cat > /etc/systemd/system/tg-tor-proxy.service << EOF
[Unit]
Description=Telegram-through-Tor proxy for VPN clients
After=tg-tor-bootstrap.service redsocks.service
Wants=tg-tor-bootstrap.service redsocks.service tg-tor-routes.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/bash -c 'systemctl start tg-tor-routes.service && echo "tg-tor-proxy active"'
ExecStop=/bin/bash -c 'systemctl stop tg-tor-routes.service'

[Install]
WantedBy=multi-user.target
EOF

    # Persistent watchdog script — download from GitHub
    local wd_url="https://raw.githubusercontent.com/sysbedlam/tg-tor-proxy/main/tg-tor-watchdog.sh"
    if curl -fsSL --connect-timeout 10 "$wd_url" -o /usr/local/bin/tg-tor-watchdog.sh 2>/dev/null; then
        log "Watchdog script downloaded"
    else
        warn "Could not download watchdog from GitHub, using bundled version"
        cat > /usr/local/bin/tg-tor-watchdog.sh << 'WDEOF'
#!/bin/bash
COOKIE="/run/tor/control.authcookie"; CONTROL="/run/tor/control"; LOG_TAG="tg-tor-watchdog"
log() { logger -t "$LOG_TAG" "$*"; echo "$(date '+%H:%M:%S') $*"; }
get_pct() { python3 -c "
import socket,re
try:
 with open('$COOKIE','rb') as f: c=f.read().hex()
 s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); s.settimeout(3); s.connect('$CONTROL')
 s.send(f'AUTHENTICATE {c}\r\n'.encode()); s.recv(200)
 s.send(b'GETINFO status/bootstrap-phase\r\n'); r=s.recv(500).decode(); s.close()
 m=re.search(r'PROGRESS=(\d+)',r); print(m.group(1) if m else '-1')
except: print('-1')
" 2>/dev/null || echo -1; }
sighup_tor() { local p; p=$(systemctl show tor@default --property=MainPID --value 2>/dev/null||echo 0)
 [ "$p" != "0" ] && kill -HUP "$p" 2>/dev/null && log "SIGHUP sent" && sleep 15; }
STUCK=0; LAST=-1; FAILS=0; RSCOOL=0
log "Watchdog started"
while true; do sleep 10; pct=$(get_pct)
 if [ "$pct" -eq -1 ]; then FAILS=$((FAILS+1))
  [ $FAILS -ge 3 ] && ! systemctl is-active --quiet tor@default && \
   log "Tor down — restarting" && systemctl restart tor@default && sleep 20 && FAILS=0 && LAST=-1 && STUCK=0
  continue; fi; FAILS=0
 if [ "$pct" -eq 100 ]; then STUCK=0; LAST=100
  ! systemctl is-active --quiet redsocks && log "Redsocks down" && systemctl restart redsocks && RSCOOL=6
  if [ "$RSCOOL" -gt 0 ]; then RSCOOL=$((RSCOOL-1))
  elif journalctl -u redsocks --since "30 seconds ago" --no-pager -q 2>/dev/null | grep -q "backing off"; then
   log "Redsocks fd exhaustion" && systemctl restart redsocks && RSCOOL=6; fi
 else log "Tor bootstrap: ${pct}%"
  [ "$pct" -eq "$LAST" ] && STUCK=$((STUCK+1)) || { STUCK=0; LAST=$pct; }
  [ $STUCK -eq 3 ] && { log "Stuck at ${pct}% — SIGHUP"; sighup_tor; STUCK=0; }
  [ $STUCK -ge 12 ] && { log "Stuck — restarting Tor"; systemctl restart tor@default; sleep 20; STUCK=0; LAST=-1; }
 fi; done
WDEOF
    fi
    chmod +x /usr/local/bin/tg-tor-watchdog.sh

    # Watchdog service
    cat > /etc/systemd/system/tg-tor-watchdog.service << EOF
[Unit]
Description=Tor + Redsocks stability watchdog for tg-tor-proxy
After=tor@default.service redsocks.service
Wants=tor@default.service

[Service]
Type=simple
ExecStart=/usr/local/bin/tg-tor-watchdog.sh
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    # Systemd drop-ins for auto-restart
    mkdir -p /etc/systemd/system/tor@default.service.d
    cat > /etc/systemd/system/tor@default.service.d/restart.conf << EOF
[Service]
Restart=always
RestartSec=10
EOF

    mkdir -p /etc/systemd/system/redsocks.service.d
    cat > /etc/systemd/system/redsocks.service.d/limits.conf << EOF
[Service]
Restart=always
RestartSec=5
LimitNOFILE=65536
EOF

    systemctl daemon-reload
    systemctl enable redsocks tg-tor-routes tg-tor-bootstrap tg-tor-proxy tg-tor-watchdog 2>/dev/null || true
    log "Systemd services installed and enabled"
}

# ─────────────────────────────────────────────────────────────────────────────
# APPLY ROUTES (start iptables)
# ─────────────────────────────────────────────────────────────────────────────
apply_routes() {
    bash "$ROUTES_SCRIPT" start
    systemctl start tg-tor-routes 2>/dev/null || true
    log "iptables rules applied"
}

# ─────────────────────────────────────────────────────────────────────────────
# FULL INSTALL
# ─────────────────────────────────────────────────────────────────────────────
cmd_install() {
    local bridges_arg="${1:-}"

    require_root

    echo ""
    echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════╗"
    echo -e "║   tg-tor-proxy v${VERSION} — Installer      ║"
    echo -e "╚══════════════════════════════════════════╝${NC}"
    echo ""

    # 1. Detect containers
    hdr "Detecting VPN containers"
    detect_vpn_containers

    # 2. Install packages
    install_packages

    # 3. Configure redsocks
    configure_redsocks

    # 4. Try Tor direct
    local use_bridges=false
    if test_tor_direct; then
        log "Using Tor in direct mode (no bridges needed)"
        echo "mode=direct" > "$CONFIG_FILE"
    else
        use_bridges=true
        echo "mode=bridges" > "$CONFIG_FILE"
    fi

    # 5. If bridges needed
    if $use_bridges; then
        hdr "Bridge mode required"
        if [ -n "$bridges_arg" ]; then
            prompt_bridges "$bridges_arg"
        else
            prompt_bridges ""
        fi
        configure_tor_bridges "$BRIDGES_FILE"

        info "Waiting for Tor to bootstrap with bridges..."
        if wait_tor_bootstrap "$BRIDGE_BOOTSTRAP_TIMEOUT" 999 true "$BRIDGE_STUCK_SIGHUP"; then
            log "Tor bootstrapped with bridges!"
        else
            warn "Tor bootstrap timed out. It may still complete in background."
            warn "Check status with: $0 --diagnose"
        fi
    fi

    # 6. Setup iptables
    generate_routes_script
    apply_routes

    # 7. Install systemd
    install_systemd_services

    # 8. Final test
    hdr "Final verification"
    local tor_ip
    tor_ip=$(curl -s --connect-timeout 15 \
        --socks5-hostname "127.0.0.1:$TOR_PORT" \
        https://check.torproject.org/api/ip 2>/dev/null \
        | grep -oP '"IP":"\K[^"]+' || true)

    if [ -n "$tor_ip" ]; then
        log "SUCCESS — Tor exit IP: ${BOLD}$tor_ip${NC}"
    else
        warn "Could not verify Tor exit IP (it may still be bootstrapping)"
    fi

    # Install global command so user can just type 'tg-tor-proxy'
    local self
    self="$(readlink -f "$0")"
    if [ "$self" != "/usr/local/bin/tg-tor-proxy" ]; then
        cp "$self" /usr/local/bin/tg-tor-proxy
        chmod +x /usr/local/bin/tg-tor-proxy
        log "Команда установлена: ${BOLD}tg-tor-proxy${NC}"
    fi

    echo ""
    echo -e "${GREEN}${BOLD}Установка завершена!${NC}"
    echo ""
    echo -e "Теперь вы можете просто набрать ${BOLD}${CYAN}tg-tor-proxy${NC} для открытия меню"
    echo ""
    echo -e "Или прямые команды:"
    echo -e "  ${CYAN}tg-tor-proxy --diagnose${NC}      — полный отчёт"
    echo -e "  ${CYAN}tg-tor-proxy --add-bridges${NC}   — обновить мосты"
    echo -e "  ${CYAN}tg-tor-proxy --check-tor${NC}     — проверить Tor"
    echo -e "  ${CYAN}tg-tor-proxy --remove${NC}        — удалить всё"
    echo -e "  ${CYAN}journalctl -t redsocks -f${NC}    — live Telegram сессии"
}

# ─────────────────────────────────────────────────────────────────────────────
# REMOVE EVERYTHING
# ─────────────────────────────────────────────────────────────────────────────
cmd_remove() {
    require_root

    hdr "Removing tg-tor-proxy"

    echo -e "${YELLOW}This will remove:${NC}"
    echo "  • iptables rules (TELEGRAM_TOR chain)"
    echo "  • Systemd services (tg-tor-routes, tg-tor-bootstrap, tg-tor-proxy)"
    echo "  • Redsocks configuration"
    echo "  • Tor configuration"
    echo "  • Config directory: $CONFIG_DIR"
    echo "  • Scripts: $ROUTES_SCRIPT, $BOOTSTRAP_SCRIPT"
    echo ""
    read -rp "Remove packages (tor, redsocks, obfs4proxy) too? [y/N]: " rm_pkgs
    echo ""
    read -rp "Confirm removal? [y/N]: " confirm
    [[ "${confirm^^}" != "Y" ]] && { info "Cancelled."; exit 0; }

    # Stop and disable services
    for svc in tg-tor-proxy tg-tor-routes tg-tor-bootstrap tg-tor-watchdog; do
        systemctl stop "$svc"  2>/dev/null || true
        systemctl disable "$svc" 2>/dev/null || true
        rm -f "/etc/systemd/system/${svc}.service"
    done
    # Remove systemd drop-ins
    rm -rf /etc/systemd/system/tor@default.service.d
    rm -rf /etc/systemd/system/redsocks.service.d
    # Remove watchdog script
    rm -f /usr/local/bin/tg-tor-watchdog.sh
    systemctl daemon-reload 2>/dev/null || true

    # Flush iptables
    if [ -x "$ROUTES_SCRIPT" ]; then
        bash "$ROUTES_SCRIPT" stop 2>/dev/null || true
    else
        iptables_cmd -t nat -F TELEGRAM_TOR 2>/dev/null || true
        iptables_cmd -t nat -D PREROUTING -j TELEGRAM_TOR 2>/dev/null || true
        iptables_cmd -t nat -X TELEGRAM_TOR 2>/dev/null || true
    fi
    log "iptables rules removed"

    # Remove scripts
    rm -f "$ROUTES_SCRIPT" "$BOOTSTRAP_SCRIPT"

    # Remove config
    rm -rf "$CONFIG_DIR"

    # Restore default redsocks config
    if [ -f /etc/redsocks.conf.orig ]; then
        cp /etc/redsocks.conf.orig /etc/redsocks.conf
    fi
    systemctl stop redsocks 2>/dev/null || true

    # Restore default torrc
    cat > "$TORRC" << 'EOF'
## Default torrc restored by tg-tor-proxy --remove
SocksPort 9050
Log notice syslog
EOF
    systemctl stop tor@default 2>/dev/null || systemctl stop tor 2>/dev/null || true

    # Remove packages if requested
    if [[ "${rm_pkgs^^}" == "Y" ]]; then
        apt-get remove -y tor redsocks obfs4proxy 2>/dev/null || true
        apt-get autoremove -y 2>/dev/null || true
        log "Packages removed"
    fi

    # Remove global command
    rm -f /usr/local/bin/tg-tor-proxy

    log "tg-tor-proxy fully removed"
    info "Команда 'tg-tor-proxy' удалена"
}

# ─────────────────────────────────────────────────────────────────────────────
# DIAGNOSTICS
# ─────────────────────────────────────────────────────────────────────────────
cmd_diagnose() {
    require_root

    echo ""
    echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════╗"
    echo -e "║   tg-tor-proxy v${VERSION} — Diagnostics   ║"
    echo -e "╚══════════════════════════════════════════╝${NC}"
    echo ""

    # ── Services ──────────────────────────────────────────────────────────
    hdr "Services"
    for svc in tor@default redsocks tg-tor-routes tg-tor-bootstrap tg-tor-proxy; do
        local status
        status=$(systemctl is-active "$svc" 2>/dev/null; true)
        case "$status" in
            active)   echo -e "  ${GREEN}●${NC} $svc — active" ;;
            inactive) echo -e "  ${YELLOW}●${NC} $svc — inactive" ;;
            "")       echo -e "  ${RED}●${NC} $svc — not found" ;;
            *)        echo -e "  ${RED}●${NC} $svc — $status" ;;
        esac
    done

    # ── Tor bootstrap ─────────────────────────────────────────────────────
    hdr "Tor Status"
    local pct mode_line
    pct=$(tor_bootstrap_pct 2>/dev/null || echo "N/A")
    echo -e "  Bootstrap: ${BOLD}${pct}%${NC}"

    if [ -f "$CONFIG_FILE" ]; then
        mode_line=$(grep mode "$CONFIG_FILE" 2>/dev/null || echo "mode=unknown")
        echo -e "  Mode: ${BOLD}${mode_line#mode=}${NC}"
    fi

    if [ "$pct" = "100" ]; then
        # Test Tor SOCKS
        local tor_ip
        tor_ip=$(curl -s --connect-timeout 10 \
            --socks5-hostname "127.0.0.1:$TOR_PORT" \
            https://check.torproject.org/api/ip 2>/dev/null \
            | grep -oP '"IP":"\K[^"]+' || echo "test failed")
        echo -e "  Tor exit IP: ${BOLD}$tor_ip${NC}"

        # Telegram connectivity via Tor
        local tg_test
        tg_test=$(curl -s --connect-timeout 10 \
            --socks5-hostname "127.0.0.1:$TOR_PORT" \
            -o /dev/null -w "%{http_code}" \
            "https://149.154.167.51" -k 2>/dev/null || echo "0")
        if [ "$tg_test" != "0" ]; then
            echo -e "  Telegram via Tor: ${GREEN}reachable (HTTP $tg_test)${NC}"
        else
            echo -e "  Telegram via Tor: ${YELLOW}no HTTP response (normal for Telegram)${NC}"
        fi
    else
        echo -e "  ${YELLOW}Tor not fully bootstrapped${NC}"
        journalctl -u tor@default --no-pager -n 5 2>/dev/null | grep -E 'Bootstrap|warn|err' | \
            sed 's/^/  /' || true
    fi

    # Bridges info
    if [ -f "$TORRC" ] && grep -q "UseBridges 1" "$TORRC"; then
        echo ""
        echo -e "  Configured bridges:"
        grep "^Bridge" "$TORRC" 2>/dev/null | while read -r b; do
            echo "    $(echo "$b" | cut -c1-70)"
        done
    fi

    # ── Redsocks ──────────────────────────────────────────────────────────
    hdr "Redsocks"
    local rs_connections
    rs_connections=$(ss -tn | grep -c ":$REDSOCKS_PORT" 2>/dev/null || echo "0")
    echo -e "  Active connections: ${BOLD}$rs_connections${NC}"

    local rs_listen
    rs_listen=$(ss -tlnp | grep ":$REDSOCKS_PORT" | head -1 | awk '{print $4}')
    echo -e "  Listening on: ${rs_listen:-not listening}"

    # Recent Telegram sessions
    echo "  Recent Telegram sessions (last 10):"
    local sessions
    sessions=$(journalctl -t redsocks --no-pager -n 200 2>/dev/null \
        | grep 'accepted' | tail -10 \
        | grep -oP '\[\K[^\]]+(?=\]: accepted)' || true)
    if [ -n "$sessions" ]; then
        echo "$sessions" | sed 's/^/    /'
    else
        echo "    (no sessions yet)"
    fi

    # ── iptables ──────────────────────────────────────────────────────────
    hdr "iptables Rules"
    local rule_count
    rule_count=$(iptables_cmd -t nat -L TELEGRAM_TOR -n 2>/dev/null | wc -l || echo "0")
    if [ "$rule_count" -gt 2 ]; then
        echo -e "  TELEGRAM_TOR chain: ${GREEN}active (${rule_count} lines)${NC}"
        local prerouting
        prerouting=$(iptables_cmd -t nat -L PREROUTING -n 2>/dev/null | grep TELEGRAM_TOR | head -1)
        [ -n "$prerouting" ] && echo -e "  PREROUTING: ${GREEN}linked${NC}" || echo -e "  PREROUTING: ${RED}NOT linked!${NC}"
    else
        echo -e "  TELEGRAM_TOR chain: ${RED}NOT active${NC}"
    fi

    # ── Docker networks ───────────────────────────────────────────────────
    hdr "Docker / VPN Containers"
    if command -v docker &>/dev/null; then
        docker ps --format '  {{.Names}}\t{{.Image}}\t{{.Status}}' 2>/dev/null | \
            grep -iE 'amnezia|awg|xray|v2ray|sing|outline|Names' || \
            echo "  (no matching VPN containers running)"
    else
        echo "  Docker not available"
    fi

    if [ -f "$NETWORKS_FILE" ]; then
        echo "  Intercepted networks:"
        sed 's/^/    /' "$NETWORKS_FILE"
    fi

    # ── Live connectivity test ────────────────────────────────────────────
    hdr "Connectivity Tests"

    # Tor working check — get exit IP via check.torproject.org
    if [ "$pct" = "100" ]; then
        local tor_ip
        tor_ip=$(curl -s --connect-timeout 15 \
            --socks5-hostname "127.0.0.1:$TOR_PORT" \
            "https://check.torproject.org/api/ip" 2>/dev/null \
            | grep -oP '"IP":"\K[^"]+' || true)
        if [ -n "$tor_ip" ]; then
            echo -e "  Tor SOCKS5: ${GREEN}working${NC} (exit IP: ${tor_ip})"
        else
            echo -e "  Tor SOCKS5: ${RED}no response${NC} (Tor bootstrapped but SOCKS5 unreachable)"
        fi
    else
        echo -e "  Tor SOCKS5: ${YELLOW}not ready${NC} (bootstrap: ${pct}%)"
    fi

    # iptables interception check
    local chain_lines
    chain_lines=$(iptables_cmd -t nat -L TELEGRAM_TOR 2>/dev/null | wc -l || echo 0)
    if [ "$chain_lines" -gt 5 ]; then
        echo -e "  iptables TELEGRAM_TOR: ${GREEN}active${NC} (${chain_lines} rules) — VPN client traffic intercepted"
    else
        echo -e "  iptables TELEGRAM_TOR: ${RED}missing${NC} — run: tg-tor-proxy --apply-rules"
    fi

    # Redsocks port check
    if ss -tlnp 2>/dev/null | grep -q ":${REDSOCKS_PORT}"; then
        echo -e "  Redsocks :${REDSOCKS_PORT}: ${GREEN}listening${NC}"
    else
        echo -e "  Redsocks :${REDSOCKS_PORT}: ${RED}not listening${NC}"
    fi

    echo ""
    echo -e "${BOLD}Useful commands:${NC}"
    echo -e "  journalctl -t redsocks -f          — live session log"
    echo -e "  journalctl -u tor@default -f       — Tor log"
    echo -e "  $0 --add-bridges                   — update bridges"
    echo -e "  $0 --check-tor                     — retest Tor"
    echo ""
}

# ─────────────────────────────────────────────────────────────────────────────
# ADD/UPDATE BRIDGES
# ─────────────────────────────────────────────────────────────────────────────
cmd_add_bridges() {
    local bridges_arg="${1:-}"

    require_root
    hdr "Updating bridges"

    # Backup old bridges
    [ -f "$BRIDGES_FILE" ] && cp "$BRIDGES_FILE" "${BRIDGES_FILE}.bak"

    if [ -n "$bridges_arg" ]; then
        mkdir -p "$CONFIG_DIR"
        # Handle bridges that may or may not start with "Bridge "
        echo "$bridges_arg" | while IFS= read -r line; do
            [ -z "$line" ] && continue
            if echo "$line" | grep -q "^Bridge "; then
                echo "$line"
            else
                echo "Bridge $line"
            fi
        done > "$BRIDGES_FILE"
        log "Bridges updated from argument"
    else
        prompt_bridges ""
    fi

    if [ ! -f "$BRIDGES_FILE" ] || [ ! -s "$BRIDGES_FILE" ]; then
        die "No bridges were saved"
    fi

    log "Applying new bridge configuration..."
    configure_tor_bridges "$BRIDGES_FILE"

    info "Waiting for Tor to bootstrap with new bridges..."
    if wait_tor_bootstrap "$BRIDGE_BOOTSTRAP_TIMEOUT" 999 true "$BRIDGE_STUCK_SIGHUP"; then
        local tor_ip
        tor_ip=$(curl -s --connect-timeout 15 \
            --socks5-hostname "127.0.0.1:$TOR_PORT" \
            https://check.torproject.org/api/ip 2>/dev/null \
            | grep -oP '"IP":"\K[^"]+' || echo "unknown")
        log "Tor working with new bridges! Exit IP: $tor_ip"
        echo "mode=bridges" > "$CONFIG_FILE"
    else
        warn "Bootstrap timeout. Tor may still connect in background."
        warn "Run '$0 --diagnose' to check status."
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# ADD BRIDGES FROM FILE
# ─────────────────────────────────────────────────────────────────────────────
cmd_add_bridges_file() {
    local filepath="$1"
    require_root

    [ -f "$filepath" ] || die "File not found: $filepath"

    hdr "Loading bridges from file: $filepath"
    mkdir -p "$CONFIG_DIR"

    # Process file — allow both "Bridge obfs4 ..." and "obfs4 ..." formats
    local count=0
    > "$BRIDGES_FILE"
    while IFS= read -r line; do
        line="${line#"${line%%[![:space:]]*}"}"  # trim leading whitespace
        [ -z "$line" ] && continue
        [[ "$line" == "#"* ]] && continue
        if echo "$line" | grep -q "^Bridge "; then
            echo "$line" >> "$BRIDGES_FILE"
        else
            echo "Bridge $line" >> "$BRIDGES_FILE"
        fi
        count=$((count + 1))
    done < "$filepath"

    log "$count bridge(s) loaded from file"
    cmd_add_bridges ""
}

# ─────────────────────────────────────────────────────────────────────────────
# CHECK TOR ONLY
# ─────────────────────────────────────────────────────────────────────────────
cmd_check_tor() {
    require_root
    hdr "Checking Tor connectivity"

    local pct
    pct=$(tor_bootstrap_pct 2>/dev/null || echo "0")
    echo -e "Current bootstrap: ${BOLD}${pct}%${NC}"

    if [ "$pct" != "100" ]; then
        warn "Tor not at 100%. Current state:"
        journalctl -u tor@default --no-pager -n 10 2>/dev/null | \
            grep -E 'Bootstrap|warn|error' | tail -5 || true

        echo ""
        read -rp "Try to force bootstrap via SIGHUP? [Y/n]: " ans
        ans=${ans:-Y}
        if [[ "${ans^^}" == "Y" ]]; then
            local tor_pid
            tor_pid=$(systemctl show tor@default --property=MainPID --value 2>/dev/null || echo "0")
            [ "$tor_pid" != "0" ] && kill -HUP "$tor_pid" 2>/dev/null && info "SIGHUP sent"
            wait_tor_bootstrap 60 999 false
            pct=$(tor_bootstrap_pct 2>/dev/null || echo "0")
        fi
    fi

    if [ "$pct" = "100" ]; then
        local tor_ip
        tor_ip=$(curl -s --connect-timeout 15 \
            --socks5-hostname "127.0.0.1:$TOR_PORT" \
            https://check.torproject.org/api/ip 2>/dev/null \
            | grep -oP '"IP":"\K[^"]+' || echo "failed")
        if [ "$tor_ip" != "failed" ] && [ -n "$tor_ip" ]; then
            log "Tor is working! Exit IP: ${BOLD}$tor_ip${NC}"
        else
            err "Tor at 100% but SOCKS5 proxy not responding"
        fi
    else
        err "Tor bootstrap failed (at ${pct}%)"
        echo ""
        echo "If Tor is consistently blocked, add obfs4 bridges:"
        echo -e "  ${CYAN}$0 --add-bridges${NC}"
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────
usage() {
    cat << EOF
${BOLD}tg-tor-proxy v${VERSION}${NC} — Route Telegram through Tor for VPN clients

${BOLD}Usage:${NC}
  $(basename "$0") [OPTION] [ARGUMENT]

${BOLD}Options:${NC}
  (none) / --install            Detect containers, setup Tor+Redsocks+iptables
  --remove                      Remove all rules, configs, and services
  --diagnose                    Full diagnostic report
  --check-tor                   Test Tor connectivity
  --add-bridges [BRIDGE_LINE]   Add/replace obfs4 bridges (interactive or inline)
  --add-bridges-file FILE       Load bridges from a text file
  --help, -h                    Show this help

${BOLD}Examples:${NC}
  # Fresh install (auto-detects containers):
  sudo $(basename "$0")

  # Add bridges interactively:
  sudo $(basename "$0") --add-bridges

  # Add bridges inline:
  sudo $(basename "$0") --add-bridges "obfs4 1.2.3.4:1234 FINGERPRINT cert=... iat-mode=0"

  # Load bridges from file:
  sudo $(basename "$0") --add-bridges-file /tmp/my_bridges.txt

  # Full status report:
  sudo $(basename "$0") --diagnose

  # Clean removal:
  sudo $(basename "$0") --remove

${BOLD}Bridge format:${NC}
  obfs4 IP:PORT FINGERPRINT cert=BASE64_CERT iat-mode=0
  (The 'Bridge ' prefix is optional — the script handles both)

${BOLD}Get bridges:${NC}
  https://bridges.torproject.org/?transport=obfs4   (from unblocked device)
  Email: bridges@torproject.org   (subject: get transport obfs4)
EOF
}

# ─────────────────────────────────────────────────────────────────────────────
# INTERACTIVE MENU
# ─────────────────────────────────────────────────────────────────────────────
show_menu() {
    # Quick one-line status for menu header
    local tor_status redsocks_status rules_status tor_pct
    tor_status=$(systemctl is-active tor@default 2>/dev/null; true)
    redsocks_status=$(systemctl is-active redsocks 2>/dev/null; true)
    tor_pct=$(tor_bootstrap_pct 2>/dev/null || echo "?")

    local rules_ok="no"
    iptables_cmd -t nat -L TELEGRAM_TOR -n &>/dev/null && rules_ok="yes"

    local mode="—"
    [ -f "$CONFIG_FILE" ] && mode=$(grep mode "$CONFIG_FILE" 2>/dev/null | cut -d= -f2 || echo "—")

    clear 2>/dev/null || true
    echo ""
    echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════════╗"
    echo -e "║   tg-tor-proxy  v${VERSION}                    ║"
    echo -e "║   Telegram через Tor для VPN-клиентов        ║"
    echo -e "╚══════════════════════════════════════════════╝${NC}"
    echo ""

    # Status line
    local tor_icon redsocks_icon rules_icon
    [ "$tor_status"      = "active" ] && tor_icon="${GREEN}●${NC}" || tor_icon="${RED}●${NC}"
    [ "$redsocks_status" = "active" ] && redsocks_icon="${GREEN}●${NC}" || redsocks_icon="${RED}●${NC}"
    [ "$rules_ok"        = "yes"   ] && rules_icon="${GREEN}●${NC}" || rules_icon="${RED}●${NC}"

    echo -e "  Tor ${tor_icon} ${tor_pct}% (${mode})   Redsocks ${redsocks_icon}   iptables ${rules_icon}"
    echo ""
    echo -e "${BOLD}  Выберите действие:${NC}"
    echo ""
    echo -e "  ${CYAN}1)${NC}  Установить / настроить заново"
    echo -e "  ${CYAN}2)${NC}  Диагностика (полный отчёт)"
    echo -e "  ${CYAN}3)${NC}  Проверить Tor"
    echo -e "  ${CYAN}4)${NC}  Добавить / заменить мосты (obfs4 bridges)"
    echo -e "  ${CYAN}5)${NC}  Загрузить мосты из файла"
    echo -e "  ${CYAN}6)${NC}  Применить iptables правила (если слетели)"
    echo -e "  ${CYAN}7)${NC}  Показать активные Telegram-сессии (live)"
    echo -e "  ${RED}8)${NC}  Удалить всё (deinstall)"
    echo -e "  ${CYAN}0)${NC}  Выход"
    echo ""
}

interactive_menu() {
    require_root

    while true; do
        show_menu
        read -rp "  Ваш выбор [0-8]: " choice
        echo ""

        case "$choice" in
            1)
                cmd_install ""
                echo ""
                read -rp "  Нажмите Enter для возврата в меню..." _dummy
                ;;
            2)
                cmd_diagnose
                echo ""
                read -rp "  Нажмите Enter для возврата в меню..." _dummy
                ;;
            3)
                cmd_check_tor
                echo ""
                read -rp "  Нажмите Enter для возврата в меню..." _dummy
                ;;
            4)
                hdr "Добавление мостов"
                echo ""
                echo -e "${CYAN}Вставьте строки мостов (по одной на строку).${NC}"
                echo "Формат: obfs4 IP:PORT FINGERPRINT cert=... iat-mode=0"
                echo "(можно без префикса 'Bridge ' — скрипт добавит сам)"
                echo "Пустая строка — завершить ввод."
                echo ""
                local bridges_input=()
                while IFS= read -r line; do
                    [ -z "$line" ] && break
                    bridges_input+=("$line")
                done
                if [ ${#bridges_input[@]} -gt 0 ]; then
                    local joined
                    joined=$(printf '%s\n' "${bridges_input[@]}")
                    cmd_add_bridges "$joined"
                else
                    warn "Мосты не введены"
                fi
                echo ""
                read -rp "  Нажмите Enter для возврата в меню..." _dummy
                ;;
            5)
                hdr "Загрузка мостов из файла"
                read -rp "  Путь к файлу с мостами: " bridges_file
                if [ -f "$bridges_file" ]; then
                    cmd_add_bridges_file "$bridges_file"
                else
                    err "Файл не найден: $bridges_file"
                fi
                echo ""
                read -rp "  Нажмите Enter для возврата в меню..." _dummy
                ;;
            6)
                hdr "Применение iptables правил"
                if [ -x "$ROUTES_SCRIPT" ]; then
                    bash "$ROUTES_SCRIPT" stop 2>/dev/null || true
                    bash "$ROUTES_SCRIPT" start
                    log "Правила применены"
                else
                    warn "Скрипт правил не найден: $ROUTES_SCRIPT"
                    warn "Запустите установку (пункт 1)"
                fi
                echo ""
                read -rp "  Нажмите Enter для возврата в меню..." _dummy
                ;;
            7)
                hdr "Активные Telegram-сессии (Ctrl+C для выхода)"
                echo -e "${CYAN}Формат: клиент:порт → Telegram_IP:порт${NC}"
                echo ""
                journalctl -t redsocks -f --no-pager 2>/dev/null | \
                    grep --line-buffered 'accepted\|closed' | \
                    grep -oP '\[\K[^\]]+(?=\]: (accepted|closed))' | \
                    sed 's/^/  /' || true
                echo ""
                read -rp "  Нажмите Enter для возврата в меню..." _dummy
                ;;
            8)
                cmd_remove
                echo ""
                read -rp "  Нажмите Enter для возврата в меню..." _dummy
                ;;
            0|q|Q|exit|quit)
                echo -e "  ${GREEN}Выход.${NC}"
                exit 0
                ;;
            *)
                warn "Неверный выбор: '$choice'"
                ;;
        esac
    done
}

# ─────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# When run without args → interactive menu
# When run with args   → direct command (для CI/скриптов)
# ─────────────────────────────────────────────────────────────────────────────
main() {
    local cmd="${1:-}"
    local arg="${2:-}"

    # No arguments → interactive menu
    if [ -z "$cmd" ]; then
        interactive_menu
        return
    fi

    # With arguments → direct mode (удобно для автоматизации)
    case "$cmd" in
        --install|-i)
            require_root; cmd_install "$arg"
            ;;
        --remove|--uninstall|-r)
            require_root; cmd_remove
            ;;
        --diagnose|--status|-d|-s)
            require_root; cmd_diagnose
            ;;
        --check-tor|-t)
            require_root; cmd_check_tor
            ;;
        --add-bridges|-b)
            require_root; cmd_add_bridges "$arg"
            ;;
        --add-bridges-file)
            [ -n "$arg" ] || die "Укажите путь: $0 --add-bridges-file /путь/к/файлу"
            require_root; cmd_add_bridges_file "$arg"
            ;;
        --apply-rules)
            require_root
            [ -x "$ROUTES_SCRIPT" ] || die "Скрипт правил не найден. Запустите установку."
            bash "$ROUTES_SCRIPT" stop 2>/dev/null; bash "$ROUTES_SCRIPT" start
            ;;
        --help|-h|help)
            cat << EOF

${BOLD}tg-tor-proxy v${VERSION}${NC} — Telegram через Tor для VPN-клиентов

Без аргументов запускается интерактивное меню.

${BOLD}Прямые команды (для автоматизации):${NC}
  --install                     Установить / настроить
  --remove                      Удалить всё
  --diagnose                    Диагностический отчёт
  --check-tor                   Проверить Tor
  --add-bridges [СТРОКА]        Добавить мосты (интерактивно или строкой)
  --add-bridges-file ФАЙЛ       Загрузить мосты из файла
  --apply-rules                 Применить iptables правила заново
  --help                        Эта справка

${BOLD}Формат моста:${NC}
  obfs4 IP:PORT ОТПЕЧАТОК cert=... iat-mode=0

${BOLD}Получить мосты (с другого устройства/сети):${NC}
  https://bridges.torproject.org/?transport=obfs4
  Email: bridges@torproject.org  (тема: get transport obfs4)
EOF
            ;;
        *)
            err "Неизвестная команда: $cmd"
            echo "  Запустите без аргументов для меню, или с --help для справки."
            exit 1
            ;;
    esac
}

main "$@"
