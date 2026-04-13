#!/bin/bash
# =============================================================================
# tg-tor-proxy.sh — Route Telegram through Tor for AmneziaWG / Xray VPN clients
# Version: 2.1.8
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
readonly VERSION="2.2.4"
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
# Multi-tor ports: inst0=9050/12345, inst1=9052/12346, inst2=9053/12347
readonly TOR_PORTS=(9050 9052 9053)
readonly RS_PORTS=(12345 12346 12347)
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
    "185.76.151.0/24" "188.166.0.0/17"  "192.178.0.0/15"  "199.232.0.1/16"
    "204.212.0.1/14"  "209.85.128.0/17" "209.97.0.0/18"   "213.180.193.0/24"
    "216.58.192.0/19" "34.192.0.1/10"   "34.64.0.0/10"    "35.184.0.0/13"
    "35.224.0.0/12"   "35.240.0.0/13"   "40.96.0.0/12"    "44.192.0.1/10"
    "50.128.0.0/9"    "52.96.0.0/12"    "64.233.160.0/19" "66.102.0.1/20"
    "66.151.176.0/20" "74.125.0.0/16"   "8.0.0.0/13"      "8.32.0.1/11"
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

# Bootstrap % for a specific tor instance (by index)
tor_bootstrap_pct_inst() {
    local idx="$1"
    local sock="/run/tor/inst${idx}/control"
    local cookie="/run/tor/inst${idx}/control.authcookie"
    python3 -c "
import socket, re
try:
    with open('${cookie}', 'rb') as f:
        c = f.read().hex()
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect('${sock}')
    s.send(f'AUTHENTICATE {c}\r\n'.encode())
    s.recv(200)
    s.send(b'GETINFO status/bootstrap-phase\r\n')
    r = s.recv(500).decode()
    s.close()
    m = re.search(r'PROGRESS=(\d+)', r)
    print(m.group(1) if m else '0')
except:
    print('0')
" 2>/dev/null || echo "0"
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
    # iptables-persistent — сохраняет правила iptables между перезагрузками
    dpkg -l netfilter-persistent &>/dev/null || pkgs+=(netfilter-persistent iptables-persistent)

    if [ ${#pkgs[@]} -gt 0 ]; then
        info "Installing: ${pkgs[*]}"
        apt-get update -qq 2>/dev/null
        # Предотвращаем интерактивный диалог iptables-persistent
        echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections 2>/dev/null || true
        echo iptables-persistent iptables-persistent/autosave_v6 boolean false | debconf-set-selections 2>/dev/null || true
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${pkgs[@]}" 2>/dev/null
        log "Packages installed"
    else
        log "All packages already installed"
    fi
}

save_iptables_rules() {
    if command -v netfilter-persistent &>/dev/null; then
        netfilter-persistent save &>/dev/null || true
    elif command -v iptables-save &>/dev/null; then
        local savefile="/etc/iptables/rules.v4"
        mkdir -p /etc/iptables
        iptables-save > "$savefile" || true
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
# ─────────────────────────────────────────────────────────────────────────────
# MULTI-TOR SETUP
# ─────────────────────────────────────────────────────────────────────────────
get_tor_instances() {
    local count
    count=$(grep '^tor_instances=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2)
    echo "${count:-1}"
}

configure_tor_instance() {
    local idx="$1"        # 0, 1, 2
    local mode="$2"       # direct | bridges
    local bridges_file="${3:-}"
    local socks_port="${TOR_PORTS[$idx]}"
    local data_dir="/var/lib/tor/inst${idx}"
    local run_dir="/run/tor/inst${idx}"
    local torrc_file="/etc/tor/torrc.inst${idx}"
    local control_sock="${run_dir}/control"

    mkdir -p "$data_dir" "$run_dir"
    chown debian-tor:debian-tor "$data_dir" "$run_dir" 2>/dev/null || true
    chmod 700 "$data_dir"

    {
        echo "## tg-tor-proxy instance ${idx}"
        echo "SocksPort 127.0.0.1:${socks_port}"
        echo "DataDirectory ${data_dir}"
        echo "PidFile ${run_dir}/tor.pid"
        echo "ControlSocket ${control_sock} GroupWritable RelaxDirModeCheck"
        echo "CookieAuthentication 1"
        echo "CookieAuthFile ${run_dir}/control.authcookie"
        echo "Log notice syslog"
        echo "# Circuit stability"
        echo "CircuitBuildTimeout 30"
        echo "LearnCircuitBuildTimeout 0"
        echo "MaxCircuitDirtiness 600"
        echo "NumEntryGuards 4"
        echo "NewCircuitPeriod 15"
        echo "MaxClientCircuitsPending 128"
        echo "KeepalivePeriod 30"
        echo "# Latency optimizations"
        echo "## OptimisticData removed (obsolete in Tor >= 0.4.x)"
        echo "CircuitStreamTimeout 15"
        if [ "$mode" = "bridges" ] && [ -f "$bridges_file" ]; then
            grep -q "^Bridge obfs4" "$bridges_file" && \
                echo "ClientTransportPlugin obfs4 exec /usr/bin/obfs4proxy"
            echo "UseBridges 1"
            grep -v '^#' "$bridges_file" | grep -v '^$' | while read -r line; do
                echo "$line" | grep -q "^Bridge " && echo "$line" || echo "Bridge $line"
            done
        fi
    } > "$torrc_file"

    # Systemd service for this instance
    cat > "/etc/systemd/system/tg-tor-inst${idx}.service" << EOF
[Unit]
Description=Tor instance ${idx} for tg-tor-proxy
After=network.target
[Service]
Type=notify
User=debian-tor
ExecStartPre=/usr/bin/tor --verify-config -f ${torrc_file}
ExecStart=/usr/bin/tor -f ${torrc_file}
ExecReload=/bin/kill -HUP \${MAINPID}
Restart=always
RestartSec=10
LimitNOFILE=65536
[Install]
WantedBy=multi-user.target
EOF

    # Redsocks config for this instance
    cat > "/etc/redsocks.conf.inst${idx}" << EOF
base {
    log_debug = off;
    log_info = on;
    log = "syslog:daemon";
    daemon = off;
    user = redsocks;
    group = redsocks;
    redirector = iptables;
}
redsocks {
    local_ip = 0.0.0.0;
    local_port = ${RS_PORTS[$idx]};
    ip = 127.0.0.1;
    port = ${socks_port};
    type = socks5;
}
EOF

    # Redsocks service for this instance
    cat > "/etc/systemd/system/redsocks-inst${idx}.service" << EOF
[Unit]
Description=Redsocks instance ${idx} for tg-tor-proxy
After=tg-tor-inst${idx}.service
[Service]
Type=simple
ExecStart=/usr/sbin/redsocks -c /etc/redsocks.conf.inst${idx}
Restart=always
RestartSec=5
LimitNOFILE=65536
[Install]
WantedBy=multi-user.target
EOF
}

start_tor_instances() {
    local count="$1"
    systemctl daemon-reload
    for ((i=0; i<count; i++)); do
        systemctl enable --now "tg-tor-inst${i}" 2>/dev/null || true
        systemctl enable --now "redsocks-inst${i}" 2>/dev/null || true
        log "Started tor instance ${i} (SOCKS :${TOR_PORTS[$i]}, redsocks :${RS_PORTS[$i]})"
    done
}

stop_tor_instances() {
    for i in 0 1 2; do
        systemctl stop "tg-tor-inst${i}" 2>/dev/null || true
        systemctl disable "tg-tor-inst${i}" 2>/dev/null || true
        systemctl stop "redsocks-inst${i}" 2>/dev/null || true
        systemctl disable "redsocks-inst${i}" 2>/dev/null || true
        rm -f "/etc/systemd/system/tg-tor-inst${i}.service"
        rm -f "/etc/systemd/system/redsocks-inst${i}.service"
        rm -f "/etc/tor/torrc.inst${i}"
        rm -f "/etc/redsocks.conf.inst${i}"
    done
    systemctl daemon-reload 2>/dev/null || true
}

configure_tor_direct() {
    cat > "$TORRC" << 'TOREOF'
## Managed by tg-tor-proxy
SocksPort 9050
Log notice syslog
# Circuit stability
CircuitBuildTimeout 30
LearnCircuitBuildTimeout 0
MaxCircuitDirtiness 600
NumEntryGuards 4
NewCircuitPeriod 15
MaxClientCircuitsPending 128
KeepalivePeriod 30
# Latency optimizations
## OptimisticData removed (obsolete in Tor >= 0.4.x)
CircuitStreamTimeout 15
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
        echo "CircuitBuildTimeout 30"
        echo "LearnCircuitBuildTimeout 0"
        echo "MaxCircuitDirtiness 600"
        echo "NumEntryGuards 4"
        echo "NewCircuitPeriod 15"
        echo "MaxClientCircuitsPending 128"
        echo "KeepalivePeriod 30"
        echo "# Latency optimizations"
        echo "## OptimisticData removed (obsolete in Tor >= 0.4.x)"
        echo "CircuitStreamTimeout 15"
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

# Wait for a specific tor instance to bootstrap (used in multi-instance mode)
wait_tor_instance_bootstrap() {
    local idx="$1"
    local max_wait="${2:-$BRIDGE_BOOTSTRAP_TIMEOUT}"
    local use_sighup="${3:-false}"

    local elapsed=0 interval=5 last_pct=-1 stuck_for=0 sighup_for=0

    info "Ожидаю bootstrap инстанса ${idx} (max ${max_wait}s)..."

    while [ $elapsed -lt $max_wait ]; do
        local pct
        pct=$(tor_bootstrap_pct_inst "$idx" 2>/dev/null || echo "0")
        pct=${pct:-0}

        local bar_len=30 filled=$(( pct * 30 / 100 )) bar=""
        for ((i=0; i<filled; i++)); do bar+="█"; done
        for ((i=filled; i<bar_len; i++)); do bar+="░"; done
        printf "\r  [inst%d] [%s] %3d%% (%ds)" "$idx" "$bar" "$pct" "$elapsed"

        if [ "$pct" -eq 100 ]; then
            echo ""
            log "Инстанс ${idx} загрузился!"
            return 0
        fi

        if [ "$pct" -eq "$last_pct" ]; then
            stuck_for=$((stuck_for + interval))
            sighup_for=$((sighup_for + interval))
            if $use_sighup && [ $sighup_for -ge "$BRIDGE_STUCK_SIGHUP" ]; then
                echo ""
                local pid
                pid=$(systemctl show "tg-tor-inst${idx}" --property=MainPID --value 2>/dev/null || echo "0")
                [ "$pid" != "0" ] && kill -HUP "$pid" 2>/dev/null || true
                info "SIGHUP → inst${idx} (застрял на ${pct}%)"
                sighup_for=0
            fi
        else
            stuck_for=0; sighup_for=0; last_pct=$pct
        fi

        sleep $interval
        elapsed=$((elapsed + interval))
    done

    echo ""
    warn "Инстанс ${idx} не загрузился за ${max_wait}s (на ${last_pct}%)"
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

    local tor_count="${1:-1}"

    cat > "$ROUTES_SCRIPT" << 'HEREDOC'
#!/bin/bash
# Managed by tg-tor-proxy — do not edit manually
TOR_COUNT=TOR_COUNT_PLACEHOLDER
RS_PORTS=(RS_PORTS_PLACEHOLDER)

TELEGRAM_NETS="
TELEGRAM_NETS_PLACEHOLDER
"

IPT() { iptables-legacy "$@" 2>/dev/null || iptables "$@" 2>/dev/null; }

flush_rules() {
    IPT -t nat -F TELEGRAM_TOR 2>/dev/null
    IPT -t nat -D PREROUTING -j TELEGRAM_TOR 2>/dev/null
    IPT -t nat -X TELEGRAM_TOR 2>/dev/null
    for i in 0 1 2; do
        IPT -t nat -F "TELEGRAM_TOR_${i}" 2>/dev/null
        IPT -t nat -X "TELEGRAM_TOR_${i}" 2>/dev/null
    done
    # Remove redsocks port protection rules
    for port in "${RS_PORTS[@]}"; do
        for net in 127.0.0.0/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16; do
            IPT -D INPUT -p tcp --dport "$port" -s "$net" -j ACCEPT 2>/dev/null || true
        done
        IPT -D INPUT -p tcp --dport "$port" -j DROP 2>/dev/null || true
    done
    return 0
}

protect_redsocks_ports() {
    # Block external access to redsocks ports — allow only private/docker ranges
    for port in "${RS_PORTS[@]}"; do
        for net in 127.0.0.0/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16; do
            IPT -C INPUT -p tcp --dport "$port" -s "$net" -j ACCEPT 2>/dev/null || \
            IPT -I INPUT -p tcp --dport "$port" -s "$net" -j ACCEPT
        done
        IPT -C INPUT -p tcp --dport "$port" -j DROP 2>/dev/null || \
        IPT -A INPUT -p tcp --dport "$port" -j DROP
    done
}

add_rules() {
    IPT -t nat -N TELEGRAM_TOR 2>/dev/null || true

    # Skip bogon destinations
    for bogon in 0.0.0.0/8 10.0.0.0/8 127.0.0.0/8 169.254.0.0/16 \
                 192.168.0.0/16 224.0.0.0/4 240.0.0.0/4; do
        IPT -t nat -A TELEGRAM_TOR -d "$bogon" -j RETURN
    done

    if [ "$TOR_COUNT" -eq 1 ]; then
        # Single instance — direct redirect
        for net in $TELEGRAM_NETS; do
            [ -z "$net" ] && continue
            IPT -t nat -A TELEGRAM_TOR -p tcp -d "$net" \
                -j REDIRECT --to-ports "${RS_PORTS[0]}"
        done
    else
        # Multiple instances — round-robin via statistic module
        for net in $TELEGRAM_NETS; do
            [ -z "$net" ] && continue
            for ((i=0; i<TOR_COUNT; i++)); do
                remaining=$((TOR_COUNT - i))
                if [ $remaining -eq 1 ]; then
                    # Last one gets all remaining
                    IPT -t nat -A TELEGRAM_TOR -p tcp -d "$net" \
                        -j REDIRECT --to-ports "${RS_PORTS[$i]}"
                else
                    IPT -t nat -A TELEGRAM_TOR -p tcp -d "$net" \
                        -m statistic --mode nth --every "$remaining" --packet 0 \
                        -j REDIRECT --to-ports "${RS_PORTS[$i]}"
                fi
            done
        done
    fi

    IPT -t nat -I PREROUTING -j TELEGRAM_TOR
}

case "${1:-}" in
    start) flush_rules; add_rules; protect_redsocks_ports; echo "Telegram → Tor rules applied (${TOR_COUNT} instance(s))" ;;
    stop)  flush_rules; echo "Telegram → Tor rules removed" ;;
    status)
        echo "=== TELEGRAM_TOR chain ==="
        IPT -t nat -L TELEGRAM_TOR -n --line-numbers 2>/dev/null || echo "Chain not found"
        ;;
    *) echo "Usage: $0 {start|stop|status}"; exit 1 ;;
esac
HEREDOC

    # Substitute placeholders
    local tg_nets_str
    tg_nets_str=$(printf '%s\n' "${TELEGRAM_NETS[@]}")
    local rs_ports_str="${RS_PORTS[*]:0:$tor_count}"

    sed -i "s|TOR_COUNT_PLACEHOLDER|${tor_count}|g" "$ROUTES_SCRIPT"
    sed -i "s|RS_PORTS_PLACEHOLDER|${rs_ports_str}|g" "$ROUTES_SCRIPT"

    python3 - "$ROUTES_SCRIPT" "$tg_nets_str" << 'PYEOF'
import sys
script_path, tg_nets = sys.argv[1], sys.argv[2]
with open(script_path) as f:
    content = f.read()
content = content.replace('TELEGRAM_NETS_PLACEHOLDER', tg_nets)
with open(script_path, 'w') as f:
    f.write(content)
PYEOF

    chmod +x "$ROUTES_SCRIPT"
    log "Routes script written: $ROUTES_SCRIPT (${tor_count} Tor instance(s))"
}

# ─────────────────────────────────────────────────────────────────────────────
# INSTALL SYSTEMD SERVICES
# ─────────────────────────────────────────────────────────────────────────────
install_systemd_services() {
    local tor_count_arg="${1:-1}"
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

    # Routes service — dependency varies by single vs multi-instance
    local tor_count_now="$tor_count_arg"
    local routes_after routes_wants
    if [ "$tor_count_now" -gt 1 ]; then
        routes_after="network.target tg-tor-inst0.service"
        routes_wants="tg-tor-inst0.service"
    else
        routes_after="network.target redsocks.service"
        routes_wants="redsocks.service"
    fi

    cat > /etc/systemd/system/tg-tor-routes.service << EOF
[Unit]
Description=Telegram → Tor iptables routes
After=${routes_after}
Wants=${routes_wants}

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
    local wd_after wd_wants
    if [ "$tor_count_now" -gt 1 ]; then
        wd_after="tg-tor-inst0.service"
        wd_wants="tg-tor-inst0.service"
    else
        wd_after="tor@default.service redsocks.service"
        wd_wants="tor@default.service"
    fi
    cat > /etc/systemd/system/tg-tor-watchdog.service << EOF
[Unit]
Description=Tor + Redsocks stability watchdog for tg-tor-proxy
After=${wd_after}
Wants=${wd_wants}

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
# BLOCK EXTERNAL ACCESS TO REDSOCKS PORTS
# Вызывается при apply_routes и из пункта 6 меню — независимо от routes-скрипта
# ─────────────────────────────────────────────────────────────────────────────
apply_redsocks_protection() {
    local protected=0
    for port in "${RS_PORTS[@]}"; do
        # Проверяем нет ли уже DROP правила для этого порта
        if iptables_cmd -C INPUT -p tcp --dport "$port" -j DROP &>/dev/null; then
            continue  # уже защищён
        fi
        for net in 127.0.0.0/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16; do
            iptables_cmd -C INPUT -p tcp --dport "$port" -s "$net" -j ACCEPT &>/dev/null || \
            iptables_cmd -I INPUT -p tcp --dport "$port" -s "$net" -j ACCEPT
        done
        iptables_cmd -A INPUT -p tcp --dport "$port" -j DROP
        protected=$((protected + 1))
    done
    [ $protected -gt 0 ] && log "Redsocks порты закрыты от внешнего доступа" || true
}

# ─────────────────────────────────────────────────────────────────────────────
# APPLY ROUTES (start iptables)
# ─────────────────────────────────────────────────────────────────────────────
apply_routes() {
    bash "$ROUTES_SCRIPT" start
    systemctl start tg-tor-routes 2>/dev/null || true
    apply_redsocks_protection
    save_iptables_rules
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

    # 6. Ask for number of Tor instances
    echo ""
    hdr "Количество Tor-инстансов"
    echo ""
    echo -e "  ${CYAN}1${NC} — один инстанс    (до 15 клиентов)"
    echo -e "  ${CYAN}2${NC} — два инстанса    (15-30 клиентов, рекомендуется)"
    echo -e "  ${CYAN}3${NC} — три инстанса    (30-40+ клиентов)"
    echo ""
    read -rp "  Выберите количество [1-3, Enter = 1]: " inst_choice
    local tor_instances=1
    case "${inst_choice:-1}" in
        2) tor_instances=2 ;;
        3) tor_instances=3 ;;
        *) tor_instances=1 ;;
    esac

    # Сохраняем в конфиг
    {
        grep -v '^tor_instances=' "$CONFIG_FILE" 2>/dev/null || true
        echo "tor_instances=${tor_instances}"
    } > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"

    if [ "$tor_instances" -gt 1 ]; then
        hdr "Настройка ${tor_instances} Tor-инстансов"

        # Отключаем системные сервисы — их порты займут инстансы
        systemctl stop tor@default redsocks 2>/dev/null || true
        systemctl disable tor@default redsocks 2>/dev/null || true

        local inst_mode
        inst_mode=$(grep '^mode=' "$CONFIG_FILE" | cut -d= -f2 || echo "direct")

        for ((i=0; i<tor_instances; i++)); do
            info "Настраиваю инстанс ${i} (SOCKS :${TOR_PORTS[$i]}, redsocks :${RS_PORTS[$i]})..."
            configure_tor_instance "$i" "$inst_mode" "$BRIDGES_FILE"
        done

        start_tor_instances "$tor_instances"

        # Ждём bootstrap только инстанса 0; остальные догонят в фоне
        local use_sig=false
        $use_bridges && use_sig=true
        wait_tor_instance_bootstrap 0 "$BRIDGE_BOOTSTRAP_TIMEOUT" "$use_sig" || \
            warn "Инстанс 0 не загрузился за ${BRIDGE_BOOTSTRAP_TIMEOUT}s — продолжаем"
    fi

    # 7. Setup iptables
    generate_routes_script "$tor_instances"
    apply_routes

    # 8. Install systemd
    install_systemd_services "$tor_instances"

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

    # Stop multi-instance Tor and Redsocks services
    stop_tor_instances

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

    # Remove multi-instance data directories
    for i in 0 1 2; do
        rm -rf "/var/lib/tor/inst${i}"
        rm -rf "/run/tor/inst${i}"
        rm -f "/etc/redsocks.conf.inst${i}"
        rm -f "/etc/tor/torrc.inst${i}"
    done

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
    local tor_instances
    tor_instances=$(get_tor_instances)

    print_svc_status() {
        local svc="$1"
        local status
        status=$(systemctl is-active "$svc" 2>/dev/null; true)
        case "$status" in
            active)   echo -e "  ${GREEN}●${NC} $svc — active" ;;
            inactive) echo -e "  ${YELLOW}●${NC} $svc — inactive" ;;
            "")       echo -e "  ${RED}●${NC} $svc — not found" ;;
            *)        echo -e "  ${RED}●${NC} $svc — $status" ;;
        esac
    }

    if [ "$tor_instances" -gt 1 ]; then
        for ((i=0; i<tor_instances; i++)); do
            print_svc_status "tg-tor-inst${i}"
            print_svc_status "redsocks-inst${i}"
        done
    else
        print_svc_status "tor@default"
        print_svc_status "redsocks"
    fi
    print_svc_status "tg-tor-routes"
    print_svc_status "tg-tor-watchdog"

    # ── Tor bootstrap ─────────────────────────────────────────────────────
    hdr "Tor Status"
    local pct mode_line
    if [ -f "$CONFIG_FILE" ]; then
        mode_line=$(grep '^mode=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2 || echo "unknown")
        echo -e "  Mode: ${BOLD}${mode_line}${NC}   Инстансов: ${BOLD}${tor_instances}${NC}"
    fi

    if [ "$tor_instances" -gt 1 ]; then
        local all_ready=true
        for ((i=0; i<tor_instances; i++)); do
            local ipct
            ipct=$(tor_bootstrap_pct_inst "$i" 2>/dev/null || echo "0")
            local color="${GREEN}"
            [ "$ipct" != "100" ] && color="${YELLOW}" && all_ready=false
            echo -e "  inst${i} bootstrap: ${color}${BOLD}${ipct}%${NC}  (SOCKS :${TOR_PORTS[$i]}, redsocks :${RS_PORTS[$i]})"
        done
        pct=$(tor_bootstrap_pct_inst 0 2>/dev/null || echo "0")
        if $all_ready; then
            # Показываем exit IP для каждого инстанса
            for ((i=0; i<tor_count; i++)); do
                local tor_ip
                tor_ip=$(curl -s --connect-timeout 10 \
                    --socks5-hostname "127.0.0.1:${TOR_PORTS[$i]}" \
                    https://check.torproject.org/api/ip 2>/dev/null \
                    | grep -oP '"IP":"\K[^"]+' || echo "недоступен")
                echo -e "  Tor exit IP (inst${i}): ${BOLD}${tor_ip}${NC}"
            done
        fi
    else
        pct=$(tor_bootstrap_pct 2>/dev/null || echo "N/A")
        echo -e "  Bootstrap: ${BOLD}${pct}%${NC}"

        if [ "$pct" = "100" ]; then
            local tor_ip
            tor_ip=$(curl -s --connect-timeout 10 \
                --socks5-hostname "127.0.0.1:$TOR_PORT" \
                https://check.torproject.org/api/ip 2>/dev/null \
                | grep -oP '"IP":"\K[^"]+' || echo "test failed")
            echo -e "  Tor exit IP: ${BOLD}$tor_ip${NC}"
        else
            echo -e "  ${YELLOW}Tor not fully bootstrapped${NC}"
            journalctl -u tor@default --no-pager -n 5 2>/dev/null | grep -E 'Bootstrap|warn|err' | \
                sed 's/^/  /' || true
        fi
    fi

    # Bridges info
    local bridges_torrc="$TORRC"
    [ "$tor_instances" -gt 1 ] && bridges_torrc="/etc/tor/torrc.inst0"
    if [ -f "$bridges_torrc" ] && grep -q "UseBridges 1" "$bridges_torrc"; then
        echo ""
        echo -e "  Configured bridges:"
        grep "^Bridge" "$bridges_torrc" 2>/dev/null | while read -r b; do
            echo "    $(echo "$b" | cut -c1-70)"
        done
    fi

    # ── Redsocks ──────────────────────────────────────────────────────────
    hdr "Redsocks"
    if [ "$tor_instances" -gt 1 ]; then
        local total_conns=0
        for ((i=0; i<tor_instances; i++)); do
            local rport="${RS_PORTS[$i]}"
            local conns rl
            conns=$(ss -tn 2>/dev/null | grep ":${rport}" | wc -l) || conns=0
            rl=$(ss -tlnp 2>/dev/null | grep ":${rport}" | head -1 | awk '{print $4}') || rl=""
            echo -e "  redsocks-inst${i} :${rport} — соединений: ${BOLD}${conns}${NC}  ${rl:-(не слушает)}"
            total_conns=$((total_conns + conns))
        done
        echo -e "  Всего соединений: ${BOLD}${total_conns}${NC}"
    else
        local rs_connections rs_listen
        rs_connections=$(ss -tn 2>/dev/null | grep ":$REDSOCKS_PORT" | wc -l) || rs_connections=0
        rs_listen=$(ss -tlnp 2>/dev/null | grep ":$REDSOCKS_PORT" | head -1 | awk '{print $4}') || rs_listen=""
        echo -e "  Active connections: ${BOLD}$rs_connections${NC}"
        echo -e "  Listening on: ${rs_listen:-not listening}"
    fi

    # Recent Telegram sessions
    echo "  Recent Telegram sessions (last 10):"
    local rs_jctl_args=(-t redsocks)
    if [ "$tor_instances" -gt 1 ]; then
        for ((i=0; i<tor_instances; i++)); do
            rs_jctl_args+=(-u "redsocks-inst${i}")
        done
    fi
    local sessions
    sessions=$(journalctl "${rs_jctl_args[@]}" --no-pager -n 300 2>/dev/null \
        | grep -E '\[.*->.*\]: accepted' | tail -10 \
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

    # ── Авто-починка ─────────────────────────────────────────────────────
    local fixes=()

    # Собираем список проблем
    if [ "$tor_instances" -gt 1 ]; then
        for ((i=0; i<tor_instances; i++)); do
            if ! systemctl is-active --quiet "tg-tor-inst${i}" 2>/dev/null; then
                fixes+=("tor-inst${i}")
            fi
            if ! systemctl is-active --quiet "redsocks-inst${i}" 2>/dev/null; then
                fixes+=("redsocks-inst${i}")
            fi
        done
    else
        if ! systemctl is-active --quiet redsocks 2>/dev/null; then
            fixes+=("redsocks")
        fi
        if ! systemctl is-active --quiet tor@default 2>/dev/null; then
            fixes+=("tor")
        fi
    fi

    local chain_fix
    chain_fix=$(iptables_cmd -t nat -L TELEGRAM_TOR 2>/dev/null | wc -l || echo 0)
    if [ "$chain_fix" -le 5 ]; then
        fixes+=("iptables")
    fi
    if ! systemctl is-active --quiet tg-tor-watchdog 2>/dev/null; then
        fixes+=("watchdog")
    fi

    if [ ${#fixes[@]} -gt 0 ]; then
        echo ""
        echo -e "${YELLOW}${BOLD}  Обнаружены проблемы: ${fixes[*]}${NC}"
        read -rp "  Исправить автоматически? [Y/n]: " autofix
        if [[ "${autofix,,}" != "n" ]]; then
            echo ""
            for fix in "${fixes[@]}"; do
                case "$fix" in
                    redsocks)
                        info "Запускаю redsocks..."
                        systemctl restart redsocks && log "redsocks запущен" || warn "Не удалось"
                        ;;
                    tor)
                        info "Запускаю tor@default..."
                        systemctl restart tor@default && log "Tor запущен" || warn "Не удалось"
                        ;;
                    tor-inst*)
                        local svc="tg-tor-${fix}"
                        info "Запускаю ${svc}..."
                        systemctl restart "$svc" && log "${svc} запущен" || warn "Не удалось"
                        ;;
                    redsocks-inst*)
                        info "Запускаю ${fix}..."
                        systemctl restart "$fix" && log "${fix} запущен" || warn "Не удалось"
                        ;;
                    iptables)
                        info "Применяю iptables правила..."
                        if [ -x "$ROUTES_SCRIPT" ]; then
                            bash "$ROUTES_SCRIPT" stop 2>/dev/null || true
                            bash "$ROUTES_SCRIPT" start && \
                                { apply_redsocks_protection; save_iptables_rules; log "iptables правила применены"; } || warn "Ошибка"
                        else
                            warn "Скрипт правил не найден — запустите установку (пункт 1)"
                        fi
                        ;;
                    watchdog)
                        info "Запускаю watchdog..."
                        systemctl restart tg-tor-watchdog && log "Watchdog запущен" || warn "Не удалось"
                        ;;
                esac
            done
            echo ""
            log "Авто-починка завершена. Запустите диагностику повторно для проверки."
        fi
    else
        echo ""
        echo -e "  ${GREEN}${BOLD}Проблем не обнаружено — всё работает.${NC}"
    fi

    echo ""
    echo -e "${BOLD}Команды для мониторинга:${NC}"
    echo -e "  journalctl -t redsocks -f          — live session log"
    echo -e "  journalctl -u tor@default -f       — Tor log"
    echo -e "  journalctl -u tg-tor-watchdog -f   — watchdog log"
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
cmd_update() {
    require_root

    local gh_repo="sysbedlam/tg-tor-proxy"
    local raw_base="https://raw.githubusercontent.com/${gh_repo}"

    hdr "Обновление tg-tor-proxy"

    # Текущий канал из конфига
    local current_channel
    current_channel=$(grep '^channel=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2 || echo "main")
    [ -z "$current_channel" ] && current_channel="main"

    echo -e "  Текущая версия:  ${BOLD}v${VERSION}${NC}"
    echo -e "  Канал:           ${BOLD}${current_channel}${NC}"
    echo ""
    echo -e "  Выберите канал обновления:"
    echo -e "  ${CYAN}1)${NC} stable  (main)                        — стабильная версия"
    echo -e "  ${CYAN}2)${NC} testing (fix/direct-mode-stability)   — тестовая ветка"
    echo -e "  ${CYAN}3)${NC} Оставить текущий канал (${current_channel})"
    echo ""
    read -rp "  Ваш выбор [1-3]: " ch_choice

    local branch
    case "$ch_choice" in
        1) branch="main" ;;
        2) branch="fix/direct-mode-stability" ;;
        3) branch="$current_channel" ;;
        *) branch="$current_channel" ;;
    esac

    local ts; ts=$(date +%s)
    local api_base="https://api.github.com/repos/${gh_repo}"

    echo ""
    info "Проверяю версию..."

    local remote_version release_download_url="" wd_download_url="" release_json=""

    # Извлекаем API URLs ассетов (не browser_download_url — он кешируется CDN).
    # API URL вида https://api.github.com/repos/.../releases/assets/ID
    # при запросе с Accept: application/octet-stream отдаёт файл напрямую без CDN.
    _parse_asset_urls() {
        local json="$1"
        release_download_url=$(echo "$json" | python3 -c "
import json,sys
try:
    d=json.load(sys.stdin)
    assets=d.get('assets',[])
    a=[x for x in assets if x['name']=='tg-tor-proxy.sh']
    print(a[0]['url'] if a else '')
except: print('')
" 2>/dev/null || true)
        wd_download_url=$(echo "$json" | python3 -c "
import json,sys
try:
    d=json.load(sys.stdin)
    assets=d.get('assets',[])
    a=[x for x in assets if x['name']=='tg-tor-watchdog.sh']
    print(a[0]['url'] if a else '')
except: print('')
" 2>/dev/null || true)
    }

    if [ "$branch" = "main" ]; then
        # Stable: /releases/latest
        release_json=$(curl -fsSL --connect-timeout 10 \
            "${api_base}/releases/latest" 2>/dev/null || true)
        remote_version=$(echo "$release_json" \
            | grep -oP '"tag_name":\s*"v?\K[^"]+' | head -1 || true)
        _parse_asset_urls "$release_json"
    else
        # Testing: ищем последний pre-release
        local all_releases
        all_releases=$(curl -fsSL --connect-timeout 10 \
            "${api_base}/releases?per_page=10" 2>/dev/null || true)

        if [ -n "$all_releases" ]; then
            release_json=$(echo "$all_releases" | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    pre = [r for r in data if r.get('prerelease')]
    print(json.dumps(pre[0]) if pre else '{}')
except: print('{}')
" 2>/dev/null) || release_json="{}"
        fi

        remote_version=$(echo "$release_json" \
            | grep -oP '"tag_name":\s*"v?\K[^"]+' | head -1 || true)
        _parse_asset_urls "$release_json"
    fi

    if [ -z "$remote_version" ]; then
        warn "Не удалось получить версию с GitHub. Проверьте соединение или название ветки."
        return 0
    fi

    echo -e "  Версия в ветке '${branch}': ${BOLD}v${remote_version}${NC}"
    echo ""

    if [ "$remote_version" = "$VERSION" ] && [ "$branch" = "$current_channel" ]; then
        log "Уже установлена последняя версия (v${VERSION}) из канала '${branch}'."
        return 0
    fi

    if [ "$branch" != "$current_channel" ]; then
        echo -e "  ${YELLOW}Смена канала: '${current_channel}' → '${branch}'${NC}"
    fi
    if [ "$remote_version" != "$VERSION" ]; then
        echo -e "  ${GREEN}Обновление: v${VERSION} → v${remote_version}${NC}"
    fi
    echo ""
    read -rp "  Продолжить? [Y/n]: " confirm
    [[ "${confirm,,}" == "n" ]] && { info "Отменено."; return 0; }

    echo ""
    info "Скачиваю tg-tor-proxy..."
    local dl_script="${release_download_url:-}"
    [ -z "$dl_script" ] && dl_script="${raw_base}/${branch}/tg-tor-proxy.sh?${ts}"
    # Accept: application/octet-stream — скачиваем через GitHub API напрямую, минуя CDN-кеш
    if curl -fsSL --connect-timeout 15 \
            -H "Accept: application/octet-stream" \
            "$dl_script" -o /usr/local/bin/tg-tor-proxy.new 2>/dev/null; then
        chmod +x /usr/local/bin/tg-tor-proxy.new
        mv /usr/local/bin/tg-tor-proxy.new /usr/local/bin/tg-tor-proxy
        # Сохраняем выбранный канал
        mkdir -p "$CONFIG_DIR"
        grep -v '^channel=' "$CONFIG_FILE" 2>/dev/null > "${CONFIG_FILE}.tmp" || true
        echo "channel=${branch}" >> "${CONFIG_FILE}.tmp"
        mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
        log "Основной скрипт обновлён"
    else
        warn "Ошибка при скачивании скрипта"
        return 0
    fi

    info "Скачиваю watchdog..."
    local wd_dl_url="${wd_download_url:-}"
    [ -z "$wd_dl_url" ] && wd_dl_url="${raw_base}/${branch}/tg-tor-watchdog.sh?${ts}"
    if curl -fsSL --connect-timeout 15 \
            -H "Accept: application/octet-stream" \
            "$wd_dl_url" -o /usr/local/bin/tg-tor-watchdog.sh.new 2>/dev/null; then
        chmod +x /usr/local/bin/tg-tor-watchdog.sh.new
        mv /usr/local/bin/tg-tor-watchdog.sh.new /usr/local/bin/tg-tor-watchdog.sh
        systemctl restart tg-tor-watchdog 2>/dev/null || true
        log "Watchdog обновлён и перезапущен"
    else
        warn "Watchdog не обновлён (основной скрипт обновлён)"
    fi

    echo ""
    log "Обновление завершено! Перезапускаю..."
    sleep 1
    exec /usr/local/bin/tg-tor-proxy
}

cmd_check_tor() {
    require_root
    hdr "Проверка Tor"

    local tor_count
    tor_count=$(get_tor_instances)

    if [ "$tor_count" -gt 1 ]; then
        # Multi-instance: проверяем каждый инстанс
        local all_ok=true
        for ((i=0; i<tor_count; i++)); do
            local pct svc port
            svc="tg-tor-inst${i}"
            port="${TOR_PORTS[$i]}"
            pct=$(tor_bootstrap_pct_inst "$i" 2>/dev/null || echo "0")
            echo -e "  [inst${i}] Bootstrap: ${BOLD}${pct}%${NC}"
            if [ "$pct" != "100" ]; then
                all_ok=false
                warn "[inst${i}] Tor не на 100%. Последние логи:"
                journalctl -u "$svc" --no-pager -n 5 2>/dev/null | \
                    grep -E 'Bootstrap|warn|error' | tail -3 || true
                echo ""
                read -rp "  SIGHUP для inst${i}? [Y/n]: " ans
                ans=${ans:-Y}
                if [[ "${ans^^}" == "Y" ]]; then
                    local tor_pid
                    tor_pid=$(systemctl show "$svc" --property=MainPID --value 2>/dev/null || echo "0")
                    [ "$tor_pid" != "0" ] && kill -HUP "$tor_pid" 2>/dev/null && info "SIGHUP отправлен"
                fi
            else
                local tor_ip
                tor_ip=$(curl -s --connect-timeout 10 \
                    --socks5-hostname "127.0.0.1:${port}" \
                    https://check.torproject.org/api/ip 2>/dev/null \
                    | grep -oP '"IP":"\K[^"]+' || echo "")
                [ -n "$tor_ip" ] && log "[inst${i}] Работает! Exit IP: ${BOLD}${tor_ip}${NC}" || \
                    warn "[inst${i}] 100% но SOCKS5 не отвечает"
            fi
        done
    else
        # Single instance
        local pct
        pct=$(tor_bootstrap_pct 2>/dev/null || echo "0")
        echo -e "  Bootstrap: ${BOLD}${pct}%${NC}"

        if [ "$pct" != "100" ]; then
            warn "Tor не на 100%. Последние логи:"
            journalctl -u tor@default --no-pager -n 10 2>/dev/null | \
                grep -E 'Bootstrap|warn|error' | tail -5 || true
            echo ""
            read -rp "  SIGHUP? [Y/n]: " ans
            ans=${ans:-Y}
            if [[ "${ans^^}" == "Y" ]]; then
                local tor_pid
                tor_pid=$(systemctl show tor@default --property=MainPID --value 2>/dev/null || echo "0")
                [ "$tor_pid" != "0" ] && kill -HUP "$tor_pid" 2>/dev/null && info "SIGHUP отправлен"
                wait_tor_bootstrap 60 999 false
                pct=$(tor_bootstrap_pct 2>/dev/null || echo "0")
            fi
        fi

        if [ "$pct" = "100" ]; then
            local tor_ip
            tor_ip=$(curl -s --connect-timeout 15 \
                --socks5-hostname "127.0.0.1:$TOR_PORT" \
                https://check.torproject.org/api/ip 2>/dev/null \
                | grep -oP '"IP":"\K[^"]+' || echo "")
            [ -n "$tor_ip" ] && log "Работает! Exit IP: ${BOLD}${tor_ip}${NC}" || \
                err "Tor на 100% но SOCKS5 не отвечает"
        else
            err "Tor bootstrap failed (${pct}%)"
            echo -e "  Добавьте obfs4 мосты: ${CYAN}tg-tor-proxy --add-bridges${NC}"
        fi
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
    local tor_status redsocks_status tor_pct
    local tor_count
    tor_count=$(get_tor_instances)

    if [ "$tor_count" -gt 1 ]; then
        tor_status=$(systemctl is-active "tg-tor-inst0" 2>/dev/null; true)
        redsocks_status=$(systemctl is-active "redsocks-inst0" 2>/dev/null; true)
        tor_pct=$(tor_bootstrap_pct_inst 0 2>/dev/null || echo "?")
    else
        tor_status=$(systemctl is-active tor@default 2>/dev/null; true)
        redsocks_status=$(systemctl is-active redsocks 2>/dev/null; true)
        tor_pct=$(tor_bootstrap_pct 2>/dev/null || echo "?")
    fi

    local rules_ok="no"
    iptables_cmd -t nat -L TELEGRAM_TOR -n &>/dev/null && rules_ok="yes"

    local mode="—"
    [ -f "$CONFIG_FILE" ] && mode=$(grep '^mode=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2 || echo "—")

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

    local inst_label=""
    [ "$tor_count" -gt 1 ] && inst_label=" ×${tor_count}"
    echo -e "  Tor ${tor_icon} ${tor_pct}%${inst_label} (${mode})   Redsocks ${redsocks_icon}   iptables ${rules_icon}"
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
    echo -e "  ${CYAN}9)${NC}  Проверить и установить обновление"
    echo -e "  ${RED}8)${NC}  Удалить всё (deinstall)"
    echo -e "  ${CYAN}0)${NC}  Выход"
    echo ""
}

interactive_menu() {
    require_root

    while true; do
        show_menu
        read -rp "  Ваш выбор [0-9]: " choice
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
                apply_redsocks_protection
                save_iptables_rules
                echo ""
                read -rp "  Нажмите Enter для возврата в меню..." _dummy
                ;;
            7)
                hdr "Активные Telegram-сессии (Ctrl+C для выхода)"
                echo -e "${CYAN}Формат: клиент:порт → Telegram_IP:порт${NC}"
                echo ""
                local rs_jctl=(-t redsocks)
                local live_count
                live_count=$(get_tor_instances)
                if [ "$live_count" -gt 1 ]; then
                    for ((li=0; li<live_count; li++)); do
                        rs_jctl+=(-u "redsocks-inst${li}")
                    done
                fi
                journalctl "${rs_jctl[@]}" -f --no-pager 2>/dev/null | \
                    grep --line-buffered -E '\[.*->.*\]' | \
                    grep --line-buffered -oP 'redsocks\[\d+\]: \K\[.*\]: .*' | \
                    sed 's/^/  /' || true
                echo ""
                read -rp "  Нажмите Enter для возврата в меню..." _dummy
                ;;
            9)
                cmd_update
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
# AUTO-MIGRATE
# Runs once per version after update — applies config/package changes silently
# ─────────────────────────────────────────────────────────────────────────────
auto_migrate() {
    # Только если уже установлено (конфиг есть)
    [ -f "$CONFIG_FILE" ] || return 0
    # Пропускаем если уже мигрировали на эту версию
    local last_migrated
    last_migrated=$(grep '^migrated_version=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2 || echo "")
    [ "$last_migrated" = "$VERSION" ] && return 0

    log "Применяю обновление конфигурации v${VERSION}..."

    # 1. Установить netfilter-persistent если отсутствует
    if ! dpkg -l netfilter-persistent &>/dev/null 2>&1; then
        info "Устанавливаю netfilter-persistent..."
        echo iptables-persistent iptables-persistent/autosave_v4 boolean true \
            | debconf-set-selections 2>/dev/null || true
        echo iptables-persistent iptables-persistent/autosave_v6 boolean false \
            | debconf-set-selections 2>/dev/null || true
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
            netfilter-persistent iptables-persistent 2>/dev/null \
            && log "netfilter-persistent установлен" || warn "Не удалось установить netfilter-persistent"
    fi

    # 2. Single-instance redsocks.conf — добавить user/group если отсутствует
    if [ -f "$REDSOCKS_CONF" ] && ! grep -q 'user = redsocks' "$REDSOCKS_CONF"; then
        sed -i '/daemon = /a\    user = redsocks;\n    group = redsocks;' "$REDSOCKS_CONF"
        systemctl restart redsocks 2>/dev/null || true
        log "redsocks.conf: добавлен user/group, сервис перезапущен"
    fi

    # 3. Multi-instance redsocks.conf.inst* — добавить user/group если отсутствует
    for conf in /etc/redsocks.conf.inst*; do
        [ -f "$conf" ] || continue
        if ! grep -q 'user = redsocks' "$conf"; then
            sed -i '/daemon = /a\    user = redsocks;\n    group = redsocks;' "$conf"
            local _idx="${conf##*inst}"
            systemctl restart "redsocks-inst${_idx}" 2>/dev/null || true
            log "${conf}: добавлен user/group, сервис перезапущен"
        fi
    done

    # 4. Сохранить iptables правила (переживут ребут)
    if command -v netfilter-persistent &>/dev/null; then
        netfilter-persistent save &>/dev/null \
            && log "iptables правила сохранены (persistent)" || true
    fi

    # 5. Обновить torrc: убрать устаревший OptimisticData, добавить CircuitStreamTimeout,
    #    снизить CircuitBuildTimeout с 60 до 30
    local tor_changed=false
    for torrc_f in "$TORRC" /etc/tor/torrc.inst*; do
        [ -f "$torrc_f" ] || continue
        local changed_f=false
        # Убираем OptimisticData если есть (obsolete в Tor >= 0.4.x, вызывает warn)
        if grep -q 'OptimisticData' "$torrc_f"; then
            sed -i '/OptimisticData/d' "$torrc_f"
            changed_f=true
        fi
        if ! grep -q 'CircuitStreamTimeout' "$torrc_f"; then
            echo "CircuitStreamTimeout 15" >> "$torrc_f"
            changed_f=true
        fi
        # Снижаем CircuitBuildTimeout с 60 до 30
        if grep -q 'CircuitBuildTimeout 60' "$torrc_f"; then
            sed -i 's/CircuitBuildTimeout 60/CircuitBuildTimeout 30/' "$torrc_f"
            changed_f=true
        fi
        $changed_f && tor_changed=true
    done
    if $tor_changed; then
        log "Tor: применены оптимизации латентности (CircuitStreamTimeout, CircuitBuildTimeout 30)"
        systemctl reload-or-restart tor@default 2>/dev/null || true
        for i in 0 1 2; do
            systemctl is-active --quiet "tg-tor-inst${i}" 2>/dev/null && \
                systemctl reload-or-restart "tg-tor-inst${i}" 2>/dev/null || true
        done
    fi

    # 6. Перезапустить watchdog чтобы подхватил новый скрипт
    if systemctl is-active --quiet tg-tor-watchdog; then
        systemctl restart tg-tor-watchdog 2>/dev/null \
            && log "Watchdog перезапущен" || true
    fi

    # Запомнить что мигрировали на эту версию
    {
        grep -v '^migrated_version=' "$CONFIG_FILE" 2>/dev/null || true
        echo "migrated_version=$VERSION"
    } > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"

    log "Миграция v${VERSION} завершена"
}

# ─────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# When run without args → interactive menu
# When run with args   → direct command (для CI/скриптов)
# ─────────────────────────────────────────────────────────────────────────────
main() {
    local cmd="${1:-}"
    local arg="${2:-}"

    # Auto-apply config migrations for newly installed version
    auto_migrate

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
            apply_redsocks_protection
            save_iptables_rules
            ;;
        --update|-u)
            require_root; cmd_update
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
