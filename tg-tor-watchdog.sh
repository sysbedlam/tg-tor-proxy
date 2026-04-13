#!/bin/bash
# Persistent watchdog for tg-tor-proxy stack
# Monitors Tor bootstrap and redsocks health, restarts as needed

COOKIE="/run/tor/control.authcookie"
CONTROL="/run/tor/control"
LOG_TAG="tg-tor-watchdog"
TOR_PORT=9050

log() { logger -t "$LOG_TAG" "$*"; echo "$(date '+%H:%M:%S') $*"; }

get_bootstrap_pct() {
    python3 -c "
import socket, re
try:
    with open('$COOKIE','rb') as f: c=f.read().hex()
    s=socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(3); s.connect('$CONTROL')
    s.send(f'AUTHENTICATE {c}\r\n'.encode()); s.recv(200)
    s.send(b'GETINFO status/bootstrap-phase\r\n')
    r=s.recv(500).decode(); s.close()
    m=re.search(r'PROGRESS=(\d+)',r)
    print(m.group(1) if m else '-1')
except: print('-1')
" 2>/dev/null || echo -1
}

get_tor_pid() {
    systemctl show tor@default --property=MainPID --value 2>/dev/null || echo 0
}

sighup_tor() {
    local pid
    pid=$(get_tor_pid)
    if [ "$pid" != "0" ]; then
        kill -HUP "$pid" 2>/dev/null
        log "SIGHUP sent to Tor (PID $pid) — pausing 15s for reload"
        sleep 15
    fi
}

restart_redsocks() {
    log "Restarting redsocks..."
    systemctl restart redsocks
    REDSOCKS_COOLDOWN=6  # skip backing-off check for 60s after restart
}

restart_tor() {
    log "Restarting tor@default..."
    systemctl restart tor@default
    sleep 20
}

# Keepalive: make a tiny request through Tor SOCKS5 to keep circuits warm
keepalive_tor() {
    curl -s --connect-timeout 10 --max-time 15 \
        --socks5-hostname "127.0.0.1:${TOR_PORT}" \
        "http://detectportal.firefox.com/success.txt" \
        -o /dev/null 2>/dev/null &
}

# --- Main loop ---
STUCK_COUNT=0
LAST_PCT=-1
PCT_100_TICKS=0
FAIL_COUNT=0
KEEPALIVE_TICKS=0
REDSOCKS_COOLDOWN=0

log "Watchdog started"

while true; do
    sleep 10

    pct=$(get_bootstrap_pct)

    # Control socket unreachable — could be Tor starting up or crashed
    if [ "$pct" -eq -1 ]; then
        FAIL_COUNT=$((FAIL_COUNT + 1))
        if [ $FAIL_COUNT -ge 3 ]; then
            log "Tor unreachable for $((FAIL_COUNT * 10))s — checking service..."
            if ! systemctl is-active --quiet tor@default; then
                log "Tor is down — restarting..."
                restart_tor
            else
                log "Tor active but control socket unavailable — waiting..."
            fi
            FAIL_COUNT=0
            LAST_PCT=-1
            STUCK_COUNT=0
        fi
        continue
    fi

    FAIL_COUNT=0

    if [ "$pct" -eq 100 ]; then
        PCT_100_TICKS=$((PCT_100_TICKS + 1))
        KEEPALIVE_TICKS=$((KEEPALIVE_TICKS + 1))
        STUCK_COUNT=0
        LAST_PCT=100

        # Check redsocks
        if ! systemctl is-active --quiet redsocks; then
            log "Redsocks is down — restarting..."
            restart_redsocks
        else
            # Detect fd exhaustion (backing off) — skip during cooldown after restart
            if [ "$REDSOCKS_COOLDOWN" -gt 0 ]; then
                REDSOCKS_COOLDOWN=$((REDSOCKS_COOLDOWN - 1))
            elif journalctl -u redsocks --since "30 seconds ago" --no-pager -q 2>/dev/null | grep -q "backing off"; then
                log "Redsocks fd exhaustion — restarting..."
                restart_redsocks
            fi
        fi

        # Keepalive every 2 min (12 ticks × 10s) to keep Tor circuits warm
        if [ $((KEEPALIVE_TICKS % 12)) -eq 0 ]; then
            keepalive_tor
        fi

        # No periodic SIGHUP — it kills live circuits unnecessarily

    else
        log "Tor bootstrap: ${pct}%"
        PCT_100_TICKS=0
        KEEPALIVE_TICKS=0

        if [ "$pct" -eq "$LAST_PCT" ]; then
            STUCK_COUNT=$((STUCK_COUNT + 1))

            # Stuck for 30s → SIGHUP (uses cached consensus)
            if [ $STUCK_COUNT -eq 3 ]; then
                log "Stuck at ${pct}% for 30s — SIGHUP"
                sighup_tor
                STUCK_COUNT=0
            fi

            # Stuck for 2+ min total → full restart
            if [ $STUCK_COUNT -ge 12 ]; then
                log "Stuck for $((STUCK_COUNT * 10))s — restarting Tor"
                restart_tor
                STUCK_COUNT=0
                LAST_PCT=-1
            fi
        else
            STUCK_COUNT=0
            LAST_PCT=$pct
        fi
    fi
done
