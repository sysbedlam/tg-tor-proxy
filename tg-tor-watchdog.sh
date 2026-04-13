#!/bin/bash
# Persistent watchdog for tg-tor-proxy stack
# Monitors Tor bootstrap and redsocks health for 1-3 instances

CONFIG_FILE="/etc/tg-tor-proxy/config"
LOG_TAG="tg-tor-watchdog"

TOR_PORTS=(9050 9052 9053)
RS_PORTS=(12345 12346 12347)

log() { logger -t "$LOG_TAG" "$*"; echo "$(date '+%H:%M:%S') $*"; }

get_tor_count() {
    local count
    count=$(grep '^tor_instances=' "$CONFIG_FILE" 2>/dev/null | cut -d= -f2)
    echo "${count:-1}"
}

# Get bootstrap % for an instance
# $1 = instance index (0, 1, 2) for multi; "default" for tor@default
get_bootstrap_pct() {
    local idx="$1"
    local cookie control
    if [ "$idx" = "default" ]; then
        cookie="/run/tor/control.authcookie"
        control="/run/tor/control"
    else
        cookie="/run/tor/inst${idx}/control.authcookie"
        control="/run/tor/inst${idx}/control"
    fi
    python3 -c "
import socket, re
try:
    with open('${cookie}','rb') as f: c=f.read().hex()
    s=socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(3); s.connect('${control}')
    s.send(f'AUTHENTICATE {c}\r\n'.encode()); s.recv(200)
    s.send(b'GETINFO status/bootstrap-phase\r\n')
    r=s.recv(500).decode(); s.close()
    m=re.search(r'PROGRESS=(\d+)',r)
    print(m.group(1) if m else '-1')
except: print('-1')
" 2>/dev/null || echo -1
}

get_tor_pid() {
    local svc="$1"
    systemctl show "$svc" --property=MainPID --value 2>/dev/null || echo 0
}

sighup_tor() {
    local svc="$1"
    local pid
    pid=$(get_tor_pid "$svc")
    if [ "$pid" != "0" ] && [ "$pid" != "" ]; then
        kill -HUP "$pid" 2>/dev/null
        log "SIGHUP → ${svc} (PID $pid) — пауза 15s"
        sleep 15
    fi
}

restart_tor_svc() {
    local svc="$1"
    log "Перезапуск ${svc}..."
    systemctl restart "$svc"
    sleep 20
}

restart_redsocks_svc() {
    local svc="$1"
    log "Перезапуск ${svc}..."
    systemctl restart "$svc"
}

# Keepalive: make a tiny request through a Tor SOCKS5 to keep circuits warm
keepalive_tor() {
    local port="$1"
    curl -s --connect-timeout 10 --max-time 15 \
        --socks5-hostname "127.0.0.1:${port}" \
        "http://detectportal.firefox.com/success.txt" \
        -o /dev/null 2>/dev/null &
}

# ─── Monitor a single instance ───────────────────────────────────────────────
# State arrays indexed by instance index
declare -a STUCK_COUNT LAST_PCT FAIL_COUNT KEEPALIVE_TICKS REDSOCKS_COOLDOWN

init_state() {
    local count="$1"
    for ((i=0; i<count; i++)); do
        STUCK_COUNT[$i]=0
        LAST_PCT[$i]=-1
        FAIL_COUNT[$i]=0
        KEEPALIVE_TICKS[$i]=0
        REDSOCKS_COOLDOWN[$i]=0
    done
}

check_instance() {
    local idx="$1"
    local tor_svc="$2"
    local rs_svc="$3"
    local tor_port="$4"

    local pct
    pct=$(get_bootstrap_pct "$idx")

    if [ "$pct" -eq -1 ]; then
        FAIL_COUNT[$idx]=$(( ${FAIL_COUNT[$idx]} + 1 ))
        if [ ${FAIL_COUNT[$idx]} -ge 3 ]; then
            log "[inst${idx}] Tor недоступен — проверяю сервис..."
            if ! systemctl is-active --quiet "$tor_svc"; then
                log "[inst${idx}] Tor упал — перезапуск..."
                restart_tor_svc "$tor_svc"
            else
                log "[inst${idx}] Tor активен, control socket недоступен — ожидание..."
            fi
            FAIL_COUNT[$idx]=0
            LAST_PCT[$idx]=-1
            STUCK_COUNT[$idx]=0
        fi
        return
    fi

    FAIL_COUNT[$idx]=0

    if [ "$pct" -eq 100 ]; then
        STUCK_COUNT[$idx]=0
        LAST_PCT[$idx]=100
        KEEPALIVE_TICKS[$idx]=$(( ${KEEPALIVE_TICKS[$idx]} + 1 ))

        # Redsocks check
        if ! systemctl is-active --quiet "$rs_svc"; then
            log "[inst${idx}] Redsocks упал — перезапуск..."
            restart_redsocks_svc "$rs_svc"
            REDSOCKS_COOLDOWN[$idx]=6
        else
            if [ "${REDSOCKS_COOLDOWN[$idx]}" -gt 0 ]; then
                REDSOCKS_COOLDOWN[$idx]=$(( ${REDSOCKS_COOLDOWN[$idx]} - 1 ))
            elif journalctl -u "$rs_svc" --since "30 seconds ago" --no-pager -q 2>/dev/null \
                    | grep -q "backing off"; then
                log "[inst${idx}] Redsocks fd exhaustion — перезапуск..."
                restart_redsocks_svc "$rs_svc"
                REDSOCKS_COOLDOWN[$idx]=6
            fi
        fi

        # Keepalive every 2 min (12 ticks × 10s)
        if [ $(( ${KEEPALIVE_TICKS[$idx]} % 12 )) -eq 0 ]; then
            keepalive_tor "$tor_port"
        fi

    else
        log "[inst${idx}] Tor bootstrap: ${pct}%"
        KEEPALIVE_TICKS[$idx]=0

        if [ "$pct" -eq "${LAST_PCT[$idx]}" ]; then
            STUCK_COUNT[$idx]=$(( ${STUCK_COUNT[$idx]} + 1 ))

            # Stuck 30s → SIGHUP
            if [ ${STUCK_COUNT[$idx]} -eq 3 ]; then
                log "[inst${idx}] Застрял на ${pct}% — SIGHUP"
                sighup_tor "$tor_svc"
                STUCK_COUNT[$idx]=0
            fi

            # Stuck 2+ min → restart
            if [ ${STUCK_COUNT[$idx]} -ge 12 ]; then
                log "[inst${idx}] Застрял — перезапуск Tor"
                restart_tor_svc "$tor_svc"
                STUCK_COUNT[$idx]=0
                LAST_PCT[$idx]=-1
            fi
        else
            STUCK_COUNT[$idx]=0
            LAST_PCT[$idx]=$pct
        fi
    fi
}

# ─── Main loop ────────────────────────────────────────────────────────────────
log "Watchdog запущен"

TOR_COUNT=$(get_tor_count)
log "Режим: ${TOR_COUNT} инстанс(ов)"

if [ "$TOR_COUNT" -gt 1 ]; then
    init_state "$TOR_COUNT"
    while true; do
        sleep 10
        TOR_COUNT=$(get_tor_count)
        for ((i=0; i<TOR_COUNT; i++)); do
            check_instance "$i" "tg-tor-inst${i}" "redsocks-inst${i}" "${TOR_PORTS[$i]}"
        done
    done
else
    # Single instance mode — monitor tor@default + redsocks
    STUCK_COUNT_S=0
    LAST_PCT_S=-1
    PCT_100_TICKS=0
    FAIL_COUNT_S=0
    KEEPALIVE_TICKS_S=0
    REDSOCKS_COOLDOWN_S=0

    while true; do
        sleep 10
        pct=$(get_bootstrap_pct "default")

        if [ "$pct" -eq -1 ]; then
            FAIL_COUNT_S=$((FAIL_COUNT_S + 1))
            if [ $FAIL_COUNT_S -ge 3 ]; then
                log "Tor недоступен — проверяю..."
                if ! systemctl is-active --quiet tor@default; then
                    log "Tor упал — перезапуск..."
                    restart_tor_svc "tor@default"
                else
                    log "Tor активен, control socket недоступен — ожидание..."
                fi
                FAIL_COUNT_S=0
                LAST_PCT_S=-1
                STUCK_COUNT_S=0
            fi
            continue
        fi

        FAIL_COUNT_S=0

        if [ "$pct" -eq 100 ]; then
            PCT_100_TICKS=$((PCT_100_TICKS + 1))
            KEEPALIVE_TICKS_S=$((KEEPALIVE_TICKS_S + 1))
            STUCK_COUNT_S=0
            LAST_PCT_S=100

            if ! systemctl is-active --quiet redsocks; then
                log "Redsocks упал — перезапуск..."
                restart_redsocks_svc "redsocks"
                REDSOCKS_COOLDOWN_S=6
            else
                if [ "$REDSOCKS_COOLDOWN_S" -gt 0 ]; then
                    REDSOCKS_COOLDOWN_S=$((REDSOCKS_COOLDOWN_S - 1))
                elif journalctl -u redsocks --since "30 seconds ago" --no-pager -q 2>/dev/null \
                        | grep -q "backing off"; then
                    log "Redsocks fd exhaustion — перезапуск..."
                    restart_redsocks_svc "redsocks"
                    REDSOCKS_COOLDOWN_S=6
                fi
            fi

            if [ $((KEEPALIVE_TICKS_S % 12)) -eq 0 ]; then
                keepalive_tor 9050
            fi

        else
            log "Tor bootstrap: ${pct}%"
            PCT_100_TICKS=0
            KEEPALIVE_TICKS_S=0

            if [ "$pct" -eq "$LAST_PCT_S" ]; then
                STUCK_COUNT_S=$((STUCK_COUNT_S + 1))

                if [ $STUCK_COUNT_S -eq 3 ]; then
                    log "Застрял на ${pct}% — SIGHUP"
                    sighup_tor "tor@default"
                    STUCK_COUNT_S=0
                fi

                if [ $STUCK_COUNT_S -ge 12 ]; then
                    log "Застрял — перезапуск Tor"
                    restart_tor_svc "tor@default"
                    STUCK_COUNT_S=0
                    LAST_PCT_S=-1
                fi
            else
                STUCK_COUNT_S=0
                LAST_PCT_S=$pct
            fi
        fi
    done
fi
