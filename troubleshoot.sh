#!/bin/bash

# Troubleshooter for run.sh (svoboda-vpn)
# Checks permissions, dependencies, config, network, services, tunnel, and firewall

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log() { echo -e "$YELLOW[~] $1$NC"; }
ok() { echo -e "$GREEN[+] $1$NC"; }
err() { echo -e "$RED[x] $1$NC"; }

# 1. Check OS and permissions
if [ "$(uname -s)" != "Linux" ]; then
    err "This script is only for Linux!"
    exit 1
else
    ok "Running on Linux."
fi

if [ "$EUID" -ne 0 ]; then
    err "Run as root! (sudo ./troubleshoot.sh)"
    exit 1
else
    ok "Running as root."
fi

# 2. Check required binaries
REQUIRED_BINS=(systemctl iptables dig curl wget python3 python dnscrypt-proxy xray)
MISSING=()
for bin in "${REQUIRED_BINS[@]}"; do
    if ! command -v "$bin" &>/dev/null; then
        MISSING+=("$bin")
    fi
done
if [ ${#MISSING[@]} -ne 0 ]; then
    err "Missing required binaries: ${MISSING[*]}"
else
    ok "All required binaries are installed."
fi

# 3. Check config file
CONFIG="./config.json"
if [ ! -f "$CONFIG" ]; then
    err "Config file not found: $CONFIG"
else
    ok "Config file exists: $CONFIG"
    if ! jq . "$CONFIG" &>/dev/null; then
        err "Config file is not valid JSON. (Install jq to check this)"
    else
        ok "Config file is valid JSON."
    fi
fi

# 4. Check internet connectivity
log "Checking internet connectivity (ping 9.9.9.9)..."
if ping -c 1 9.9.9.9 &>/dev/null; then
    ok "Internet connectivity: OK"
else
    err "No internet connectivity!"
fi

# 5. Check systemd and service status
if ! command -v systemctl &>/dev/null; then
    err "systemctl not found! Systemd is required."
else
    ok "systemctl found."
    for svc in dnscrypt-proxy xray; do
        if systemctl is-enabled --quiet $svc; then
            ok "$svc is enabled."
        else
            log "$svc is not enabled."
        fi
        if systemctl is-active --quiet $svc; then
            ok "$svc is running."
        else
            log "$svc is not running."
        fi
    done
fi

# 6. Check tunnel interface
TUN_NAME="svo-tun0"
if ip link show "$TUN_NAME" &>/dev/null; then
    ok "Tunnel interface $TUN_NAME exists."
else
    log "Tunnel interface $TUN_NAME does not exist."
fi

# 7. Check firewall/iptables rules (basic check)
if command -v iptables &>/dev/null; then
    log "Checking iptables rules for killswitch..."
    iptables -L -n | grep -q "DROP" && ok "DROP rules found in iptables (killswitch may be active)." || log "No DROP rules found in iptables."
else
    log "iptables not found, skipping firewall check."
fi

# 8. Suggest next steps
log "If you see any [x] errors above, address them before running run.sh."
log "For more details, check logs: journalctl -u dnscrypt-proxy, journalctl -u xray, or systemctl status <service>."
log "If the tunnel is not working, check your config.json and network connectivity."

ok "Troubleshooting complete." 