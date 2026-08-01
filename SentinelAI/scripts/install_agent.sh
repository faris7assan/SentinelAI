#!/usr/bin/env bash
# ============================================================
# SentinelAI — Linux Agent Installer
# Usage: sudo bash install_agent.sh --server http://10.0.0.1:8000 --token YOUR_TOKEN
# ============================================================
set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'; BOLD='\033[1m'
ok()   { echo -e "${GREEN}✅ $1${NC}"; }
warn() { echo -e "${YELLOW}⚠️  $1${NC}"; }
err()  { echo -e "${RED}❌ $1${NC}"; exit 1; }

# ─── Parse args ──────────────────────────────────────────────
SERVER_URL=""
TOKEN=""
AGENT_ID=$(hostname)

while [[ $# -gt 0 ]]; do
    case "$1" in
        --server) SERVER_URL="$2"; shift 2 ;;
        --token)  TOKEN="$2";      shift 2 ;;
        --id)     AGENT_ID="$2";   shift 2 ;;
        *) err "Unknown argument: $1" ;;
    esac
done

[[ -z "$SERVER_URL" ]] && err "Required: --server http://SENTINELAI_SERVER:8000"

echo -e "${BOLD}🛡️  SentinelAI Agent Installer${NC}"
echo -e "Server: ${GREEN}$SERVER_URL${NC} | Agent ID: ${GREEN}$AGENT_ID${NC}\n"

# ─── Check root ──────────────────────────────────────────────
[[ $EUID -ne 0 ]] && err "Run as root: sudo bash $0 $*"

# ─── Install dependencies ────────────────────────────────────
echo "Installing Python dependencies..."
apt-get update -q
apt-get install -y -q python3 python3-pip auditd

pip3 install -q aiohttp loguru --break-system-packages 2>/dev/null || \
    pip3 install -q aiohttp loguru
ok "Python dependencies installed"

# ─── Create user & directories ───────────────────────────────
useradd --system --no-create-home --shell /sbin/nologin sentinelai 2>/dev/null || true
mkdir -p /opt/sentinelai-agent /etc/sentinelai
ok "Created sentinelai user and directories"

# ─── Download agent ──────────────────────────────────────────
echo "Installing agent files..."
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cp "$SCRIPT_DIR/log_agent.py" /opt/sentinelai-agent/
chown -R sentinelai:sentinelai /opt/sentinelai-agent
chmod 750 /opt/sentinelai-agent/log_agent.py
ok "Agent files installed to /opt/sentinelai-agent/"

# ─── Write environment config ─────────────────────────────────
cat > /etc/sentinelai/agent.env << EOF
SENTINELAI_API=${SERVER_URL}
AGENT_ID=${AGENT_ID}
SENTINELAI_TOKEN=${TOKEN}
BATCH_SIZE=50
FLUSH_INTERVAL=5
EOF
chmod 640 /etc/sentinelai/agent.env
chown root:sentinelai /etc/sentinelai/agent.env
ok "Environment config written to /etc/sentinelai/agent.env"

# ─── Configure auditd rules ──────────────────────────────────
cat > /etc/audit/rules.d/sentinelai.rules << 'EOF'
# SentinelAI auditd rules
-w /etc/passwd         -p wa -k user_modification
-w /etc/shadow         -p wa -k credential_access
-w /etc/sudoers        -p wa -k privilege_escalation
-w /bin/bash           -p x  -k shell_execution
-a always,exit -F arch=b64 -S execve -k process_execution
-a always,exit -F arch=b64 -S connect -k network_connect
-a always,exit -F arch=b64 -S setuid  -k privilege_escalation
EOF
service auditd restart 2>/dev/null || true
ok "Auditd rules configured"

# ─── Install systemd service ──────────────────────────────────
cp "$SCRIPT_DIR/sentinelai-agent.service" /etc/systemd/system/
# Substitute server URL in service file
sed -i "s|http://SENTINELAI_SERVER_IP:8000|${SERVER_URL}|g" /etc/systemd/system/sentinelai-agent.service
sed -i "s|HOSTNAME_HERE|${AGENT_ID}|g" /etc/systemd/system/sentinelai-agent.service

systemctl daemon-reload
systemctl enable sentinelai-agent
systemctl start sentinelai-agent
ok "Systemd service installed and started"

# ─── Verify ──────────────────────────────────────────────────
sleep 3
if systemctl is-active --quiet sentinelai-agent; then
    ok "Agent is running!"
    systemctl status sentinelai-agent --no-pager --lines=5
else
    warn "Agent may not have started. Check: journalctl -u sentinelai-agent -f"
fi

echo ""
echo -e "${BOLD}${GREEN}✅ SentinelAI Agent installed successfully!${NC}"
echo -e "  ${BOLD}Logs:${NC}   journalctl -u sentinelai-agent -f"
echo -e "  ${BOLD}Status:${NC} systemctl status sentinelai-agent"
echo -e "  ${BOLD}Config:${NC} /etc/sentinelai/agent.env"
