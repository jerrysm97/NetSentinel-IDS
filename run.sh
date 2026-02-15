#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
#  SENTINEL LAB — One-Click Launcher for Kali Linux
# ═══════════════════════════════════════════════════════════════════════════════
# Usage: chmod +x run.sh && sudo ./run.sh

set -e

GREEN='\033[0;32m'
CYAN='\033[0;36m'
RED='\033[0;31m'
NC='\033[0m'

echo ""
echo -e "${CYAN}╔═══════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║     🛡️  SENTINEL LAB — Kali Linux Launcher       ║${NC}"
echo -e "${CYAN}╚═══════════════════════════════════════════════════╝${NC}"
echo ""

# Check root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}❌ Please run with sudo: sudo ./run.sh${NC}"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# 1. Install Python dependencies
echo -e "${GREEN}📦 Checking Python dependencies...${NC}"
pip3 install -q scapy python-dotenv requests flask flask-cors netifaces --break-system-packages 2>/dev/null || \
pip3 install -q scapy python-dotenv requests flask flask-cors netifaces 2>/dev/null || \
echo "   ⚠️  Some Python packages may already be installed via apt"
echo -e "   ${GREEN}✅ Python deps OK${NC}"

# 2. Install Node.js dependencies
echo -e "${GREEN}📦 Checking Node.js dependencies...${NC}"
cd "$SCRIPT_DIR/Backend"
npm install --silent 2>/dev/null
echo -e "   ${GREEN}✅ Node deps OK${NC}"
cd "$SCRIPT_DIR"

# 3. Enable IP forwarding (required for MITM)
echo -e "${GREEN}🔧 Enabling IP forwarding...${NC}"
sysctl -w net.ipv4.ip_forward=1 > /dev/null 2>&1
echo -e "   ${GREEN}✅ IP forwarding enabled${NC}"

# 4. Detect network interface
IFACE=$(ip route | grep default | awk '{print $5}' | head -1)
LOCAL_IP=$(hostname -I | awk '{print $1}')

echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════${NC}"
echo -e "  Interface: ${GREEN}${IFACE}${NC}"
echo -e "  Local IP:  ${GREEN}${LOCAL_IP}${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════${NC}"
echo ""

# 5. Start server
echo -e "${GREEN}🚀 Starting Sentinel Server...${NC}"
echo -e "   Open: ${CYAN}http://localhost:3000${NC}"
echo -e "   Phone: ${CYAN}http://${LOCAL_IP}:3000${NC}"
echo ""

cd "$SCRIPT_DIR/Backend"
node server.js
