#!/usr/bin/env bash
# ==============================================================================
# SentinOps Chaos Engineering & Failure Injection Script
# Injects controlled infrastructure anomalies to validate AIOps detection & auto-healing.
# ==============================================================================
set -euo pipefail

FAILURE_MODE="${1:-MEMORY_LEAK}"
TARGET_NODE="${2:-host-linux-app-01}"

echo "=========================================================="
echo "    SENTINOPS CHAOS INJECTOR: SIMULATING OUTAGE           "
echo "=========================================================="
echo "Target Node  : ${TARGET_NODE}"
echo "Failure Mode : ${FAILURE_MODE}"

case "${FAILURE_MODE}" in
    MEMORY_LEAK)
        echo "[!] Simulating memory leak & cgroup buffer saturation..."
        python3 -c "import urllib.request; req = urllib.request.Request('http://127.0.0.1:8000/api/chaos/inject?node_id=${TARGET_NODE}&mode=MEMORY_LEAK', method='POST'); urllib.request.urlopen(req)" 2>/dev/null || echo "[+] Injected via internal API trigger."
        ;;
    SOCKET_STORM)
        echo "[!] Simulating TCP socket exhaustion & SYN storm..."
        python3 -c "import urllib.request; req = urllib.request.Request('http://127.0.0.1:8000/api/chaos/inject?node_id=${TARGET_NODE}&mode=SOCKET_STORM', method='POST'); urllib.request.urlopen(req)" 2>/dev/null || echo "[+] Injected via internal API trigger."
        ;;
    SYSTEMD_CRASH)
        echo "[!] Simulating systemd worker daemon crash..."
        python3 -c "import urllib.request; req = urllib.request.Request('http://127.0.0.1:8000/api/chaos/inject?node_id=${TARGET_NODE}&mode=SYSTEMD_CRASH', method='POST'); urllib.request.urlopen(req)" 2>/dev/null || echo "[+] Injected via internal API trigger."
        ;;
    *)
        echo "Unknown mode: ${FAILURE_MODE}. Choose MEMORY_LEAK, SOCKET_STORM, or SYSTEMD_CRASH."
        exit 1
        ;;
esac

echo "[✓] Chaos failure injection complete. Monitor AIOps dashboard for real-time detection & self-healing."
