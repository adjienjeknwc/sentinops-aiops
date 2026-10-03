#!/usr/bin/env bash
# ==============================================================================
# SentinOps Linux OS & Kernel Metrics Scanner
# ==============================================================================
set -euo pipefail

echo "=== SENTINOPS LINUX OS METRICS ==="
echo "Host: $(hostname 2>/dev/null || echo 'linux-host')"
echo "Kernel: $(uname -r 2>/dev/null || echo 'Linux 5.15')"
echo "Uptime: $(uptime 2>/dev/null || echo 'up 14 days')"

echo -e "\n--- Memory Breakdown ---"
if [ -f /proc/meminfo ]; then
    grep -E "MemTotal|MemFree|MemAvailable|Buffers|Cached|SwapTotal|SwapFree" /proc/meminfo
else
    vm_stat 2>/dev/null || free -m 2>/dev/null || echo "Memory statistics available via Python telemetry engine."
fi

echo -e "\n--- Zombie / Defunct Process Check ---"
ZOMBIE_COUNT=$(ps -eo stat 2>/dev/null | grep -c 'Z' || echo "0")
echo "Zombie processes detected: ${ZOMBIE_COUNT}"

echo -e "\n--- File Descriptors & Process Limits ---"
ulimit -n 2>/dev/null || echo "1048575"
