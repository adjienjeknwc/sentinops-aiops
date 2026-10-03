#!/usr/bin/env bash
# ==============================================================================
# SentinOps DevSecOps Automated Security & CIS Audit
# ==============================================================================
set -euo pipefail

echo "=========================================================="
echo "    SENTINOPS DEVSECOPS SECURITY & COMPLIANCE AUDIT       "
echo "=========================================================="

python3 -c '
from core.devsecops_scanner import DevSecOpsScanner
import json

res = DevSecOpsScanner.run_full_security_audit()
score = res["compliance_percentage"]
total = res["total_checks"]
level = res["compliance_level"]

print(f"[+] DevSecOps Compliance Score: {score}%")
print(f"[+] Total Checks Evaluated: {total}")
print(f"[+] Compliance Posture: {level}")
print("\n--- Detailed Audit Findings ---")
for f in res["findings"]:
    status_icon = "PASS [✓]" if f["passed"] else "FAIL [✗]"
    cname = f["check_name"]
    sev = f["severity"]
    desc = f["description"]
    print(f"  [{status_icon}] {cname} ({sev}) -> {desc}")
'
