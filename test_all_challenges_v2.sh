#!/bin/bash
# Test all DV-MCP challenges with mcpsf v2 (with --mode support)

echo "=========================================="
echo "  Testing All DV-MCP Challenges (v2)"
echo "  Mode: AGGRESSIVE (Active Testing)"
echo "=========================================="
echo ""

CHALLENGES=(
    "9001:Challenge_1_Basic_Prompt_Injection"
    "9002:Challenge_2_Tool_Poisoning"
    "9003:Challenge_3_Excessive_Permissions"
    "9004:Challenge_4_Rug_Pull_Attack"
    "9005:Challenge_5_Tool_Shadowing"
    "9006:Challenge_6_Indirect_Prompt_Injection"
    "9007:Challenge_7_Token_Theft"
    "9008:Challenge_8_Malicious_Code_Execution"
    "9009:Challenge_9_Remote_Access_Control"
    "9010:Challenge_10_Multi_Vector_Attack"
)

TOTAL=0
DETECTED=0

for challenge in "${CHALLENGES[@]}"; do
    PORT="${challenge%%:*}"
    NAME="${challenge##*:}"

    echo ""
    echo "=========================================="
    echo "Testing ${NAME} (port ${PORT})"
    echo "=========================================="

    python mcpsf.py assess "http://localhost:${PORT}/sse" --mode aggressive 2>&1 | tee -a test_results_v2.log

    EXIT_CODE=${PIPESTATUS[0]}
    TOTAL=$((TOTAL + 1))

    if [ $EXIT_CODE -eq 1 ]; then
        echo "[!] ${NAME}: Vulnerabilities DETECTED"
        DETECTED=$((DETECTED + 1))
    else
        echo "[✓] ${NAME}: No vulnerabilities detected"
    fi

    echo ""
    sleep 2
done

echo ""
echo "=========================================="
echo "  TEST SUMMARY"
echo "=========================================="
echo "Total Challenges: ${TOTAL}"
echo "Vulnerabilities Detected: ${DETECTED}"
echo "Detection Rate: $((DETECTED * 100 / TOTAL))%"
echo ""
echo "Reports saved in: reports/"
ls -l reports/ | grep Challenge
