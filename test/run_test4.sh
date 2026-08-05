#!/bin/bash
echo "=== Running Test 4: Per-symbol dynamic suppression ==="

export LD_AUDIT="$MUX_SO"
export LD_AUDIT2="${LIBS_DIR}/libtest4_auditor1.so:${LIBS_DIR}/libtest4_auditor2.so"

OUTPUT=$("${TEST_DIR}/test4_main" 2>&1)
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ] || echo "$OUTPUT" | grep -q "FAIL"; then
    echo "Test 4 Failed. Output was:"
    echo "$OUTPUT"
    exit 1
else
    echo "Test 4 Passed."
    exit 0
fi