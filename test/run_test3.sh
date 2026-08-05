#!/bin/bash
echo "=== Running Test 3: Dynamic loading inside la_preinit ==="

export LD_AUDIT="$MUX_SO"
export LD_AUDIT2="${LIBS_DIR}/libtest3_auditor1.so:${LIBS_DIR}/libtest3_auditor2.so"

OUTPUT=$("${TEST_DIR}/dummy_main" 2>&1)

if echo "$OUTPUT" | grep -q "\[test3_auditor2\] Success: observed libtest3_payload.so being loaded!"; then
    echo "Test 3 Passed."
    exit 0
else
    echo "Test 3 Failed. Output was:"
    echo "$OUTPUT"
    exit 1
fi