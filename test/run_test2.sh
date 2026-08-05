#!/bin/bash
echo "=== Running Test 2: V2 Debugger Protocol Map Iteration ==="

AUDITOR_SO="${LIBS_DIR}/libtest2_auditor.so"
OUTPUT=$(LD_AUDIT="$MUX_SO" LD_AUDIT2="$AUDITOR_SO" "${TEST_DIR}/dummy_main" 2>&1)

if echo "$OUTPUT" | grep -q "\[TEST2\] Discovered map via _r_debug:"; then
    echo "Test 2 Passed."
    exit 0
else
    echo "Test 2 Failed: Did not discover any maps."
    echo "Output was: $OUTPUT"
    exit 1
fi