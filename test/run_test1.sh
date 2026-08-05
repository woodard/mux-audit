#!/bin/bash
echo "=== Running Test 1: Basic Multiplexer Functionality ==="

AUDITOR_SO="${LIBS_DIR}/libtest1_auditor.so"
OUTPUT=$(LD_AUDIT="$MUX_SO" LD_AUDIT2="$AUDITOR_SO" "${TEST_DIR}/dummy_main" 2>&1)

if echo "$OUTPUT" | grep -q "\[TEST1\] la_version called"; then
    echo "Test 1 Passed."
    exit 0
else
    echo "Test 1 Failed: Multiplexer did not forward la_version."
    echo "Output was: $OUTPUT"
    exit 1
fi