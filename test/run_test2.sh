#!/bin/bash

echo "=== Running Test 2: V2 Debugger Protocol Map Iteration ==="

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$(dirname "$TEST_DIR")"
LIBS_DIR="${BUILD_DIR}/.libs"

# Dynamically locate the multiplexer .so file (excluding libaudit_utils.so)
MUX_SO=$(ls "$LIBS_DIR"/*.so 2>/dev/null | grep -v "utils" | head -n 1)

if [ -z "$MUX_SO" ] || [ ! -f "$MUX_SO" ]; then
    echo "Error: Multiplexer shared object not found in $LIBS_DIR"
    exit 1
fi

AUDITOR_SO="${TEST_DIR}/.libs/libtest2_auditor.so"
echo "Using multiplexer: $MUX_SO"

OUTPUT=$(LD_LIBRARY_PATH="$LIBS_DIR" \
         LD_AUDIT="$MUX_SO" \
         LD_AUDIT2="$AUDITOR_SO" \
         "${TEST_DIR}/dummy_main" 2>&1)

echo "$OUTPUT"

if echo "$OUTPUT" | grep -q "\[TEST2\] Discovered map via _r_debug:"; then
    echo "Test 2 Passed: V2 debugger rendezvous map iteration succeeded."
    exit 0
else
    echo "Test 2 Failed: Did not discover any maps."
    exit 1
fi
