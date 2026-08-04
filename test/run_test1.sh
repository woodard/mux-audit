#!/bin/bash

echo "=== Running Test 1: Basic Multiplexer Functionality ==="

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$(dirname "$TEST_DIR")"
LIBS_DIR="${BUILD_DIR}/.libs"

# Dynamically locate the multiplexer .so file (excluding libaudit_utils.so)
MUX_SO=$(ls "$LIBS_DIR"/*.so 2>/dev/null | grep -v "utils" | head -n 1)

if [ -z "$MUX_SO" ] || [ ! -f "$MUX_SO" ]; then
    echo "Error: Multiplexer shared object not found in $LIBS_DIR"
    echo "Please ensure you have run 'make' at the project root before running 'make check'."
    echo "Current contents of $LIBS_DIR:"
    ls -la "$LIBS_DIR" 2>/dev/null || echo "Directory does not exist."
    exit 1
fi

AUDITOR_SO="${TEST_DIR}/.libs/libtest1_auditor.so"
echo "Using multiplexer: $MUX_SO"

OUTPUT=$(LD_LIBRARY_PATH="$LIBS_DIR" \
         LD_AUDIT="$MUX_SO" \
         LD_AUDIT2="$AUDITOR_SO" \
         "${TEST_DIR}/dummy_main" 2>&1)

echo "$OUTPUT"

if echo "$OUTPUT" | grep -q "\[TEST1\] la_version called"; then
    echo "Test 1 Passed: Basic multiplexing works."
    exit 0
else
    echo "Test 1 Failed: Multiplexer did not forward la_version."
    exit 1
fi
