#!/bin/bash

export LD_AUDIT="../.libs/audit_multiplexer.so"
export LD_AUDIT2="./.libs/libtest4_auditor1.so:./.libs/libtest4_auditor2.so"

echo "=== Running Test 4: Per-symbol dynamic suppression ==="

# Run the test app, capture output and the exit code
OUTPUT=$(./test4_main 2>&1)
EXIT_CODE=$?

# Validate success criteria
if [ $EXIT_CODE -ne 0 ] || echo "$OUTPUT" | grep -q "FAIL"; then
    echo "Test 4 Failed. Output was:"
    echo "$OUTPUT"
    exit 1
else
    echo "Test 4 Passed."
    exit 0
fi