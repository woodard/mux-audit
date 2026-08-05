#!/bin/bash

# FIX: Use the correct environment variable for your multiplexer
export LD_AUDIT="../.libs/audit_multiplexer.so"
export LD_AUDIT2="./.libs/libtest3_auditor1.so:./.libs/libtest3_auditor2.so"

echo "=== Running Test 3: Dynamic loading inside la_preinit ==="

# Run the dummy executable and capture all output
OUTPUT=$(./dummy_main 2>&1)

# Check if Auditor 2 successfully saw the payload
if echo "$OUTPUT" | grep -q "\[test3_auditor2\] Success: observed libtest3_payload.so being loaded!"; then
    echo "Test 3 Passed."
    exit 0
else
    echo "Test 3 Failed. Output was:"
    echo "$OUTPUT"
    exit 1
fi