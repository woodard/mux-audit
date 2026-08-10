#!/bin/bash

echo "==========================================================="
echo "=== Running DT_AUDIT Test ==="
echo "==========================================================="

# Assuming the DT_AUDIT compiled target is available in the build directory
TARGET="./dt_audit_app"

# Run the test executable and capture both stdout and stderr
OUTPUT=$(LD_AUDIT="${MUX_SO}" LD_LIBRARY_PATH="./.libs:${LD_LIBRARY_PATH}" $TARGET 2>&1)
EXIT_CODE=$?

# Verify that execution was successful
if [ $EXIT_CODE -ne 0 ]; then
    echo "FAIL: Application exited with error code $EXIT_CODE."
    echo "Output:"
    echo "$OUTPUT"
    exit 1
fi

# Verify the multiplexer successfully detected and warned about the rogue auditor
if echo "$OUTPUT" | grep -q "\[audit_multiplexer\] WARNING: Foreign DT_AUDIT directive detected"; then
    echo "PASS: Multiplexer correctly printed the warning and allowed execution to continue."
    exit 0
else
    echo "FAIL: Multiplexer failed to print the DT_AUDIT warning."
    echo "Output:"
    echo "$OUTPUT"
    exit 1
fi
