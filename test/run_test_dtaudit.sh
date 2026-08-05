#!/bin/bash
# Test: Verify multiplexer handles DT_AUDIT directives and intercepts LD_AUDIT

set -e

echo "=== Running DT_AUDIT Test ==="

# Trigger the environment: 
# The rogue auditor is provided via LD_AUDIT using the dummy auditor.
# The multiplexer is inherently triggered via DT_AUDIT in the executable itself.
export LD_AUDIT="$LIBS_DIR/libdummy_auditor.so"

# Run the application and capture standard out and error
OUTPUT=$("$TEST_DIR/dt_audit_app" 2>&1)
echo "$OUTPUT"

# Verify the multiplexer successfully detected and migrated the rogue auditor
if echo "$OUTPUT" | grep -q "Moving prior auditor to LD_AUDIT2"; then
    echo "PASS: Multiplexer intercepted LD_AUDIT from a DT_AUDIT load."
    exit 0
else
    echo "FAIL: Multiplexer failed to intercept the rogue auditor."
    exit 1
fi