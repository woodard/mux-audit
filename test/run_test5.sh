#!/bin/bash
echo "=== Running Test 5: Prior Auditor Detection ==="

DUMMY="${LIBS_DIR}/libdummy_auditor.so"

# Run with dummy auditor FIRST to simulate an uncontrolled prior auditor
OUTPUT=$(env LD_AUDIT="${DUMMY}:${MUX_SO}" "${TEST_DIR}/dummy_main" 2>&1)
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    echo "Test 5 Failed: target crashed."
    echo "Output: $OUTPUT"
    exit 1
fi

if ! echo "$OUTPUT" | grep -q "WARNING: Uncontrolled auditors detected" || \
   ! echo "$OUTPUT" | grep -q "Moving prior auditor to LD_AUDIT2: .*libdummy_auditor.so"; then
    echo "Test 5 Failed: Multiplexer did not correctly detect and extract prior auditor."
    echo "Output: $OUTPUT"
    exit 1
fi

echo "Test 5 Passed."
exit 0