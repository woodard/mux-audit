#!/bin/bash
echo "=== Running Test 6: Subsequent LD_AUDIT entries ==="

DUMMY="${LIBS_DIR}/libdummy_auditor.so"

# Run with dummy auditor AFTER the multiplexer to simulate an uncontrolled trailing auditor
OUTPUT=$(env LD_AUDIT="${MUX_SO}:${DUMMY}" "${TEST_DIR}/dummy_main" 2>&1)
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    echo "Test 6 Failed: target crashed."
    echo "Output: $OUTPUT"
    exit 1
fi

if ! echo "$OUTPUT" | grep -q "WARNING: Uncontrolled auditors detected" || \
   ! echo "$OUTPUT" | grep -q "Moving subsequent LD_AUDIT entry to LD_AUDIT2: .*libdummy_auditor.so"; then
    echo "Test 6 Failed: Multiplexer did not correctly shift the subsequent auditor to LD_AUDIT2."
    echo "Output: $OUTPUT"
    exit 1
fi

echo "Test 6 Passed."
exit 0