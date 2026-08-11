#!/bin/bash

echo "==========================================================="
echo "=== Running Activity Ordering Test ==="
echo "=== Basic State Machine Ordering ==="
echo "==========================================================="

cp ${LIBS_DIR}/test_activity_auditor.so ${LIBS_DIR}/test_activity_auditor1.so
cp ${LIBS_DIR}/test_activity_auditor.so ${LIBS_DIR}/test_activity_auditor2.so

OUTPUT=$(LD_AUDIT="${MUX_SO}" LD_AUDIT2="${LIBS_DIR}/test_activity_auditor1.so:${LIBS_DIR}/test_activity_auditor2.so" ./test_activity_main 2>&1)
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    echo "FAIL: Application exited with error code $EXIT_CODE."
    echo "$OUTPUT"
    exit 1
fi

if echo "$OUTPUT" | grep -q "FATAL:"; then
    echo "FAIL: State ordering violation detected."
    echo "$OUTPUT"
    exit 1
else
    echo "PASS: Original State ordering (ADD -> OPEN -> CONSISTENT)."
    exit 0
fi