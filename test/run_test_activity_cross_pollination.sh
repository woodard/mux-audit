#!/bin/bash

echo "==========================================================="
echo "=== Running Activity Ordering Test ==="
echo "=== Condition 1: First auditor sees loading of 2nd auditor"
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

if ! echo "$OUTPUT" | grep -q "\[test_activity_auditor1.so\] la_objopen('test_activity_auditor2.so')"; then
    echo "FAIL: Auditor1 did not see la_objopen for Auditor2."
    echo "$OUTPUT"
    exit 1
else
    echo "PASS: Condition 1 (Auditor1 sees Auditor2 load)."
    exit 0
fi