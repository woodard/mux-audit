#!/bin/bash

echo "==========================================================="
echo "=== Running Activity Ordering Test ==="
echo "=== Condition 2: Cookie match between ADD and DELETE for the 2nd auditor's namespace"
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

LINE_NUM=$(echo "$OUTPUT" | grep -n "\[test_activity_auditor1.so\] la_objopen('test_activity_auditor2.so')" | cut -d: -f1 | head -n 1)

if [ -z "$LINE_NUM" ]; then
    echo "FAIL: Could not locate la_objopen for Auditor2 to establish baseline."
    echo "$OUTPUT"
    exit 1
fi

NS_COOKIE=$(echo "$OUTPUT" | head -n $LINE_NUM | grep "\[test_activity_auditor1.so\] la_activity(ADD)" | tail -n 1 | grep -oE "cookie=0x[0-9a-f]+")

if [ -z "$NS_COOKIE" ]; then
    echo "FAIL: Could not locate LA_ACT_ADD cookie for Auditor2's namespace."
    echo "$OUTPUT"
    exit 1
fi

if ! echo "$OUTPUT" | grep -q "\[test_activity_auditor1.so\] la_activity(DELETE) cookie=$NS_COOKIE"; then
    echo "FAIL: Auditor1 did not see LA_ACT_DELETE for Auditor2's namespace with matching cookie=$NS_COOKIE."
    echo "$OUTPUT"
    exit 1
else
    echo "PASS: Condition 2 (Stable namespace cookie for Auditor2 matching ADD and DELETE)."
    exit 0
fi