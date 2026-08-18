#!/bin/bash

echo "==========================================================="
echo "=== Running Activity Ordering Test ==="
echo "=== Condition 3: First auditor sees la_objclose for 2nd auditor"
echo "==========================================================="

cp ${LIBS_DIR}/test_activity_auditor.so ${LIBS_DIR}/test_activity_auditor1.so
cp ${LIBS_DIR}/test_activity_auditor.so ${LIBS_DIR}/test_activity_auditor2.so

OUTPUT=$(LD_AUDIT="${MUX_SO}" LD_AUDIT2="${LIBS_DIR}/test_activity_auditor1.so:${LIBS_DIR}/test_activity_auditor2.so" "${TEST_DIR}/test_activity_main" 2>&1)
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    echo "FAIL: Application exited with error code $EXIT_CODE."
    echo "$OUTPUT"
    exit 1
fi

AUD2_OBJ_COOKIE=$(echo "$OUTPUT" | grep "\[test_activity_auditor1.so\] la_objopen('test_activity_auditor2.so')" | grep -oE "cookie=0x[0-9a-f]+" | head -n 1)

if [ -z "$AUD2_OBJ_COOKIE" ]; then
    echo "FAIL: Could not locate object cookie for Auditor2."
    echo "$OUTPUT"
    exit 1
fi

if ! echo "$OUTPUT" | grep -q "\[test_activity_auditor1.so\] la_objclose() $AUD2_OBJ_COOKIE"; then
    echo "FAIL: Auditor1 did not see la_objclose for Auditor2's object ($AUD2_OBJ_COOKIE)."
    echo "$OUTPUT"
    exit 1
else
    echo "PASS: Condition 3 (Auditor1 sees la_objclose for Auditor2)."
    exit 0
fi