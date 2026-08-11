#!/bin/bash

echo "==========================================================="
echo "=== Running Activity Ordering Test ==="
echo "=== Chaining: Multiplexer -> Auditor1 -> Auditor2 ==="
echo "==========================================================="

# Copy the auditor to simulate two distinct libraries
cp ${LIBS_DIR}/test_activity_auditor.so ${LIBS_DIR}/test_activity_auditor1.so
cp ${LIBS_DIR}/test_activity_auditor.so ${LIBS_DIR}/test_activity_auditor2.so

# Run the test executable
OUTPUT=$(LD_AUDIT="${MUX_SO}" LD_AUDIT2="${LIBS_DIR}/test_activity_auditor1.so:${LIBS_DIR}/test_activity_auditor2.so" ./test_activity_main 2>&1)
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    echo "FAIL: Application exited with error code $EXIT_CODE."
    echo "$OUTPUT"
    exit 1
fi

# Original condition: Ensure no FATAL state ordering errors occurred
if echo "$OUTPUT" | grep -q "FATAL:"; then
    echo "FAIL: State ordering violation detected."
    echo "$OUTPUT"
    exit 1
else
    echo "PASS: Original State ordering (ADD -> OPEN -> CONSISTENT)."
fi

# Condition 1: First auditor sees loading of 2nd auditor
if ! echo "$OUTPUT" | grep -q "\[test_activity_auditor1.so\] la_objopen('test_activity_auditor2.so')"; then
    echo "FAIL: Auditor1 did not see la_objopen for Auditor2."
    echo "$OUTPUT"
    exit 1
else
    echo "PASS: Condition 1 (Auditor1 sees Auditor2 load)."
fi

# Condition 2: Cookie match between ADD and DELETE for the 2nd auditor's namespace
LINE_NUM=$(echo "$OUTPUT" | grep -n "\[test_activity_auditor1.so\] la_objopen('test_activity_auditor2.so')" | cut -d: -f1 | head -n 1)
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
fi

# Condition 3: First auditor sees la_objclose for 2nd auditor
AUD2_OBJ_COOKIE=$(echo "$OUTPUT" | grep "\[test_activity_auditor1.so\] la_objopen('test_activity_auditor2.so')" | grep -oE "cookie=0x[0-9a-f]+" | head -n 1)
if ! echo "$OUTPUT" | grep -q "\[test_activity_auditor1.so\] la_objclose() $AUD2_OBJ_COOKIE"; then
    echo "FAIL: Auditor1 did not see la_objclose for Auditor2's object ($AUD2_OBJ_COOKIE)."
    echo "$OUTPUT"
    exit 1
else
    echo "PASS: Condition 3 (Auditor1 sees la_objclose for Auditor2)."
fi

echo "All Activity conditions passed."
exit 0