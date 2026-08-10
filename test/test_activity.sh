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
if ! echo "$OUTPUT" | grep -q "la_objopen('test_activity_auditor2.so')"; then
    echo "FAIL: Auditor1 did not see the la_objopen for Auditor2."
    echo "$OUTPUT"
    exit 1
else
    echo "PASS: Condition 1 (Sibling auditor cross-pollination)."
fi

# Condition 2: Cookie match between ADD and DELETE for the 2nd auditor
ADD_COOKIE=$(echo "$OUTPUT" | grep -B1 "la_objopen('test_activity_auditor2.so')" | grep "la_activity(ADD)" | grep -oE "cookie=0x[0-9a-f]+" | head -n 1)
DELETE_COOKIE=$(echo "$OUTPUT" | grep -A2 "la_objclose() cookie=${ADD_COOKIE#cookie=}" | grep "la_activity(DELETE)" | grep -oE "cookie=0x[0-9a-f]+" | tail -n 1)

if [ -z "$ADD_COOKIE" ]; then
    echo "FAIL: Could not locate LA_ACT_ADD cookie for Auditor2."
    echo "$OUTPUT"
    exit 1
fi

if [ "$ADD_COOKIE" != "$DELETE_COOKIE" ]; then
    # Fallback lookup in case ordering interleaved slightly
    DELETE_COOKIE=$(echo "$OUTPUT" | grep "la_activity(DELETE) $ADD_COOKIE" | grep -oE "cookie=0x[0-9a-f]+" | tail -n 1)
    if [ "$ADD_COOKIE" != "$DELETE_COOKIE" ]; then
        echo "FAIL: Cookie mismatch! ADD: $ADD_COOKIE != DELETE: $DELETE_COOKIE"
        exit 1
    fi
fi
echo "PASS: Condition 2 (Stable la_activity cookie through lifecycle)."

# Condition 3: First auditor sees la_objclose for 2nd auditor
OBJCLOSE_TARGET_COOKIE=${ADD_COOKIE#cookie=}
if ! echo "$OUTPUT" | grep -q "la_objclose() cookie=${OBJCLOSE_TARGET_COOKIE}"; then
    echo "FAIL: Auditor1 did not see la_objclose for Auditor2's objects."
    echo "$OUTPUT"
    exit 1
else
    echo "PASS: Condition 3 (la_objclose sibling interception)."
fi

echo "All Activity conditions passed."
exit 0