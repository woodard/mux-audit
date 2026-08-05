#!/bin/bash
set -e

echo "=== Running LD_AUDIT Multiplexer Test ==="

# Get the directory where this script is located
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Resolve paths based on the script's location
MULTIPLEXER_SO="${DIR}/../.libs/audit_multiplexer.so"
DUMMY_AUDITOR_SO="${DIR}/.libs/dummy_auditor.so"
APP="${DIR}/dummy_app"

# Verify they exist
if [ ! -f "$MULTIPLEXER_SO" ]; then
    echo "Error: $MULTIPLEXER_SO not found!"
    exit 1
fi

if [ ! -f "$DUMMY_AUDITOR_SO" ]; then
    echo "Error: $DUMMY_AUDITOR_SO not found!"
    exit 1
fi

# Ensure the dynamic linker can find the newly created libaudit_utils.so
export LD_LIBRARY_PATH="${DIR}/../.libs${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

# Run the app under the multiplexer
env LD_AUDIT="$MULTIPLEXER_SO" LD_AUDIT2="$DUMMY_AUDITOR_SO" "$APP" > "${DIR}/test_output.log" 2>&1

echo "=== Test Output ==="
cat "${DIR}/test_output.log"
echo "==================="

# Basic verification: check if the dummy auditor actually logged anything
if grep -q "\[Dummy Auditor\] la_version called with:" "${DIR}/test_output.log"; then
    echo "PASS: Dummy auditor was successfully loaded and executed by the multiplexer."
else
    echo "FAIL: Dummy auditor output not found. Multiplexer may have failed to load it."
    exit 1
fi

echo ""
echo "=== Running Test 4: Per-symbol dynamic suppression ==="

# Resolve paths for Test 4
APP4="${DIR}/test4_main"
AUDITOR4_1="${DIR}/.libs/libtest4_auditor1.so"
AUDITOR4_2="${DIR}/.libs/libtest4_auditor2.so"

# Verify Test 4 binaries exist
if [ ! -f "$APP4" ]; then
    echo "Error: $APP4 not found! Did you build it?"
    exit 1
fi

if [ ! -f "$AUDITOR4_1" ] || [ ! -f "$AUDITOR4_2" ]; then
    echo "Error: Test 4 auditor shared objects not found!"
    exit 1
fi

# Temporarily disable 'set -e' so we can manually catch auditor exit codes
set +e
env LD_AUDIT="$MULTIPLEXER_SO" LD_AUDIT2="${AUDITOR4_1}:${AUDITOR4_2}" "$APP4" > "${DIR}/test4_output.log" 2>&1
TEST4_EXIT_CODE=$?
set -e

echo "=== Test 4 Output ==="
cat "${DIR}/test4_output.log"
echo "====================="

# Verify Test 4 results
if [ $TEST4_EXIT_CODE -ne 0 ] || grep -q "FAIL" "${DIR}/test4_output.log"; then
    echo "FAIL: Test 4 (Per-symbol dynamic suppression) failed."
    exit 1
else
    echo "PASS: Test 4 successfully executed and verified suppression rules."
fi

# Exit successfully if all tests pass
exit 0