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
    exit 0
else
    echo "FAIL: Dummy auditor output not found. Multiplexer may have failed to load it."
    exit 1
fi