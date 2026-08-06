#!/bin/bash
set -e

# Use environment variables provided by AM_TESTS_ENVIRONMENT in Makefile.am.
# Fallbacks are provided just in case the script is run manually outside of 'make check'.
TEST_DIR=${TEST_DIR:-.}
LIBS_DIR=${LIBS_DIR:-${TEST_DIR}/.libs}
MUX_SO=${MUX_SO:-../.libs/audit_multiplexer.so}

AUDITOR_SO="${LIBS_DIR}/test_activity_auditor.so"
MAIN_BIN="${TEST_DIR}/test_activity_main"

if [ ! -f "$MUX_SO" ]; then
    echo "Multiplexer not found at $MUX_SO. Did you run 'make'?"
    exit 1
fi

if [ ! -f "$AUDITOR_SO" ]; then
    echo "Test auditor not found at $AUDITOR_SO. Did you run 'make check'?"
    exit 1
fi

echo "==========================================================="
echo "Running Activity Ordering Test"
echo "Chaining: Multiplexer -> Strict Auditor"
echo "==========================================================="

# Ensure LIBS_DIR is in the library path so libbad.so can find libgood.so
# (Automake already sets this, but this ensures it works if run manually)
export LD_LIBRARY_PATH="${LIBS_DIR}:${LD_LIBRARY_PATH}"

# Execute the test. If test_activity_auditor.c calls exit(1), this script will fail.
LD_AUDIT="$MUX_SO:$AUDITOR_SO" "$MAIN_BIN"

echo "==========================================================="
echo "SUCCESS: All activity states were perfectly consistent!"
echo "==========================================================="