#!/bin/bash

echo "==========================================================="
echo "=== Running Static TLS Alignment Test ==="
echo "=== Verifying glibc alignment compliance for auditors ==="
echo "==========================================================="

OUTPUT=$(LD_AUDIT="${MUX_SO}" LD_AUDIT2="${LIBS_DIR}/test_tls_align_auditor.so" "${TEST_DIR}/test_tls_align_main" 2>&1)
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    echo "FAIL: Application exited with error code $EXIT_CODE."
    echo "Output:"
    echo "$OUTPUT"
    exit 1
fi

# Ensure the auditor did not trigger its own internal failure condition
if echo "$OUTPUT" | grep -q "ERROR: test_align_tls is not"; then
    echo "FAIL: Auditor reported incorrect TLS alignment and likely crashed."
    echo "Output:"
    echo "$OUTPUT"
    exit 1
fi

# Confirm the auditor actually ran and validated the alignment
if echo "$OUTPUT" | grep -q "TLS is correctly aligned at"; then
    echo "PASS: Auditor verified correct static TLS alignment."
else
    echo "FAIL: Did not see success message from auditor. Did it load?"
    echo "Output:"
    echo "$OUTPUT"
    exit 1
fi

echo "All TLS Alignment conditions passed."
exit 0