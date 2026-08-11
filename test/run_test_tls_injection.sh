#!/bin/bash

echo "==========================================================="
echo "=== Running Static TLS Injection Test ==="
echo "=== Verifying GLIBC_TUNABLES sizing and injection ==="
echo "==========================================================="

OUTPUT=$(LD_AUDIT="${MUX_SO}" LD_AUDIT2="${LIBS_DIR}/test_tls_auditor.so" ./test_tls_main 2>&1)
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    echo "FAIL: Application exited with error code $EXIT_CODE. (Likely failed to allocate TLS)"
    echo "Output:"
    echo "$OUTPUT"
    exit 1
fi

# Condition 1: Verify the multiplexer detected the requirement and injected the tunable
if echo "$OUTPUT" | grep -q "audit_multiplexer: reexecing to acquire more static TLS."; then
    echo "PASS: Multiplexer dynamically calculated and injected GLIBC_TUNABLES."
else
    echo "FAIL: Multiplexer did not emit the GLIBC_TUNABLES adjustment warning."
    echo "Output:"
    echo "$OUTPUT"
    exit 1
fi

# Condition 2: Verify the application actually reached main() without crashing
if echo "$OUTPUT" | grep -q "\[main\] Application executing successfully with large IE TLS."; then
    echo "PASS: Application accessed the large TLS block and executed successfully."
else
    echo "FAIL: Application failed to reach or complete main()."
    echo "Output:"
    echo "$OUTPUT"
    exit 1
fi

echo "All TLS Injection conditions passed."
exit 0