# LD_AUDIT Multiplexer Test Suite

This directory contains the test suite for the `LD_AUDIT` multiplexer library. The tests are designed to validate the correct interception, chaining, and forwarding of dynamic linker events to multiple loaded auditors. 

The suite is integrated with the Autotools build system and can be executed automatically.

## Test Scenarios

### Test 1: Basic Event Forwarding
*   **Objective:** Verify that the multiplexer successfully intercepts the initial `LD_AUDIT` startup sequence and loads chained auditors.
*   **Mechanism:** Uses a simple `dummy_auditor.so` and `dummy_app`. 
*   **Validation:** Confirms that `la_version` and standard initialization callbacks are correctly forwarded to the sub-auditor and that its output is visible in the logs.

### Test 2: Namespace Traversal
*   **Objective:** Ensure the multiplexer correctly handles link maps across different linker namespaces (e.g., via `dlmopen`).
*   **Mechanism:** Tests the `am_iterate_maps` function and the translation of auditor cookies back to `link_map` structures.
*   **Validation:** Verifies that sub-auditors can reliably query and iterate through loaded modules outside of the primary namespace without causing segmentation faults or missing objects.

### Test 3: Dynamic Load Chain Reaction
*   **Objective:** Validate multiplexer stability during runtime dynamic module loading.
*   **Mechanism:** Triggers `dlopen` calls during early initialization phases (such as `la_preinit`) or from within shared libraries themselves.
*   **Validation:** Ensures that recursive or nested dynamic linker events do not deadlock the multiplexer and that new objects are correctly announced to all loaded sub-auditors via `la_objopen`.

### Test 4: Per-Symbol PLT Suppression
*   **Objective:** Test architecture-specific PLT interception (`la_pltenter` / `la_pltexit`) and the accurate merging of symbol-specific flags (`LA_SYMB_NOPLTENTER` / `LA_SYMB_NOPLTEXIT`).
*   **Mechanism:** Uses two chained auditors (`test4_auditor1` and `test4_auditor2`) tracking a target application (`test4_main`) executing three distinct functions (`func1`, `func2`, `func3`). 
*   **Validation:** 
    *   **func1:** Both enter and exit are suppressed.
    *   **func2:** Only enter is suppressed.
    *   **func3:** Only exit is suppressed.
    *   The test fails if the dynamic linker invokes `ARCH_LA_PLTENTER` or `ARCH_LA_PLTEXIT` when a sub-auditor has explicitly applied a suppression flag in `la_symbind`.

---

## Running the Tests

To compile and run the entire test suite, execute the following from the project root:

```bash
make check