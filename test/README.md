# LD_AUDIT Multiplexer Test Suite

This directory contains the test suite for the `LD_AUDIT` multiplexer library.[cite: 3] The tests are designed to validate the correct interception, chaining, and forwarding of dynamic linker events to multiple loaded auditors.[cite: 3]

The suite is integrated with the Autotools build system and can be executed automatically.[cite: 3]

## Test Scenarios

### Test 1: Basic Event Forwarding
*   **Objective:** Verify that the multiplexer successfully intercepts the initial `LD_AUDIT` startup sequence and loads chained auditors.[cite: 3]
*   **Mechanism:** Uses a simple `dummy_auditor.so` and `dummy_app`.[cite: 3]
*   **Validation:** Confirms that `la_version` and standard initialization callbacks are correctly forwarded to the sub-auditor and that its output is visible in the logs.[cite: 3]

### Test 2: Namespace Traversal
*   **Objective:** Ensure the multiplexer correctly handles link maps across different linker namespaces (e.g., via `dlmopen`).[cite: 3]
*   **Mechanism:** Tests the `am_iterate_maps` function and the translation of auditor cookies back to `link_map` structures.[cite: 3]
*   **Validation:** Verifies that sub-auditors can reliably query and iterate through loaded modules outside of the primary namespace without causing segmentation faults or missing objects.[cite: 3]

### Test 3: Dynamic Load Chain Reaction
*   **Objective:** Validate multiplexer stability during runtime dynamic module loading.[cite: 3]
*   **Mechanism:** Triggers `dlopen` calls during early initialization phases (such as `la_preinit`) or from within shared libraries themselves.[cite: 3]
*   **Validation:** Ensures that recursive or nested dynamic linker events do not deadlock the multiplexer and that new objects are correctly announced to all loaded sub-auditors via `la_objopen`.[cite: 3]

### Test 4: Per-Symbol PLT Suppression
*   **Objective:** Test architecture-specific PLT interception (`la_pltenter` / `la_pltexit`) and the accurate merging of symbol-specific flags (`LA_SYMB_NOPLTENTER` / `LA_SYMB_NOPLTEXIT`).[cite: 3]
*   **Mechanism:** Uses two chained auditors (`test4_auditor1` and `test4_auditor2`) tracking a target application (`test4_main`) executing three distinct functions (`func1`, `func2`, `func3`).[cite: 3]
*   **Validation:** 
    *   **func1:** Both enter and exit are suppressed.[cite: 3]
    *   **func2:** Only enter is suppressed.[cite: 3]
    *   **func3:** Only exit is suppressed.[cite: 3]
    *   The test fails if the dynamic linker invokes `ARCH_LA_PLTENTER` or `ARCH_LA_PLTEXIT` when a sub-auditor has explicitly applied a suppression flag in `la_symbind`.[cite: 3]

### Test 5: Prior Auditor Hijacking
*   **Objective:** Verify that the multiplexer can detect uncontrolled "rogue" auditors that the dynamic linker loaded *before* the multiplexer in the `LD_AUDIT` chain.
*   **Mechanism:** Places `libdummy_auditor.so` before `audit_multiplexer.so` in the `LD_AUDIT` environment variable during process launch.
*   **Validation:** Ensures the multiplexer securely detects the prior auditor via linker namespace introspection (without invoking unsafe `dlopen`/`dlsym` calls), force-migrates the rogue auditor into `LD_AUDIT2`, and safely triggers a process re-execution to gain exclusive control.

### Test 6: Subsequent Auditor Hijacking
*   **Objective:** Verify that the multiplexer successfully intercepts uncontrolled auditors that appear *after* it in the `LD_AUDIT` chain.
*   **Mechanism:** Appends `libdummy_auditor.so` after `audit_multiplexer.so` in the `LD_AUDIT` environment variable.
*   **Validation:** Verifies the multiplexer successfully parses the `LD_AUDIT` environment string during `la_version`, properly constructs an updated `LD_AUDIT2` chain, and executes its self-healing re-execution while enforcing strict binding (`LD_BIND_NOW=1`) to prevent linker assertion panics.

### DT_AUDIT Integration Test (`run_test_dtaudit.sh`)
*   **Objective:** Verifies that the multiplexer successfully asserts control over the chain even when initialized via a hardcoded ELF `DT_AUDIT` directive instead of the standard environment variables.
*   **Mechanism:** Compiles a minimal application (`dt_audit_app`) with the multiplexer directly injected into its `.dynamic` section via `-Wl,--audit`. Concurrently, it injects `libdummy_auditor.so` into the `LD_AUDIT` environment variable.
*   **Validation:** 
    *   Ensures the `AM_MUX_ACTIVE` lock successfully prevents feedback loops and double-loading.
    *   Validates that the multiplexer safely intercepts the rogue environment auditor from a `DT_AUDIT` context and successfully orchestrates the process re-execution.

---

## Running the Tests

To compile and run the entire test suite, execute the following from the project root:[cite: 3]

```bash
make check