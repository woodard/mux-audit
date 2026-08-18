# LD_AUDIT Multiplexer (`audit_multiplexer`)

The `audit_multiplexer` is a robust, self-healing dynamic linker auditing (`LD_AUDIT`) library. Its primary purpose is to maintain exclusive control over the `ld.so` audit chain and safely multiplex dynamic linker events (such as object loading, symbol binding, and PLT execution) to multiple chained sub-auditors.

Since `ld.so` only supports a single `LD_AUDIT` namespace and can exhibit undefined behavior or panics when multiple auditors conflict, `audit_multiplexer` solves this by forcing itself as the sole primary auditor and orchestrating all other auditors via an internal mechanism.

## Key Features

*   **Self-Healing & Auditor Hijacking:** Automatically detects uncontrolled "rogue" auditors loaded via the `LD_AUDIT` environment variable. If found, the multiplexer safely rewrites the environment, migrating all other libraries to `LD_AUDIT2`, and re-executes the process to gain exclusive control.
*   **Foreign DT_AUDIT Detection:** Safely parses the target executable's `.dynamic` section during early initialization (`la_preinit`). Emits soft warnings if foreign `DT_AUDIT` directives are detected, suggesting remediation via `patchelf`.
*   **Multi-Namespace Support:** Safely manages link maps across different linker namespaces (e.g., from `dlmopen`), using safe iterations over `struct r_debug_extended`.
*   **Per-Symbol PLT Chaining:** Intelligently merges architecture-specific PLT suppression flags (`LA_SYMB_NOPLTENTER`, `LA_SYMB_NOPLTEXIT`) from multiple sub-auditors to ensure efficient symbol binding without missing requested events.
*   **Anti-Reentrancy Defenses:** Employs safe initialization (`dladdr`), an environmental lock (`AM_MUX_ACTIVE`), and forces strict binding (`LD_BIND_NOW=1`) to prevent catastrophic `ld.so` re-entrancy panics during dynamic object loading.

## Building and Installation

This project uses the GNU Autotools build system.

### Prerequisites
*   `autoconf`, `automake`, `libtool`
*   A C++17 (or newer) compatible compiler (GCC or Clang)
*   GNU C Library (glibc) providing `<link.h>`

### Build Instructions

```bash
# 1. Generate the configure script (if cloning from a repository)
autoreconf -fi

# 2. Configure the build environment
./configure

# 3. Build the multiplexer and tests
make

# 4. Install (typically requires root)
sudo make install

# 5. Generate the API reference (requires Doxygen)
make doxygen

```

### Standalone TLS Calculator

The `tls-calculator` utility calculates the optional static TLS surplus for an
application and any auditors that will be loaded at startup:

```bash
tls-calculator --audit /path/to/auditor.so --verbose /path/to/application
```

Pass `--audit` once for each auditor. The final output is a glibc tunable that
can be placed in `GLIBC_TUNABLES`:

```text
glibc.rtld.optional_static_tls=45056
```

## Usage

To use the multiplexer, you must set `audit_multiplexer.so` as your primary auditor, and specify your desired chained auditors in the `LD_AUDIT2` environment variable, separated by colons.

```bash
export LD_AUDIT=/path/to/audit_multiplexer.so
export LD_AUDIT2=/path/to/my_auditor1.so:/path/to/my_auditor2.so

./my_target_application

```

### Self-Healing Behavior

If you or a third-party script accidentally invokes your application with other `LD_AUDIT` libraries:

```bash
export LD_AUDIT=/usr/lib/rogue_auditor.so:/path/to/audit_multiplexer.so

```

The multiplexer will automatically detect the loss of exclusive control, reconfigure the environment to `LD_AUDIT2=/usr/lib/rogue_auditor.so`, set `LD_BIND_NOW=1`, and re-execute the application completely transparently.

### Hardcoded Executable Directives (DT_AUDIT)

If your target application was compiled with a hardcoded ELF audit tag (e.g., `gcc -Wl,--audit=...`), the multiplexer will detect this during `la_preinit` and emit a warning to `stderr`. The application will not terminate, but the hardcoded auditor will bypass the multiplexer's event chaining.

To fix this, it is recommended to patch the executable:

```bash
patchelf --remove-audit /path/to/rogue_auditor.so <executable>
patchelf --add-audit /path/to/audit_multiplexer.so <executable>

```

## Test Suite

The project includes a comprehensive, Automake-managed test suite that validates event chaining, namespace traversal, dynamic loading stability, PLT flag suppression, and the self-healing mechanisms.

To run the full suite:

```bash
make check

```

For more specific information on the testing architecture, refer to `test/README.md`.
