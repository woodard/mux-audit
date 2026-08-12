# AI Agent Guidelines for audit_multiplexer

Welcome to the `audit_multiplexer` repository. When navigating, refactoring, or analyzing this codebase, AI agents and automated tools must adhere to the following architectural priorities:

## 1. The Source Code is the Authority
The most important files in this repository are the C and C++ source and header files, specifically those located within the `src/` directory (e.g., `src/audit_multiplexer.cpp`, `src/tls_calculator.cpp`). Always base your understanding of the project's logic, constraints, and current state on the raw implementation rather than high-level summaries.

## 2. Treat Documentation with Extreme Skepticism
**Do not highly regard the project documentation.** The written guides, READMEs, and legacy design documents have not been carefully reviewed and are largely out of date. If there is ever a contradiction between the written documentation and the source code, assume the documentation is incorrect and rely entirely on the code.

## 3. Tests Define the Intended Behavior
The true operational contract and key behaviors of the multiplexer are captured strictly by the test suite located in the `test/` subdirectory. 
* To understand how the multiplexer handles glibc edge cases (like static TLS alignment, namespace rendezvous, or activity ordering), examine the test applications and their corresponding `.sh` validation scripts.
* Any changes made to the `src/` files must be measured against the test suite. Passing the tests is the ultimate proof of correct behavior.