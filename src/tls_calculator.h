#ifndef TLS_CALCULATOR_H
#define TLS_CALCULATOR_H

#include <cstddef>
#include <string>
#include <vector>

struct TlsLibraryInfo {
    std::string path;
    size_t size;
    size_t alignment;
    bool requires_initial_exec;
};

struct TlsCalculationResult {
    size_t required_tls;
    size_t maximum_alignment;
    std::vector<TlsLibraryInfo> libraries;
};

// Calculates the combined Initial Exec (IE) static TLS requirement and
// returns the details of every ELF object visited during dependency scanning.
TlsCalculationResult calculate_ie_tls_report(
        const std::vector<std::string> &audit_libs, const std::string &app_name);

// Calculates the combined Initial Exec (IE) static TLS size requirement
// for the given list of auditor libraries and the main application.
size_t calculate_ie_tls(const std::vector<std::string> &audit_libs,
                        const std::string &app_name);

#endif // TLS_CALCULATOR_H