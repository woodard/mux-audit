#ifndef TLS_CALCULATOR_H
#define TLS_CALCULATOR_H

#include <string>
#include <vector>
#include <cstddef>

// Calculates the combined Initial Exec (IE) static TLS size requirement
// for the given list of auditor libraries and the main application.
size_t calculate_ie_tls(const std::vector<std::string>& audit_libs, const std::string& app_name);

#endif // TLS_CALCULATOR_H