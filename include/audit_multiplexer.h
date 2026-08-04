#ifndef AUDIT_MULTIPLEXER_H
#define AUDIT_MULTIPLEXER_H

#include <link.h>
#include <cstdint>

#ifdef __cplusplus
extern "C" {
#endif

// Custom search flag to indicate the path was modified by a previous auditor
#ifndef LA_SER_AUDIT
#define LA_SER_AUDIT 0x1000
#endif

// Converts the cookie returned by la_objopen into a link_map pointer
struct link_map* la_cookie_to_link_map(uintptr_t* cookie);

#ifdef __cplusplus
}
#endif

#endif // AUDIT_MULTIPLEXER_H