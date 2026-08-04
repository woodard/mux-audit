#ifndef AUDIT_MULTIPLEXER_H
#define AUDIT_MULTIPLEXER_H

#include <link.h>
#include <cstdint>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef LA_SER_AUDIT
#define LA_SER_AUDIT 0x1000
#endif

// Converts the cookie returned by la_objopen into a link_map pointer
struct link_map* la_cookie_to_link_map(uintptr_t* cookie);

// Allows sub-auditors to iterate through all known link_maps across all namespaces
void am_iterate_maps(void (*cb)(struct link_map*));

#ifdef __cplusplus
}
#endif

#endif // AUDIT_MULTIPLEXER_H