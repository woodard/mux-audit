#include "audit_multiplexer.h"

extern "C" {

struct link_map* la_cookie_to_link_map(uintptr_t* cookie) {
    return reinterpret_cast<struct link_map*>(cookie);
}

} // extern "C"