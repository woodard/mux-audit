#include "audit_multiplexer.h"
#include <link.h>
#include <cstdlib>
#include <cstdio>

extern "C" {

struct link_map* la_cookie_to_link_map(uintptr_t* cookie) {
    return reinterpret_cast<struct link_map*>(cookie);
}

void am_iterate_maps(void (*cb)(struct link_map*)) {
    // Abort if the system dynamically fell back to a glibc version older than 2.35
    if (_r_debug.r_version < 2) {
        fprintf(stderr, "[audit_utils] Error: System dynamic linker does not support r_version >= 2.\n");
        return;
    }

    // Cast to the extended structure introduced in glibc 2.35
    struct r_debug_extended* ext_debug = reinterpret_cast<struct r_debug_extended*>(&_r_debug);

    // Traverse the linked list of namespaces
    while (ext_debug != nullptr) {
        struct link_map* lmap = ext_debug->base.r_map;
        
        // Ensure we start at the absolute head of this namespace's link_map chain
        while (lmap && lmap->l_prev) {
            lmap = lmap->l_prev;
        }

        // Iterate through all objects loaded into this specific namespace
        while (lmap) {
            cb(lmap);
            lmap = lmap->l_next;
        }

        // Move to the next namespace
        ext_debug = ext_debug->r_next;
    }
}

} // extern "C"