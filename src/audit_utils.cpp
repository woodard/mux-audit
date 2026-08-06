#include "audit_multiplexer.h"
#include <link.h>
#include <cstdlib>
#include <cstdio>
#include <elf.h>
#include <cstddef>
#include <unordered_map>
#include <shared_mutex>
#include <mutex>

// Stateful maps for namespace tracking
static std::unordered_map<Lmid_t, uintptr_t*> g_lmid_to_ns_cookie;
static std::unordered_map<uintptr_t*, uintptr_t*> g_obj_to_ns_cookie;

// Note on Thread Safety:
// While the glibc dynamic linker (ld.so) strictly serializes object
// loading and unloading (meaning la_objopen and la_objclose will
// never run concurrently), a shared mutex is still mandatory. This
// protects against catastrophic map rehashing if a thread calls
// dlopen() (triggering a write via la_objopen) at the exact same time
// another thread executes a PLT intercept (triggering a read via
// la_pltenter), or if a sub-auditor queries the map from a background
// thread.
static std::shared_mutex g_cookie_map_mutex;

extern "C" {

struct link_map* la_cookie_to_link_map(uintptr_t* cookie) {
    if (!cookie) return nullptr;
    // Dereference to get the stored address, then cast
    return reinterpret_cast<struct link_map*>(*cookie);
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

void am_track_ns_cookie(Lmid_t lmid, uintptr_t* cookie) {
    std::unique_lock<std::shared_mutex> lock(g_cookie_map_mutex);
    
    // The first object we see for a given LMID is the namespace head
    if (g_lmid_to_ns_cookie.find(lmid) == g_lmid_to_ns_cookie.end()) {
        g_lmid_to_ns_cookie[lmid] = cookie; 
    }
    
    // Map this object's cookie to its namespace head cookie
    g_obj_to_ns_cookie[cookie] = g_lmid_to_ns_cookie[lmid];
}

void am_untrack_ns_cookie(uintptr_t* cookie) {
    std::unique_lock<std::shared_mutex> lock(g_cookie_map_mutex);
    
    auto it = g_obj_to_ns_cookie.find(cookie);
    if (it != g_obj_to_ns_cookie.end()) {
        uintptr_t* ns_cookie = it->second;
        g_obj_to_ns_cookie.erase(it);

        // If the closing object IS the namespace head, clean up the LMID map
        if (ns_cookie == cookie) {
            for (auto ns_it = g_lmid_to_ns_cookie.begin(); ns_it != g_lmid_to_ns_cookie.end(); ++ns_it) {
                if (ns_it->second == cookie) {
                    g_lmid_to_ns_cookie.erase(ns_it);
                    break;
                }
            }
        }
    }
}

uintptr_t* la_obj_cookie_to_ns_cookie(uintptr_t* cookie) {
    std::shared_lock<std::shared_mutex> lock(g_cookie_map_mutex);
    
    auto it = g_obj_to_ns_cookie.find(cookie);
    if (it != g_obj_to_ns_cookie.end()) {
        return it->second;
    }
    
    return nullptr;
}

} // extern "C"


// Internal static helper to reduce duplication for constructors/destructors
static std::vector<am_init_fini_fn_t> am_get_init_fini(struct link_map* map, bool is_init) {
    std::vector<am_init_fini_fn_t> funcs;
    if (!map || !map->l_ld) return funcs;

    ElfW(Dyn)* dyn = (ElfW(Dyn)*)map->l_ld;
    ElfW(Addr) single_ptr = 0;
    ElfW(Addr) array_ptr = 0;
    size_t array_sz = 0;

    // Determine which ELF tags we are searching for
    long tag_single = is_init ? DT_INIT : DT_FINI;
    long tag_array  = is_init ? DT_INIT_ARRAY : DT_FINI_ARRAY;
    long tag_arraysz = is_init ? DT_INIT_ARRAYSZ : DT_FINI_ARRAYSZ;

    // Parse the dynamic section for the correct tags
    for (ElfW(Dyn)* d = dyn; d->d_tag != DT_NULL; ++d) {
        if (d->d_tag == tag_single) {
            single_ptr = d->d_un.d_ptr;
        } else if (d->d_tag == tag_array) {
            array_ptr = d->d_un.d_ptr;
        } else if (d->d_tag == tag_arraysz) {
            array_sz = d->d_un.d_val;
        }
    }

    // Add the legacy constructor/destructor if present
    if (single_ptr) {
        funcs.push_back(
            reinterpret_cast<am_init_fini_fn_t>(map->l_addr + single_ptr)
        );
    }

    // Add all functions from the array
    if (array_ptr && array_sz > 0) {
        size_t num_funcs = array_sz / sizeof(ElfW(Addr));
        ElfW(Addr)* array = reinterpret_cast<ElfW(Addr)*>(map->l_addr + array_ptr);
        
        // Note: Destructors in DT_FINI_ARRAY are typically executed in reverse order by the dynamic linker
        for (size_t i = 0; i < num_funcs; ++i) {
            if (array[i] != 0 && array[i] != static_cast<ElfW(Addr)>(-1)) {
                // array[i] contains the offset/address of the function
                funcs.push_back(
                    reinterpret_cast<am_init_fini_fn_t>(map->l_addr + array[i])
                );
            }
        }
    }

    return funcs;
}


std::vector<am_init_fini_fn_t> am_get_constructors(struct link_map* map) {
    return am_get_init_fini(map, true);
}


std::vector<am_init_fini_fn_t> am_get_destructors(struct link_map* map) {
    return am_get_init_fini(map, false);
}
