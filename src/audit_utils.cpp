#include "audit_multiplexer.h"
#include <link.h>
#include <cstdlib>
#include <cstdio>
#include <elf.h>
#include <cstddef>
#include <unordered_map>
#include <unordered_set>
#include <shared_mutex>
#include <mutex>

static std::unordered_map<Lmid_t, uintptr_t*> g_lmid_to_ns_cookie;
static std::unordered_map<uintptr_t*, uintptr_t*> g_obj_to_ns_cookie;
static std::unordered_set<uintptr_t*> g_ns_deleting_set;
static std::unordered_set<uintptr_t*> g_ns_added_set;
static std::unordered_map<uintptr_t*, size_t> g_ns_refcount;
static std::shared_mutex g_cookie_map_mutex;

extern "C" {

void am_iterate_maps(void (*cb)(struct link_map*)) {
    if (_r_debug.r_version < 2) {
        fprintf(stderr, "[audit_utils] Error: System dynamic linker does not support r_version >= 2.\n");
        return;
    }
    struct r_debug_extended* ext_debug = reinterpret_cast<struct r_debug_extended*>(&_r_debug);
    while (ext_debug != nullptr) {
        struct link_map* lmap = ext_debug->base.r_map;
        while (lmap && lmap->l_prev) {
            lmap = lmap->l_prev;
        }
        while (lmap) {
            cb(lmap);
            lmap = lmap->l_next;
        }
        ext_debug = ext_debug->r_next;
    }
}

bool am_track_ns_cookie(Lmid_t lmid, uintptr_t* cookie) {
    std::unique_lock<std::shared_mutex> lock(g_cookie_map_mutex);
    bool is_new_ns = false;
    if (g_lmid_to_ns_cookie.find(lmid) == g_lmid_to_ns_cookie.end()) {
        g_lmid_to_ns_cookie[lmid] = cookie;
        is_new_ns = true;
    }
    uintptr_t* ns_cookie = g_lmid_to_ns_cookie[lmid];
    g_obj_to_ns_cookie[cookie] = ns_cookie;
    g_ns_refcount[ns_cookie]++;
    return is_new_ns;
}

void am_untrack_ns_cookie(uintptr_t* cookie) {
    std::unique_lock<std::shared_mutex> lock(g_cookie_map_mutex);
    auto it = g_obj_to_ns_cookie.find(cookie);
    if (it != g_obj_to_ns_cookie.end()) {
        uintptr_t* ns_cookie = it->second;
        g_obj_to_ns_cookie.erase(it);
        auto ref_it = g_ns_refcount.find(ns_cookie);
        if (ref_it != g_ns_refcount.end()) {
            ref_it->second--;
            if (ref_it->second == 0) {
                g_ns_refcount.erase(ref_it);
                g_ns_deleting_set.erase(ns_cookie);
                g_ns_added_set.erase(ns_cookie);
                for (auto ns_it = g_lmid_to_ns_cookie.begin(); ns_it != g_lmid_to_ns_cookie.end(); ) {
                    if (ns_it->second == ns_cookie) {
                        ns_it = g_lmid_to_ns_cookie.erase(ns_it);
                    } else {
                        ++ns_it;
                    }
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

bool am_mark_ns_deleting(uintptr_t* ns_cookie) {
    std::unique_lock<std::shared_mutex> lock(g_cookie_map_mutex);
    if (!ns_cookie) return false;
    return g_ns_deleting_set.insert(ns_cookie).second;
}

void am_unmark_ns_deleting(uintptr_t* ns_cookie) {
    std::unique_lock<std::shared_mutex> lock(g_cookie_map_mutex);
    if (ns_cookie) {
        g_ns_deleting_set.erase(ns_cookie);
    }
}

bool am_mark_ns_added(uintptr_t* ns_cookie) {
    std::unique_lock<std::shared_mutex> lock(g_cookie_map_mutex);
    if (!ns_cookie) return false;
    return g_ns_added_set.insert(ns_cookie).second;
}

void am_unmark_ns_added(uintptr_t* ns_cookie) {
    std::unique_lock<std::shared_mutex> lock(g_cookie_map_mutex);
    if (ns_cookie) {
        g_ns_added_set.erase(ns_cookie);
    }
}

} // extern "C"

static std::vector<am_init_fini_fn_t> am_get_init_fini(struct link_map* map, bool is_init) {
    std::vector<am_init_fini_fn_t> funcs;
    if (!map || !map->l_ld) return funcs;

    ElfW(Dyn)* dyn = (ElfW(Dyn)*)map->l_ld;
    ElfW(Addr) single_ptr = 0;
    ElfW(Addr) array_ptr = 0;
    size_t array_sz = 0;

    long tag_single = is_init ? DT_INIT : DT_FINI;
    long tag_array  = is_init ? DT_INIT_ARRAY : DT_FINI_ARRAY;
    long tag_arraysz = is_init ? DT_INIT_ARRAYSZ : DT_FINI_ARRAYSZ;

    for (ElfW(Dyn)* d = dyn; d->d_tag != DT_NULL; ++d) {
        if (d->d_tag == tag_single) single_ptr = d->d_un.d_ptr;
        else if (d->d_tag == tag_array) array_ptr = d->d_un.d_ptr;
        else if (d->d_tag == tag_arraysz) array_sz = d->d_un.d_val;
    }

    if (single_ptr) {
        funcs.push_back(reinterpret_cast<am_init_fini_fn_t>(map->l_addr + single_ptr));
    }

    if (array_ptr && array_sz > 0) {
        size_t num_funcs = array_sz / sizeof(ElfW(Addr));
        ElfW(Addr)* array = reinterpret_cast<ElfW(Addr)*>(map->l_addr + array_ptr);
        for (size_t i = 0; i < num_funcs; ++i) {
            if (array[i] != 0 && array[i] != static_cast<ElfW(Addr)>(-1)) {
                funcs.push_back(reinterpret_cast<am_init_fini_fn_t>(map->l_addr + array[i]));
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