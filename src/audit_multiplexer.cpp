/**
 * ==============================================================================
 * AUDIT MULTIPLEXER LIMITATIONS & ARCHITECTURAL DOCUMENTATION
 * ==============================================================================
 *
 * 1. la_objsearch Semantics Limitation:
 *    Because sub-auditors are loaded natively by glibc in `la_version`, glibc 
 *    suppresses their initial startup events from their own perspective. We
 *    manually replay history for `la_objsearch` and `la_objopen`. Consequently, 
 *    if a sub-auditor attempts to modify the search path during this replay, 
 *    the modification is IGNORED, as the object is already mapped.
 * 
 * 2. Lack of Auditor-to-Auditor PLT / Symbind Interception:
 *    Glibc does not emit `la_symbind`, `la_pltenter`, or `la_pltexit` events for 
 *    objects loaded into an auditor's namespace (LM_ID_NEWLM). As a result, the 
 *    multiplexer cannot broadcast these events between sibling sub-auditors. 
 * ==============================================================================
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "audit_multiplexer.h"
#include <link.h>
#include <dlfcn.h>
#include <unistd.h>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <string>
#include <mutex>
#include <shared_mutex>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <memory>
#include <cstdio>
#include <iostream>
#include <fstream>
#include <sstream>
#include <elf.h>

// -----------------------------------------------------------------------------
// Core Tracking Structures
// -----------------------------------------------------------------------------

struct SymBindKey {
    uintptr_t* refcook;
    uintptr_t* defcook;
    unsigned int ndx;
    bool operator==(const SymBindKey& other) const {
        return refcook == other.refcook && defcook == other.defcook && ndx == other.ndx;
    }
};

struct SymBindKeyHash {
    std::size_t operator()(const SymBindKey& k) const {
        auto h1 = std::hash<uintptr_t*>{}(k.refcook);
        auto h2 = std::hash<uintptr_t*>{}(k.defcook);
        auto h3 = std::hash<unsigned int>{}(k.ndx);
        return h1 ^ (h2 << 1) ^ (h3 << 2);
    }
};

struct Auditor {
    void* handle;

    // Function Pointers
    unsigned int (*version)(unsigned int);
    char* (*objsearch)(const char*, uintptr_t*, unsigned int);
    unsigned int (*objopen)(struct link_map*, Lmid_t, uintptr_t*);
    void (*preinit)(uintptr_t*);
    void (*activity)(uintptr_t*, unsigned int);
    unsigned int (*objclose)(uintptr_t*);
    uintptr_t (*symbind64)(Elf64_Sym*, unsigned int, uintptr_t*, uintptr_t*, unsigned int*, const char*);
    Elf64_Addr (*pltenter)(Elf64_Sym*, unsigned int, uintptr_t*, uintptr_t*, ARCH_REGS*, unsigned int*, const char*, long int*);
    unsigned int (*pltexit)(Elf64_Sym*, unsigned int, uintptr_t*, uintptr_t*, const ARCH_REGS*, ARCH_RETVAL*, const char*);

    // State Tracking
    std::shared_mutex obj_mutex;
    std::unordered_map<uintptr_t*, unsigned int> obj_flags;

    std::shared_mutex sym_mutex;
    std::unordered_map<SymBindKey, unsigned int, SymBindKeyHash> sym_flags;

    bool wants_symbind(uintptr_t* refcook, uintptr_t* defcook) {
        std::shared_lock<std::shared_mutex> lock(obj_mutex);
        if (obj_flags.count(refcook) && obj_flags.at(refcook) == 0) return false;
        if (obj_flags.count(defcook) && obj_flags.at(defcook) == 0) return false;
        return true;
    }
};

static std::vector<std::unique_ptr<Auditor>>& get_auditors() {
    static std::vector<std::unique_ptr<Auditor>>* auditors = new std::vector<std::unique_ptr<Auditor>>();
    return *auditors;
}

static std::vector<struct link_map*> g_all_maps;
static std::mutex g_maps_mutex;

static void am_register_map(struct link_map* map) {
    std::lock_guard<std::mutex> lock(g_maps_mutex);
    for (auto m : g_all_maps) if (m == map) return;
    g_all_maps.push_back(map);
}

struct ObjectRecord {
    struct link_map* lmap;
    Lmid_t lmid;
    uintptr_t* cookie;
};
static std::vector<ObjectRecord> g_history;
static std::mutex g_history_mutex;

static std::unordered_map<struct link_map*, uintptr_t> g_synthesized_cookies;
static std::mutex g_synth_cookie_mutex;

// Track the namespace LMID of every cookie (native or synthetic) for self-reporting bypass
static std::unordered_map<uintptr_t*, Lmid_t> g_cookie_to_lmid;
static std::mutex g_cookie_lmid_mutex;

// Structural offset calculated at runtime to robustly map uninitialized glibc cookies
static size_t g_cookie_offset = 0;

static void set_cookie_lmid(uintptr_t* cookie, Lmid_t lmid) {
    if (!cookie) return;
    std::lock_guard<std::mutex> lock(g_cookie_lmid_mutex);
    g_cookie_to_lmid[cookie] = lmid;
}

static Lmid_t get_cookie_lmid(uintptr_t* cookie) {
    if (!cookie) return -1;
    std::lock_guard<std::mutex> lock(g_cookie_lmid_mutex);
    auto it = g_cookie_to_lmid.find(cookie);
    if (it != g_cookie_to_lmid.end()) {
        return it->second;
    }
    return -1;
}

static uintptr_t* get_synth_cookie(struct link_map* map) {
    std::lock_guard<std::mutex> lock(g_synth_cookie_mutex);
    if (g_synthesized_cookies.find(map) == g_synthesized_cookies.end()) {
        g_synthesized_cookies[map] = reinterpret_cast<uintptr_t>(map);
    }
    return &g_synthesized_cookies[map];
}

static struct link_map* get_lmap_from_cookie(uintptr_t* cookie) {
    if (!cookie) return nullptr;
    if (g_cookie_offset != 0) {
        return reinterpret_cast<struct link_map*>(reinterpret_cast<char*>(cookie) - g_cookie_offset);
    }
    return la_cookie_to_link_map(cookie);
}

static uintptr_t* translate_cookie(uintptr_t* glibc_cookie) {
    if (!glibc_cookie) return nullptr;
    struct link_map* lmap = get_lmap_from_cookie(glibc_cookie);
    if (lmap) {
        std::lock_guard<std::mutex> lock(g_synth_cookie_mutex);
        auto it = g_synthesized_cookies.find(lmap);
        if (it != g_synthesized_cookies.end()) {
            return &it->second;
        }
    }
    return glibc_cookie;
}

static std::vector<char*> get_cmdline_args() {
    std::vector<char*> args;
    std::ifstream cmdline("/proc/self/cmdline");
    if (!cmdline) return args;

    std::string arg;
    while (std::getline(cmdline, arg, '\0')) {
        args.push_back(strdup(arg.c_str()));
    }
    args.push_back(nullptr);
    return args;
}

extern "C" {

// 1. Initialization and Loading
unsigned int la_version(unsigned int version) {
    if (version == 0) return version;

    // Prevent Duplicate Instances (handles DT_AUDIT and duplicate LD_AUDITs)
    if (getenv("AM_MUX_ACTIVE")) {
        return 0; 
    }
    setenv("AM_MUX_ACTIVE", "1", 1);

    bool requires_reexec = false;
    std::vector<std::string> prior_auditors;
    std::vector<std::string> subsequent_auditors;

    // SAFELY get our own path without dlopen()
    Dl_info dlinfo_self;
    if (dladdr((void*)la_version, &dlinfo_self) == 0) {
        fprintf(stderr, "[audit_multiplexer] Error: dladdr failed.\n");
        return LAV_CURRENT;
    }
    std::string my_path = dlinfo_self.dli_fname;

    // Parse LD_AUDIT for subsequent/competing auditors securely
    const char* env_ld_audit = getenv("LD_AUDIT");
    if (env_ld_audit) {
        std::stringstream ss(env_ld_audit);
        std::string token;
        bool found_myself = false;

        while (std::getline(ss, token, ':')) {
            if (token == my_path || token.find("audit_multiplexer.so") != std::string::npos) {
                found_myself = true;
                continue;
            }

            if (!found_myself) {
                prior_auditors.push_back(token);
                requires_reexec = true;
            } else {
                subsequent_auditors.push_back(token);
                requires_reexec = true;
            }
        }
    }
    
    // Re-exec if we are not in exclusive control
    if (requires_reexec) {
        fprintf(stderr, "[audit_multiplexer] WARNING: Uncontrolled auditors detected. Re-configuring environment and re-executing...\n");

        std::string new_ld_audit2 = "";
        const char* current_ld_audit2 = getenv("LD_AUDIT2");

        for (const auto& aud : prior_auditors) {
            fprintf(stderr, "[audit_multiplexer] Moving prior auditor to LD_AUDIT2: %s\n", aud.c_str());
            new_ld_audit2 += aud + ":";
        }

        if (current_ld_audit2) {
            new_ld_audit2 += std::string(current_ld_audit2) + ":";
        }

        for (const auto& aud : subsequent_auditors) {
            fprintf(stderr, "[audit_multiplexer] Moving subsequent LD_AUDIT entry to LD_AUDIT2: %s\n", aud.c_str());
            new_ld_audit2 += aud + ":";
        }

        if (!new_ld_audit2.empty() && new_ld_audit2.back() == ':') {
            new_ld_audit2.pop_back();
        }

        fprintf(stderr, "[audit_multiplexer] Setting LD_AUDIT=%s\n", my_path.c_str());
        fprintf(stderr, "[audit_multiplexer] Setting LD_AUDIT2=%s\n", new_ld_audit2.c_str());
        fprintf(stderr, "[audit_multiplexer] Executing /proc/self/exe...\n");

        setenv("LD_AUDIT", my_path.c_str(), 1);
        setenv("LD_AUDIT2", new_ld_audit2.c_str(), 1);
        
        // MUST unset the lock so the newly executed process can initialize the multiplexer
        unsetenv("AM_MUX_ACTIVE");
	
        std::vector<char*> args = get_cmdline_args();
        execv("/proc/self/exe", args.data());
        perror("execv failed");
        exit(EXIT_FAILURE);
    }

    // Normal Initialization
    const char* ld_audit2 = getenv("LD_AUDIT2");
    if (!ld_audit2) return LAV_CURRENT;

    am_iterate_maps(am_register_map);

    std::string libs(ld_audit2);
    size_t start = 0;
    size_t end = libs.find(':');

    while (start != std::string::npos) {
        std::string lib = libs.substr(start, end - start);
        if (!lib.empty()) {
            void* handle = dlmopen(LM_ID_NEWLM, lib.c_str(), RTLD_NOW | RTLD_LOCAL);
            if (handle) {
                auto v_func = (unsigned int (*)(unsigned int))dlsym(handle, "la_version");

                if (v_func && v_func(LAV_CURRENT) == LAV_CURRENT) {
                    auto aud = std::make_unique<Auditor>();
                    aud->handle = handle;
                    aud->version = v_func;
                    aud->objsearch = (decltype(aud->objsearch))dlsym(handle, "la_objsearch");
                    aud->objopen = (decltype(aud->objopen))dlsym(handle, "la_objopen");
                    aud->preinit = (decltype(aud->preinit))dlsym(handle, "la_preinit");
                    aud->activity = (decltype(aud->activity))dlsym(handle, "la_activity");
                    aud->objclose = (decltype(aud->objclose))dlsym(handle, "la_objclose");
                    aud->symbind64 = (decltype(aud->symbind64))dlsym(handle, "la_symbind64");
                    aud->pltenter = (decltype(aud->pltenter))dlsym(handle, LA_PLTENTER_STR);
                    aud->pltexit = (decltype(aud->pltexit))dlsym(handle, LA_PLTEXIT_STR);

                    get_auditors().push_back(std::move(aud));
                } else {
                    dlclose(handle);
                }
            } else {
                fprintf(stderr, "[audit_multiplexer] Warning: dlmopen failed for %s: %s\n", lib.c_str(), dlerror());
            }
        }
        if (end == std::string::npos) break;
        start = end + 1;
        end = libs.find(':', start);
    }
    return LAV_CURRENT;
}

// 2. Search Path Chaining
char* la_objsearch(const char* name, uintptr_t* cookie, unsigned int flag) {
    const char* current_name = name;
    unsigned int current_flag = flag;

    for (auto& aud_ptr : get_auditors()) {
        auto& aud = *aud_ptr;
        if (aud.objsearch) {
            char* res = aud.objsearch(current_name, cookie, current_flag);
            if (res != nullptr && strcmp(res, current_name) != 0) {
                current_name = res;
                current_flag |= LA_SER_AUDIT;
            }
        }
    }
    return const_cast<char*>(current_name);
}

// 3. Object Open
unsigned int la_objopen(struct link_map* map, Lmid_t lmid, uintptr_t* cookie) {
    if (g_cookie_offset == 0 && map && cookie) {
        g_cookie_offset = reinterpret_cast<char*>(cookie) - reinterpret_cast<char*>(map);
    }

    am_register_map(map);
    set_cookie_lmid(cookie, lmid); 
    
    // Track the cookie and determine if it belongs to a new namespace
    bool is_new_ns = am_track_ns_cookie(lmid, cookie);
    uintptr_t* ns_cookie = la_obj_cookie_to_ns_cookie(cookie);

    // Inform auditors of namespace creation before processing the object
    if (is_new_ns && ns_cookie) {
        if (am_mark_ns_added(ns_cookie)) {
            for (auto& aud_ptr : get_auditors()) {
                if (aud_ptr->activity) aud_ptr->activity(ns_cookie, LA_ACT_ADD);
            }
        }
    }

    {
        std::lock_guard<std::mutex> lock(g_history_mutex);
        g_history.push_back({map, lmid, cookie});
    }

    unsigned int overall_flags = 0;
    for (auto& aud_ptr : get_auditors()) {
        auto& aud = *aud_ptr;
        if (aud.objopen) {
            unsigned int sub_flags = aud.objopen(map, lmid, cookie);
            overall_flags |= sub_flags;

            std::unique_lock<std::shared_mutex> lock(aud.obj_mutex);
            aud.obj_flags[cookie] = sub_flags;
        }
    }
    return overall_flags;
}

void la_preinit(uintptr_t* cookie) {
    // Safely check the main executable's dynamic section for foreign DT_AUDIT tags
    struct link_map* lm = la_cookie_to_link_map(cookie);
    if (lm && lm->l_ld) {
        ElfW(Dyn)* dyn = (ElfW(Dyn)*)lm->l_ld;
        const char* strtab = nullptr;
        
        // First pass: locate the string table (DT_STRTAB)
        for (ElfW(Dyn)* d = dyn; d->d_tag != DT_NULL; ++d) {
            if (d->d_tag == DT_STRTAB) {
                ElfW(Addr) ptr = d->d_un.d_ptr;
                if (lm->l_addr != 0 && ptr < lm->l_addr) ptr += lm->l_addr;
                strtab = (const char*)ptr;
                break;
            }
        }
        
        // Second pass: scan for foreign DT_AUDIT directives
        if (strtab) {
            for (ElfW(Dyn)* d = dyn; d->d_tag != DT_NULL; ++d) {
                if (d->d_tag == DT_AUDIT || d->d_tag == 0x7ffffffb) {
                    const char* audit_lib = strtab + d->d_un.d_val;
                    // If it's not us, issue a soft warning to stderr
                    if (strstr(audit_lib, "audit_multiplexer") == nullptr) {
                        fprintf(stderr, "[audit_multiplexer] WARNING: Foreign DT_AUDIT directive detected: %s\n", audit_lib);
                        fprintf(stderr, "  This auditor will load normally but bypasses the multiplexer's control.\n");
                        fprintf(stderr, "  Suggestion (Option A): Use patchelf to rewrite the executable:\n");
                        fprintf(stderr, "    patchelf --remove-audit %s <executable>\n", audit_lib);
                        fprintf(stderr, "    patchelf --add-audit /path/to/audit_multiplexer.so <executable>\n");
                    }
                }
            }
        }
    }

    struct link_map* base_map = _r_debug.r_map;
    while (base_map && base_map->l_prev) base_map = base_map->l_prev;
    
    while (base_map) {
        bool is_tracked = false;
        {
            std::lock_guard<std::mutex> lock(g_history_mutex);
            for (const auto& rec : g_history) {
                if (rec.lmap == base_map) { is_tracked = true; break; }
            }
        }
        
        if (!is_tracked) {
            uintptr_t* synthetic_cookie = get_synth_cookie(base_map);
            set_cookie_lmid(synthetic_cookie, LM_ID_BASE);
            am_track_ns_cookie(LM_ID_BASE, synthetic_cookie);

            for (auto& aud_ptr : get_auditors()) {
                if (aud_ptr->objsearch) {
                    aud_ptr->objsearch(base_map->l_name, synthetic_cookie, LA_SER_AUDIT);
                }
                if (aud_ptr->objopen) {
                    unsigned int sub_flags = aud_ptr->objopen(base_map, LM_ID_BASE, synthetic_cookie);
                    std::unique_lock<std::shared_mutex> a_lock(aud_ptr->obj_mutex);
                    aud_ptr->obj_flags[synthetic_cookie] = sub_flags;
                }
            }
        }
        base_map = base_map->l_next;
    }

    for (size_t i = 0; i < get_auditors().size(); ++i) {
        auto& aud_ptr = get_auditors()[i];
        
        Lmid_t ns_lmid = 0;
        struct link_map* lmap = nullptr;
        if (dlinfo(aud_ptr->handle, RTLD_DI_LMID, &ns_lmid) == 0 &&
            dlinfo(aud_ptr->handle, RTLD_DI_LINKMAP, &lmap) == 0) {
            
            while (lmap && lmap->l_prev) lmap = lmap->l_prev;
            
            struct link_map* iter = lmap;
            uintptr_t* ns_cookie = get_synth_cookie(lmap);
            bool announced_add = false;

            while (iter) {
                bool is_tracked = false;
                {
                    std::lock_guard<std::mutex> lock(g_maps_mutex);
                    for (auto m : g_all_maps) {
                        if (m == iter) { is_tracked = true; break; }
                    }
                }

                if (!is_tracked) {
                    am_register_map(iter);
                    uintptr_t* obj_cookie = get_synth_cookie(iter);
                    set_cookie_lmid(obj_cookie, ns_lmid);

                    bool is_new_ns = am_track_ns_cookie(ns_lmid, obj_cookie);
                    
                    if (is_new_ns) {
                        am_mark_ns_added(ns_cookie);
                        announced_add = true;
                        
                        for (size_t j = 0; j < get_auditors().size(); ++j) {
                            if (i == j) continue; 
                            auto& other_aud = get_auditors()[j];
                            if (other_aud->activity) other_aud->activity(ns_cookie, LA_ACT_ADD);
                        }
                    }

                    for (size_t j = 0; j < get_auditors().size(); ++j) {
                        if (i == j) continue; 
                        auto& other_aud = get_auditors()[j];
                        if (other_aud->objsearch) other_aud->objsearch(iter->l_name, obj_cookie, LA_SER_AUDIT);
                        if (other_aud->objopen) {
                            unsigned int sub_flags = other_aud->objopen(iter, ns_lmid, obj_cookie);
                            std::unique_lock<std::shared_mutex> a_lock(other_aud->obj_mutex);
                            other_aud->obj_flags[obj_cookie] = sub_flags;
                        }
                    }
                }
                iter = iter->l_next;
            }

            if (announced_add) {
                for (size_t j = 0; j < get_auditors().size(); ++j) {
                    if (i == j) continue;
                    auto& other_aud = get_auditors()[j];
                    if (other_aud->activity) other_aud->activity(ns_cookie, LA_ACT_CONSISTENT);
                }
                am_unmark_ns_added(ns_cookie);
            }
        }
    }

    // Continue passing the event down the chain
    for (auto& aud_ptr : get_auditors()) {
        if (aud_ptr->preinit) aud_ptr->preinit(cookie);
    }
}

void la_activity(uintptr_t* cookie, unsigned int flag) {
    uintptr_t* effective_cookie = translate_cookie(cookie);
    Lmid_t act_lmid = get_cookie_lmid(effective_cookie);

    // Deduplicate LA_ACT_DELETE events
    // glibc natively generates this event in _dl_fini and some
    // dlclose paths.  am_mark_ns_deleting atomically checks and sets
    // the deletion state.  If it returns false, the event was already
    // broadcast (either natively or synthetically), so we drop the
    // duplicate.
    if (flag == LA_ACT_ADD) {
        if (!am_mark_ns_added(effective_cookie)) return;
    } else if (flag == LA_ACT_DELETE) {
        if (!am_mark_ns_deleting(effective_cookie)) return;
    } else if (flag == LA_ACT_CONSISTENT) {
        am_unmark_ns_deleting(effective_cookie);
        am_unmark_ns_added(effective_cookie);
    }

    for (auto& aud_ptr : get_auditors()) {
        Lmid_t aud_lmid = -1;
        dlinfo(aud_ptr->handle, RTLD_DI_LMID, &aud_lmid);
        if (act_lmid != -1 && act_lmid == aud_lmid) continue;

        if (aud_ptr->activity) {
            aud_ptr->activity(effective_cookie, flag);
        }
    }
}  

unsigned int la_objclose(uintptr_t* cookie) {
    uintptr_t* effective_cookie = translate_cookie(cookie);
    uintptr_t* ns_cookie = la_obj_cookie_to_ns_cookie(effective_cookie);
    Lmid_t close_lmid = get_cookie_lmid(effective_cookie);
    
    // Identify the namespace and synthesize LA_ACT_DELETE if not yet sent
    if (ns_cookie && am_mark_ns_deleting(ns_cookie)) {
        for (auto& aud_ptr : get_auditors()) {
            Lmid_t aud_lmid = -1;
            dlinfo(aud_ptr->handle, RTLD_DI_LMID, &aud_lmid);
            if (close_lmid != -1 && close_lmid == aud_lmid) continue;

            if (aud_ptr->activity) aud_ptr->activity(ns_cookie, LA_ACT_DELETE);
        }
    }

    // Untrack MUST happen after we resolve the namespace cookie
    am_untrack_ns_cookie(effective_cookie);

    unsigned int ret = 0;
    for (auto& aud_ptr : get_auditors()) {
        auto& aud = *aud_ptr;
        bool should_close = false;
        
        {
            std::unique_lock<std::shared_mutex> lock(aud.obj_mutex);
            auto it = aud.obj_flags.find(effective_cookie);
            if (it != aud.obj_flags.end()) {
                should_close = true;
                aud.obj_flags.erase(it);
            }
        }
        
        if (should_close && aud.objclose) {
            ret = aud.objclose(effective_cookie);
        }
    }
    return ret;
}

// 4. Symbol Binding and Address Chaining
uintptr_t la_symbind64(Elf64_Sym* sym, unsigned int ndx, uintptr_t* refcook,
                       uintptr_t* defcook, unsigned int* flags, const char* symname) {

    Elf64_Sym current_sym = *sym;
    uintptr_t current_addr = 0;
    bool has_alt_addr = false;
    unsigned int final_flags = *flags;
    bool any_called = false;
    bool all_nopltenter = true;
    bool all_nopltexit = true;

    SymBindKey key = {refcook, defcook, ndx};

    for (auto& aud_ptr : get_auditors()) {
        auto& aud = *aud_ptr;
        if (!aud.symbind64 || !aud.wants_symbind(refcook, defcook)) continue;

        any_called = true;
        unsigned int sub_flags = *flags;

        if (has_alt_addr) {
            current_sym.st_value = current_addr;
            sub_flags |= LA_SYMB_ALTVALUE;
        }

        uintptr_t ret = aud.symbind64(&current_sym, ndx, refcook, defcook, &sub_flags, symname);

        {
            std::unique_lock<std::shared_mutex> lock(aud.sym_mutex);
            aud.sym_flags[key] = sub_flags;
        }

        if (ret != current_sym.st_value) {
            current_addr = ret;
            has_alt_addr = true;
        }

        if (!(sub_flags & LA_SYMB_NOPLTENTER)) all_nopltenter = false;
        if (!(sub_flags & LA_SYMB_NOPLTEXIT)) all_nopltexit = false;
    }

    if (any_called) {
        if (all_nopltenter) final_flags |= LA_SYMB_NOPLTENTER;
        if (all_nopltexit) final_flags |= LA_SYMB_NOPLTEXIT;
        *flags = final_flags;
    }

    return has_alt_addr ? current_addr : current_sym.st_value;
}

// 5. PLT Enter Execution
Elf64_Addr LA_PLTENTER_FUNC(Elf64_Sym* sym, unsigned int ndx, uintptr_t* refcook,
                            uintptr_t* defcook, ARCH_REGS* regs,
                            unsigned int* flags, const char* symname, long int* framesizep) {

    Elf64_Sym current_sym = *sym;
    Elf64_Addr current_addr = 0;
    bool has_alt_addr = false;
    bool any_called = false;
    bool all_nopltenter = true;
    bool all_nopltexit = true;

    SymBindKey key = {refcook, defcook, ndx};

    for (auto& aud_ptr : get_auditors()) {
        auto& aud = *aud_ptr;
        if (!aud.pltenter || !aud.wants_symbind(refcook, defcook)) continue;

        unsigned int current_sub_flags = *flags;
        {
            std::shared_lock<std::shared_mutex> lock(aud.sym_mutex);
            auto it = aud.sym_flags.find(key);
            if (it != aud.sym_flags.end()) current_sub_flags = it->second;
        }

        if (current_sub_flags & LA_SYMB_NOPLTENTER) continue;
        any_called = true;

        if (has_alt_addr) {
            current_sym.st_value = current_addr;
            current_sub_flags |= LA_SYMB_ALTVALUE;
        }

        Elf64_Addr ret = aud.pltenter(&current_sym, ndx, refcook, defcook, regs, &current_sub_flags, symname, framesizep);

        {
            std::unique_lock<std::shared_mutex> lock(aud.sym_mutex);
            aud.sym_flags[key] = current_sub_flags;
        }

        if (ret != current_sym.st_value) {
            current_addr = ret;
            has_alt_addr = true;
        }

        if (!(current_sub_flags & LA_SYMB_NOPLTENTER)) all_nopltenter = false;
        if (!(current_sub_flags & LA_SYMB_NOPLTEXIT)) all_nopltexit = false;
    }

    if (any_called) {
        unsigned int final_flags = *flags;
        if (all_nopltenter) final_flags |= LA_SYMB_NOPLTENTER;
        if (all_nopltexit) final_flags |= LA_SYMB_NOPLTEXIT;
        *flags = final_flags;
    }

    return has_alt_addr ? current_addr : current_sym.st_value;
}

// 6. PLT Exit Execution
unsigned int LA_PLTEXIT_FUNC(Elf64_Sym* sym, unsigned int ndx, uintptr_t* refcook,
                             uintptr_t* defcook, const ARCH_REGS* inregs,
                             ARCH_RETVAL* outregs, const char* symname) {

    unsigned int final_ret = 0;
    SymBindKey key = {refcook, defcook, ndx};

    for (auto& aud_ptr : get_auditors()) {
        auto& aud = *aud_ptr;
        if (!aud.pltexit || !aud.wants_symbind(refcook, defcook)) continue;

        {
            std::shared_lock<std::shared_mutex> lock(aud.sym_mutex);
            auto it = aud.sym_flags.find(key);
            if (it != aud.sym_flags.end() && (it->second & LA_SYMB_NOPLTEXIT)) continue;
        }
        final_ret = aud.pltexit(sym, ndx, refcook, defcook, inregs, outregs, symname);
    }
    return final_ret;
}

} // extern "C"