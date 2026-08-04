#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "audit_multiplexer.h"
#include <dlfcn.h>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <string>
#include <mutex>
#include <shared_mutex>
#include <unordered_map>
#include <utility>
#include <memory>
#include <cstdio>

// -----------------------------------------------------------------------------
// Architecture-Specific Conditional Compilation
// -----------------------------------------------------------------------------
#if defined(__x86_64__)
    #define ARCH_REGS La_x86_64_regs
    #define ARCH_RETVAL La_x86_64_retval
    #define LA_PLTENTER_STR "la_x86_64_gnu_pltenter"
    #define LA_PLTEXIT_STR  "la_x86_64_gnu_pltexit"
    #define LA_PLTENTER_FUNC la_x86_64_gnu_pltenter
    #define LA_PLTEXIT_FUNC  la_x86_64_gnu_pltexit
#elif defined(__aarch64__) 
    #define ARCH_REGS La_aarch64_regs
    #define ARCH_RETVAL La_aarch64_retval
    #define LA_PLTENTER_STR "la_aarch64_gnu_pltenter"
    #define LA_PLTEXIT_STR  "la_aarch64_gnu_pltexit"
    #define LA_PLTENTER_FUNC la_aarch64_gnu_pltenter
    #define LA_PLTEXIT_FUNC  la_aarch64_gnu_pltexit
#elif defined(__ppc64__) || defined(__PPC64__)
    #define ARCH_REGS La_ppc64_regs
    #define ARCH_RETVAL La_ppc64_retval
    #define LA_PLTENTER_STR "la_ppc64_gnu_pltenter"
    #define LA_PLTEXIT_STR  "la_ppc64_gnu_pltexit"
    #define LA_PLTENTER_FUNC la_ppc64_gnu_pltenter
    #define LA_PLTEXIT_FUNC  la_ppc64_gnu_pltexit
#elif defined(__riscv) && (__riscv_xlen == 64)
    #define ARCH_REGS La_riscv_regs
    #define ARCH_RETVAL La_riscv_retval
    #define LA_PLTENTER_STR "la_riscv_gnu_pltenter"
    #define LA_PLTEXIT_STR  "la_riscv_gnu_pltexit"
    #define LA_PLTENTER_FUNC la_riscv_gnu_pltenter
    #define LA_PLTEXIT_FUNC  la_riscv_gnu_pltexit
#else
    #error "Unsupported architecture for audit_multiplexer"
#endif

// -----------------------------------------------------------------------------
// Core Tracking Structures
// -----------------------------------------------------------------------------

// Uniquely identifies a symbol binding between a referencing and defining library
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

    // Helper to check if auditor wants symbinds for this library
    bool wants_symbind(uintptr_t* refcook, uintptr_t* defcook) {
        std::shared_lock<std::shared_mutex> lock(obj_mutex);
        if (obj_flags.count(refcook) && obj_flags.at(refcook) == 0) return false;
        if (obj_flags.count(defcook) && obj_flags.at(defcook) == 0) return false;
        return true;
    }
};

// Lazy initialization ensures this is safely created upon first access,
// avoiding C++ static initialization order fiascos during early dl startup.
static std::vector<std::unique_ptr<Auditor>>& get_auditors() {
    static std::vector<std::unique_ptr<Auditor>>* auditors = new std::vector<std::unique_ptr<Auditor>>();
    return *auditors;
}

// Global master list of link maps
static std::vector<struct link_map*> g_all_maps;
static std::mutex g_maps_mutex;

static void am_register_map(struct link_map* map) {
    std::lock_guard<std::mutex> lock(g_maps_mutex);
    for (auto m : g_all_maps) if (m == map) return;
    g_all_maps.push_back(map);
}

extern "C" {

// 1. Initialization and Loading
unsigned int la_version(unsigned int version) {
    const char* ld_audit2 = getenv("LD_AUDIT2");
    if (!ld_audit2) return LAV_CURRENT;

    // Use the v2 rendezvous protocol to natively map all namespaces
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
                
                // Sub-auditor version must be exactly 100 greater than the main auditor's LAV_CURRENT
                if (v_func && v_func(LAV_CURRENT + 100) == LAV_CURRENT + 100) {
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
                current_flag |= LA_SER_AUDIT; // Flag that a previous auditor changed the path
            }
        }
    }
    return const_cast<char*>(current_name);
}

// 3. Object Open (Aggregate Flags)
unsigned int la_objopen(struct link_map* map, Lmid_t lmid, uintptr_t* cookie) {
    am_register_map(map); // Record new objects immediately

    unsigned int overall_flags = 0;
    
    for (auto& aud_ptr : get_auditors()) {
        auto& aud = *aud_ptr;
        if (aud.objopen) {
            unsigned int sub_flags = aud.objopen(map, lmid, cookie);
            overall_flags |= sub_flags; // Combine all flags

            std::unique_lock<std::shared_mutex> lock(aud.obj_mutex);
            aud.obj_flags[cookie] = sub_flags;
        }
    }
    return overall_flags; // Only returns 0 if ALL sub-auditors returned 0
}

void la_preinit(uintptr_t* cookie) {
    for (auto& aud_ptr : get_auditors()) if (aud_ptr->preinit) aud_ptr->preinit(cookie);
}

void la_activity(uintptr_t* cookie, unsigned int flag) {
    for (auto& aud_ptr : get_auditors()) if (aud_ptr->activity) aud_ptr->activity(cookie, flag);
}

unsigned int la_objclose(uintptr_t* cookie) {
    unsigned int ret = 0;
    for (auto& aud_ptr : get_auditors()) {
        auto& aud = *aud_ptr;
        if (aud.objclose) ret = aud.objclose(cookie);
        std::unique_lock<std::shared_mutex> lock(aud.obj_mutex);
        aud.obj_flags.erase(cookie);
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
        unsigned int sub_flags = *flags; // Initial flags for the auditor

        // If a previous auditor changed the address, inject it and flag it
        if (has_alt_addr) {
            current_sym.st_value = current_addr;
            sub_flags |= LA_SYMB_ALTVALUE;
        }

        uintptr_t ret = aud.symbind64(&current_sym, ndx, refcook, defcook, &sub_flags, symname);
        
        // Track the PLT flags returned by THIS specific auditor for THIS specific symbol
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

// 5. PLT Enter Execution (Per-Auditor/Per-Symbol Suppression & Status Updates)
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

        // Retrieve existing sub-flags populated by symbind64 (if any)
        {
            std::shared_lock<std::shared_mutex> lock(aud.sym_mutex);
            auto it = aud.sym_flags.find(key);
            if (it != aud.sym_flags.end()) {
                current_sub_flags = it->second;
            }
        }

        // Suppress calling this auditor if previously requested
        if (current_sub_flags & LA_SYMB_NOPLTENTER) continue;

        any_called = true;

        if (has_alt_addr) {
            current_sym.st_value = current_addr;
            current_sub_flags |= LA_SYMB_ALTVALUE;
        }

        Elf64_Addr ret = aud.pltenter(&current_sym, ndx, refcook, defcook, regs, &current_sub_flags, symname, framesizep);

        // Record any changes to sub-flags made by this auditor's pltenter
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

    // Suppress future loader calls if ALL executed auditors indicated they want out
    if (any_called) {
        unsigned int final_flags = *flags;
        if (all_nopltenter) final_flags |= LA_SYMB_NOPLTENTER;
        if (all_nopltexit) final_flags |= LA_SYMB_NOPLTEXIT;
        *flags = final_flags;
    }

    return has_alt_addr ? current_addr : current_sym.st_value;
}

// 6. PLT Exit Execution (Per-Auditor/Per-Symbol Suppression)
unsigned int LA_PLTEXIT_FUNC(Elf64_Sym* sym, unsigned int ndx, uintptr_t* refcook, 
                             uintptr_t* defcook, const ARCH_REGS* inregs, 
                             ARCH_RETVAL* outregs, const char* symname) {
    
    unsigned int final_ret = 0;
    SymBindKey key = {refcook, defcook, ndx};

    for (auto& aud_ptr : get_auditors()) {
        auto& aud = *aud_ptr;
        if (!aud.pltexit || !aud.wants_symbind(refcook, defcook)) continue;

        // Suppress execution if symbind64 or pltenter set LA_SYMB_NOPLTEXIT
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