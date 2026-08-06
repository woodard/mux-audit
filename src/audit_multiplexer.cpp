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
        std::cerr << "[audit_multiplexer] Error: dladdr failed." << std::endl;
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

    // Enforce Strict Binding to prevent ld.so re-entrancy panics during dlmopen
    const char* env_bind_now = getenv("LD_BIND_NOW");
    if (!env_bind_now || std::string(env_bind_now) != "1") {
        requires_reexec = true;
    }
    
    // Re-exec if we are not in exclusive control
    if (requires_reexec) {
        std::cerr << "[audit_multiplexer] WARNING: Uncontrolled auditors detected. Re-configuring environment and re-executing..." << std::endl;

        std::string new_ld_audit2 = "";
        const char* current_ld_audit2 = getenv("LD_AUDIT2");

        for (const auto& aud : prior_auditors) {
            std::cerr << "[audit_multiplexer] Moving prior auditor to LD_AUDIT2: " << aud << std::endl;
            new_ld_audit2 += aud + ":";
        }

        if (current_ld_audit2) {
            new_ld_audit2 += current_ld_audit2;
            new_ld_audit2 += ":";
        }

        for (const auto& aud : subsequent_auditors) {
            std::cerr << "[audit_multiplexer] Moving subsequent LD_AUDIT entry to LD_AUDIT2: " << aud << std::endl;
            new_ld_audit2 += aud + ":";
        }

        if (!new_ld_audit2.empty() && new_ld_audit2.back() == ':') {
            new_ld_audit2.pop_back();
        }

        std::cerr << "[audit_multiplexer] Setting LD_AUDIT=" << my_path << std::endl;
        std::cerr << "[audit_multiplexer] Setting LD_AUDIT2=" << new_ld_audit2 << std::endl;
        std::cerr << "[audit_multiplexer] Executing /proc/self/exe..." << std::endl;

        setenv("LD_AUDIT", my_path.c_str(), 1);
        setenv("LD_AUDIT2", new_ld_audit2.c_str(), 1);
        setenv("LD_BIND_NOW", "1", 1);
        
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
                current_flag |= LA_SER_AUDIT;
            }
        }
    }
    return const_cast<char*>(current_name);
}

// 3. Object Open
unsigned int la_objopen(struct link_map* map, Lmid_t lmid, uintptr_t* cookie) {
    am_register_map(map);

    // Register the cookie to its namespace
    am_track_ns_cookie(lmid, cookie);

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
    struct r_debug* rdbg = &_r_debug;
    if (rdbg && rdbg->r_map) {
        struct link_map* lm = rdbg->r_map;
        if (lm->l_ld) {
            Elf64_Dyn* dyn = (Elf64_Dyn*)lm->l_ld;
            const char* strtab = nullptr;
            
            // First pass: locate the string table (DT_STRTAB)
            for (Elf64_Dyn* d = dyn; d->d_tag != DT_NULL; ++d) {
                if (d->d_tag == DT_STRTAB) {
                    strtab = (const char*)d->d_un.d_ptr;
                    break;
                }
            }
            
            // Second pass: scan for foreign DT_AUDIT directives
            if (strtab) {
                for (Elf64_Dyn* d = dyn; d->d_tag != DT_NULL; ++d) {
                    if (d->d_tag == DT_AUDIT) {
                        const char* audit_lib = strtab + d->d_un.d_val;
                        // If it's not us, issue a soft warning to stderr
                        if (strstr(audit_lib, "audit_multiplexer") == nullptr) {
                            std::cerr << "[audit_multiplexer] WARNING: Foreign DT_AUDIT directive detected: " << audit_lib << std::endl;
                            std::cerr << "  This auditor will load normally but bypasses the multiplexer's control." << std::endl;
                            std::cerr << "  Suggestion (Option A): Use patchelf to rewrite the executable:" << std::endl;
                            std::cerr << "    patchelf --remove-audit " << audit_lib << " <executable>" << std::endl;
                            std::cerr << "    patchelf --add-audit /path/to/audit_multiplexer.so <executable>" << std::endl;
                        }
                    }
                }
            }
        }
    }

    // Continue passing the event down the chain
    for (auto& aud_ptr : get_auditors()) if (aud_ptr->preinit) aud_ptr->preinit(cookie);
}

void la_activity(uintptr_t* cookie, unsigned int flag) {
    for (auto& aud_ptr : get_auditors()) if (aud_ptr->activity) aud_ptr->activity(cookie, flag);
}

unsigned int la_objclose(uintptr_t* cookie) {
  // Untrack the cookie before it is destroyed
  am_untrack_ns_cookie(cookie);

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
            if (it != aud.sym_flags.end()) {
                current_sub_flags = it->second;
            }
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
