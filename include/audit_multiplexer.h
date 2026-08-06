#ifndef AUDIT_MULTIPLEXER_H
#define AUDIT_MULTIPLEXER_H

#include <link.h>
#include <cstdint>
#include <vector>

// -----------------------------------------------------------------------------
// Architecture-Specific Conditional Compilation
// -----------------------------------------------------------------------------
#if defined(__x86_64__)
    // Macros used internally by audit_multiplexer.cpp
    #define ARCH_REGS La_x86_64_regs
    #define ARCH_RETVAL La_x86_64_retval
    #define LA_PLTENTER_STR "la_x86_64_gnu_pltenter"
    #define LA_PLTEXIT_STR  "la_x86_64_gnu_pltexit"
    #define LA_PLTENTER_FUNC la_x86_64_gnu_pltenter
    #define LA_PLTEXIT_FUNC  la_x86_64_gnu_pltexit
    
    // Abstracted types/macros for sub-auditors and tests
    #define ARCH_LA_PLTENTER la_x86_64_gnu_pltenter
    #define ARCH_LA_PLTEXIT la_x86_64_gnu_pltexit
    typedef La_x86_64_regs arch_la_regs;
    typedef La_x86_64_retval arch_la_retval;
    typedef Elf64_Sym arch_elf_sym;

#elif defined(__aarch64__) 
    #define ARCH_REGS La_aarch64_regs
    #define ARCH_RETVAL La_aarch64_retval
    #define LA_PLTENTER_STR "la_aarch64_gnu_pltenter"
    #define LA_PLTEXIT_STR  "la_aarch64_gnu_pltexit"
    #define LA_PLTENTER_FUNC la_aarch64_gnu_pltenter
    #define LA_PLTEXIT_FUNC  la_aarch64_gnu_pltexit

    #define ARCH_LA_PLTENTER la_aarch64_gnu_pltenter
    #define ARCH_LA_PLTEXIT la_aarch64_gnu_pltexit
    typedef La_aarch64_regs arch_la_regs;
    typedef La_aarch64_retval arch_la_retval;
    typedef Elf64_Sym arch_elf_sym;

#elif defined(__ppc64__) || defined(__PPC64__)
    #define ARCH_REGS La_ppc64_regs
    #define ARCH_RETVAL La_ppc64_retval
    #define LA_PLTENTER_STR "la_ppc64_gnu_pltenter"
    #define LA_PLTEXIT_STR  "la_ppc64_gnu_pltexit"
    #define LA_PLTENTER_FUNC la_ppc64_gnu_pltenter
    #define LA_PLTEXIT_FUNC  la_ppc64_gnu_pltexit

    #define ARCH_LA_PLTENTER la_ppc64_gnu_pltenter
    #define ARCH_LA_PLTEXIT la_ppc64_gnu_pltexit
    typedef La_ppc64_regs arch_la_regs;
    typedef La_ppc64_retval arch_la_retval;
    typedef Elf64_Sym arch_elf_sym;

#elif defined(__riscv) && (__riscv_xlen == 64)
    #define ARCH_REGS La_riscv_regs
    #define ARCH_RETVAL La_riscv_retval
    #define LA_PLTENTER_STR "la_riscv_gnu_pltenter"
    #define LA_PLTEXIT_STR  "la_riscv_gnu_pltexit"
    #define LA_PLTENTER_FUNC la_riscv_gnu_pltenter
    #define LA_PLTEXIT_FUNC  la_riscv_gnu_pltexit

    #define ARCH_LA_PLTENTER la_riscv_gnu_pltenter
    #define ARCH_LA_PLTEXIT la_riscv_gnu_pltexit
    typedef La_riscv_regs arch_la_regs;
    typedef La_riscv_retval arch_la_retval;
    typedef Elf64_Sym arch_elf_sym;

#elif defined(__i386__)
    #define ARCH_REGS La_i86_regs
    #define ARCH_RETVAL La_i86_retval
    #define LA_PLTENTER_STR "la_i86_gnu_pltenter"
    #define LA_PLTEXIT_STR  "la_i86_gnu_pltexit"
    #define LA_PLTENTER_FUNC la_i86_gnu_pltenter
    #define LA_PLTEXIT_FUNC  la_i86_gnu_pltexit

    #define ARCH_LA_PLTENTER la_i86_gnu_pltenter
    #define ARCH_LA_PLTEXIT la_i86_gnu_pltexit
    typedef La_i86_regs arch_la_regs;
    typedef La_i86_retval arch_la_retval;
    typedef Elf32_Sym arch_elf_sym;
#else
    #error "Unsupported architecture for LD_AUDIT multiplexing"
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifndef LA_SER_AUDIT
#define LA_SER_AUDIT 0x1000
#endif

// Converts the cookie returned by la_objopen into a link_map pointer
struct link_map* la_cookie_to_link_map(uintptr_t* cookie);

/**
 * @brief Retrieves the namespace cookie associated with a specific object's cookie.
 * 
 * @param cookie The cookie of any object loaded in the namespace.
 * @return The uintptr_t* cookie representing the namespace head, or nullptr if unknown.
 */
uintptr_t* la_obj_cookie_to_ns_cookie(uintptr_t* cookie);

// Allows sub-auditors to iterate through all known link_maps across all namespaces
void am_iterate_maps(void (*cb)(struct link_map*));

// Statefully tracks object cookies to their namespace head cookies.
// Returns true if this is a newly discovered namespace.
bool am_track_ns_cookie(Lmid_t lmid, uintptr_t* cookie);

// Cleans up the namespace cookie tracking during object unloading
void am_untrack_ns_cookie(uintptr_t* cookie);

// Atomically checks if a namespace has been marked for deletion, and marks it if not.
// Returns true if the namespace transitioned from active to deleting.
bool am_mark_ns_deleting(uintptr_t* ns_cookie);

// Removes a namespace from the deletion tracking set when it returns to a consistent state.
void am_unmark_ns_deleting(uintptr_t* ns_cookie);
  
#ifdef __cplusplus
}
#endif

// Type definition for standard library constructor/destructor functions
typedef void (*am_init_fini_fn_t)(void);

/**
 * @brief Retrieves all constructors (DT_INIT and DT_INIT_ARRAY) for a given loaded object.
 * 
 * @param map Pointer to the link_map structure of the loaded object.
 * @return A vector of function pointers to the object's constructors.
 */
std::vector<am_init_fini_fn_t> am_get_constructors(struct link_map* map);

/**
 * @brief Retrieves all destructors (DT_FINI and DT_FINI_ARRAY) for a given loaded object.
 * 
 * @param map Pointer to the link_map structure of the loaded object.
 * @return A vector of function pointers to the object's destructors.
 */
std::vector<am_init_fini_fn_t> am_get_destructors(struct link_map* map);

#endif // AUDIT_MULTIPLEXER_H