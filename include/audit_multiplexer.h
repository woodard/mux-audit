#ifndef AUDIT_MULTIPLEXER_H
#define AUDIT_MULTIPLEXER_H

#include <link.h>
#include <cstdint>

// Architecture-specific macros and types for LD_AUDIT
#if defined(__x86_64__)
    #define ARCH_LA_PLTENTER la_x86_64_gnu_pltenter
    #define ARCH_LA_PLTEXIT la_x86_64_gnu_pltexit
    typedef La_x86_64_regs arch_la_regs;
    typedef La_x86_64_retval arch_la_retval;
    typedef Elf64_Sym arch_elf_sym;
#elif defined(__aarch64__)
    #define ARCH_LA_PLTENTER la_aarch64_gnu_pltenter
    #define ARCH_LA_PLTEXIT la_aarch64_gnu_pltexit
    typedef La_aarch64_regs arch_la_regs;
    typedef La_aarch64_retval arch_la_retval;
    typedef Elf64_Sym arch_elf_sym;
#elif defined(__i386__)
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

// Allows sub-auditors to iterate through all known link_maps across all namespaces
void am_iterate_maps(void (*cb)(struct link_map*));

#ifdef __cplusplus
}
#endif

#endif // AUDIT_MULTIPLEXER_H