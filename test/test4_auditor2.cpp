#include <link.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "audit_multiplexer.h" 

extern "C" unsigned int la_version(unsigned int version) { return version; }

extern "C" unsigned int la_objopen(struct link_map *map, Lmid_t lmid, uintptr_t *cookie) {
    return LA_FLG_BINDTO | LA_FLG_BINDFROM;
}

#if __WORDSIZE == 64
extern "C" uintptr_t la_symbind64(Elf64_Sym *sym, unsigned int ndx, uintptr_t *refcook, uintptr_t *defcook, unsigned int *flags, const char *symname) {
#else
extern "C" uintptr_t la_symbind32(Elf32_Sym *sym, unsigned int ndx, uintptr_t *refcook, uintptr_t *defcook, unsigned int *flags, const char *symname) {
#endif
    // Leave flags unmodified in symbind
    return sym->st_value;
}

// Track execution counts for suppression verification
int func1_enter_cnt = 0;
int func2_enter_cnt = 0;

extern "C" uintptr_t ARCH_LA_PLTENTER(arch_elf_sym *sym, unsigned int ndx, uintptr_t *refcook, uintptr_t *defcook, arch_la_regs *regs, unsigned int *flags, const char *symname, long int *framesizep) {
    if (strcmp(symname, "func1") == 0) {
        if (func1_enter_cnt > 0) {
            fprintf(stderr, "[test4_auditor2] FAIL: Unexpected subsequent la_pltenter for func1\n");
            exit(1);
        }
        func1_enter_cnt++;
        *flags |= (LA_SYMB_NOPLTENTER | LA_SYMB_NOPLTEXIT);
    } else if (strcmp(symname, "func2") == 0) {
        if (func2_enter_cnt > 0) {
            fprintf(stderr, "[test4_auditor2] FAIL: Unexpected subsequent la_pltenter for func2\n");
            exit(1);
        }
        func2_enter_cnt++;
        *flags |= LA_SYMB_NOPLTENTER;
    } else if (strcmp(symname, "func3") == 0) {
        // Enters are permitted, but we block exits
        *flags |= LA_SYMB_NOPLTEXIT;
    }
    
    *framesizep = 256; // Tell glibc we want an exit callback if not suppressed
    return sym->st_value;
}

extern "C" unsigned int ARCH_LA_PLTEXIT(arch_elf_sym *sym, unsigned int ndx, uintptr_t *refcook, uintptr_t *defcook, const arch_la_regs *inregs, arch_la_retval *outregs, const char *symname) {
    if (strcmp(symname, "func1") == 0 || strcmp(symname, "func3") == 0) {
        fprintf(stderr, "[test4_auditor2] FAIL: Unexpected la_pltexit for %s\n", symname);
        exit(1);
    }
    return 0;
}