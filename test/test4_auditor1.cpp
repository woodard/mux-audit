#include "audit_multiplexer.h"
#include <link.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern "C" unsigned int la_version(unsigned int version) { return version; }

extern "C" unsigned int la_objopen(struct link_map *map, Lmid_t lmid,
                                   uintptr_t *cookie) {
  return LA_FLG_BINDTO | LA_FLG_BINDFROM;
}

#if __WORDSIZE == 64
extern "C" uintptr_t la_symbind64(Elf64_Sym *sym, unsigned int ndx,
                                  uintptr_t *refcook, uintptr_t *defcook,
                                  unsigned int *flags, const char *symname) {
#else
extern "C" uintptr_t la_symbind32(Elf32_Sym *sym, unsigned int ndx,
                                  uintptr_t *refcook, uintptr_t *defcook,
                                  unsigned int *flags, const char *symname) {
#endif
  if (strcmp(symname, "func1") == 0) {
    *flags |= (LA_SYMB_NOPLTENTER | LA_SYMB_NOPLTEXIT);
  } else if (strcmp(symname, "func2") == 0) {
    *flags |= LA_SYMB_NOPLTENTER;
  } else if (strcmp(symname, "func3") == 0) {
    *flags |= LA_SYMB_NOPLTEXIT;
  }
  return sym->st_value;
}

extern "C" uintptr_t ARCH_LA_PLTENTER(arch_elf_sym *sym, unsigned int ndx,
                                      uintptr_t *refcook, uintptr_t *defcook,
                                      arch_la_regs *regs, unsigned int *flags,
                                      const char *symname,
                                      long int *framesizep) {
  if (strcmp(symname, "func1") == 0 || strcmp(symname, "func2") == 0) {
    fprintf(stderr, "[test4_auditor1] FAIL: Unexpected la_pltenter for %s\n",
            symname);
    exit(1);
  }
  *framesizep = 256; // Require pltexit for func3
  return sym->st_value;
}

extern "C" unsigned int ARCH_LA_PLTEXIT(arch_elf_sym *sym, unsigned int ndx,
                                        uintptr_t *refcook, uintptr_t *defcook,
                                        const arch_la_regs *inregs,
                                        arch_la_retval *outregs,
                                        const char *symname) {
  if (strcmp(symname, "func1") == 0 || strcmp(symname, "func3") == 0) {
    fprintf(stderr, "[test4_auditor1] FAIL: Unexpected la_pltexit for %s\n",
            symname);
    exit(1);
  }
  return 0;
}