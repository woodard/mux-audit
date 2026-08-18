#ifndef AUDIT_MULTIPLEXER_H
#define AUDIT_MULTIPLEXER_H

/** @file
 * Public helpers for multiplexing glibc dynamic linker audit events.
 */

#include <cstdint>
#include <link.h>
#include <vector>

// -----------------------------------------------------------------------------
// Architecture-Specific Conditional Compilation
// -----------------------------------------------------------------------------
#if defined(__x86_64__)
#define ARCH_REGS La_x86_64_regs
#define ARCH_RETVAL La_x86_64_retval
#define LA_PLTENTER_STR "la_x86_64_gnu_pltenter"
#define LA_PLTEXIT_STR "la_x86_64_gnu_pltexit"
#define LA_PLTENTER_FUNC la_x86_64_gnu_pltenter
#define LA_PLTEXIT_FUNC la_x86_64_gnu_pltexit

#define ARCH_LA_PLTENTER la_x86_64_gnu_pltenter
#define ARCH_LA_PLTEXIT la_x86_64_gnu_pltexit
typedef La_x86_64_regs arch_la_regs;
typedef La_x86_64_retval arch_la_retval;
typedef Elf64_Sym arch_elf_sym;

#elif defined(__aarch64__)
#define ARCH_REGS La_aarch64_regs
#define ARCH_RETVAL La_aarch64_retval
#define LA_PLTENTER_STR "la_aarch64_gnu_pltenter"
#define LA_PLTEXIT_STR "la_aarch64_gnu_pltexit"
#define LA_PLTENTER_FUNC la_aarch64_gnu_pltenter
#define LA_PLTEXIT_FUNC la_aarch64_gnu_pltexit

#define ARCH_LA_PLTENTER la_aarch64_gnu_pltenter
#define ARCH_LA_PLTEXIT la_aarch64_gnu_pltexit
typedef La_aarch64_regs arch_la_regs;
typedef La_aarch64_retval arch_la_retval;
typedef Elf64_Sym arch_elf_sym;

#elif defined(__ppc64__) || defined(__PPC64__)
#define ARCH_REGS La_ppc64_regs
#define ARCH_RETVAL La_ppc64_retval
#define LA_PLTENTER_STR "la_ppc64_gnu_pltenter"
#define LA_PLTEXIT_STR "la_ppc64_gnu_pltexit"
#define LA_PLTENTER_FUNC la_ppc64_gnu_pltenter
#define LA_PLTEXIT_FUNC la_ppc64_gnu_pltexit

#define ARCH_LA_PLTENTER la_ppc64_gnu_pltenter
#define ARCH_LA_PLTEXIT la_ppc64_gnu_pltexit
typedef La_ppc64_regs arch_la_regs;
typedef La_ppc64_retval arch_la_retval;
typedef Elf64_Sym arch_elf_sym;

#elif defined(__riscv) && (__riscv_xlen == 64)
#define ARCH_REGS La_riscv_regs
#define ARCH_RETVAL La_riscv_retval
#define LA_PLTENTER_STR "la_riscv_gnu_pltenter"
#define LA_PLTEXIT_STR "la_riscv_gnu_pltexit"
#define LA_PLTENTER_FUNC la_riscv_gnu_pltenter
#define LA_PLTEXIT_FUNC la_riscv_gnu_pltexit

#define ARCH_LA_PLTENTER la_riscv_gnu_pltenter
#define ARCH_LA_PLTEXIT la_riscv_gnu_pltexit
typedef La_riscv_regs arch_la_regs;
typedef La_riscv_retval arch_la_retval;
typedef Elf64_Sym arch_elf_sym;

#elif defined(__i386__)
#define ARCH_REGS La_i86_regs
#define ARCH_RETVAL La_i86_retval
#define LA_PLTENTER_STR "la_i86_gnu_pltenter"
#define LA_PLTEXIT_STR "la_i86_gnu_pltexit"
#define LA_PLTENTER_FUNC la_i86_gnu_pltenter
#define LA_PLTEXIT_FUNC la_i86_gnu_pltexit

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

/**
 * Convert the cookie returned by the dynamic linker to its link map.
 *
 * @param cookie Pointer to the audit cookie supplied to an audit callback.
 * @return The link map stored in the cookie, or `nullptr` when @p cookie is
 *         null.
 */
static inline struct link_map *la_cookie_to_link_map(uintptr_t *cookie) {
  if (!cookie)
    return (struct link_map *)0;
  return (struct link_map *)(*cookie);
}

/**
 * Find the namespace cookie associated with an object cookie.
 *
 * @param cookie Pointer to an object's audit cookie.
 * @return The namespace cookie, or `nullptr` if the object is not tracked.
 */
uintptr_t *la_obj_cookie_to_ns_cookie(uintptr_t *cookie);

/**
 * Visit every known link map in every linker namespace.
 *
 * @param cb Callback invoked once for each known link map.
 */
void am_iterate_maps(void (*cb)(struct link_map *));

/**
 * Associate an object cookie with a linker's namespace.
 *
 * @param lmid Linker namespace identifier.
 * @param cookie Object cookie to track.
 * @return `true` when this call first observes @p lmid; otherwise `false`.
 */
bool am_track_ns_cookie(Lmid_t lmid, uintptr_t *cookie);

/**
 * Stop tracking an object cookie and release its namespace reference.
 *
 * @param cookie Object cookie to untrack.
 */
void am_untrack_ns_cookie(uintptr_t *cookie);

/**
 * Mark a namespace as being deleted.
 *
 * @param ns_cookie Namespace cookie to mark.
 * @return `true` if the mark was newly added; otherwise `false`.
 */
bool am_mark_ns_deleting(uintptr_t *ns_cookie);

/**
 * Clear the deletion mark for a namespace.
 *
 * @param ns_cookie Namespace cookie to unmark.
 */
void am_unmark_ns_deleting(uintptr_t *ns_cookie);

/**
 * Mark a namespace as having been added.
 *
 * @param ns_cookie Namespace cookie to mark.
 * @return `true` if the mark was newly added; otherwise `false`.
 */
bool am_mark_ns_added(uintptr_t *ns_cookie);

/**
 * Clear the added mark for a namespace.
 *
 * @param ns_cookie Namespace cookie to unmark.
 */
void am_unmark_ns_added(uintptr_t *ns_cookie);
void am_unmark_ns_added(uintptr_t *ns_cookie);

#ifdef __cplusplus
}
#endif

/** Function pointer type for a shared object's initialization or finalization function. */
typedef void (*am_init_fini_fn_t)(void);

/**
 * Retrieve the DT_INIT and DT_INIT_ARRAY functions for a loaded object.
 *
 * @param map Pointer to the object's link map.
 * @return Function pointers in the order they appear in the dynamic section,
 *         or an empty vector when @p map has no usable dynamic section.
 */
std::vector<am_init_fini_fn_t> am_get_constructors(struct link_map *map);

/**
 * Retrieve the DT_FINI and DT_FINI_ARRAY functions for a loaded object.
 *
 * @param map Pointer to the object's link map.
 * @return Function pointers in the order they appear in the dynamic section,
 *         or an empty vector when @p map has no usable dynamic section.
 */
std::vector<am_init_fini_fn_t> am_get_destructors(struct link_map *map);

#endif // AUDIT_MULTIPLEXER_H