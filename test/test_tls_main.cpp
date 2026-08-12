#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <dlfcn.h>
#include <elf.h>
#include <iostream>
#include <link.h>
#include <string.h>
#include <sys/auxv.h>

// Force a large Initial Exec TLS allocation (32KB)
// This is significantly larger than glibc's default surplus TLS pool.
__thread char large_tls_array[32768] __attribute__((tls_model("initial-exec")));

// The _DYNAMIC array is populated by the linker and contains the DT_DEBUG
// pointer
extern ElfW(Dyn) _DYNAMIC[];

int main() {
  // Touch the memory across page boundaries to ensure it is fully allocated
  for (int i = 0; i < 32768; i += 4096) {
    large_tls_array[i] = 'A';
  }

  std::cout << "[main] Application executing successfully with large IE TLS."
            << std::endl;

  // Locate the canonical r_debug struct managed by ld.so via DT_DEBUG
  struct r_debug *real_r_debug = nullptr;
  for (ElfW(Dyn) *dyn = _DYNAMIC; dyn->d_tag != DT_NULL; ++dyn) {
    if (dyn->d_tag == DT_DEBUG) {
      real_r_debug = reinterpret_cast<struct r_debug *>(dyn->d_un.d_ptr);
      break;
    }
  }

  if (!real_r_debug) {
    std::cout << "[main] FATAL: Could not locate DT_DEBUG pointer."
              << std::endl;
    return 1;
  }

  struct r_debug_extended *ext_debug =
      reinterpret_cast<struct r_debug_extended *>(real_r_debug);
  if (ext_debug->base.r_version < 2) {
    std::cout << "[main] glibc r_version < 2, cannot securely traverse dynamic "
                 "namespaces."
              << std::endl;
  }

  int ns_id = 0;
  size_t grand_total_tls = 0;

  while (ext_debug != nullptr) {
    struct link_map *lmap = ext_debug->base.r_map;

    // Ensure we start at the head of the link_map chain for this namespace
    while (lmap && lmap->l_prev)
      lmap = lmap->l_prev;

    if (lmap) {
      std::cout << "[main] Discovered Namespace " << ns_id << std::endl;
    }

    size_t ns_total_tls = 0;

    while (lmap) {
      const char *name = (lmap->l_name && lmap->l_name[0])
                             ? lmap->l_name
                             : "[main executable]";
      const char *base_name = strrchr(name, '/');
      base_name = base_name ? base_name + 1 : name;

      ElfW(Phdr) *phdr = nullptr;
      size_t phnum = 0;

      // Memory-based Program Header Iteration
      if (lmap->l_addr == 0 && name[0] == '[') {
        // The main executable might not have its ELF header mapped at l_addr.
        // We use getauxval to safely locate its Program Headers.
        phdr = reinterpret_cast<ElfW(Phdr) *>(getauxval(AT_PHDR));
        phnum = getauxval(AT_PHNUM);
      } else {
        // For shared objects and PIE binaries, the ELF header is at l_addr.
        ElfW(Ehdr) *ehdr = reinterpret_cast<ElfW(Ehdr) *>(lmap->l_addr);

        // Verify the magic bytes to ensure it's a valid mapped ELF header
        if (ehdr && ehdr->e_ident[EI_MAG0] == ELFMAG0 &&
            ehdr->e_ident[EI_MAG1] == ELFMAG1 &&
            ehdr->e_ident[EI_MAG2] == ELFMAG2 &&
            ehdr->e_ident[EI_MAG3] == ELFMAG3) {

          phdr = reinterpret_cast<ElfW(Phdr) *>(lmap->l_addr + ehdr->e_phoff);
          phnum = ehdr->e_phnum;
        }
      }

      if (phdr) {
        // Iterate the headers looking for the TLS segment
        for (size_t i = 0; i < phnum; i++) {
          if (phdr[i].p_type == PT_TLS) {
            std::cout << "[main]   -> " << base_name
                      << " TLS segment size: " << phdr[i].p_memsz << " bytes."
                      << std::endl;
            ns_total_tls += phdr[i].p_memsz;
            break;
          }
        }
      }

      lmap = lmap->l_next;
    }

    std::cout << "[main] Subtotal for Namespace " << ns_id << ": "
              << ns_total_tls << " bytes." << std::endl;
    grand_total_tls += ns_total_tls;

    // If glibc doesn't support namespace iteration, stop here
    if (ext_debug->base.r_version < 2)
      break;

    ext_debug = ext_debug->r_next;
    ns_id++;
  }

  std::cout << "[main] ==============================================="
            << std::endl;
  std::cout << "[main] Grand Total TLS across all namespaces: "
            << grand_total_tls << " bytes." << std::endl;
  std::cout << "[main] ==============================================="
            << std::endl;

  return 0;
}