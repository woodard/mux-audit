#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <iostream>
#include <link.h>
#include <dlfcn.h>

// Force a large Initial Exec TLS allocation (32KB)
// This is significantly larger than glibc's default surplus TLS pool.
__thread char large_tls_array[32768] __attribute__((tls_model("initial-exec")));

// Anchor function to locate this specific binary in memory
static void anchor_function() {}

static int tls_size_callback(struct dl_phdr_info *info, size_t size, void *data) {
    size_t* out_tls_size = reinterpret_cast<size_t*>(data);
    
    // Check if this shared object contains our anchor function
    void* anchor_ptr = reinterpret_cast<void*>(anchor_function);
    if (anchor_ptr >= reinterpret_cast<void*>(info->dlpi_addr) && 
        anchor_ptr < reinterpret_cast<void*>(info->dlpi_addr + 0x10000000)) { 
        
        // Use dladdr for absolute confirmation
        Dl_info dl_info;
        if (dladdr(anchor_ptr, &dl_info) && dl_info.dli_fbase == reinterpret_cast<void*>(info->dlpi_addr)) {
            
            // Iterate through the program headers looking for the TLS segment
            for (int i = 0; i < info->dlpi_phnum; i++) {
                if (info->dlpi_phdr[i].p_type == PT_TLS) {
                    *out_tls_size = info->dlpi_phdr[i].p_memsz;
                    return 1; // Stop iterating
                }
            }
        }
    }
    return 0; // Continue iterating
}

int main() {
    // Touch the memory across page boundaries to ensure it is fully allocated
    for (int i = 0; i < 32768; i += 4096) {
        large_tls_array[i] = 'A';
    }
    
    size_t my_tls_size = 0;
    dl_iterate_phdr(tls_size_callback, &my_tls_size);
    
    std::cout << "[main] Application executing successfully with large IE TLS." << std::endl;
    std::cout << "[main] Confirmed application TLS segment size: " << my_tls_size << " bytes." << std::endl;
    
    return 0;
}