#include <iostream>

// Force a large Initial Exec TLS allocation (32KB)
// This is significantly larger than glibc's default surplus TLS pool.
__thread char large_tls_array[32768] __attribute__((tls_model("initial-exec")));

int main() {
    // Touch the memory across page boundaries to ensure it is fully allocated
    for (int i = 0; i < 32768; i += 4096) {
        large_tls_array[i] = 'A';
    }
    
    std::cout << "[main] Application executing successfully with large IE TLS." << std::endl;
    return 0;
}