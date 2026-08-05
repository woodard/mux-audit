// test/test3_auditor1.cpp
#include <link.h>
#include <dlfcn.h>
#include <stdio.h>

extern "C" unsigned int la_version(unsigned int version) {
    return version;
}

extern "C" void la_preinit(uintptr_t *cookie) {
    printf("[test3_auditor1] la_preinit called, dlopening payload...\n");
    
    // dlopen the payload library from the local .libs directory
    void* handle = dlopen("./.libs/libtest3_payload.so", RTLD_NOW);
    if (!handle) {
        printf("[test3_auditor1] dlopen failed: %s\n", dlerror());
    } else {
        printf("[test3_auditor1] dlopen succeeded.\n");
    }
}