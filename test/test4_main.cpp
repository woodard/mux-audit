#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
    void *handle = dlopen("./.libs/libtest4_payload.so", RTLD_LAZY);
    if (!handle) {
        fprintf(stderr, "FAIL: Failed to load payload: %s\n", dlerror());
        return 1;
    }

    void (*func1)() = (void (*)())dlsym(handle, "func1");
    void (*func2)() = (void (*)())dlsym(handle, "func2");
    void (*func3)() = (void (*)())dlsym(handle, "func3");

    // Call each function 3 times
    for (int i = 0; i < 3; i++) {
        func1();
        func2();
        func3();
    }

    printf("Test 4 target executable running successfully.\n");
    return 0;
}