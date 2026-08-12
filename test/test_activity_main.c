#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
  printf("[main] Calling dlopen(libgood.so)...\n");
  void *h1 = dlopen("libgood.so", RTLD_NOW);
  if (!h1) {
    fprintf(stderr, "dlopen libgood failed: %s\n", dlerror());
    return 1;
  }

  printf("[main] Calling dlclose(libgood.so)...\n");
  dlclose(h1);

  printf("[main] Calling dlopen(libbad.so)...\n");
  void *h2 = dlopen("libbad.so", RTLD_NOW);
  if (!h2) {
    fprintf(stderr, "dlopen libbad failed: %s\n", dlerror());
    return 1;
  }

  printf("[main] Exiting...\n");
  // We intentionally leave libbad.so open so the dynamic linker
  // fires LA_ACT_DELETE natively during program exit teardown.
  return 0;
}