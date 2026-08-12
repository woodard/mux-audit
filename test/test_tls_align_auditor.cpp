#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <link.h>
#include <stdio.h>
#include <stdlib.h>

#define ALIGNMENT 128
// Requesting 128-byte alignment for static TLS
__thread unsigned char test_align_tls[8]
    __attribute__((tls_model("initial-exec"), aligned(ALIGNMENT)));

extern "C" {

unsigned char *unused_func_to_create_reference() { return test_align_tls; }

unsigned int la_version(unsigned int version) {
  // Verify that glibc respected the 128-byte alignment
  if (((unsigned long)test_align_tls) % ALIGNMENT != 0) {
    printf("ERROR: test_align_tls is not %u aligned at address %p\n", ALIGNMENT,
           test_align_tls);
    exit(-1);
  }

  printf("[test_tls_align_auditor] TLS is correctly aligned at %p\n",
         test_align_tls);
  return LAV_CURRENT;
}

} // extern "C"