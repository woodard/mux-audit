#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <link.h>
#include <stdio.h>

// Request an additional 8KB of IE TLS for the auditor itself
__thread char auditor_tls[8192] __attribute__((tls_model("initial-exec")));

extern "C" {
unsigned int la_version(unsigned int version) {
  // Touch the memory to verify allocation
  auditor_tls[0] = 'B';
  auditor_tls[8191] = 'C';
  return LAV_CURRENT;
}
}