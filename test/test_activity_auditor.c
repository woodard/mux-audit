#define _GNU_SOURCE
#include <link.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Initialize to 0 (which is not a valid LA_ACT_* constant)
static unsigned int current_state = 0; 

unsigned int la_version(unsigned int v) { 
    return LAV_CURRENT; 
}

void la_activity(uintptr_t* cookie, unsigned int flag) {
    current_state = flag;
    printf("[auditor] la_activity(%s)\n", 
           flag == LA_ACT_ADD ? "ADD" : 
           flag == LA_ACT_DELETE ? "DELETE" : 
           flag == LA_ACT_CONSISTENT ? "CONSISTENT" : "UNKNOWN");
}

unsigned int la_objopen(struct link_map* m, Lmid_t lmid, uintptr_t* cookie) {
    printf("[auditor] la_objopen('%s')\n", m->l_name);
    
    if (current_state != LA_ACT_ADD) {
        fprintf(stderr, "\nFATAL: la_objopen called but state is NOT LA_ACT_ADD (state=%u)\n", current_state);
        fprintf(stderr, "This indicates the glibc startup bug or missing synthetic event.\n");
        exit(1); 
    }
    
    *cookie = (uintptr_t)m;
    return 0;
}

unsigned int la_objclose(uintptr_t* cookie) {
    struct link_map* m = (struct link_map*)*cookie;
    printf("[auditor] la_objclose('%s')\n", m ? m->l_name : "unknown");
    
    if (current_state != LA_ACT_DELETE) {
        fprintf(stderr, "\nFATAL: la_objclose called but state is NOT LA_ACT_DELETE (state=%u)\n", current_state);
        exit(1);
    }
    return 0;
}