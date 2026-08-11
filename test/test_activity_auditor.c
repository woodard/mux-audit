#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <link.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>

static unsigned int current_state = 0; // 0 = unknown/consistent, 1 = ADD, 2 = DELETE
static char my_name[256] = "unknown_auditor";

void init_my_name() {
    Dl_info info;
    if (dladdr((void*)la_version, &info) && info.dli_fname) {
        const char* base = strrchr(info.dli_fname, '/');
        strncpy(my_name, base ? base + 1 : info.dli_fname, sizeof(my_name) - 1);
    }
}

unsigned int la_version(unsigned int version) { 
    init_my_name();
    return LAV_CURRENT; 
}

unsigned int la_objopen(struct link_map *map, Lmid_t lmid, uintptr_t *cookie) {
    if (current_state != LA_ACT_ADD) {
        fprintf(stderr, "[%s] FATAL: la_objopen called but state is NOT LA_ACT_ADD (state=%u)\n", my_name, current_state);
    }
    if (map->l_name) {
        const char* base_name = strrchr(map->l_name, '/');
        base_name = base_name ? base_name + 1 : map->l_name;
        fprintf(stderr, "[%s] la_objopen('%s') cookie=%p\n", my_name, base_name, (void*)cookie);
    }
    return LA_FLG_BINDTO | LA_FLG_BINDFROM;
}

void la_activity(uintptr_t *cookie, unsigned int flag) {
    current_state = flag;
    const char* act = flag == LA_ACT_ADD ? "ADD" : (flag == LA_ACT_DELETE ? "DELETE" : "CONSISTENT");
    fprintf(stderr, "[%s] la_activity(%s) cookie=%p\n", my_name, act, (void*)cookie);
}

unsigned int la_objclose(uintptr_t *cookie) {
    if (current_state != LA_ACT_DELETE) {
        fprintf(stderr, "[%s] FATAL: la_objclose called but state is NOT LA_ACT_DELETE (state=%u)\n", my_name, current_state);
    }
    fprintf(stderr, "[%s] la_objclose() cookie=%p\n", my_name, (void*)cookie);
    return 0;
}