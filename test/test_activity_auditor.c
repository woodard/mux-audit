#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <link.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

unsigned int la_version(unsigned int version) { return LAV_CURRENT; }

unsigned int la_objopen(struct link_map *map, Lmid_t lmid, uintptr_t *cookie) {
    if (map->l_name) {
        const char* base_name = strrchr(map->l_name, '/');
        base_name = base_name ? base_name + 1 : map->l_name;
        printf("[auditor] la_objopen('%s') cookie=%p\n", base_name, (void*)cookie);
    }
    return LA_FLG_BINDTO | LA_FLG_BINDFROM;
}

void la_activity(uintptr_t *cookie, unsigned int flag) {
    const char* act = flag == LA_ACT_ADD ? "ADD" : (flag == LA_ACT_DELETE ? "DELETE" : "CONSISTENT");
    printf("[auditor] la_activity(%s) cookie=%p\n", act, (void*)cookie);
}

unsigned int la_objclose(uintptr_t *cookie) {
    printf("[auditor] la_objclose() cookie=%p\n", (void*)cookie);
    return 0;
}