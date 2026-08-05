// test/test3_auditor2.cpp
#include <link.h>
#include <stdio.h>
#include <string.h>

extern "C" unsigned int la_version(unsigned int version) {
    return version;
}

extern "C" unsigned int la_objopen(struct link_map *map, Lmid_t lmid, uintptr_t *cookie) {
    // Check if the loaded object is our payload
    if (map->l_name && strstr(map->l_name, "libtest3_payload.so")) {
        printf("[test3_auditor2] Success: observed libtest3_payload.so being loaded!\n");
    }
    return LA_FLG_BINDTO | LA_FLG_BINDFROM;
}