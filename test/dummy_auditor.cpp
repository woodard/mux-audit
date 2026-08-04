#include "audit_multiplexer.h"
#include <cstdio>

extern "C" {

unsigned int la_version(unsigned int version) {
    fprintf(stderr, "[Dummy Auditor] la_version called with: %u\n", version);
    if (version == LAV_CURRENT + 100) {
        return LAV_CURRENT + 100;
    }
    return LAV_CURRENT;
}

unsigned int la_objopen(struct link_map* map, Lmid_t lmid, uintptr_t* cookie) {
    struct link_map* verified_map = la_cookie_to_link_map(cookie);
    if (verified_map && verified_map->l_name) {
        fprintf(stderr, "[Dummy Auditor] la_objopen called for: %s\n", 
                  (verified_map->l_name[0] != '\0' ? verified_map->l_name : "main_executable"));
    }
    // We want PLT profiling for this library
    return LA_FLG_BINDTO | LA_FLG_BINDFROM;
}

} // extern "C"