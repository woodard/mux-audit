#include <iostream>
#include <link.h>

extern "C" {
    unsigned int la_version(unsigned int version) {
        std::cout << "[TEST1] la_version called with " << version << std::endl;
        return version;
    }

    unsigned int la_objopen(struct link_map* map, Lmid_t lmid, uintptr_t* cookie) {
        if (map && map->l_name) {
            std::cout << "[TEST1] la_objopen: " 
                      << (map->l_name[0] != '\0' ? map->l_name : "<main executable>") 
                      << std::endl;
        }
        return 0;
    }
}