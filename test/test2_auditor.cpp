#include "audit_multiplexer.h"
#include <iostream>
#include <link.h>

extern "C" void am_iterate_maps(void (*cb)(struct link_map *));

void map_callback(struct link_map *map) {
  if (map && map->l_name) {
    std::cout << "[TEST2] Discovered map via _r_debug: "
              << (map->l_name[0] != '\0' ? map->l_name : "<main executable>")
              << std::endl;
  }
}

extern "C" {
unsigned int la_version(unsigned int version) {
  std::cout << "[TEST2] la_version called. Testing am_iterate_maps..."
            << std::endl;

  // Trigger the V2 protocol map traversal
  am_iterate_maps(map_callback);

  return version;
}
}