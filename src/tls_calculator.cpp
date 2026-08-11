#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "tls_calculator.h"
#include <iostream>
#include <unordered_set>
#include <sstream>
#include <cstdlib>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <libelf.h>
#include <gelf.h>
#include <algorithm>

// --- glibc arithmetic macros for alignment padding ---
#define roundup(x, y)  ((((x) + (y) - 1) / (y)) * (y))

struct TlsInfo {
    size_t size;
    size_t align;
    bool requires_ie;
    std::string rpath;
    std::string runpath;
};

// -----------------------------------------------------------------------------
// Initial Exec TLS Sizing Logic
// -----------------------------------------------------------------------------

static bool file_exists(const std::string& path) {
    struct stat buffer;
    return (stat(path.c_str(), &buffer) == 0 && S_ISREG(buffer.st_mode));
}

static std::string expand_origin(std::string path, const std::string& origin) {
    size_t pos;
    while ((pos = path.find("$ORIGIN")) != std::string::npos) path.replace(pos, 7, origin);
    while ((pos = path.find("${ORIGIN}")) != std::string::npos) path.replace(pos, 9, origin);
    return path;
}

static std::string search_path_list(const std::string& path_list, const std::string& dep_name, const std::string& origin) {
    if (path_list.empty()) return "";
    std::stringstream ss(path_list);
    std::string dir;
    while (std::getline(ss, dir, ':')) {
        if (dir.empty()) continue;
        std::string expanded_dir = expand_origin(dir, origin);
        if (expanded_dir.back() != '/') expanded_dir += '/';
        std::string full_path = expanded_dir + dep_name;
        if (file_exists(full_path)) return full_path;
    }
    return "";
}

static std::string resolve_dependency_path(const std::string& dep_name, const std::string& loading_obj_path,
                                    const std::string& rpath, const std::string& runpath) {
    std::string origin = ".";
    size_t slash_pos = loading_obj_path.find_last_of('/');
    if (slash_pos != std::string::npos) origin = loading_obj_path.substr(0, slash_pos);
    else if (!loading_obj_path.empty()) origin = "."; 

    std::string found_path;
    if (runpath.empty() && !rpath.empty()) {
        found_path = search_path_list(rpath, dep_name, origin);
        if (!found_path.empty()) return found_path;
    }

    const char* ld_lib_path_env = std::getenv("LD_LIBRARY_PATH");
    if (ld_lib_path_env) {
        found_path = search_path_list(ld_lib_path_env, dep_name, origin);
        if (!found_path.empty()) return found_path;
    }

    if (!runpath.empty()) {
        found_path = search_path_list(runpath, dep_name, origin);
        if (!found_path.empty()) return found_path;
    }

    std::vector<std::string> default_paths = {"/lib/x86_64-linux-gnu/", "/usr/lib/x86_64-linux-gnu/", "/lib/", "/usr/lib/"};
    for (const auto& dir : default_paths) {
        std::string full_path = dir + dep_name;
        if (file_exists(full_path)) return full_path;
    }
    return ""; 
}

static TlsInfo get_elf_tls_info(const std::string& filepath, std::vector<std::string>& out_dependencies) {
    TlsInfo info = {0, 1, false, "", ""};
    if (elf_version(EV_CURRENT) == EV_NONE) return info;

    int fd = open(filepath.c_str(), O_RDONLY);
    if (fd < 0) return info;

    Elf* elf = elf_begin(fd, ELF_C_READ, NULL);
    if (!elf) { close(fd); return info; }

    size_t phnum;
    if (elf_getphdrnum(elf, &phnum) == 0) {
        for (size_t i = 0; i < phnum; i++) {
            GElf_Phdr phdr;
            if (gelf_getphdr(elf, i, &phdr) == &phdr && phdr.p_type == PT_TLS) {
                info.size = phdr.p_memsz;
                info.align = phdr.p_align ? phdr.p_align : 1;
            }
        }
    }

    Elf_Scn* scn = NULL;
    while ((scn = elf_nextscn(elf, scn)) != NULL) {
        GElf_Shdr shdr;
        if (gelf_getshdr(scn, &shdr) != &shdr) continue;

        if (shdr.sh_type == SHT_DYNAMIC) {
            Elf_Data* data = elf_getdata(scn, NULL);
            size_t dyn_entries = shdr.sh_size / shdr.sh_entsize;
            for (size_t i = 0; i < dyn_entries; i++) {
                GElf_Dyn dyn;
                gelf_getdyn(data, i, &dyn);
                if (dyn.d_tag == DT_FLAGS && (dyn.d_un.d_val & DF_STATIC_TLS)) info.requires_ie = true;
                else if (dyn.d_tag == DT_NEEDED) {
                    const char* dep_name = elf_strptr(elf, shdr.sh_link, dyn.d_un.d_val);
                    if (dep_name) out_dependencies.push_back(dep_name);
                } else if (dyn.d_tag == DT_RPATH) {
                    const char* r = elf_strptr(elf, shdr.sh_link, dyn.d_un.d_val);
                    if (r) info.rpath = r;
                } else if (dyn.d_tag == DT_RUNPATH) {
                    const char* r = elf_strptr(elf, shdr.sh_link, dyn.d_un.d_val);
                    if (r) info.runpath = r;
                }
            }
        }
    }

    GElf_Ehdr ehdr;
    if (gelf_getehdr(elf, &ehdr) && ehdr.e_type == ET_EXEC) info.requires_ie = true; 

    elf_end(elf);
    close(fd);
    return info;
}

size_t calculate_ie_tls(const std::vector<std::string>& audit_libs, const std::string& app_name) {
    size_t dl_tls_static_size = 0;
    size_t dl_tls_static_align = 1;
    std::unordered_set<std::string> visited;
    std::vector<std::string> to_process = audit_libs;
    to_process.push_back(app_name);

    while (!to_process.empty()) {
        std::string current_lib = to_process.back();
        to_process.pop_back();

        if (visited.find(current_lib) != visited.end()) continue;
        visited.insert(current_lib);

        std::vector<std::string> dependencies;
        TlsInfo tls_info = get_elf_tls_info(current_lib, dependencies);

        if (tls_info.size > 0 && tls_info.requires_ie) {
            dl_tls_static_align = std::max(dl_tls_static_align, tls_info.align);
            dl_tls_static_size = roundup(dl_tls_static_size, tls_info.align) + tls_info.size;
        }

        for (const auto& dep : dependencies) {
            std::string full_path = resolve_dependency_path(dep, current_lib, tls_info.rpath, tls_info.runpath);
            if (!full_path.empty() && visited.find(full_path) == visited.end()) {
                to_process.push_back(full_path);
            }
        }
    }
    return roundup(dl_tls_static_size, dl_tls_static_align);
}