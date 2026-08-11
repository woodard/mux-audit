AC_INIT([audit-multiplexer], [1.0])
AC_CONFIG_SRCDIR([src/audit_multiplexer.cpp])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])

AM_INIT_AUTOMAKE([foreign subdir-objects -Wall -Werror])

# Check for C++ compiler
AC_PROG_CXX

# Enforce C++17 support
CXXFLAGS="$CXXFLAGS -std=c++17"

# Required by Libtool when building archives
AM_PROG_AR

# Initialize Libtool
LT_INIT([shared disable-static dlopen])

# Check for version 2 debugger rendezvous protocol (glibc >= 2.35)
AC_CHECK_TYPE([struct r_debug_extended],
              [AC_DEFINE([HAVE_STRUCT_R_DEBUG_EXTENDED], [1], [Define if struct r_debug_extended exists])],
              [AC_MSG_ERROR([glibc is too old: struct r_debug_extended not found in <link.h>. A newer glibc with multi-namespace support is strictly required.])],
              [[#include <link.h>]])

# Check for libelf / elfutils (required for TLS sizing calculation)
AC_CHECK_HEADERS([libelf.h gelf.h], [], [AC_MSG_ERROR([Required elfutils headers (libelf.h, gelf.h) not found. Please install elfutils-devel or libelf-dev.])])
AC_CHECK_LIB([elf], [elf_begin], [LIBELF_LIBS="-lelf"], [AC_MSG_ERROR([libelf (elfutils) is required but was not found. Please install elfutils-libelf or libelf-dev.])])
AC_SUBST([LIBELF_LIBS])

# Output Makefiles
AC_CONFIG_FILES([
    Makefile
    test/Makefile
])
AC_OUTPUT