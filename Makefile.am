ACLOCAL_AMFLAGS = -I m4

# Build both the root directory and the test directory
SUBDIRS = . test

# Define the include directory for headers to install
include_HEADERS = include/audit_multiplexer.h

# Define the utility library AND the main audit module
lib_LTLIBRARIES = libaudit_utils.la audit_multiplexer.la

# Setup the utility library
libaudit_utils_la_SOURCES = src/audit_utils.cpp
libaudit_utils_la_CPPFLAGS = -I$(top_srcdir)/include

# Setup the multiplexer module
audit_multiplexer_la_SOURCES = src/audit_multiplexer.cpp
audit_multiplexer_la_CPPFLAGS = -I$(top_srcdir)/include
audit_multiplexer_la_LDFLAGS = -module -avoid-version -shared -Wl,-z,now
audit_multiplexer_la_LIBADD = libaudit_utils.la -ldl