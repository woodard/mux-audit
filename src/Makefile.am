lib_LTLIBRARIES = audit_multiplexer.la libaudit_utils.la

# 1. The Multiplexer Module
audit_multiplexer_la_SOURCES = audit_multiplexer.cpp tls_calculator.cpp
# Add -rpath to FORCE libtool to build the shared object
audit_multiplexer_la_LDFLAGS = -module -avoid-version -shared -rpath $(libdir) -Wl,-z,now
audit_multiplexer_la_LIBADD = libaudit_utils.la -lelf

# 2. The Utilities Library
libaudit_utils_la_SOURCES = audit_utils.cpp
# Add -rpath to FORCE libtool to build the shared object
libaudit_utils_la_LDFLAGS = -avoid-version -shared -rpath $(libdir) -Wl,-z,now