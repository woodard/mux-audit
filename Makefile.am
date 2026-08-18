ACLOCAL_AMFLAGS = -I m4

# Build both the root directory and the test directory
SUBDIRS = . test

# Define the include directory for headers to install
include_HEADERS = include/audit_multiplexer.h

# Define the utility library AND the main audit module
lib_LTLIBRARIES = libaudit_utils.la audit_multiplexer.la

# Standalone utility for calculating the optional static TLS tunable
bin_PROGRAMS = tls-calculator
tls_calculator_SOURCES = tls-calculator.cpp src/tls_calculator.cpp
tls_calculator_CPPFLAGS = -I$(top_srcdir)/src
tls_calculator_LDADD = $(LIBELF_LIBS)

# Setup the utility library
libaudit_utils_la_SOURCES = src/audit_utils.cpp
libaudit_utils_la_CPPFLAGS = -I$(top_srcdir)/include

# Setup the multiplexer module (Added tls_calculator.cpp)
audit_multiplexer_la_SOURCES = src/audit_multiplexer.cpp src/tls_calculator.cpp
audit_multiplexer_la_CPPFLAGS = -I$(top_srcdir)/include
audit_multiplexer_la_LDFLAGS = -module -avoid-version -shared -Wl,-z,now
audit_multiplexer_la_LIBADD = libaudit_utils.la -ldl $(LIBELF_LIBS)

# Specify the man pages to install in section 3
man3_MANS = \
    man/am_get_constructors.3 \
    man/am_iterate_maps.3

# Create an alias for am_get_destructors.3 pointing to am_get_constructors.3
install-data-hook:
	cd $(DESTDIR)$(man3dir) && \
	rm -f am_get_destructors.3 && \
	$(LN_S) am_get_constructors.3 am_get_destructors.3

uninstall-hook:
	rm -f $(DESTDIR)$(man3dir)/am_get_destructors.3

if HAVE_DOXYGEN
doxygen: Doxyfile
	$(DOXYGEN) $<
else
doxygen:
	@echo "Doxygen is required to build API documentation but was not found."
	@false
endif

.PHONY: doxygen

# Generated documentation and the bundle script are not installed.
CLEANFILES = Doxyfile
clean-local:
	rm -rf $(abs_builddir)/docs

EXTRA_DIST = Doxyfile.in tools/bundle_project.py