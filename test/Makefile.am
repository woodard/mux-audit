check_PROGRAMS = dummy_main
check_LTLIBRARIES = libtest1_auditor.la libtest2_auditor.la

# The target executable for both tests
dummy_main_SOURCES = dummy_main.cpp

# Test 1: Basic event forwarding
libtest1_auditor_la_SOURCES = test1_auditor.cpp
libtest1_auditor_la_LDFLAGS = -module -avoid-version -shared -rpath /tmp

# Test 2: V2 rendezvous protocol
libtest2_auditor_la_SOURCES = test2_auditor.cpp
libtest2_auditor_la_CPPFLAGS = -I$(top_srcdir)/include
# FIX: Use -L to point to the src directory, instead of a direct file dependency
libtest2_auditor_la_LDFLAGS = -module -avoid-version -shared -rpath /tmp
libtest2_auditor_la_LIBADD = $(top_builddir)/libaudit_utils.la

# Run the test scripts
TESTS = run_test1.sh run_test2.sh
EXTRA_DIST = run_test1.sh run_test2.sh
