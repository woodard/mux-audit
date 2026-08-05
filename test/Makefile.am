AM_CPPFLAGS = -I$(top_srcdir)/include

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

# --- Additions for Test 3 ---

# Add the new libraries to check_LTLIBRARIES
check_LTLIBRARIES += libtest3_auditor1.la libtest3_auditor2.la libtest3_payload.la

# Test 3: First Auditor
libtest3_auditor1_la_SOURCES = test3_auditor1.cpp
libtest3_auditor1_la_LDFLAGS = -module -avoid-version -shared -rpath /tmp
# Explicitly link libdl (needed on some older glibc versions for dlopen)
libtest3_auditor1_la_LIBADD = -ldl

# Test 3: Second Auditor
libtest3_auditor2_la_SOURCES = test3_auditor2.cpp
libtest3_auditor2_la_LDFLAGS = -module -avoid-version -shared -rpath /tmp

# Test 3: Payload Library
libtest3_payload_la_SOURCES = test3_payload.cpp
libtest3_payload_la_LDFLAGS = -module -avoid-version -shared -rpath /tmp

# Add the test script to TESTS and EXTRA_DIST
TESTS += run_test3.sh
EXTRA_DIST += run_test3.sh

# --- Additions for Test 4 ---

# Add a dedicated target executable for test 4
check_PROGRAMS += test4_main
test4_main_SOURCES = test4_main.cpp
test4_main_LDADD = -ldl

# Add the new libraries to check_LTLIBRARIES
check_LTLIBRARIES += libtest4_auditor1.la libtest4_auditor2.la libtest4_payload.la

# Test 4: Auditor 1
libtest4_auditor1_la_SOURCES = test4_auditor1.cpp
libtest4_auditor1_la_LDFLAGS = -module -avoid-version -shared -rpath /tmp

# Test 4: Auditor 2
libtest4_auditor2_la_SOURCES = test4_auditor2.cpp
libtest4_auditor2_la_LDFLAGS = -module -avoid-version -shared -rpath /tmp

# Test 4: Payload Library
libtest4_payload_la_SOURCES = test4_payload.cpp
libtest4_payload_la_LDFLAGS = -module -avoid-version -shared -rpath /tmp

# Add the test script to TESTS and EXTRA_DIST
TESTS += run_test4.sh
EXTRA_DIST += run_test4.sh README.md

