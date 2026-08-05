AM_CPPFLAGS = -I$(top_srcdir)/include

# Define environment variables available to all test scripts
AM_TESTS_ENVIRONMENT = \
    TEST_DIR='$(builddir)'; export TEST_DIR; \
    LIBS_DIR='$(builddir)/.libs'; export LIBS_DIR; \
    MUX_SO='$(top_builddir)/.libs/audit_multiplexer.so'; export MUX_SO; \
    LD_BIND_NOW=1; export LD_BIND_NOW; \
    LD_LIBRARY_PATH='$(builddir)/.libs:$(top_builddir)/.libs'; export LD_LIBRARY_PATH;

check_PROGRAMS = dummy_main test4_main dt_audit_app
check_LTLIBRARIES = \
    libtest1_auditor.la \
    libtest2_auditor.la \
    libtest3_auditor1.la \
    libtest3_auditor2.la \
    libtest3_payload.la \
    libtest4_auditor1.la \
    libtest4_auditor2.la \
    libtest4_payload.la \
    libdummy_auditor.la

# The target executable for both tests
dummy_main_SOURCES = dummy_main.cpp

# DT_AUDIT App (Compiled with the multiplexer in the ELF header)
dt_audit_app_SOURCES = dt_audit_app.cpp
dt_audit_app_LDFLAGS = -Wl,--audit="$(abs_top_builddir)/.libs/audit_multiplexer.so"

# Test 1: Basic event forwarding
libtest1_auditor_la_SOURCES = test1_auditor.cpp
libtest1_auditor_la_LDFLAGS = -module -avoid-version -shared -rpath /tmp -Wl,-z,now

# Test 2: V2 rendezvous protocol
libtest2_auditor_la_SOURCES = test2_auditor.cpp
libtest2_auditor_la_CPPFLAGS = -I$(top_srcdir)/include
libtest2_auditor_la_LDFLAGS = -module -avoid-version -shared -rpath /tmp -Wl,-z,now
libtest2_auditor_la_LIBADD = $(top_builddir)/libaudit_utils.la

# Test 3: First Auditor
libtest3_auditor1_la_SOURCES = test3_auditor1.cpp
libtest3_auditor1_la_LDFLAGS = -module -avoid-version -shared -rpath /tmp -Wl,-z,now
libtest3_auditor1_la_LIBADD = -ldl

# Test 3: Second Auditor
libtest3_auditor2_la_SOURCES = test3_auditor2.cpp
libtest3_auditor2_la_LDFLAGS = -module -avoid-version -shared -rpath /tmp -Wl,-z,now

# Test 3: Payload Library
libtest3_payload_la_SOURCES = test3_payload.cpp
libtest3_payload_la_LDFLAGS = -module -avoid-version -shared -rpath /tmp -Wl,-z,now

# Test 4: Main Target
test4_main_SOURCES = test4_main.cpp
test4_main_LDADD = -ldl

# Test 4: Auditor 1
libtest4_auditor1_la_SOURCES = test4_auditor1.cpp
libtest4_auditor1_la_LDFLAGS = -module -avoid-version -shared -rpath /tmp -Wl,-z,now

# Test 4: Auditor 2
libtest4_auditor2_la_SOURCES = test4_auditor2.cpp
libtest4_auditor2_la_LDFLAGS = -module -avoid-version -shared -rpath /tmp -Wl,-z,now

# Test 4: Payload Library
libtest4_payload_la_SOURCES = test4_payload.cpp
libtest4_payload_la_LDFLAGS = -module -avoid-version -shared -rpath /tmp -Wl,-z,now

# Tests 5 & 6 & DT_AUDIT: Dummy Auditor
libdummy_auditor_la_SOURCES = dummy_auditor.cpp
libdummy_auditor_la_LDFLAGS = -module -avoid-version -shared -rpath /tmp -Wl,-z,now

# Run the test scripts
TESTS = \
    run_test1.sh \
    run_test2.sh \
    run_test3.sh \
    run_test4.sh \
    run_test5.sh \
    run_test6.sh \
    run_test_dtaudit.sh

EXTRA_DIST = $(TESTS) README.md