check_LTLIBRARIES = dummy_auditor.la
check_PROGRAMS = dummy_app

dummy_auditor_la_SOURCES = dummy_auditor.cpp
dummy_auditor_la_CPPFLAGS = -I$(top_srcdir)/include
# Link against the utility library built in the root directory
dummy_auditor_la_LIBADD = $(top_builddir)/libaudit_utils.la
# -rpath is required here to force libtool to build a shared .so for a check_ target
dummy_auditor_la_LDFLAGS = -module -avoid-version -shared -rpath /nowhere

dummy_app_SOURCES = dummy_app.cpp

TESTS = test_runner.sh
EXTRA_DIST = test_runner.sh

clean-local:
	rm -f *.log *.trs