.PHONY: all build test
.NOTPARALLEL:

all: build test
build: libauditor.so libemptyaudit.so main libbad.so libgood.so
test: build
	@echo
	@echo 'Success requires OK (not FAIL) at the end of each line:'
	LD_AUDIT=./libauditor.so:./libemptyaudit.so ./main

libauditor.so: auditor.c
	gcc -g -o $@ $< -fPIC -shared
libemptyaudit.so: emptyaudit.c
	gcc -g -o $@ $< -fPIC -shared
main: main.c
	gcc -g -o $@ $< -ldl
libbad.so: libbad.c libgood.so
	gcc -g -o $@ $< -fPIC -shared -L. -lgood
libgood.so: libgood.c
	gcc -g -o $@ $< -fPIC -shared
