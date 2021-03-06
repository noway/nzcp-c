prefix = /usr/local
libdir = $(prefix)/lib
includedir = $(prefix)/include

# TODO: add -Wconversion
CFLAGS = -std=c99 \
	-Werror -Wall -Wstrict-prototypes -Wmissing-prototypes -Wextra -Wshadow \
	-Wno-typedef-redefinition -O3

COMPILED_SWEET_B=$(PWD)/compiled-sweet-b
COMPILED_TINYCBOR=$(PWD)/compiled-tinycbor
LIB_PATH_SWEET_B=$(COMPILED_SWEET_B)/usr/local/lib
LIB_PATH_TINYCBOR=$(COMPILED_TINYCBOR)/usr/local/lib
CPATH_SWEET_B=$(COMPILED_SWEET_B)/usr/local/include
CPATH_TINYCBOR=$(COMPILED_TINYCBOR)/usr/local/include
LIBRARY_PATH=$(LIB_PATH_SWEET_B):$(LIB_PATH_TINYCBOR)
CPATH=$(CPATH_SWEET_B):$(CPATH_TINYCBOR)
NZCP_VERSION_MAJOR=$(shell cat VERSION | cut -d "." -f 1)
NZCP_VERSION_MINOR=$(shell cat VERSION | cut -d "." -f 2)
NZCP_VERSION_PATCH=$(shell cat VERSION | cut -d "." -f 3)

.PHONY: clean-compiled clean-downloaded install uninstall objects

all: libnzcp.a

libnzcp.a: objects/libnzcp.o
	cd objects && ar qc ../libnzcp.a *.o

objects/libnzcp.o: objects nzcp.h
	LIBRARY_PATH=$(LIBRARY_PATH) CPATH=$(CPATH) $(CC) $(CFLAGS) -c -fPIC nzcp.c -o objects/libnzcp.o 

nzcp.h:
	cpp \
		-D'_NZCP_VERSION_MAJOR=$(NZCP_VERSION_MAJOR)' \
		-D'_NZCP_VERSION_MINOR=$(NZCP_VERSION_MINOR)' \
		-D'_NZCP_VERSION_PATCH=$(NZCP_VERSION_PATCH)' \
		-E -CC -P \
		nzcp.h.in \
		| sed 's/##//g' \
		| sed 's/\/\*{\*\//\/\*\*/g' \
		| sed 's/\/\*}\*\//\*\//g' > nzcp.h

objects: $(COMPILED_SWEET_B) $(COMPILED_TINYCBOR)
	mkdir -p objects
	cd objects && ar x $(LIB_PATH_SWEET_B)/libsweet_b.a
	cd objects && ar x $(LIB_PATH_TINYCBOR)/libtinycbor.a

install: libnzcp.a nzcp.h
	install -d $(DESTDIR)$(libdir)
	install -m 644 libnzcp.a $(DESTDIR)$(libdir)/libnzcp.a
	install -d $(DESTDIR)$(includedir)
	install -m 644 nzcp.h $(DESTDIR)$(includedir)/nzcp.h

uninstall:
	rm -f $(DESTDIR)$(libdir)/libnzcp.a
	rm -f $(DESTDIR)$(includedir)/nzcp.h

sweet-b.zip:
	curl -Lo sweet-b.zip https://github.com/westerndigitalcorporation/sweet-b/archive/refs/heads/master.zip
sweet-b-master: sweet-b.zip
	unzip sweet-b.zip
	cd sweet-b-master && sed -i -e 's/SHARED/STATIC/g' CMakeLists.txt
	cd sweet-b-master && sed -i -e 's/LIBRARY DESTINATION $${CMAKE_INSTALL_LIBDIR}/ARCHIVE DESTINATION "lib" LIBRARY DESTINATION "lib"/g' CMakeLists.txt

tinycbor.zip:
	curl -Lo tinycbor.zip https://github.com/intel/tinycbor/archive/refs/heads/main.zip
tinycbor-main: tinycbor.zip
	unzip tinycbor.zip
	# TODO: more elegant patch which doesn't require removing can_read_bytes
	patch --forward -p 0 < tinycbor-copy-byte-string.patch # tinycbor refuses to copy string fully and fails prematurely
	patch --forward -p 0 < tinycbor-unreasonable-chunk-len.patch # tinycbor segfaults on unreasonable chunk length
	cd tinycbor-main && sed -i -e 's/BUILD_SHARED = .*/BUILD_SHARED = 0/g' Makefile

$(COMPILED_SWEET_B): sweet-b-master
	cd sweet-b-master && CFLAGS="-fPIC" cmake . && make && DESTDIR=$(COMPILED_SWEET_B) make install

$(COMPILED_TINYCBOR): tinycbor-main
	cd tinycbor-main && CPPFLAGS="-fPIC" make && DESTDIR=$(COMPILED_TINYCBOR) make install

doc: nzcp.h
	VERSION=$(shell cat VERSION) doxygen

clean-compiled:
	rm -rf $(COMPILED_SWEET_B)
	rm -rf $(COMPILED_TINYCBOR)
	rm -rf $(PWD)/compiled-nzcp
	rm -rf $(PWD)/objects
	rm -rf $(PWD)/html
	rm -rf $(PWD)/latex
	rm -f $(PWD)/main
	rm -f $(PWD)/libnzcp.dylib
	rm -f $(PWD)/libnzcp.a
	rm -f $(PWD)nzcp.h

clean-downloaded:
	rm -rf $(PWD)/sweet-b-master
	rm -rf $(PWD)/tinycbor-main
	rm -f $(PWD)/sweet-b.zip
	rm -f $(PWD)/tinycbor.zip

clean: clean-compiled clean-downloaded