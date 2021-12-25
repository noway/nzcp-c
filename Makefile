prefix = /usr/local
libdir = $(prefix)/lib
includedir = $(prefix)/include

# TODO: add -Wconversion
CFLAGS = -std=c99 \
	-Werror -Wall -Wstrict-prototypes -Wmissing-prototypes -Wextra -Wshadow \
	-Wno-typedef-redefinition -O3
LIBRARY_PATH=$(PWD)/compiled/usr/local/lib
CPATH=$(PWD)/compiled/usr/local/include

.PHONY: clean build_sweet_b build_tinycbor install uninstall

build: libnzcp.a

install:
	install -d $(DESTDIR)$(libdir)
	install -m 644 libnzcp.a $(DESTDIR)$(libdir)/libnzcp.a
	install -d $(DESTDIR)$(includedir)
	install -m 644 nzcp.h $(DESTDIR)$(includedir)/nzcp.h

uninstall:
	rm -f $(DESTDIR)$(libdir)/libnzcp.a
	rm -f $(DESTDIR)$(includedir)/nzcp.h

libnzcp.a: build_sweet_b build_tinycbor
	mkdir -p objects
	LIBRARY_PATH=$(LIBRARY_PATH) CPATH=$(CPATH) $(CC) $(CFLAGS) -c -fPIC nzcp.c -o objects/libnzcp.o 
	cd objects && ar x $(LIBRARY_PATH)/libsweet_b.a
	cd objects && ar x $(LIBRARY_PATH)/libtinycbor.a
	cd objects && ar qc ../libnzcp.a *.o

sweet-b.zip:
	curl -Lo sweet-b.zip https://github.com/westerndigitalcorporation/sweet-b/archive/refs/heads/master.zip
sweet-b-master: sweet-b.zip
	unzip sweet-b.zip
	cd sweet-b-master && sed -i -e 's/SHARED/STATIC/g' CMakeLists.txt
	cd sweet-b-master && sed -i -e 's/LIBRARY DESTINATION $${CMAKE_INSTALL_LIBDIR}/ARCHIVE DESTINATION $${CMAKE_INSTALL_LIBDIR} LIBRARY DESTINATION $${CMAKE_INSTALL_LIBDIR}/g' CMakeLists.txt

tinycbor.zip:
	curl -Lo tinycbor.zip https://github.com/intel/tinycbor/archive/refs/heads/main.zip
tinycbor-main: tinycbor.zip
	unzip tinycbor.zip
	cd tinycbor-main && sed -i -e 's/BUILD_SHARED = .*/BUILD_SHARED = 0/g' Makefile

build_sweet_b: sweet-b-master
	cd sweet-b-master && cmake . && make && DESTDIR=$(PWD)/compiled make install

build_tinycbor: tinycbor-main
	cd tinycbor-main && make && DESTDIR=$(PWD)/compiled make install

clean:
	rm -rf $(PWD)/compiled
	rm -rf $(PWD)/sweet-b-master
	rm -rf $(PWD)/tinycbor-main
	rm -rf $(PWD)/objects
	rm -f $(PWD)/main
	rm -f $(PWD)/libnzcp.dylib
	rm -f $(PWD)/libnzcp.a
	rm -f $(PWD)/sweet-b.zip
	rm -f $(PWD)/tinycbor.zip
