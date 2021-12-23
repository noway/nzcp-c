prefix = /usr/local
libdir = $(prefix)/lib
includedir = $(prefix)/include

CFLAGS = -Wall -Wextra -O3
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

sweet-b:
	git clone git@github.com:westerndigitalcorporation/sweet-b.git
	cd sweet-b && sed -i -e 's/SHARED/STATIC/g' CMakeLists.txt
	cd sweet-b && sed -i -e 's/LIBRARY DESTINATION $${CMAKE_INSTALL_LIBDIR}/ARCHIVE DESTINATION $${CMAKE_INSTALL_LIBDIR} LIBRARY DESTINATION $${CMAKE_INSTALL_LIBDIR}/g' CMakeLists.txt

tinycbor:
	git clone git@github.com:intel/tinycbor.git
	cd tinycbor && sed -i -e 's/BUILD_SHARED = .*/BUILD_SHARED = 0/g' Makefile

build_sweet_b: sweet-b
	cd sweet-b && cmake . && make && DESTDIR=$(PWD)/compiled make install

build_tinycbor: tinycbor
	cd tinycbor && make && DESTDIR=$(PWD)/compiled make install

clean:
	rm -rf $(PWD)/compiled
	rm -rf $(PWD)/sweet-b
	rm -rf $(PWD)/tinycbor
	rm -rf $(PWD)/objects
	rm -f $(PWD)/main
	rm -f $(PWD)/libnzcp.dylib
	rm -f $(PWD)/libnzcp.a
