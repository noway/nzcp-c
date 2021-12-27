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

.PHONY: clean install uninstall

build: $(COMPILED_SWEET_B) $(COMPILED_TINYCBOR)
	mkdir -p objects
	LIBRARY_PATH=$(LIBRARY_PATH) CPATH=$(CPATH) $(CC) $(CFLAGS) -c -fPIC nzcp.c -o objects/libnzcp.o 
	cd objects && ar x $(LIB_PATH_SWEET_B)/libsweet_b.a
	cd objects && ar x $(LIB_PATH_TINYCBOR)/libtinycbor.a
	cd objects && ar qc ../libnzcp.a *.o

install:
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
	cd tinycbor-main && sed -i -e 's/BUILD_SHARED = .*/BUILD_SHARED = 0/g' Makefile

$(COMPILED_SWEET_B): sweet-b-master
	cd sweet-b-master && cmake . && make && DESTDIR=$(COMPILED_SWEET_B) make install

$(COMPILED_TINYCBOR): tinycbor-main
	cd tinycbor-main && make && DESTDIR=$(COMPILED_TINYCBOR) make install

clean:
	rm -rf $(COMPILED_SWEET_B)
	rm -rf $(COMPILED_TINYCBOR)
	rm -rf $(PWD)/sweet-b-master
	rm -rf $(PWD)/tinycbor-main
	rm -rf $(PWD)/objects
	rm -f $(PWD)/main
	rm -f $(PWD)/libnzcp.dylib
	rm -f $(PWD)/libnzcp.a
	rm -f $(PWD)/sweet-b.zip
	rm -f $(PWD)/tinycbor.zip
