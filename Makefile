CFLAGS = -Wall -Wextra -O3
LIBRARY_PATH=$(PWD)/compiled/usr/local/lib:$(PWD)/build/lib
CPATH=$(PWD)/compiled/usr/local/include:$(PWD)/build/include

.PHONY: clean build_sweet_b build_tinycbor

build: build/lib/libnzcp.dylib build/include/nzcp.h
	LIBRARY_PATH=$(LIBRARY_PATH) CPATH=$(CPATH) $(CC) $(CFLAGS) main.c -o main -lnzcp

build/lib/libnzcp.dylib: build_sweet_b build_tinycbor
	mkdir -p build/lib
	LIBRARY_PATH=$(LIBRARY_PATH) CPATH=$(CPATH) $(CC) $(CFLAGS) -dynamiclib -fPIC nzcp.c -o build/lib/libnzcp.dylib -ltinycbor -lsweet_b

build/include/nzcp.h:
	mkdir -p build/include
	cp nzcp.h build/include/nzcp.h

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
	rm -rf $(PWD)/build
	rm -rf $(PWD)/sweet-b
	rm -rf $(PWD)/tinycbor
	rm -f $(PWD)/main
