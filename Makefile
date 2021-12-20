LIBRARY_PATH=$(PWD)/compiled-sweet-b/usr/local/lib:$(PWD)/compiled-tinycbor/usr/local/lib
CPATH=$(PWD)/compiled-sweet-b/usr/local/include:$(PWD)/compiled-tinycbor/usr/local/include

.PHONY: clean

build: compiled-sweet-b compiled-tinycbor
	LIBRARY_PATH=$(LIBRARY_PATH) CPATH=$(CPATH) $(CC) main.c base32.c -o main -ltinycbor -lsweet_b

sweet-b:
	git clone git@github.com:westerndigitalcorporation/sweet-b.git
	cd sweet-b && sed -i -e 's/SHARED/STATIC/g' CMakeLists.txt
	cd sweet-b && sed -i -e 's/LIBRARY DESTINATION $${CMAKE_INSTALL_LIBDIR}/ARCHIVE DESTINATION $${CMAKE_INSTALL_LIBDIR} LIBRARY DESTINATION $${CMAKE_INSTALL_LIBDIR}/g' CMakeLists.txt

tinycbor:
	git clone git@github.com:intel/tinycbor.git
	cd tinycbor && sed -i -e 's/BUILD_SHARED = .*/BUILD_SHARED = 0/g' Makefile

compiled-sweet-b: sweet-b
	cd sweet-b && cmake . && make && DESTDIR=$(PWD)/compiled-sweet-b make install

compiled-tinycbor: tinycbor
	cd tinycbor && make && DESTDIR=$(PWD)/compiled-tinycbor make install

clean:
	rm -rf $(PWD)/compiled-sweet-b
	rm -rf $(PWD)/compiled-tinycbor
	rm -rf $(PWD)/sweet-b
	rm -rf $(PWD)/tinycbor
	rm -f $(PWD)/main
