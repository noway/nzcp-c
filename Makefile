LIBRARY_PATH=$(PWD)/compiled/usr/local/lib
CPATH=$(PWD)/compiled/usr/local/include

build:
	make git_clone_sweet_b
	make git_clone_tinycbor
	make build_sweet_b
	make build_tinycbor
	LIBRARY_PATH=$(LIBRARY_PATH) CPATH=$(CPATH) $(CC) main.c base32.c -o main -ltinycbor -lsweet_b

clean:
	rm -rf $(PWD)/compiled
	rm -rf $(PWD)/sweet-b
	rm -rf $(PWD)/tinycbor
	rm -f $(PWD)/main

git_clone_sweet_b:
	git clone git@github.com:westerndigitalcorporation/sweet-b.git || true
git_clone_tinycbor:
	git clone git@github.com:intel/tinycbor.git || true

build_sweet_b:
	cd sweet-b ; sed -i -e 's/SHARED/STATIC/g' CMakeLists.txt
	cd sweet-b ; sed -i -e 's/        LIBRARY DESTINATION $${CMAKE_INSTALL_LIBDIR}/        ARCHIVE DESTINATION $${CMAKE_INSTALL_LIBDIR} LIBRARY DESTINATION $${CMAKE_INSTALL_LIBDIR}/g' CMakeLists.txt
	cd sweet-b ; cmake . ;  make ; DESTDIR=$(PWD)/compiled make install
build_tinycbor:
	cd tinycbor ; sed -i -e 's/BUILD_SHARED = .*/BUILD_SHARED = 0/g' Makefile
	cd tinycbor ; make ; DESTDIR=$(PWD)/compiled make install
