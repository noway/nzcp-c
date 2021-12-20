build:
	make git_clone_sweet_b
	make git_clone_tinycbor
	make build_sweet_b
	make build_tinycbor
	clang -ltinycbor -lsweet_b -o main main.c base32.c -I $(PWD)/compiled/usr/local/include -L $(PWD)/compiled/usr/local/lib

clean:
	rm -rf $(PWD)/compiled
	rm -rf $(PWD)/sweet-b
	rm -rf $(PWD)/tinycbor
	rm $(PWD)/main

git_clone_sweet_b:
	git clone git@github.com:westerndigitalcorporation/sweet-b.git || true
git_clone_tinycbor:
	git clone git@github.com:intel/tinycbor.git || true

build_sweet_b:
	cd sweet-b ; sed -i -e 's/SHARED/STATIC/g' CMakeLists.txt
	cd sweet-b ; cmake . ;  make ; DESTDIR=$(PWD)/compiled make install
build_tinycbor:
	cd tinycbor ; make ; DESTDIR=$(PWD)/compiled make install
