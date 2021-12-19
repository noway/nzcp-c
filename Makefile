build:
	make build_sweet_b
	make build_tinycbor
	clang -ltinycbor -lsweet_b -o main main.c base32.c -I $(PWD)/compiled/usr/local/include -L $(PWD)/compiled/usr/local/lib
clean:
	cd sweet-b ; make clean
	cd tinycbor ; make clean
	rm -rf $(PWD)/compiled
build_tinycbor:
	cd tinycbor ; make ; DESTDIR=$(PWD)/compiled make install
build_sweet_b:
	cd sweet-b ; cmake . ;  make ; DESTDIR=$(PWD)/compiled make install
