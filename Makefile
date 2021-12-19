build:
	make build_tinycbor ; make build_sweet_b ; clang -ltinycbor -lsweet_b -o main main.c base32.c -I $(PWD)/compiled/usr/local/include -L $(PWD)/compiled/usr/local/lib
clean:
	cd tinycbor ; make clean
	cd sweet-b ; make clean
	rm -rf $(PWD)/compiled
build_tinycbor:
	cd tinycbor ; make ; make install DESTDIR=$(PWD)/compiled
build_sweet_b:
	cd sweet-b ; cmake . ;  make ; DESTDIR=$(PWD)/compiled make install
