.PHONY: clean

all: ../libnzcp.a
	$(CC) -I ../ -L ../ nzcp_tests.c -lnzcp 

../libnzcp.a:
	cd .. && make

clean:
	cd .. && make clean
	rm -f a.out