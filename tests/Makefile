.PHONY: clean

all: ../libnzcp.a
	$(CC) -I ../ -L ../ nzcp_tests.c -o nzcp_tests -lnzcp 
	$(CC) -I ../ -L ../ nzcp_tests_chunk_overruns.c -o nzcp_tests_chunk_overruns -lnzcp 

../libnzcp.a:
	cd .. && make

clean:
	cd .. && make clean
	rm -f nzcp_tests
