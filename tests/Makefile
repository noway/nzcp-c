CFLAGS = -Wall -Wextra -fsanitize=address,undefined -fsanitize-recover=address,undefined

.PHONY: clean nzcp_tests nzcp_tests_chunk_overruns

all: nzcp_tests nzcp_tests_chunk_overruns fuzz

nzcp_tests: ../libnzcp.a
	$(CC) $(CFLAGS) -I ../ -L ../ nzcp_tests.c -o nzcp_tests -lnzcp 

nzcp_tests_chunk_overruns: ../libnzcp.a
	$(CC) $(CFLAGS) -I ../ -L ../ nzcp_tests_chunk_overruns.c -o nzcp_tests_chunk_overruns -lnzcp 

fuzz:
	./generate_fuzz

../libnzcp.a:
	cd .. && make

clean:
	cd .. && make clean
	rm -f nzcp_tests
