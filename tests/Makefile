CFLAGS = -Wall -Wextra -fsanitize=address,undefined -fsanitize-recover=address,undefined

.PHONY: clean nzcp_tests

all: nzcp_tests fuzz

nzcp_tests: ../libnzcp.a
	$(CC) $(CFLAGS) -I ../ -L ../ nzcp_tests.c -o nzcp_tests -lnzcp 

fuzz:
	./generate_fuzz

../libnzcp.a:
	cd .. && make

clean:
	cd .. && make clean
	rm -f nzcp_tests
