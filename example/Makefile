CFLAGS = -Wall -Wextra -O3

.PHONY: clean

build: ../libnzcp.a
	$(CC) $(CFLAGS) -I ../ -L ../ main.c -o main -lnzcp

../libnzcp.a:
	cd .. && make

clean:
	cd .. && make clean
	rm -f main