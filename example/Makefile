COMPILED=$(PWD)/compiled
LIBRARY_PATH=$(COMPILED)/usr/local/lib
CPATH=$(COMPILED)/usr/local/include

CFLAGS = -Wall -Wextra -O3

.PHONY: clean

build: $(COMPILED)
	LIBRARY_PATH=$(LIBRARY_PATH) CPATH=$(CPATH) $(CC) $(CFLAGS) main.c -o main -lnzcp

$(COMPILED):
	cd .. && make && DESTDIR=$(COMPILED) make install

clean:
	rm -rf $(COMPILED)