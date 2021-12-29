CFLAGS = -Wall -Wextra -O3 
OPENJDK=$(shell brew --prefix openjdk@11)

all:
	javac -h . NZCPJNI.java
	$(CC) $(CFLAGS) \
		-fPIC -shared \
		-I "$(OPENJDK)/include" -I ../ \
		-L ../ \
		NZCPJNI.cpp \
		-o libnzcpjni.so \
		-lnzcp
