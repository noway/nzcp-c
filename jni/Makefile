CFLAGS = -Wall -Wextra -O3 

.PHONY: all clean

all: ../libnzcp.a
	cpp -P NZCPJNI.java.in NZCPJNI.java
	javac -h . NZCPJNI.java
	$(CC) $(CFLAGS) \
		-fPIC -shared \
		-I "$(JAVA_HOME)/include" \
		-I ../ \
		-L ../ \
		NZCPJNI.cpp \
		-o libnzcpjni.so \
		-lnzcp

../libnzcp.a:
	cd .. && make

clean:
	cd .. && make clean
	rm -rf *.class NZCPJNI.java libnzcpjni.so