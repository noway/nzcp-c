CFLAGS = -Wall -Wextra -O3 
CPATH=$(JAVA_HOME)/include:$(JAVA_HOME)/include/linux:../
LIBRARY_PATH=../

.PHONY: clean

libnzcpjni.so: ../libnzcp.a NZCPJNI.h
	LIBRARY_PATH=$(LIBRARY_PATH) CPATH=$(CPATH) $(CC) $(CFLAGS) -fPIC -shared NZCPJNI.cpp -o $@ -lnzcp

NZCPJNI.h: NZCPJNI.java
	javac -h . $<

NZCPJNI.java: NZCPJNI.java.in
	cpp -P $< > $@

../libnzcp.a:
	cd .. && make

clean:
	cd .. && make clean
	rm -rf *.class NZCPJNI.java NZCPJNI.h libnzcpjni.so