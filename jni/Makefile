OPENJDK=$(shell brew --prefix openjdk@11)

all:
	javac -h . NZCPJNI.java
	clang -fPIC -shared \
		-I "$(OPENJDK)/include"\
		-I .\
		-o libnzcpjni.so\
		NZCPJNI.cpp