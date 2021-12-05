build:
	clang -ltinycbor -lsweet_b -pthread -o main main.c base32.c