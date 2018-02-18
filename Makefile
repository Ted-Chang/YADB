# Author: Ted Zhang
CFLAGS = -Wall -g
CC = gcc

all: bptest bench

bptest:
	$(CC) -D_UNITTEST bptree.c -o bptest

bench: bench.o bptree.o
	$(CC) $^ -o $@

clean:
	rm *.o yadb bench

