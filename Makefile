# Author: Ted Zhang
CFLAGS = -Wall -g
CC = gcc

all: bptest bench

bptest:
	$(CC) -g -D_UNITTEST bptree.c -lpthread -o bptest

bench: bench.o bptree.o
	$(CC) $^ -lpthread -o $@

clean:
	rm *.o bptest bench

