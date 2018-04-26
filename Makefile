# Author: Ted Zhang
CFLAGS = -Wall -g -fstack-protector
CC = gcc

all: bptest bench lktest pgdump

lktest:
	$(CC) -g -D_LOCK_UNITTEST lock.c -lpthread -o lktest

bptest:
	$(CC) -g -D_BPT_UNITTEST bptree.c lock.c -lpthread -o bptest

bench: bench.o bptree.o lock.o
	$(CC) $^ -lpthread -lrt -o $@

pgdump: pgdump.o bptree.o lock.o
	$(CC) $^ -lpthread -lrt -o $@

clean:
	rm *.o bptest bench lktest pgdump

