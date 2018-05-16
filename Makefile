# Author: Ted Zhang
CFLAGS = -Wall -g -fstack-protector
CC = gcc

all: bptest bench lktest

lktest:
	$(CC) -D_LOCK_UNITTEST lock.c -lpthread -o lktest

bptest:
	$(CC) -D_BPT_UNITTEST bptree.c lock.c -lpthread -o bptest

bench: bench.o bptree.o lock.o
	$(CC) $^ -lpthread -lrt -o $@

clean:
	rm *.o bptest bench lktest

