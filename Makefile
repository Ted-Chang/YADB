# Author: Ted Zhang
CFLAGS = -Wall -g -fstack-protector
CC = gcc

all: bptest bench lktest

lktest:
	$(CC) $(CFLAGS) -D_LOCK_UNITTEST lock.c -lpthread -o lktest

bptest:
	$(CC) $(CFLAGS) -D_BPT_UNITTEST bptree.c lock.c -lpthread -o bptest

bench: bench.o bptree.o lock.o
	$(CC) $(CFLAGS) $^ -lpthread -lrt -o $@

check:
	rm bpt.dat -f
	valgrind ./bptest

clean:
	rm *.o bptest bench lktest

