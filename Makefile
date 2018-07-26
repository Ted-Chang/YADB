# Author: Ted Zhang
CFLAGS = -Wall -g -fstack-protector -I./rbtrace/include
CC = gcc

all: bptest bench lktest yadb

lktest:
	$(CC) $(CFLAGS) -D_LOCK_UNITTEST lock.c -lpthread -o lktest

bptest:
	$(CC) $(CFLAGS) -D_BPT_UNITTEST bptree.c lock.c -lpthread -o bptest

bench:
	$(CC) $(CFLAGS) bptree.c lock.c bench.c -lpthread -lrt -o $@

librbtrace:
	cd rbtrace && $(MAKE) librbtrace

yadb: librbtrace
	$(CC) $(CFLAGS) standalone.c bptree.c lock.c rbtrace/librbtrace.a -lrt -lpthread -o yadb

check:
	rm bpt.dat -f
	valgrind ./bptest

clean:
	rm -rf *.o bptest bench lktest yadb rbtrace/*.o rbtrace/*.a

