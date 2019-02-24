# Author: Ted Zhang
CFLAGS = -Wall -g -fstack-protector -I./rbtrace/include
CC = gcc

all: db_test db_bench lktest yadb

lktest:
	$(CC) $(CFLAGS) -D_LOCK_UNITTEST lock.c -lpthread -o lktest

db_test:
	$(CC) $(CFLAGS) -D_BPT_UNITTEST bptree.c lock.c -lpthread -o $@

db_bench:
	$(CC) $(CFLAGS) bptree.c lock.c bench.c -lpthread -lrt -o $@

librbtrace:
	cd rbtrace && $(MAKE) librbtrace

yadb: librbtrace
	$(CC) $(CFLAGS) standalone.c bptree.c lock.c rbtrace/librbtrace.a -lrt -lpthread -o yadb

check:
	rm bpt.dat -f
	valgrind ./db_test

clean:
	rm -rf *.o db_test db_bench lktest yadb rbtrace/*.o rbtrace/*.a

