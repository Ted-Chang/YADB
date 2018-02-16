# Author: Ted Zhang
CFLAGS = -Wall -g
CC = gcc

all: yadb

yadb: bptree.o
	$(CC) $^ -o $@
	rm *.o

clean:
	rm *.o yadb

