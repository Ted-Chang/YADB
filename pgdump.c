#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <errno.h>
#include "bptree.h"
#include "bptdef.h"
#include "bpt_private.h"

static char buf[BPT_MAX_PAGE_SIZE];

int main(int argc, char *argv[])
{
	int rc = 0;
	unsigned int pg_size;
	struct bpt_page *pg = NULL;

	pg_size = read(STDIN_FILENO, buf, sizeof(buf));
	if ((pg_size < BPT_MIN_PAGE_SIZE) ||
	    (pg_size % BPT_MIN_PAGE_SIZE)) {
		rc = errno;
		printf("Invalid page data size:%d!\n", pg_size);
	} else {
		pg = (struct bpt_page *)buf;
		dump_bpt_page(pg, pg_size);
	}

	return rc;
}
