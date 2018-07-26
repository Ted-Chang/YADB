#include <stdio.h>
#include <stdbool.h>
#include "rbtrace.h"

int main(int argc, char *argv[])
{
	int rc = 0;
	bool rbtrace_inited = false;

	rc = rbtrace_init();
	if (rc != 0) {
		fprintf(stderr, "rbtrace_init failed, error:%d\n", rc);
		goto out;
	}
	rbtrace_inited = true;

 out:
	if (rbtrace_inited) {
		rbtrace_exit();
	}

	return rc;
}
