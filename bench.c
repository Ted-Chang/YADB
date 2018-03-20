#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdarg.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/mman.h>
#include "bptree.h"

pthread_mutex_t bench_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t bench_cond = PTHREAD_COND_INITIALIZER;
int ready_threads = 0;

struct key_value {
	unsigned char len;
	char key[64];
	unsigned long long value;
};

struct bench_option {
	unsigned int page_bits;
	int rounds;
	int read;
	int random;
	int cleanup;
	unsigned int cache_capacity;
	unsigned int nr_threads;
	unsigned int nr_processes;
};

struct shm_bench_kv {
	unsigned int index;
	unsigned int nr_kvs;
	struct key_value kvs[0];
};

struct thread_info {
	pthread_t thread;
	bptree_t bpt;
	struct shm_bench_kv *bench_kv;
};

static void usage();
static void print_seperator();

struct bench_option opts = {
	12,	// page_bits
	64*1024,// rounds
	1,	// read
	0,	// random
	1,	// cleanup
	0,	// cache_capacity
	1,	// nr_threads
	1	// nr_processes
};

static void dump_options(struct bench_option *options)
{
	printf("Page bits: %d\n", options->page_bits);
	printf("Number of keys: %d\n", options->rounds);
	printf("Operation: %s\n", options->read ? "read" : "write");
	printf("IO pattern: %s\n", options->random ? "random" : "sequential");
	printf("Cache capacity: %d\n", options->cache_capacity);
	printf("Number of threads: %d\n", options->nr_threads);
	printf("Number of processes: %d\n", options->nr_processes);
	printf("Clean up: %s\n", options->cleanup ? "true" : "false");
}

static void vperror(const char *fmt, ...)
{
	int old_errno = errno;
	char buf[256];
	va_list ap;

	va_start(ap, fmt);
	if (vsnprintf(buf, sizeof(buf), fmt, ap) == -1) {
		buf[sizeof(buf) - 1] = '\0';
	}
	va_end(ap);

	errno = old_errno;

	perror(buf);
}

static void dump_bpt_iostat(struct bpt_iostat *iostat)
{
	printf("BPT iostat:\n");
	printf("reads        : %lld\n", iostat->reads);
	printf("writes       : %lld\n", iostat->writes);
	printf("cache miss   : %lld\n", iostat->cache_miss);
	printf("cache hit    : %lld\n", iostat->cache_hit);
	printf("cache retire : %lld\n", iostat->cache_retire);
}

static void *benchmark_thread(void *arg)
{
	int rc;
	int i;
	struct thread_info *ti;
	struct shm_bench_kv *bench_kv;
	struct key_value *kv;

	ti = (struct thread_info *)arg;
	bench_kv = ti->bench_kv;
	
	/* Mutex unlocked if condition signaled */
	rc = pthread_mutex_lock(&bench_mutex);
	if (rc != 0) {
		goto out;
	}

	printf("benchmark_thread started!\n");

	__sync_add_and_fetch(&ready_threads, 1);
	
	rc = pthread_cond_wait(&bench_cond, &bench_mutex);
	if (rc != 0) {
		goto out;
	}

	rc = pthread_mutex_unlock(&bench_mutex);
	if (rc != 0) {
		goto out;
	}

	while ((i = __sync_add_and_fetch(&bench_kv->index, 1)) <
	       bench_kv->nr_kvs) {
		kv = &bench_kv->kvs[i];
		rc = bpt_insertkey(ti->bpt, (unsigned char *)kv->key,
				   kv->len, 0, kv->value);
		if (rc != 0) {
			fprintf(stderr, "Failed to insert key: %s\n",
				kv->key);
			goto out;
		}
	}

 out:
	return NULL;
}

int main(int argc, char *argv[])
{
	int rc = 0;
	int ch = 0;
	bptree_t h = NULL;
	struct bpt_iostat iostat;
	int i, j, x;
	struct timespec start, end;
	double t;
	struct shm_bench_kv *bench_kv = MAP_FAILED;
	struct key_value temp;
	struct thread_info *ti = NULL;
	size_t shm_size = 0;
	int shmfd = -1;
	char *shm_name = "/bpt_bench";

	while ((ch = getopt(argc, argv, "p:n:o:rc:t:P:Ch")) != -1) {
		switch (ch) {
		case 'p':
			opts.page_bits = atoi(optarg);
			break;
		case 'n':
			opts.rounds = atoi(optarg);
			if (opts.rounds == 0) {
				fprintf(stderr, "rounds must greater than 0\n");
				goto out;
			}
			break;
		case 'o':
			if (strcmp(optarg, "r") == 0) {
				opts.read = 1;
			} else if (strcmp(optarg, "w") == 0) {
				opts.read = 0;
			} else if (strcmp(optarg, "rw") == 0) {
				opts.read = 0;
			} else {
				fprintf(stderr, "Illegal operation:%s\n", optarg);
				goto out;
			}
			break;
		case 'r':
			opts.random = 1;
			break;
		case 'c':
			opts.cache_capacity = atoi(optarg);
			if (opts.cache_capacity == 0) {
				fprintf(stderr, "cache capacity must greater than 0\n");
				goto out;
			}
			break;
		case 't':
			opts.nr_threads = atoi(optarg);
			if (opts.nr_threads == 0) {
				fprintf(stderr, "threads number must greater than 0\n");
				goto out;
			}
			break;
		case 'P':
			opts.nr_processes = atoi(optarg);
			if (opts.nr_processes == 0) {
				fprintf(stderr, "process number must greater than 0\n");
				goto out;
			}
			break;
		case 'C':
			opts.cleanup = 1;
			break;
		case 'h':
		default:
			usage();
			goto out;
		}
	}

	/* Create shared memory for kvs used for benchmarking */
	shm_size = offsetof(struct shm_bench_kv, kvs) +
		opts.rounds * sizeof(struct key_value);

	shmfd = shm_open(shm_name, O_RDWR|O_CREAT|O_EXCL, 0666);
	if (shmfd == -1) {
		vperror("shm_open failed!");
		goto out;
	}

	rc = ftruncate(shmfd, shm_size);
	if (rc == -1) {
		vperror("ftruncate failed!");
		goto out;
	}

	bench_kv = mmap(NULL, shm_size, PROT_READ | PROT_WRITE,
			MAP_SHARED, shmfd, 0);
	if (bench_kv == MAP_FAILED) {
		vperror("mmap failed!");
		goto out;
	}

	/* Create/Open database */
	h = bpt_open("bpt.dat", opts.page_bits, opts.cache_capacity);
	if (h == NULL) {
		fprintf(stderr, "Failed to create/open bplustree!\n");
		goto out;
	}

	/* Key prefill */
	memset(bench_kv, 0, shm_size);
	bench_kv->nr_kvs = opts.rounds;
	for (i = 0; i < bench_kv->nr_kvs; i++) {
		bench_kv->kvs[i].len = sprintf(bench_kv->kvs[i].key, "benchmark_%08d", i);
		bench_kv->kvs[i].value = i;
	}

	if (opts.random) {
		/* Random exchange the position of the key value */
		x = 0;
		srand(time(NULL));
		do {
			i = rand() % opts.rounds;
			j = rand() % opts.rounds;
			temp = bench_kv->kvs[i];
			bench_kv->kvs[i] = bench_kv->kvs[j];
			bench_kv->kvs[j] = temp;
			x++;
		} while(x < (bench_kv->nr_kvs / 2));
	}

	/* Create threads if necessary */
	if (opts.nr_threads > 1) {
		/* Allocate thread info */
		ti = malloc(opts.nr_threads * sizeof(struct thread_info));
		if (ti == NULL) {
			fprintf(stderr, "Failed to allocate thread info!\n");
			rc = -1;
			goto out;
		}
		memset(ti, 0, opts.nr_threads * sizeof(ti[0]));
		
		/* Create threads */
		for (i = 0; i < opts.nr_threads; i++) {
			ti[i].bpt = h;
			ti[i].bench_kv = bench_kv;
			rc = pthread_create(&ti[i].thread, NULL,
					    benchmark_thread,
					    &ti[i]);
			if (rc != 0) {
				fprintf(stderr, "Failed to create thread %d!\n", i);
				goto out;
			}
		}
		
		/* Make sure all threads are ready */
		while (ready_threads < opts.nr_threads) {
			sleep(1);
		}
	}

	clock_gettime(CLOCK_REALTIME, &start);
	
	/* Start bench */
	if (opts.nr_threads > 1) {// Multi-thread bench
		printf("Multi-thread bench not supported yet. Comming soon!\n");
		goto out;
		
		rc = pthread_mutex_lock(&bench_mutex);
		if (rc != 0) {
			fprintf(stderr, "Failed to lock bench mutex!\n");
			goto out;
		}
		
		rc = pthread_cond_broadcast(&bench_cond);
		if (rc != 0) {
			fprintf(stderr, "Failed to broadcast bench condition!\n");
			goto out;
		}

		rc = pthread_mutex_unlock(&bench_mutex);
		if (rc != 0) {
			fprintf(stderr, "Failed to unlock bench mutex!\n");
			goto out;
		}

		for (i = 0; i < opts.nr_threads; i++) {
			rc = pthread_join(ti[i].thread, NULL);
			if (rc != 0) {
				fprintf(stderr, "Failed to join thread %d\n", i);
				goto out;
			}
		}
	} else {
		while ((i = __sync_add_and_fetch(&bench_kv->index, 1)) <
		       bench_kv->nr_kvs) {
			rc = bpt_insertkey(h, (unsigned char *)bench_kv->kvs[i].key,
					   bench_kv->kvs[i].len, 0,
					   bench_kv->kvs[i].value);
			if (rc != 0) {
				fprintf(stderr, "Failed to insert key: %s\n",
					bench_kv->kvs[i].key);
				goto out;
			}
		}
	}

	clock_gettime(CLOCK_REALTIME, &end);

	bpt_getiostat(h, &iostat);

	t = ((end.tv_sec - start.tv_sec) * 1e9 + (end.tv_nsec - start.tv_nsec)) / 1e9;

	printf("Bench summary: \n");
	print_seperator();
	dump_options(&opts);
	print_seperator();
	printf("Elapsed time: %f seconds\n", t);
	print_seperator();
	dump_bpt_iostat(&iostat);

	if (opts.cleanup) {
		struct key_value *kv = NULL;
		for (i = 0; i < bench_kv->nr_kvs; i++) {
			kv = &bench_kv->kvs[i];
			rc = bpt_deletekey(h, (unsigned char *)kv->key,
					   kv->len, 0);
			if (rc != 0) {
				fprintf(stderr, "Failed to delete key: %s\n",
					kv->key);
			}
		}
	}

 out:
	if (shmfd) {
		if (bench_kv != MAP_FAILED) {
			munmap(bench_kv, shm_size);
		}
		close(shmfd);
		shm_unlink(shm_name);
	}
	if (h) {
		bpt_close(h);
	}
	return rc;
}

static void usage()
{
	printf("usage: bench [-p <page-bits>] [-n <num-keys>] [-o <read/write>] [-r] \\\n"
	       "  [-c <capacity>] [-C] [-P <#processes>]\n");
	printf("default options:\n");
	dump_options(&opts);
}

static void print_seperator()
{
	printf("========================================\n");
}

