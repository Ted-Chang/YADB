#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>
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
	unsigned int cache_capacity;
	unsigned int nr_threads;
};

struct thread_info {
	pthread_t thread;
	bpt_handle bpt;
	struct key_value *kv;
	int kv_cnt;
};

static void usage();
static void print_seperator();

struct bench_option opts = {
	12,
	50000,
	1,
	0,
	0,
	1
};

static void dump_options(struct bench_option *options)
{
	printf("Page bits: %d\n", options->page_bits);
	printf("Number of keys: %d\n", options->rounds);
	printf("Operation: %s\n", options->read ? "read" : "write");
	printf("IO pattern: %s\n", options->random ? "random" : "sequential");
	printf("Cache capacity: %d\n", options->cache_capacity);
	printf("Number of threads: %d\n", options->nr_threads);
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
	struct key_value *kv;

	ti = (struct thread_info *)arg;
	
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

	for (i = 0; i < ti->kv_cnt; i++) {
		kv = &ti->kv[i];
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
	bpt_handle h = NULL;
	struct bpt_iostat iostat;
	int i, j, x;
	struct timespec start, stop;
	double t;
	struct key_value *kv = NULL;
	struct key_value temp;
	struct thread_info *ti = NULL;
	int kv_cnt = 0;

	while ((ch = getopt(argc, argv, "p:n:o:rc:t:h")) != -1) {
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
		case 'h':
		default:
			usage();
			goto out;
		}
	}

	/* Create/Open database */
	h = bpt_open("bpt.dat", opts.page_bits, opts.cache_capacity);
	if (h == NULL) {
		fprintf(stderr, "Failed to create/open bplustree!\n");
		goto out;
	}

	/* Allocate key values */
	kv = malloc(opts.rounds * sizeof(struct key_value));
	if (kv == NULL) {
		rc = -1;
		fprintf(stderr, "Failed to allocate key value buffer!\n");
		goto out;
	}
	memset(kv, 0, opts.rounds * sizeof(struct key_value));

	/* Fill in keys */
	for (i = 0; i < opts.rounds; i++) {
		kv[i].len = sprintf(kv[i].key, "benchmark_%08d", i);
		kv[i].value = i + 2;
	}

	if (opts.random) {
		x = 0;
		srand(time(NULL));
		do {
			i = rand() % opts.rounds;
			j = rand() % opts.rounds;
			temp = kv[i];
			kv[i] = kv[j];
			kv[j] = temp;
			x++;
		} while(x < (opts.rounds / 2));
	}

	/* Create threads if necessary */
	kv_cnt = opts.rounds / opts.nr_threads;
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
			ti[i].kv = &kv[i * kv_cnt];
			ti[i].kv_cnt = kv_cnt;
			rc = pthread_create(&ti[i].thread, NULL,
					    benchmark_thread, &ti[i]);
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

	clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start);
	
	/* Start bench */
	if (opts.nr_threads > 1) {// Multi-thread bench
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
		for (i = 0; i < opts.rounds; i++) {
			rc = bpt_insertkey(h, (unsigned char *)kv[i].key,
					   kv[i].len, 0, kv[i].value);
			if (rc != 0) {
				fprintf(stderr, "Failed to insert key: %s\n",
					kv[i].key);
				goto out;
			}
		}
	}

	clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &stop);

	bpt_getiostat(h, &iostat);

	t = (stop.tv_sec - start.tv_sec) + (stop.tv_nsec - start.tv_nsec) / 1e9;

	printf("Bench summary: \n");
	print_seperator();
	dump_options(&opts);
	print_seperator();
	printf("Elapsed time: %f seconds\n", t);
	print_seperator();
	dump_bpt_iostat(&iostat);

 out:
	if (h) {
		bpt_close(h);
	}
	return rc;
}

static void usage()
{
	printf("usage: bench [-p <page-bits>] [-n <num-keys>] [-o <read/write>] [-r] [-c <capacity>]\n");
	printf("default options:\n"
	       "\tPage bits      : %d\n"
	       "\tNumber of keys : %d\n"
	       "\tOperation      : %s\n"
	       "\tIO pattern     : %s\n"
	       "\tCache capacity : %d\n",
	       opts.page_bits, opts.rounds, opts.read ? "read" : "write",
	       opts.random ? "random" : "sequential", opts.cache_capacity);
}

static void print_seperator()
{
	printf("========================================\n");
}

