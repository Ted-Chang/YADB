#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <assert.h>
#include "lock.h"
#include "bptdef.h"
#include "bptree.h"

static pthread_rwlockattr_t rwattr;

static void rwlock_initattr() __attribute__((constructor));
static void rwlock_initattr()
{
	pthread_rwlockattr_init(&rwattr);
	pthread_rwlockattr_setpshared(&rwattr, PTHREAD_PROCESS_SHARED);
}

void rwlock_init(struct rwlock *lock)
{
	pthread_rwlock_init(&lock->rwlock, &rwattr);
}

void rwlock_rdlock(struct rwlock *lock)
{
	pthread_rwlock_rdlock(&lock->rwlock);
}

void rwlock_wrlock(struct rwlock *lock)
{
	pthread_rwlock_wrlock(&lock->rwlock);
}

void rwlock_rdunlock(struct rwlock *lock)
{
	pthread_rwlock_unlock(&lock->rwlock);
}

void rwlock_wrunlock(struct rwlock *lock)
{
	pthread_rwlock_unlock(&lock->rwlock);
}

void spin_init(struct spin_rwlock *lock)
{
	assert(lock != NULL);
	memset(lock, 0, sizeof(*lock));
}

void spin_rdlock(struct spin_rwlock *lock)
{
	unsigned int prev;

	do {
		if (__sync_lock_test_and_set(&lock->mutex, 1)) {
			continue;
		}
		if ((prev = !(lock->exclusive | lock->pending))) {
			lock->share++;
		}
		__sync_lock_release(&lock->mutex);

		if (prev) {
			return;
		}

		sched_yield();
	} while (TRUE);
}

void spin_wrlock(struct spin_rwlock *lock)
{
	unsigned int prev;

	do {
		if (__sync_lock_test_and_set(&lock->mutex, 1)) {
			continue;
		}
		if ((prev = !(lock->share | lock->exclusive))) {
			lock->exclusive = 1;
			lock->pending = 0;
		} else {
			lock->pending = 1;
		}
		__sync_lock_release(&lock->mutex);

		if (prev) {
			return;
		}

		sched_yield();
	} while (TRUE);
}

void spin_rdunlock(struct spin_rwlock *lock)
{
	while (__sync_lock_test_and_set(&lock->mutex, 1)) {
		sched_yield();
	}

	lock->share--;
	__sync_lock_release(&lock->mutex);
}

void spin_wrunlock(struct spin_rwlock *lock)
{
	while (__sync_lock_test_and_set(&lock->mutex, 1)) {
		sched_yield();
	}

	lock->exclusive = 0;
	__sync_lock_release(&lock->mutex);
}

int spin_trywrlock(struct spin_rwlock *lock)
{
	unsigned int prev;

	if (__sync_lock_test_and_set(&lock->mutex, 1)) {
		return 0;
	}

	if ((prev = !(lock->exclusive | lock->share))) {
		lock->exclusive = 1;
	}

	__sync_lock_release(&lock->mutex);

	return prev;
}

#ifdef _LOCK_UNITTEST

#define NR_TEST_ROUNDS	(4 * 1024)

struct lock_test {
	struct rwlock lock;
	struct spin_rwlock spin;
	bool_t do_lock_test;
	bool_t do_spin_test;
};

static void lock_test(struct lock_test *test)
{
	int i;
	pid_t tid;

	tid = gettid();
	for (i = 0; i < NR_TEST_ROUNDS; i++) {
		if (test->do_lock_test) {
			rwlock_rdlock(&test->lock);
			printf("thread:%06d round:%#x acquired rdlock\n", tid, i);
			rwlock_rdunlock(&test->lock);
			printf("thread:%06d round:%#x released rdlock\n", tid, i);
			rwlock_wrlock(&test->lock);
			printf("thread:%06d round:%#x acquired wrlock\n", tid, i);
			rwlock_wrunlock(&test->lock);
			printf("thread:%06d round:%#x released wrlock\n", tid, i);
		}
		if (test->do_spin_test) {
			spin_rdlock(&test->spin);
			printf("thread:%06d round:%#x acquired rdspin\n", tid, i);
			spin_rdunlock(&test->spin);
			printf("thread:%06d round:%#x released rdspin\n", tid, i);
			spin_wrlock(&test->spin);
			printf("thread:%06d round:%#x acquired wrspin\n", tid, i);
			spin_wrunlock(&test->spin);
			printf("thread:%06d round:%#x released wrspin\n", tid, i);
		}
	}
}

static void *lock_test_thread(void *arg)
{
	struct lock_test *test;

	test = (struct lock_test *)arg;

	if (test->do_lock_test && test->do_spin_test) {
		fprintf(stderr, "Can't do lock and spin test simultaneously!");
		goto out;
	}

	lock_test(test);

 out:
	return NULL;
}

int main(int argc, char *argv[])
{
	int rc = 0;
	struct lock_test test;
	pthread_t thread;

	rwlock_init(&test.lock);
	spin_init(&test.spin);

	test.do_lock_test = TRUE;
	test.do_spin_test = FALSE;
	rc = pthread_create(&thread, NULL, lock_test_thread, &test);
	if (rc != 0) {
		fprintf(stderr, "Failed to create test thread, error:%d\n", rc);
		goto out;
	}

	lock_test(&test);
	pthread_join(thread, NULL);

	rc = pthread_create(&thread, NULL, lock_test_thread, &test);
	if (rc != 0) {
		fprintf(stderr, "Failed to create test thread, error:%d\n", rc);
		goto out;
	}

	test.do_lock_test = FALSE;
	test.do_spin_test = TRUE;
	lock_test(&test);
	pthread_join(thread, NULL);

 out:

	return rc;
}

#endif	/* _LOCK_UNITTEST */
