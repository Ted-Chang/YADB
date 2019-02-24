#ifndef __LOCK_H__
#define __LOCK_H__

#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

struct rwlock {
	pthread_rwlock_t rwlock;
};

/* Spin rwlock, grant write access when share == 0 */
struct spin_rwlock {
	volatile unsigned char mutex;
	volatile unsigned char exclusive:1; // set for write access
	volatile unsigned char pending:1;
	volatile unsigned short share;	// number of read accessors
};

extern void rwlock_init(struct rwlock *lock);
extern void rwlock_rdlock(struct rwlock *lock);
extern void rwlock_wrlock(struct rwlock *lock);
extern void rwlock_rdunlock(struct rwlock *lock);
extern void rwlock_wrunlock(struct rwlock *lock);

extern void spin_init(struct spin_rwlock *lock);
extern void spin_rdlock(struct spin_rwlock *lock);
extern void spin_wrlock(struct spin_rwlock *lock);
extern void spin_rdunlock(struct spin_rwlock *lock);
extern void spin_wrunlock(struct spin_rwlock *lock);
extern int spin_trywrlock(struct spin_rwlock *lock);

#ifdef __cplusplus
}
#endif

#endif	/* __LOCK_H__ */
