#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <assert.h>
#include "bptree.h"
#include "bptdef.h"
#include "bpt_private.h"
#include "log.h"

static void bpt_putpageno(unsigned char *dst, pageno_t page_no)
{
	int i = PAGE_NUM_BYTES;

	while (i--) {
		dst[i] = (unsigned char)page_no;
		if (page_no) {
			page_no >>= 8;
		}
	}
}

static pageno_t bpt_getpageno(unsigned char *src)
{
	pageno_t page_no = 0;
	int i;

	for (i = 0; i < PAGE_NUM_BYTES; i++) {
		page_no <<= 8;
		page_no += src[i];
	}

	return page_no;
}

int keycmp(struct bpt_key *key1, unsigned char *key2, unsigned int len2)
{
	int ret;
	unsigned short len1 = key1->len;

	ret = memcmp(key1->key, key2, len1 > len2 ? len2 : len1);
	if (ret) {
		return ret;
	}
	if (len1 > len2) {
		return 1;
	}
	if (len1 < len2) {
		return -1;
	}
	return 0;
}

struct bpt_page *bpt_page(struct bptree *bpt, struct bpt_pool *pool,
			  pageno_t page_no)
{
	struct bpt_page *page;
	unsigned int subpage;

	subpage = (unsigned int)(page_no & bpt->mgr->pool_mask);
	page = (struct bpt_page *)(pool->map + (subpage << bpt->mgr->page_bits));

	return page;
}

static void bpt_initlatch(struct bpt_latch *latch)
{
	bpt_bzero(latch, sizeof(*latch));

	rwlock_init(&latch->rdwr);
	rwlock_init(&latch->access);
	rwlock_init(&latch->parent);
}

static int bpt_mapsegment(struct bptree *bpt, struct bpt_pool *pool,
			  pageno_t page_no)
{
	off_t offset;
	int flags;

	bpt->status = 0;
	offset = (page_no & ~bpt->mgr->pool_mask) << bpt->mgr->page_bits;

	flags = PROT_READ | PROT_WRITE;
	pool->map = mmap(NULL, (bpt->mgr->pool_mask + 1) << bpt->mgr->page_bits,
			 flags, MAP_SHARED, bpt->mgr->fd, offset);
	if (pool->map == MAP_FAILED) {
		bpt->status = -1;
	}

	return bpt->status;
}

static void bpt_linklatch(struct bptree *bpt, unsigned short hash_val,
			  unsigned short victim, pageno_t page_no)
{
	struct bpt_latch *latch;

	latch = &bpt->mgr->latches[victim];
	if ((latch->next = bpt->mgr->latchmgr->buckets[hash_val].slot)) {
		bpt->mgr->latches[latch->next].prev = victim;
	}

	bpt->mgr->latchmgr->buckets[hash_val].slot = victim;
	latch->page_no = page_no;
	latch->hashv = hash_val;
	latch->prev = 0;
}

static struct bpt_latch *bpt_pinlatch(struct bptree *bpt, pageno_t page_no)
{
	struct bpt_latch *latch;
	struct bpt_mgr *mgr;
	unsigned short hashv;
	unsigned short avail;
	unsigned short slot;
	unsigned short victim;
	unsigned short idx;

	latch = NULL;
	mgr = bpt->mgr;
	hashv = page_no % mgr->latchmgr->nr_buckets;
	avail = 0;

	/* Try to find the latch table entry and pin it for this page */
	spin_rdlock(&mgr->latchmgr->buckets[hashv].lock);

	if ((slot = mgr->latchmgr->buckets[hashv].slot)) {
		do {
			latch = &mgr->latches[slot];
			if (page_no == latch->page_no) {
				break;
			}
		} while ((slot = latch->next));
	}
	if (slot) {
		__sync_fetch_and_add(&latch->pin, 1);
	}

	spin_rdunlock(&mgr->latchmgr->buckets[hashv].lock);

	if (slot) {
		/* Found the latch and pinned it */
		goto out;
	}

	/* Latch not found, reacquire write lock as we may allocate a
	 * new entry from buckets
	 */
	spin_wrlock(&mgr->latchmgr->buckets[hashv].lock);

	if ((slot = mgr->latchmgr->buckets[hashv].slot)) {
		do {
			latch = &mgr->latches[slot];
			if (page_no == latch->page_no) {
				break;
			}
			if ((latch->pin == 0) && (avail == 0)) {
				/* bookmark the first unpinned latch */
				avail = slot;
			}
		} while ((slot = latch->next));
	}

	/* Found our entry, or take an unpinned one */
	if (slot || (slot = avail)) {
		latch = &mgr->latches[slot];
		__sync_fetch_and_add(&latch->pin, 1);
		latch->page_no = page_no;
		spin_wrunlock(&mgr->latchmgr->buckets[hashv].lock);
		goto out;
	}

	/* Entry not found, and no unpinned latch. Allocate a new entry
	 * if buckets are not full
	 */
	victim = __sync_fetch_and_add(&mgr->latchmgr->latch_deployed, 1) + 1;
	if (victim < mgr->latchmgr->nr_latch_total) {
		latch = &mgr->latches[victim];
		bpt_initlatch(latch);
		__sync_fetch_and_add(&latch->pin, 1);
		bpt_linklatch(bpt, hashv, victim, page_no);
		spin_wrunlock(&mgr->latchmgr->buckets[hashv].lock);
		goto out;
	}

	/* Restore latch deployed counter */
	victim = __sync_fetch_and_add(&mgr->latchmgr->latch_deployed, -1);

	/* Scan all the buckets and try to find a victim to evict */
	while (TRUE) {
		victim = __sync_fetch_and_add(&mgr->latchmgr->victim, 1);
		if ((victim %= mgr->latchmgr->nr_latch_total)) {
			latch = &mgr->latches[victim];
		} else {
			continue;
		}

		/* Take control of the slot from other threads */
		if (latch->pin || !spin_trywrlock(&latch->busy)) {
			continue;
		}

		idx = latch->hashv;

		/* Try to acquire write lock on hash chain
		 * Skip entry if not obtained or has outstanding locks
		 */
		if (!spin_trywrlock(&mgr->latchmgr->buckets[idx].lock)) {
			spin_wrunlock(&latch->busy);
			continue;
		}

		if (latch->pin) {
			spin_wrunlock(&latch->busy);
			spin_wrunlock(&mgr->latchmgr->buckets[idx].lock);
			continue;
		}

		/* Unlink available victim from its hash chain */
		if (latch->prev) {
			mgr->latches[latch->prev].next = latch->next;
		} else {
			mgr->latchmgr->buckets[idx].slot = latch->next;
		}

		if (latch->next) {
			mgr->latches[latch->next].prev = latch->prev;
		}

		spin_wrunlock(&mgr->latchmgr->buckets[idx].lock);

		/* Pin it and link to our hash chain */
		__sync_fetch_and_add(&latch->pin, 1);
		bpt_linklatch(bpt, hashv, victim, page_no);

		spin_wrunlock(&mgr->latchmgr->buckets[hashv].lock);
		spin_wrunlock(&latch->busy);
		goto out;
	}

 out:
	return latch;
}

static void bpt_unpinlatch(struct bpt_latch *latch)
{
	__sync_fetch_and_add(&latch->pin, -1);
}

static void bpt_linkpool(struct bptree *bpt, struct bpt_pool *pool,
			 pageno_t page_no, int hash_val)
{
	struct bpt_pool *node;
	unsigned int slot;

	pool->hash_prev = pool->hash_next = NULL;
	pool->basepage = page_no & ~bpt->mgr->pool_mask;
	pool->pin = CLOCK_BIT + 1;

	slot = bpt->mgr->pool_bkts[hash_val];
	if (slot) {
		node = &bpt->mgr->pools[slot];
		pool->hash_next = node;
		node->hash_prev = pool;
	}

	bpt->mgr->pool_bkts[hash_val] = pool->slot;
}

struct bpt_pool *bpt_findpool(struct bptree *bpt, pageno_t page_no,
			      unsigned int hash_val)
{
	struct bpt_pool *pool;
	unsigned int slot;

	if ((slot = bpt->mgr->pool_bkts[hash_val])) {
		pool = &bpt->mgr->pools[slot];
	} else {
		pool = NULL;
		goto out;
	}

	page_no &= ~bpt->mgr->pool_mask;

	while (pool->basepage != page_no) {
		if ((pool = pool->hash_next)) {
			continue;
		} else {
			goto out;
		}
	}

 out:
	return pool;
}

struct bpt_pool *bpt_pinpool(struct bptree *bpt, pageno_t page_no)
{
	unsigned int slot;
	unsigned int hashv;
	unsigned int idx;
	unsigned int victim;
	struct bpt_mgr *mgr;
	struct bpt_pool *pool;
	struct bpt_pool *node;

	mgr = bpt->mgr;

	/* Lock the page pool bucket */
	hashv = (unsigned int)(page_no >> mgr->seg_bits) % mgr->hash_size;
	spin_wrlock(&mgr->pool_bkt_locks[hashv]);

	/* Lookup the page in hash table */
	if ((pool = bpt_findpool(bpt, page_no, hashv))) {
		__sync_fetch_and_or(&pool->pin, CLOCK_BIT);
		__sync_fetch_and_add(&pool->pin, 1);
		spin_wrunlock(&bpt->mgr->pool_bkt_locks[hashv]);
		goto out;
	}

	/* Allocate a new pool node and add to hash table */
	slot = __sync_fetch_and_add(&mgr->pool_cnt, 1);
	if (++slot < mgr->pool_max) {
		pool = &mgr->pools[slot];
		pool->slot = slot;

		if (bpt_mapsegment(bpt, pool, page_no)) {
			pool = NULL;
			goto out;
		}

		bpt_linkpool(bpt, pool, page_no, hashv);
		spin_wrunlock(&mgr->pool_bkt_locks[hashv]);
		goto out;
	}

	/* Page pool is full. Find a pool entry to evict */
	__sync_fetch_and_add(&mgr->pool_cnt, -1);

	while (TRUE) {
		victim = __sync_fetch_and_add(&mgr->evicted, 1);
		victim %= bpt->mgr->pool_max;
		pool = &bpt->mgr->pools[victim];
		idx = (unsigned int)(pool->basepage >> mgr->seg_bits) %
			mgr->hash_size;

		if (!victim) {
			continue;
		}

		if (!spin_trywrlock(&mgr->pool_bkt_locks[idx])) {
			continue;
		}

		/* Skip this entry if page is pinned or clock bit is set */
		if (pool->pin) {
			__sync_fetch_and_and(&pool->pin, ~CLOCK_BIT);
			spin_wrunlock(&mgr->pool_bkt_locks[idx]);
			continue;
		}

		/* Unlink victim pool node from hash table */
		if ((node = pool->hash_prev)) {
			node->hash_next = pool->hash_next;
		} else if ((node = pool->hash_next)) {
			mgr->pool_bkts[idx] = node->slot;
		} else {
			mgr->pool_bkts[idx] = 0;
		}

		if ((node = pool->hash_next)) {
			node->hash_prev = pool->hash_prev;
		}

		spin_wrunlock(&mgr->pool_bkt_locks[idx]);

		/* Remove old file mapping */
		munmap(pool->map, (mgr->pool_mask + 1) << mgr->page_bits);
		pool->map = NULL;

		/* Create new pool mapping and link into hash table */
		if (bpt_mapsegment(bpt, pool, page_no)) {
			pool = NULL;
			goto out;
		}

		bpt_linkpool(bpt, pool, page_no, hashv);
		spin_wrunlock(&mgr->pool_bkt_locks[hashv]);

		goto out;
	}

 out:
	return pool;
}

void bpt_unpinpool(struct bpt_pool *pool)
{
	__sync_fetch_and_add(&pool->pin, -1);
}

static void bpt_lockpage(struct bpt_latch *latch, bpt_mode_t mode)
{
	switch (mode) {
	case BPT_LOCK_READ:
		rwlock_rdlock(&latch->rdwr);
		break;
	case BPT_LOCK_WRITE:
		rwlock_wrlock(&latch->rdwr);
		break;
	case BPT_LOCK_ACCESS:
		rwlock_rdlock(&latch->access);
		break;
	case BPT_LOCK_DELETE:
		rwlock_wrlock(&latch->access);
		break;
	case BPT_LOCK_PARENT:
		rwlock_wrlock(&latch->parent);
		break;
	default:
		assert(0);
	}
}

static void bpt_unlockpage(struct bpt_latch *latch, bpt_mode_t mode)
{
	switch (mode) {
	case BPT_LOCK_READ:
		rwlock_rdunlock(&latch->rdwr);
		break;
	case BPT_LOCK_WRITE:
		rwlock_wrunlock(&latch->rdwr);
		break;
	case BPT_LOCK_ACCESS:
		rwlock_rdunlock(&latch->access);
		break;
	case BPT_LOCK_DELETE:
		rwlock_wrunlock(&latch->access);
		break;
	case BPT_LOCK_PARENT:
		rwlock_wrunlock(&latch->parent);
		break;
	default:
		assert(0);
	}
}

void bpt_closemgr(struct bpt_mgr *mgr)
{
	munmap(mgr->latches,
	       mgr->latchmgr->nr_latch_pages * mgr->page_size);
	munmap(mgr->latchmgr, mgr->page_size);
	
	if (mgr->fd) {
		close(mgr->fd);
	}
	if (mgr->pools) {
		bpt_free(mgr->pools);
	}
	if (mgr->pool_bkts) {
		bpt_free(mgr->pool_bkts);
	}
	if (mgr->pool_bkt_locks) {
		bpt_free(mgr->pool_bkt_locks);
	}
	bpt_free(mgr);
}

/* b+tree file layout
 * +------------------------+
 * |      Super block       |
 * +------------------------+
 * |      alloc page[0]   --+--+
 * |      alloc page[1]   --+--+--+
 * +------------------------+  |  |
 * |       root page        |  |  |
 * +------------------------+  |  |
 * |       leaf page        |  |  |page free list
 * +------------------------+  |  |
 * |        latches         |  |  |
 * |          ...           |  |  |
 * +------------------------+  |  |
 * |          ...           |<-+--+
 * +------------------------+  |
 *                        ^    |always point to last+1 page
 *                        +----+
 */
struct bpt_mgr *bpt_openmgr(const char *name,
			    unsigned int page_bits,
			    unsigned int pool_max,
			    unsigned int hash_size)
{
	int rc = 0;
	struct bpt_mgr *mgr = NULL;
	struct bpt_latch_mgr *latchmgr = NULL;
	struct bpt_super_block *sb = NULL;
	struct bpt_key *key = NULL;
	struct bpt_slot *sptr = NULL;
	off_t fsize;
	unsigned int cache_blk;
	unsigned int last;
	unsigned int latch_per_page;
	unsigned int nr_buckets;
	unsigned short nr_latch_pages = 0;
	int flags;
	bpt_level_t level;
	
	if (page_bits > BPT_MAX_PAGE_SHIFT ||
	    page_bits < BPT_MIN_PAGE_SHIFT) {
		rc = -1;
		goto out;
	}

	if (pool_max == 0) {
		/* Must have buffer pool */
		rc = -1;
		goto out;
	}

	mgr = bpt_malloc(sizeof(*mgr));
	if (mgr == NULL) {
		LOG(ERR, "allocate bpt_mgr failed\n");
		rc = -1;
		goto out;
	}

	bpt_bzero(mgr, sizeof(*mgr));
	mgr->fd = open(name, O_RDWR|O_CREAT, 0666);
	if (mgr->fd == -1) {
		LOG(ERR, "open %s failed\n", name);
		rc = -1;
		goto out;
	}

	cache_blk = sysconf(_SC_PAGE_SIZE);
	if (cache_blk == -1) {
		LOG(ERR, "sysconf PAGE_SIZE failed\n");
		rc = -1;
		goto out;
	}
	
	latchmgr = bpt_malloc(BPT_MAX_PAGE_SIZE);
	if (latchmgr == NULL) {
		LOG(ERR, "allocate bpt_latch_mgr failed\n");
		rc = -1;
		goto out;
	}
	bpt_bzero(latchmgr, BPT_MAX_PAGE_SIZE);

	/* Read minimum page size to get super block info */
	if ((fsize = lseek(mgr->fd, 0, SEEK_END)) >= BPT_MIN_PAGE_SIZE) {
		sb = (struct bpt_super_block *)bpt_malloc(BPT_MIN_PAGE_SIZE);
		pread(mgr->fd, sb, BPT_MIN_PAGE_SIZE, 0);
		if (strcmp(sb->magic, BPT_MAGIC) != 0) {
			rc = -1;
		} else if ((sb->page_bits < BPT_MIN_PAGE_SHIFT) ||
			   (sb->page_bits > BPT_MAX_PAGE_SHIFT)) {
			rc = -1;
		} else {
			page_bits = sb->page_bits;
		}

		bpt_free(sb);
		if (rc != 0) {
			goto out;
		}
	}

	mgr->page_bits = page_bits;
	mgr->page_size = 1 << page_bits;

	mgr->pool_max = pool_max;

	if (cache_blk < mgr->page_size) {
		cache_blk = mgr->page_size;
	}

	mgr->pool_mask = (cache_blk >> page_bits) - 1;

	mgr->seg_bits = 0;
	while ((1 << mgr->seg_bits) <= mgr->pool_mask) {
		mgr->seg_bits++;
	}

	mgr->hash_size = hash_size;

	mgr->pools = calloc(pool_max, sizeof(struct bpt_pool));
	if (mgr->pools == NULL) {
		goto out;
	}
	mgr->pool_bkts = calloc(hash_size, sizeof(unsigned short));
	if (mgr->pool_bkts == NULL) {
		goto out;
	}
	mgr->pool_bkt_locks = calloc(hash_size, sizeof(struct spin_rwlock));
	if (mgr->pool_bkt_locks == NULL) {
		goto out;
	}

	if (fsize >= mgr->page_size) {
		goto map_latches;
	}

	/* Write super block */
	sb = (struct bpt_super_block *)latchmgr;
	strcpy(sb->magic, BPT_MAGIC);
	sb->major = BPT_MAJOR;
	sb->minor = BPT_MINOR;
	sb->page_bits = page_bits;

	if (write(mgr->fd, sb, mgr->page_size) < mgr->page_size) {
		LOG(ERR, "write sb, %d bytes failed\n", mgr->page_size);
		rc = -1;
		goto out;
	}

	bpt_bzero(latchmgr, mgr->page_size);

	/* Calculate how many pages we need for latches */
	latch_per_page = mgr->page_size / sizeof(struct bpt_latch);
	nr_latch_pages = (unsigned short)(BPT_LATCH_TABLE / latch_per_page + 1);
	latchmgr->nr_latch_pages = nr_latch_pages;
	latchmgr->nr_latch_total = (unsigned short)(nr_latch_pages * latch_per_page);
	bpt_putpageno(latchmgr->alloc->right,
		      PAGE_ROOT + MIN_LEVEL + nr_latch_pages);

	/* Calculate how many hash entries can alloc page holds */
	nr_buckets = (unsigned short)((mgr->page_size - sizeof(*latchmgr)) /
				      sizeof(struct hash_entry));
	if (nr_buckets > latchmgr->nr_latch_total) {
		nr_buckets = latchmgr->nr_latch_total;
	}

	latchmgr->nr_buckets = nr_buckets;

	if (write(mgr->fd, latchmgr, mgr->page_size) < mgr->page_size) {
		LOG(ERR, "write latchmgr, %d bytes failed\n", mgr->page_size);
		rc = -1;
		goto out;
	}

	/* Top to down initialization of empty b+tree with only root
	 * page and leaf page.
	 */
	for (level = MIN_LEVEL; level--; ) {
		sptr = slotptr(latchmgr->alloc, 1);
		sptr->offset = mgr->page_size - STOPPER_KEY_LEN;

		/* For empty b+tree the child node of root is PAGE_LEAF,
		 * the child node of PAGE_LEAF is 0
		 */
		bpt_putpageno(sptr->page_no,
			      level ? MIN_LEVEL - level + PAGE_ROOT : 0);
		
		/* Create stopper key */
		key = keyptr(latchmgr->alloc, 1);
		key->len = 2;
		key->key[0] = 0xFF;
		key->key[1] = 0xFF;

		latchmgr->alloc->min = mgr->page_size - STOPPER_KEY_LEN;
		latchmgr->alloc->level = level;
		latchmgr->alloc->count = 1;
		latchmgr->alloc->active = 1;

		if (write(mgr->fd, latchmgr, mgr->page_size) < mgr->page_size) {
			LOG(ERR, "write page, level %d failed\n", level);
			rc = -1;
			goto out;
		}
	}

	/* Zero pages for latches */
	bpt_bzero(latchmgr, mgr->page_size);
	last = MIN_LEVEL + PAGE_ROOT;
	while (last <= ((MIN_LEVEL + PAGE_ROOT + nr_latch_pages) | mgr->pool_mask)) {
		pwrite(mgr->fd, latchmgr, mgr->page_size, last << mgr->page_bits);
		last++;
	}

 map_latches:

	flags = PROT_READ | PROT_WRITE;
	mgr->latchmgr = mmap(NULL, mgr->page_size, flags, MAP_SHARED,
			     mgr->fd, PAGE_ALLOC * mgr->page_size);
	if (mgr->latchmgr == MAP_FAILED) {
		rc = -1;
		goto out;
	}

	mgr->latches = mmap(NULL, mgr->latchmgr->nr_latch_pages * mgr->page_size,
			    flags, MAP_SHARED, mgr->fd,
			    PAGE_LATCH * mgr->page_size);
	if (mgr->latches == MAP_FAILED) {
		rc = -1;
		goto out;
	}

 out:

	if (latchmgr) {
		bpt_free(latchmgr);
	}
	if (rc != 0) {
		if (mgr) {
			bpt_closemgr(mgr);
		}
		mgr = NULL;
	}
	return mgr;
}

bptree_t bpt_open(struct bpt_mgr *mgr)
{
	int rc = 0;
	struct bptree *bpt = NULL;

	if (mgr == NULL) {
		rc = -1;
		goto out;
	}

	bpt = bpt_malloc(sizeof(*bpt));
	if (bpt == NULL) {
		rc = -1;
		goto out;
	}

	bpt_bzero(bpt, sizeof(*bpt));
	bpt->mgr = mgr;

	/* Total 3 in-memory page buffer */
	bpt->mem = bpt_malloc(BPT_BUF_PAGES * mgr->page_size);
	if (bpt->mem == NULL) {
		rc = -1;
		goto out;
	}

	bpt_bzero(bpt->mem, BPT_BUF_PAGES * mgr->page_size);
	bpt->frame = (struct bpt_page *)(bpt->mem);
	bpt->cursor = (struct bpt_page *)(bpt->mem + mgr->page_size);
	bpt->zero = (struct bpt_page *)(bpt->mem + 2 * mgr->page_size);

 out:
	if (rc != 0 && bpt) {
		bpt_close(bpt);
		bpt = NULL;
	}

	return bpt;
}

void bpt_close(bptree_t h)
{
	struct bptree *bpt;

	bpt = (struct bptree *)h;
	if (bpt->mem) {
		bpt_free(bpt->mem);
	}
	bpt_free(bpt);
}

pageno_t bpt_newpage(struct bptree *bpt, struct bpt_page *page)
{
	struct bpt_mgr *mgr;
	struct bpt_page_set set;
	ssize_t bytes;
	pageno_t new_page;
	bool_t reuse;

	mgr = bpt->mgr;
	new_page = 0;
	reuse = FALSE;

	spin_wrlock(&mgr->latchmgr->lock);

	/* Try page free list first
	 * otherwise allocate new empty page
	 */
	if ((new_page = bpt_getpageno(mgr->latchmgr->alloc[1].right))) {
		if ((set.pool = bpt_pinpool(bpt, new_page))) {
			new_page = 0;
			goto out;
		}

		set.page = bpt_page(bpt, set.pool, new_page);
		bpt_putpageno(mgr->latchmgr->alloc[1].right,
			      bpt_getpageno(set.page->right));
		bpt_unpinpool(set.pool);
		reuse = TRUE;
		LOG(DBG, "reuse free page(0x%llx)\n", new_page);
	} else {
		/* Alloc page always point to the tail page. */
		new_page = bpt_getpageno(mgr->latchmgr->alloc->right);
		bpt_putpageno(mgr->latchmgr->alloc->right, new_page+1);
		reuse = FALSE;
		LOG(DBG, "allocating new page(0x%llx)\n", new_page);
	}

	bytes = pwrite(mgr->fd, page, mgr->page_size,
		       new_page << mgr->page_bits);
	if (bytes < mgr->page_size) {
		new_page = 0;
		goto out;
	}

	/* If writing first page of cache block, zero last page
	 * in the block
	 */
	if (!reuse &&
	    (mgr->pool_mask > 0) &&
	    ((new_page & mgr->pool_mask) == 0)) {
		/* Use zero buffer to write zeros */
		bytes = pwrite(mgr->fd, bpt->zero, mgr->page_size,
			       (new_page|mgr->pool_mask) << mgr->page_bits);
		if (bytes < mgr->page_size) {
			LOG(ERR, "page(0x%llx) pwrite failed\n", new_page);
			new_page = 0;
			bpt->status = -1;
			goto out;
		}
	}

 out:
	spin_wrunlock(&mgr->latchmgr->lock);

	return new_page;
}

int bpt_freepage(struct bptree *bpt, struct bpt_page_set *set)
{
	spin_wrlock(&bpt->mgr->latchmgr->lock);

	/* Insert the page to be freed into the empty chain
	 * in second alloc page.
	 * alloc[1] -> page_no -> ...  -> free page -> 0
	 */
	bpt_putpageno(set->page->right,
		      bpt_getpageno(bpt->mgr->latchmgr->alloc[1].right));
	bpt_putpageno(bpt->mgr->latchmgr->alloc[1].right, set->page_no);
	set->page->free = 1;

	/* Unlock the page for write and delete */
	bpt_unlockpage(set->latch, BPT_LOCK_WRITE);
	bpt_unlockpage(set->latch, BPT_LOCK_DELETE);
	bpt_unpinlatch(set->latch);
	bpt_unpinpool(set->pool);

	spin_wrunlock(&bpt->mgr->latchmgr->lock);

	LOG(DBG, "page(0x%llx) freed\n", set->page_no);

	return bpt->status;
}

unsigned int bpt_findslot(struct bpt_page_set *set,
			  unsigned char *key,
			  unsigned int len)
{
	int slot;
	int low;
	int high;

	low = 1;	// slot index start from 1
	high = set->page->count;

	if (bpt_getpageno(set->page->right)) {
		/* If next page exists, this page has no stopper
		 * key, so high index should be count+1
		 */
		high++;
	}

	/* Do binary search to find the key */
	while (high > low) {
		slot = low + ((high - low) / 2);
		if (keycmp(keyptr(set->page, slot), key, len) < 0) {
			low = slot + 1;
		} else {
			high = slot;
		}
	}

	return (high > set->page->count) ? 0 : high;
}

unsigned int bpt_loadpage(struct bptree *bpt,
			  struct bpt_page_set *set,
			  unsigned char *key, unsigned int len,
			  bpt_level_t level, bpt_mode_t lock)
{
	pageno_t page_no;
	pageno_t prev_page;
	struct bpt_latch *prev_latch;
	struct bpt_pool *prev_pool;
	struct bpt_slot *sptr;
	unsigned int slot;
	bpt_mode_t mode;
	bpt_mode_t prev_mode;
	unsigned char drill;

	page_no = PAGE_ROOT;
	prev_page = 0;
	prev_mode = 0;
	drill = 0xFF;

	do {
		/* Determine lock mode of drill level. */
		mode = (drill == level) ? lock : BPT_LOCK_READ;

		set->latch = bpt_pinlatch(bpt, page_no);
		set->page_no = page_no;

		if ((set->pool = bpt_pinpool(bpt, page_no))) {
			set->page = bpt_page(bpt, set->pool, page_no);
		} else {
			goto out;
		}

		if (page_no > PAGE_ROOT) {
			bpt_lockpage(set->latch, BPT_LOCK_ACCESS);
		}

		if (prev_page) {
			bpt_unlockpage(prev_latch, prev_mode);
			bpt_unpinlatch(prev_latch);
			bpt_unpinpool(prev_pool);
			prev_page = 0;
		}

		bpt_lockpage(set->latch, mode);

		if (set->page->free) {
			bpt->status = -1;
			goto out;
		}

		if (page_no > PAGE_ROOT) {
			bpt_unlockpage(set->latch, BPT_LOCK_ACCESS);
		}

		/* re-read and re-lock root after determining actual
		 * level of root.
		 */
		if (set->page->level != drill) {
			if (set->page_no != PAGE_ROOT) {
				LOG(ERR, "page(0x%llx) illegal lvl(%d), drill(%d)\n",
				    set->page_no, set->page->level, drill);
				bpt->status = -1;
				goto out;
			}

			/* Get the level of root page */
			drill = set->page->level;

			/* If we are updating root page, then we need to
			 * release read lock on root page first and then
			 * re-lock and re-read root page.
			 */
			if ((lock != BPT_LOCK_READ) && (drill == level)) {
				bpt_unlockpage(set->latch, mode);
				bpt_unpinlatch(set->latch);
				bpt_unpinpool(set->pool);
				continue;
			}
		}

		prev_page = set->page_no;
		prev_latch = set->latch;
		prev_pool = set->pool;
		prev_mode = mode;

		/* Find the key on page at this level and descend
		 * to requested level.
		 */
		if (!set->page->kill) {
			if ((slot = bpt_findslot(set, key, len))) {
				/* Skip all dead slots */
				while ((sptr = slotptr(set->page, slot))->dead) {
					if (slot < set->page->count) {
						slot++;
						continue;
					} else {
						goto next_page;
					}
				}

				/* Current level is the requested level,
				 * return slot number
				 */
				if (drill == level) {
					return slot;
				}

				/* Descend to next level */
				page_no = bpt_getpageno(sptr->page_no);
				drill--;
				continue;
			}
		}

		/* Or slide into next page */
 next_page:
		page_no = bpt_getpageno(set->page->right);
	} while (page_no);

	LOG(ERR, "Key not found\n");
	bpt->status = -1;
 out:
	return 0;
}

unsigned int bpt_cleanpage(struct bptree *bpt,
			   struct bpt_page *page,
			   unsigned int len,
			   unsigned int slot)
{
	struct bpt_key *key;
	unsigned int max;
	unsigned int size;
	unsigned int newslot;
	unsigned int i, count;
	unsigned int next;

	max = page->count;
	newslot = slot;
	size = (max + 1) * sizeof(struct bpt_slot) + sizeof(*page) + len + 1;
	
	/* There is enough space for the key and its slot, just return */
	if (page->min >= size) {
		return slot;
	}
	
	/* Skip cleanup if nothing to reclaim */
	if (!page->dirty) {
		return 0;
	}

	memcpy(bpt->frame, page, bpt->mgr->page_size);
	bpt_bzero(page+1, bpt->mgr->page_size - sizeof(*page));
	page->dirty = 0;
	page->active = 0;
	next = bpt->mgr->page_size;

	for (i = 1, count = 0; i <= max; i++) {
		if (i == slot) {
			newslot = count + 1;
		}
		/* Skip all dead keys */
		if (i <= max && slotptr(bpt->frame, i)->dead) {
			continue;
		}

		count++;
		/* Copy key */
		key = keyptr(bpt->frame, i);
		next -= (key->len + 1);
		memcpy(((char *)page) + next, key, key->len + 1);

		/* Copy slot */
		memcpy(slotptr(page, count)->page_no,
		       slotptr(bpt->frame, i)->page_no,
		       PAGE_NUM_BYTES);
		if (!(slotptr(page, count)->dead =
		      slotptr(bpt->frame, i)->dead)) {
			page->active++;
		}
		slotptr(page, count)->offset = next;
	}

	page->min = next;
	page->count = count;

	if (page->min >= size) {
		return newslot;
	}
	
	return 0;
}

int bpt_splitroot(struct bptree *bpt, struct bpt_page_set *root,
		  unsigned char *leftkey, pageno_t page_no2)
{
	pageno_t left;
	unsigned int next;

	next = bpt->mgr->page_size;

	/* Make a copy of current root page */
	if (!(left = bpt_newpage(bpt, root->page))) {
		goto out;
	}

	bpt_bzero(root->page + 1, bpt->mgr->page_size - sizeof(*root->page));

	/* Insert first key on new root page and link old root
	 * page as left child
	 */
	next -= leftkey[0] + 1;
	memcpy(((char *)root->page) + next, leftkey, leftkey[0] + 1);
	bpt_putpageno(slotptr(root->page, 1)->page_no, left);
	slotptr(root->page, 1)->offset = next;

	/* Insert stopper key and link new page as right child */
	next -= STOPPER_KEY_LEN;
	((unsigned char *)root->page)[next] = 2;
	((unsigned char *)root->page)[next+1] = 0xFF;
	((unsigned char *)root->page)[next+2] = 0xFF;
	bpt_putpageno(slotptr(root->page, 2)->page_no, page_no2);
	slotptr(root->page, 2)->offset = next;

	bpt_putpageno(root->page->right, 0);
	root->page->min = next;
	root->page->count = 2;
	root->page->active = 2;
	root->page->level++;

	bpt_unlockpage(root->latch, BPT_LOCK_WRITE);
	bpt_unpinlatch(root->latch);
	bpt_unpinpool(root->pool);

	LOG(DBG, "root splitted, page_no2(0x%llx)\n", page_no2);

 out:
	return bpt->status;
}

int bpt_splitpage(struct bptree *bpt, struct bpt_page_set *set)
{
	struct bpt_mgr *mgr;
	struct bpt_key *key;
	struct bpt_page_set right;
	unsigned int max;
	unsigned int count;
	unsigned int i;
	unsigned int next;
	bpt_level_t level;
	unsigned char fencekey[257];
	unsigned char rightkey[257];

	key = NULL;
	mgr = bpt->mgr;
	level = set->page->level;

	/* Split higher half of keys to bpt->frame */
	bpt_bzero(bpt->frame, mgr->page_size);
	max = set->page->count;

	count = 0;
	next = mgr->page_size;
	for (i = max/2 + 1; i <= max; i++) {
		count++;
		key = keyptr(set->page, i);
		next -= (key->len + 1);
		/* Copy key */
		memcpy(((char *)bpt->frame) + next, key, key->len + 1);
		/* Copy slot */
		memcpy(slotptr(bpt->frame, count)->page_no,
		       slotptr(set->page, i)->page_no,
		       PAGE_NUM_BYTES);
		if (!(slotptr(bpt->frame, count)->dead =
		      slotptr(set->page, i)->dead)) {
			bpt->frame->active++;
		}
		slotptr(bpt->frame, count)->offset = next;
	}

	/* Remember fence key for new right page */
	memcpy(rightkey, key, key->len + 1);

	bpt->frame->min = next;
	bpt->frame->count = count;
	bpt->frame->level = level;

	/* Link right node */
	if (set->page_no > PAGE_ROOT) {
		memcpy(bpt->frame->right, set->page->right, PAGE_NUM_BYTES);
	}

	/* Allocate a new page and write frame to it */
	if (!(right.page_no = bpt_newpage(bpt, bpt->frame))) {
		goto out;
	}

	/* Update lower half in old page */
	memcpy(bpt->frame, set->page, mgr->page_size);
	bpt_bzero(set->page + 1, mgr->page_size - sizeof(*set->page));
	set->page->dirty = 0;
	set->page->active = 0;

	count = 0;
	next = mgr->page_size;
	for (i = 1; i <= max/2; i++) {
		count++;
		key = keyptr(bpt->frame, i);
		next -= (key->len + 1);
		/* Copy key */
		memcpy((char *)set->page + next, key, key->len + 1);
		/* Copy slot */
		memcpy(slotptr(set->page, count)->page_no,
		       slotptr(bpt->frame, i)->page_no,
		       PAGE_NUM_BYTES);
		slotptr(set->page, count)->offset = next;
		set->page->active++;
	}

	/* Remember fence key for old page */
	memcpy(fencekey, key, key->len + 1);

	bpt_putpageno(set->page->right, right.page_no);
	set->page->min = next;
	set->page->count = count;

	/* If current page is root page, split it */
	if (set->page_no == PAGE_ROOT) {
		bpt_splitroot(bpt, set, fencekey, right.page_no);
		goto out;
	}

	/* Lock right page */
	right.latch = bpt_pinlatch(bpt, right.page_no);
	bpt_lockpage(right.latch, BPT_LOCK_PARENT);

	bpt_lockpage(set->latch, BPT_LOCK_PARENT);
	bpt_unlockpage(set->latch, BPT_LOCK_WRITE);

	/* Insert new fence into left block */
	if (bpt_insertkey(bpt, &fencekey[1], fencekey[0], level+1, set->page_no)) {
		goto out;
	}

	if (bpt_insertkey(bpt, &rightkey[1], rightkey[0], level+1, right.page_no)) {
		goto out;
	}

	bpt_unlockpage(set->latch, BPT_LOCK_PARENT);
	bpt_unpinlatch(set->latch);
	bpt_unpinpool(set->pool);

	bpt_unlockpage(right.latch, BPT_LOCK_PARENT);
	bpt_unpinlatch(right.latch);

	LOG(DBG, "page(0x%llx) splitted, sibling(0x%llx)\n",
	    set->page_no, right.page_no);

 out:
	return bpt->status;
}

int bpt_insertkey(bptree_t h, unsigned char *key,
		  unsigned int len, bpt_level_t level,
		  pageno_t page_no)
{
	struct bptree *bpt;
	struct bpt_key *ptr;
	struct bpt_page_set set;
	unsigned int slot;
	unsigned int i;

	bpt = (struct bptree *)h;

	while (TRUE) {
		if ((slot = bpt_loadpage(bpt, &set, key, len, level,
					 BPT_LOCK_WRITE))) {
			ptr = keyptr(set.page, slot);
		} else {
			LOG(ERR, "Failed to load page, level(%d), page(0x%llx)\n",
			    level, page_no);
			if (bpt->status == 0) {
				bpt->status = -1;
			}
			goto out;
		}

		/* If key already exists, update page number
		 * and return.
		 */
		if (keycmp(ptr, key, len) == 0) {
			if (slotptr(set.page, slot)->dead) {
				set.page->active++;
			}
			slotptr(set.page, slot)->dead = 0;
			bpt_putpageno(slotptr(set.page, slot)->page_no, page_no);
			LOG(DBG, "Key updated, level(%d), curr-page(0x%llx), "
			    "page(0x%llx)\n", level, set.page_no, page_no);
			bpt->status = 0;
			goto unlock_page;
		}

		/* Check whether page has enough space to reclaim */
		slot = bpt_cleanpage(bpt, set.page, len, slot);
		if (slot) {
			break;
		}

		/* Not enough space for the key, do page split */
		if (bpt_splitpage(bpt, &set)) {
			goto out;
		}
	}

	/* First copy the key into the page */
	set.page->min -= (len + 1);
	((unsigned char *)set.page)[set.page->min] = len;
	memcpy((char *)set.page + set.page->min + 1, key, len);

	/* Then insert new entry into the slot array */
	for (i = slot; i < set.page->count; i++) {
		if (slotptr(set.page, i)->dead) {
			break;
		}
	}

	if (i == set.page->count) {
		i++;
		set.page->count++;	// No dead slot can be reused
	}

	set.page->active++;

	for ( ; i > slot; i--) {
		*slotptr(set.page, i) = *slotptr(set.page, i - 1);
	}

	bpt_putpageno(slotptr(set.page, slot)->page_no, page_no);
	slotptr(set.page, slot)->offset = set.page->min;
	slotptr(set.page, slot)->dead = 0;

 unlock_page:

	bpt_unlockpage(set.latch, BPT_LOCK_WRITE);
	bpt_unpinlatch(set.latch);
	bpt_unpinpool(set.pool);

 out:
	return bpt->status;
}

pageno_t bpt_findkey(bptree_t h, unsigned char *key,
		     unsigned int len)
{
	unsigned int slot;
	struct bptree *bpt;
	struct bpt_key *ptr;
	struct bpt_page_set set;
	pageno_t page_no;

	bpt = (struct bptree *)h;
	page_no = 0;

	if ((slot = bpt_loadpage(bpt, &set, key, len, 0, BPT_LOCK_READ))) {
		/* If key exists return page number, otherwise return 0. */
		ptr = keyptr(set.page, slot);
		if (keycmp(ptr, key, len) == 0) {
			page_no = bpt_getpageno(slotptr(set.page, slot)->page_no);
		}
		bpt_unlockpage(set.latch, BPT_LOCK_READ);
		bpt_unpinlatch(set.latch);
		bpt_unpinpool(set.pool);
	}

	return page_no;
}

int bpt_fixfence(struct bptree *bpt,
		 struct bpt_page_set *set,
		 bpt_level_t level)
{
	struct bpt_key *ptr;
	pageno_t page_no;
	unsigned char leftkey[257];
	unsigned char rightkey[257];

	ptr = keyptr(set->page, set->page->count);
	memcpy(rightkey, ptr, ptr->len + 1);

	bpt_bzero(slotptr(set->page, set->page->count), sizeof(struct bpt_slot));
	set->page->count--;
	set->page->dirty = 1;

	ptr = keyptr(set->page, set->page->count);
	memcpy(leftkey, ptr, ptr->len + 1);
	page_no = set->page_no;

	bpt_lockpage(set->latch, BPT_LOCK_PARENT);
	bpt_unlockpage(set->latch, BPT_LOCK_WRITE);

	if (bpt_insertkey(bpt, &leftkey[1], leftkey[0], level+1, page_no)) {
		goto out;
	}

	if (bpt_deletekey(bpt, &rightkey[1], rightkey[0], level+1)) {
		goto out;
	}

	bpt_unlockpage(set->latch, BPT_LOCK_PARENT);
	bpt_unpinlatch(set->latch);
	bpt_unpinpool(set->pool);

 out:
	return bpt->status;
}

int bpt_collapseroot(struct bptree *bpt, struct bpt_page_set *root)
{
	struct bpt_page_set child;
	unsigned int i;

	/* Find child entry and promote to new root */
	do {
		for (i = 1; i <= root->page->count; i++) {
			if (!slotptr(root->page, i)->dead) {
				break;
			}
		}

		child.page_no = bpt_getpageno(slotptr(root->page, i)->page_no);

		child.latch = bpt_pinlatch(bpt, child.page_no);
		/* Lock child for delete and write */
		bpt_lockpage(child.latch, BPT_LOCK_DELETE);
		bpt_lockpage(child.latch, BPT_LOCK_WRITE);
		
		if ((child.pool = bpt_pinpool(bpt, child.page_no))) {
			child.page = bpt_page(bpt, child.pool, child.page_no);
		} else {
			goto out;
		}

		memcpy(root->page, child.page, bpt->mgr->page_size);

		if (bpt_freepage(bpt, &child)) {
			goto out;
		}
	} while ((root->page->level > 1) && (root->page->active == 1));

	bpt_unlockpage(root->latch, BPT_LOCK_WRITE);
	bpt_unpinlatch(root->latch);
	bpt_unpinpool(root->pool);

	LOG(DBG, "root collapsed, child(0x%llx) freed\n", child.page_no);

 out:
	return bpt->status;
}

int bpt_deletekey(bptree_t h, unsigned char *key,
		  unsigned int len, bpt_level_t level)
{
	struct bptree *bpt;
	struct bpt_key *ptr;
	unsigned int slot;
	unsigned int i;
	struct bpt_page_set right;
	struct bpt_page_set set;
	bool_t fence = FALSE;
	bool_t found = FALSE;
	bool_t dirty = FALSE;
	unsigned char lowerkey[257];
	unsigned char higherkey[257];

	bpt = (struct bptree *)h;
	bpt->status = 0;

	if ((slot = bpt_loadpage(bpt, &set, key, len, level, BPT_LOCK_WRITE))) {
		ptr = keyptr(set.page, slot);
	} else {
		goto out;
	}

	fence = (slot == set.page->count);

	/* If the key was found delete it, otherwise ignore the request */
	if ((found = (keycmp(ptr, key, len) == 0))) {
		if ((found = !slotptr(set.page, slot)->dead)) {
			dirty = TRUE;
			slotptr(set.page, slot)->dead = 1;
			set.page->dirty = 1;
			set.page->active--;

			/* Collapse empty slots */
			while ((i = (set.page->count - 1))) {
				if (slotptr(set.page, i)->dead) {
					*slotptr(set.page, i) =
						*slotptr(set.page, i+1);
					bpt_bzero(slotptr(set.page, set.page->count),
						  sizeof(struct bpt_slot));
					set.page->count--;
				} else {
					break;
				}
			}
		}
	}

	if (!found) {
		bpt_unlockpage(set.latch, BPT_LOCK_WRITE);
		bpt_unpinlatch(set.latch);
		bpt_unpinpool(set.pool);
		goto foundkey;
	}

	/* Did we delete a fence key in an upper level? */
	if (dirty && level && set.page->active && fence) {
		if (bpt_fixfence(bpt, &set, level)) {
			goto out;
		}
		goto foundkey;
	}

	/* Is this a collapsed root? */
	if ((level > 1) &&
	    (set.page_no == PAGE_ROOT) &&
	    (set.page->active == 1)) {
		if (bpt_collapseroot(bpt, &set)) {
			goto out;
		}
		goto foundkey;
	}

	/* Return if page is not empty */
	if (set.page->active) {
		bpt_unlockpage(set.latch, BPT_LOCK_WRITE);
		bpt_unpinlatch(set.latch);
		bpt_unpinpool(set.pool);
		goto foundkey;
	}

	/* Cache a copy of fence key in order to find parent */
	ptr = keyptr(set.page, set.page->count);
	memcpy(lowerkey, ptr, ptr->len + 1);

	/* Pull contents of next page into current empty page */
	right.page_no = bpt_getpageno(set.page->right);
	right.latch = bpt_pinlatch(bpt, right.page_no);
	bpt_lockpage(right.latch, BPT_LOCK_WRITE);

	if ((right.pool = bpt_pinpool(bpt, right.page_no))) {
		right.page = bpt_page(bpt, right.pool, right.page_no);
	} else {
		goto out;
	}

	if (right.page->kill) {
		LOG(ERR, "page(0x%llx) killed\n", right.page_no);
		bpt->status = -1;
		goto out;
	}

	memcpy(set.page, right.page, bpt->mgr->page_size);

	ptr = keyptr(right.page, set.page->count);
	memcpy(higherkey, ptr, ptr->len + 1);

	/* Mark right page as deleted */
	bpt_putpageno(right.page->right, set.page_no);
	right.page->kill = 1;

	bpt_lockpage(right.latch, BPT_LOCK_PARENT);
	bpt_unlockpage(right.latch, BPT_LOCK_WRITE);

	bpt_lockpage(set.latch, BPT_LOCK_PARENT);
	bpt_unlockpage(set.latch, BPT_LOCK_WRITE);

	/* Insert new higher key to upper level */
	if (bpt_insertkey(bpt, &higherkey[1], higherkey[0],
			  level+1, set.page_no)) {
		goto out;
	}

	/* Delete old lower key from upper level */
	if (bpt_deletekey(bpt, &lowerkey[1], lowerkey[0], level+1)) {
		goto out;
	}

	/* Acquire write and delete lock on deleted page */
	bpt_unlockpage(right.latch, BPT_LOCK_PARENT);
	bpt_lockpage(right.latch, BPT_LOCK_DELETE);
	bpt_lockpage(right.latch, BPT_LOCK_WRITE);

	/* Free right page */
	bpt_freepage(bpt, &right);

	/* Remove parent modify lock */
	bpt_unlockpage(set.latch, BPT_LOCK_PARENT);
	bpt_unpinlatch(set.latch);
	bpt_unpinpool(set.pool);

 foundkey:
	bpt->found = found;
 out:
	return bpt->status;
}

struct bpt_key *bpt_key(bptree_t h, unsigned int slot)
{
	struct bptree *bpt;
	
	bpt = (struct bptree *)h;
	
	return keyptr(bpt->cursor, slot);
}

unsigned int bpt_firstkey(bptree_t h, unsigned char *key,
			  unsigned int len)
{
	struct bptree *bpt;
	struct bpt_page_set set;
	unsigned int slot;

	bpt = (struct bptree *)h;
	
	if ((slot = bpt_loadpage(bpt, &set, key, len, 0, BPT_LOCK_READ))) {
		memcpy(bpt->cursor, set.page, bpt->mgr->page_size);
	} else {
		return 0;
	}

	bpt->cursor_page = set.page_no;

	bpt_unlockpage(set.latch, BPT_LOCK_READ);
	bpt_unpinlatch(set.latch);
	bpt_unpinpool(set.pool);

	return slot;
}

unsigned int bpt_nextkey(bptree_t h, unsigned int slot)
{
	struct bptree *bpt;
	struct bpt_page_set set;
	pageno_t right;

	bpt = (struct bptree *)h;
	
	do {
		right = bpt_getpageno(bpt->cursor->right);

		for (slot++; slot <= bpt->cursor->count; slot++) {
			if (slotptr(bpt->cursor, slot)->dead) {
				continue;
			} else if (right || (slot < bpt->cursor->count)) {
				/* If no next page then the last slot
				 * is stopper key, don't return it.
				 */
				return slot;
			} else {
				break;
			}
		}
		
		/* No next page, just break out */
		if (right == 0) {
			break;
		}
		
		bpt->cursor_page = right;

		if ((set.pool = bpt_pinpool(bpt, right))) {
			set.page = bpt_page(bpt, set.pool, right);
		} else {
			goto out;
		}

		set.latch = bpt_pinlatch(bpt, right);
		bpt_lockpage(set.latch, BPT_LOCK_READ);

		memcpy(bpt->cursor, set.page, bpt->mgr->page_size);

		bpt_unlockpage(set.latch, BPT_LOCK_READ);
		bpt_unpinlatch(set.latch);
		bpt_unpinpool(set.pool);

		slot = 0;
	} while (TRUE);

	bpt->status = 0;
 out:
	return 0;
}

void bpt_getiostat(bptree_t h, struct bpt_iostat *iostat)
{
	;
}

void dump_key(struct bpt_key *k)
{
	unsigned int i;

	for (i = 0; i < k->len; i++) {
		printf("%c", k->key[i]);
	}

	printf(" ");
}

void dump_keys_in_page(struct bpt_page *page)
{
	int i;
	struct bpt_key *k;
	unsigned char stopper[] = {0xFF, 0xFF};

	for (i = 1; i <= page->count; i++) {
		/* Prepend a '*' before dead keys */
		if (slotptr(page, i)->dead) {
			printf("[*]");
		}

		/* If this is stopper key, just print a ';' */
		k = keyptr(page, i);
		if (keycmp(k, stopper, sizeof(stopper)) == 0) {
			printf(";");
			continue;
		}

		/* Dump the actual key */
		dump_key(k);
	}
	printf("\n");
}

void dump_bpt_page(struct bpt_page *page)
{
	printf("---------- b+tree page info -----------\n"
	       " count  : %d\n"
	       " active : %d\n"
	       " level  : %d\n"
	       " min    : %d\n"
	       " free   : %d\n"
	       " kill   : %d\n"
	       " dirty  : %d\n"
	       " right  : 0x%llx\n"
	       " keys   : ",
	       page->count, page->active, page->level, page->min,
	       page->free, page->kill, page->dirty, bpt_getpageno(page->right));

	dump_keys_in_page(page);
}

static int dbg_load_page(int fd, struct bpt_page *page,
			 unsigned int page_size,
			 pageno_t page_no)
{
	int rc = 0;
	off_t offset;

	offset = page_no * page_size;
	if (pread(fd, page, page_size, offset) != page_size) {
		rc = -1;
	}

	return rc;
}

void dump_free_page_list(int fd, struct bpt_page *alloc,
			 unsigned int page_size)
{
	int rc = 0;
	struct bpt_page *page;
	pageno_t page_no;

	page = bpt_malloc(page_size);
	if (page == NULL) {
		printf("Failed to allocate page!\n");
		return;
	}

	printf("-------- b+tree free page list --------\n");

	page_no = bpt_getpageno(alloc->right);
	while (page_no) {
		printf("0x%llx->", page_no);
		rc = dbg_load_page(fd, page, page_size, page_no);
		if (rc != 0) {
			printf("Failed to load page 0x%llx, error:%d\n",
			       page_no, rc);
			break;
		}
		page_no = bpt_getpageno(page->right);
	}

	if (rc == 0) {
		printf("nil\n");
	}

	free(page);
}

#ifdef _BPT_UNITTEST

int main(int argc, char *argv[])
{
	int rc = 0;
	bptree_t h = NULL;
	pageno_t page_no;
	const char *path = "bpt.dat";
	struct bptree *bpt = NULL;
	struct bpt_mgr *mgr = NULL;
	struct bpt_key *k = NULL;
	char *key1 = "test1";
	char *key2 = "test2";
	char *key3 = "test3";
	unsigned int key1_len = strlen(key1);
	unsigned int key2_len = strlen(key2);
	unsigned int key3_len = strlen(key3);
	int ret = 0;
	unsigned int slot;
	int i;
	char key[9];
	unsigned int key_len = sizeof(key);

	mgr = bpt_openmgr(path, 12, 128, 13);
	if (mgr == NULL) {
		fprintf(stderr, "Failed to open bpt_mgr!\n");
		goto out;
	}

	h = bpt_open(mgr);
	if (h == NULL) {
		fprintf(stderr, "Failed to open bptree!\n");
		goto out;
	}

	bpt = (struct bptree *)h;
	
	rc = bpt_insertkey(bpt, (unsigned char *)key1, key1_len, 0, 5);
	if (rc != 0) {
		fprintf(stderr, "Failed to insert key: %s\n", key1);
		goto out;
	}

	rc = bpt_insertkey(bpt, (unsigned char *)key3, key3_len, 0, 7);
	if (rc != 0) {
		fprintf(stderr, "Failed to insert key: %s\n", key3);
		goto out;
	}

	rc = bpt_insertkey(bpt, (unsigned char *)key2, key2_len, 0, 6);
	if (rc != 0) {
		fprintf(stderr, "Failed to insert key: %s\n", key2);
		goto out;
	}

	page_no = bpt_findkey(bpt, (unsigned char *)key2, key2_len);
	if (page_no == 0) {
		fprintf(stderr, "Page not found for key: %s\n", key2);
		goto out;
	} else {
		printf("key %s mapped to page 0x%llx\n", key2, page_no);
	}

	rc = bpt_deletekey(bpt, (unsigned char *)key2, key2_len, 0);
	if (rc != 0) {
		fprintf(stderr, "Failed to delete key: %s\n", key2);
		goto out;
	}

	/* Verify key deletion */
	page_no = bpt_findkey(bpt, (unsigned char *)key2, key2_len);
	if (page_no != 0) {
		fprintf(stderr, "Deleted key found: %s->0x%llx\n", key2, page_no);
		goto out;
	}

	rc = bpt_deletekey(bpt, (unsigned char *)key2, key2_len, 0);
	if (rc != 0) {
		fprintf(stderr, "Delete nonexistent key failed!\n");
		goto out;
	} else if (bpt->found != 0) {
		fprintf(stderr, "Nonexistent key found!\n");
		goto out;
	}

	for (i = 0; i < 512; i++) {
		ret = sprintf(key, "%08x", i);
		rc = bpt_insertkey(bpt, (unsigned char *)key, key_len, 0, i);
		if (rc != 0) {
			fprintf(stderr, "Failed to insert key: %s\n", key);
			goto out;
		}
	}

	ret = sprintf(key, "%08x", 87);
	page_no = bpt_findkey(bpt, (unsigned char *)key, key_len);
	if (page_no == 0) {
		fprintf(stderr, "Page not found for key: %s\n", key);
		goto out;
	} else {
		printf("key %s mapped to page 0x%llx\n", key, page_no);
	}

	printf("Begin key iteration:\n");
	slot = bpt_firstkey(bpt, (unsigned char *)key, key_len);
	if (slot == 0) {
		fprintf(stderr, "Failed to iterate key: %s\n", key);
		goto out;
	}

	for (i = 511; i >= 0; i--) {
		ret = sprintf(key, "%08x", i);
		rc = bpt_deletekey(bpt, (unsigned char *)key, key_len, 0);
		if (rc != 0) {
			fprintf(stderr, "Failed to delete key: %s\n", key);
			goto out;
		}
	}

 out:
	if (mgr) {
		bpt_closemgr(mgr);
	}
	if (h) {
		bpt_close(h);
	}
	return rc;
}

#endif	/* _BPT_UNITTEST */
