#ifndef __BPT_PRIVATE_H__
#define __BPT_PRIVATE_H__

#include "lock.h"

#define PAGE_SUPER	0	// page 0 is always reserved for super block
#define PAGE_ALLOC	1	// alloc page is the head of free page list
#define PAGE_ROOT	2	// root is always located at page 2
#define PAGE_LEAF	3	// the first leaf page of level zero is always located at page 2
#define PAGE_LATCH	4	// page for latch manager

#define BPT_BUF_PAGES	3

#define BPT_LATCH_TABLE	128	// number of latch manager slots

/* maximum addressable space is 6-bytes integer * max-page-size */
#define PAGE_NUM_BYTES	6	

/* stopper key is 2 bytes, plus 1 byte for key length, so 3 bytes */
#define STOPPER_KEY_LEN	3

/* minimum level of a new b+tree */
#define MIN_LEVEL	2

struct bpt_super_block {
	char magic[16];
	uint32_t major;
	uint32_t minor;
	uint32_t page_bits;
};

typedef enum {
	BPT_LOCK_ACCESS,
	BPT_LOCK_DELETE,
	BPT_LOCK_READ,
	BPT_LOCK_WRITE,
	BPT_LOCK_PARENT
} bpt_mode_t;

struct bpt_slot {
	uint32_t offset:BPT_MAX_PAGE_SHIFT;	// page offset for the key
	uint32_t dead:1;			// set for deleted key
	uint32_t reserved:17;			// reserved bits
	unsigned char page_no[PAGE_NUM_BYTES];  // child page associated with slot
};

struct bpt_key {
	uint8_t len;
	unsigned char key[0];
};

/* macros to address slot and keys within the page.
 * page slots index beginning from 1.
 */
#define slotptr(page, slot) (((struct bpt_slot *)(page+1)) + (slot-1))
#define keyptr(page, slot) ((struct bpt_key *)((char *)(page) + slotptr(page, slot)->offset))

/* b+tree page latch */
struct bpt_latch {
	struct rwlock rdwr;	// read/write access lock
	struct rwlock parent;	// parent update lock
	struct rwlock access;	// access intent/page delete
	struct spin_rwlock busy;
	volatile uint16_t prev;	// prev entry in hash table chain
	volatile uint16_t next;	// next entry in hash table chain
	volatile uint16_t pin;	// number of outstanding locks
	volatile uint16_t hashv;// hash value
	volatile pageno_t page_no;// latch page number
};

struct latch_hash_bucket {
	struct spin_rwlock lock;
	volatile uint16_t slot;	// head of the latch hash bucket
};

/* b+tree page layout
 * +---------------------+      -
 * |     page header     |      ^
 * |              +------+      |
 * |              |right-+------+--------->next sibling
 * +--------------+------+      |
 * |       slots.offset--+--+   |
 * |       slots.page_no-+--+---+--------->child
 * |       ...           |  |   |
 * +---------------------+  |  page size
 * |     free space      |  |   |
 * +---------------------+  |   |
 * |      bpt keys       |  |   |
 * |       ...           |<-+   v
 * +---------------------+      -
 */
struct bpt_page {
	uint32_t count;		// number of keys in page
	uint32_t active;	// number of active keys
	uint32_t min;		// next key offset
	uint8_t free:1;		// page is on free list
	uint8_t kill:1;		// page is being deleted
	uint8_t dirty:1;	// page is dirty
	uint8_t reserved:5;	// reserved bits
	bpt_level_t level;	// page level in the tree
	unsigned char right[PAGE_NUM_BYTES]; // Next page number
};

/* page pool */
struct bpt_pool {
	pageno_t basepage;	// mapped base pageno
	char *map;		// mapped memory pointer
	uint16_t slot;
	uint16_t pin;		// mapped page pin counter
	struct bpt_pool *hash_prev;
	struct bpt_pool *hash_next;
};

#define CLOCK_BIT	0x8000	// bit for pool->pin

struct bpt_page_set {
	pageno_t page_no;
	struct bpt_page *page;  // the b+tree page itself
	struct bpt_pool *pool;	// page pool this page lies on
	struct bpt_latch *latch;
};

/* b+tree latch manager
 * +-----------------------+  -
 * |        alloc[1]       |  ^
 * |        alloc[2]       |  |
 * +-----------------------+ page size
 * |      other fields     |  |
 * +-------+-------+-------+<-+----- latch_tbl
 * | lock  |  ...  | lock  |  |
 * | slot  |       | slot  |  v
 * +-------+-------+-------+  -
 */
struct bpt_latch_mgr {
	struct bpt_page alloc[2];
	struct bpt_iostat iostat;// I/O statistics info
	struct spin_rwlock lock;
	uint16_t latch_deployed;
	uint16_t nr_latch_pages;
	uint16_t nr_latch_total;
	uint16_t victim;
	uint16_t tbl_size;
	struct latch_hash_bucket latch_tbl[0];
};

struct bpt_mgr {
	uint32_t page_size;
	uint32_t page_bits;
	uint32_t seg_bits;	// segment size in pages in bits
	int fd;			// index file descriptor

	int pool_cnt;		// current number of page pool
	int pool_max;		// maximum number of page pool
	int pool_mask;		// number of pages in segments - 1
	int tbl_size;		// size of page segments pool hash table

	/* last evicted pool hash table entry */
	volatile uint32_t evicted;
	uint16_t *pool_tbl;	// hash table for page segments pool

	/* locks for pool hash table */
	struct spin_rwlock *pool_tbl_locks;
	
	/* mapped latch page from allocation page */
	struct bpt_latch_mgr *latchmgr;

	/* mapped latches from latch pages */
	struct bpt_latch *latches;

	struct bpt_pool *pools;	// page segments pool
};

/* b+tree handle */
struct bptree {
	struct bpt_mgr *mgr;	// b+tree manager
	int status;		// status of last operation
	pageno_t cursor_page;	// current cursor page number
	struct bpt_page *cursor;// cached frame for first/next
	struct bpt_page *frame;	// spare frame for page split
	struct bpt_page *zero;	// zeros frame buffer (never mapped)
	unsigned char *mem;

	/* deletekey returns OK even when the key does not exist.
	 * This is used to indicate whether the key was found in tree.
	 */
	int found;
};

#endif	/* __BPT_PRIVATE_H__ */
