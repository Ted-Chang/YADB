#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>
#include "bptree.h"

#ifndef LOG
#define LOG(_fmt_, ...) \
	do {							\
		printf("[BPT]%s(%d):", __FUNCTION__, __LINE__); \
		printf(_fmt_, ##__VA_ARGS__);			\
	} while (0)
#endif	/* LOG */

/* Minimum page size 512 bytes and max page size 64K */
#define MAX_BPT_PAGE_SHIFT	16
#define MIN_BPT_PAGE_SHIFT	9

#define PAGE_ALLOC	0
#define PAGE_ROOT	1	// root is always located at page 1
#define PAGE_LEAF	2	// The first leaf page of level zero is always located at page 2

#define PAGE_NUM_BYTES	6	// Maximum addressable space is 6-bytes integer*max-page-size

/* Minimum level of a new b+tree */
#define MIN_LEVEL	2

struct bpt_slot {
	unsigned int offset:MAX_BPT_PAGE_SHIFT;	// Page offset for the key start
	unsigned int dead:1;	// Set for deleted key
	unsigned int reserved:17;
	unsigned char page_no[PAGE_NUM_BYTES]; // Page number associated with slot
};

struct bpt_key {
	unsigned char len;
	unsigned char key[0];
};

/* Macros to address slot and keys within the page.
 * Page slots index beginning from 1.
 */
#define slotptr(page, slot) (((struct bpt_slot *)(page+1)) + (slot-1))
#define keyptr(page, slot) ((struct bpt_key *)((unsigned char *)(page) + slotptr(page, slot)->offset))

/* Page header */
struct bpt_page {
	unsigned int count;	// number of keys in page
	unsigned int active;	// number of active keys
	unsigned int min;	// next key offset
	unsigned char free:1;	// page is on free list
	unsigned char kill:1;	// page is being deleted
	unsigned char dirty:1;	// page is dirty
	unsigned char reserved:5;
	bpt_level level;	// page level in the tree
	unsigned char right[PAGE_NUM_BYTES]; // Next page number
};

struct bplustree {
	unsigned int page_size;
	unsigned int page_bits;
	int errno;		// errno of last operation
	bpt_pageno_t page_no;	// current page number
	bpt_pageno_t cursor_page;// current cursor page number
	struct bpt_page *temp;
	struct bpt_page *alloc;	// frame buffer for alloc page (page 0)
	struct bpt_page *cursor;// cached frame for first/next
	struct bpt_page *frame;	// spare frame for page split
	struct bpt_page *page;	// current page
	int fd;
	unsigned char *mem;
	struct bpt_iostat iostat;
};

int bpt_insertkey(bpt_handle h, unsigned char *key,
		  unsigned int len, bpt_level level,
		  bpt_pageno_t page_no);
int bpt_deletekey(bpt_handle h, unsigned char *key,
		  unsigned int len, bpt_level level);

void bpt_putpageno(unsigned char *dst, bpt_pageno_t page_no)
{
	int i = PAGE_NUM_BYTES;

	while (i--) {
		dst[i] = (unsigned char)page_no;
		if (page_no) {
			page_no >>= 8;
		}
	}
}

bpt_pageno_t bpt_getpageno(unsigned char *src)
{
	bpt_pageno_t page_no = 0;
	int i;

	for (i = 0; i < PAGE_NUM_BYTES; i++) {
		page_no <<= 8;
		page_no += src[i];
	}

	return page_no;
}

int keycmp(struct bpt_key *key1, unsigned char *key2, unsigned int len2)
{
	int ret = 0;
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

bpt_handle bpt_open(const char *name, unsigned int page_bits)
{
	int rc = 0;
	struct bplustree *bpt = NULL;
	struct bpt_key *key = NULL;
	bpt_level level;

	if (page_bits > MAX_BPT_PAGE_SHIFT ||
	    page_bits < MIN_BPT_PAGE_SHIFT) {
		rc = -1;
		goto out;
	}

	bpt = malloc(sizeof(struct bplustree));
	if (bpt == NULL) {
		rc = -1;
		goto out;
	}
	
	memset(bpt, 0, sizeof(struct bplustree));
	bpt->fd = open(name, O_RDWR|O_CREAT, 0666);
	if (bpt->fd == -1) {
		rc = -1;
		goto out;
	}

	bpt->page_bits = page_bits;
	bpt->page_size = 1 << page_bits;

	/* Total 6 in-memory pages */
	bpt->mem = malloc(6 * bpt->page_size);
	if (bpt->mem == NULL) {
		rc = -1;
		goto out;
	}

	memset(bpt->mem, 0, 6 * bpt->page_size);
	bpt->frame = (struct bpt_page *)(bpt->mem);
	bpt->cursor = (struct bpt_page *)(bpt->mem + bpt->page_size);
	bpt->page = (struct bpt_page *)(bpt->mem + 2*bpt->page_size);
	bpt->alloc = (struct bpt_page *)(bpt->mem + 3*bpt->page_size);
	bpt->temp = (struct bpt_page *)(bpt->mem + 4*bpt->page_size);

	bpt_putpageno(bpt->alloc->right, MIN_LEVEL+1);

	/* Write alloc page */
	if (write(bpt->fd, bpt->alloc, bpt->page_size) < bpt->page_size) {
		rc = -1;
		goto out;
	}

	/* Initialize empty b+tree with root page and page of leaves. */
	for (level = MIN_LEVEL; level--; ) {
		slotptr(bpt->frame, 1)->offset = bpt->page_size - 3;
		bpt_putpageno(slotptr(bpt->frame, 1)->page_no,
			      level ? MIN_LEVEL-level+1 : 0);
		
		/* Create stopper key */
		key = keyptr(bpt->frame, 1);
		key->len = 2;
		key->key[0] = 0xFF;
		key->key[1] = 0xFF;

		bpt->frame->min = bpt->page_size - 3;
		bpt->frame->level = level;
		bpt->frame->count = 1;
		bpt->frame->active = 1;

		if (write(bpt->fd, bpt->frame, bpt->page_size) < bpt->page_size) {
			rc = -1;
			goto out;
		}
	}

 out:
	if (rc != 0 && bpt) {
		bpt_close(bpt);
		bpt = NULL;
	}

	return bpt;
}

void bpt_close(bpt_handle h)
{
	struct bplustree *bpt;

	bpt = (struct bplustree *)h;
	if (bpt->mem) {
		free(bpt->mem);
	}
	if (bpt->fd) {
		close(bpt->fd);
	}
	free(bpt);
}

int bpt_updatepage(bpt_handle h, struct bpt_page *page, bpt_pageno_t page_no)
{
	struct bplustree *bpt;
	off_t offset;

	bpt = (struct bplustree *)h;
	offset = page_no << bpt->page_bits;
	if (pwrite(bpt->fd, page, bpt->page_size, offset) != bpt->page_size) {
		LOG("page(%llx) pwrite failed\n", page_no);
		bpt->errno = -1;
		return -1;
	}

	__sync_add_and_fetch(&bpt->iostat.writes, 1);
	return 0;
}

int bpt_mappage(bpt_handle h, struct bpt_page *page, bpt_pageno_t page_no)
{
	struct bplustree *bpt;
	off_t offset;

	bpt = (struct bplustree *)h;
	offset = page_no << bpt->page_bits;
	if (pread(bpt->fd, page, bpt->page_size, offset) < bpt->page_size) {
		LOG("page(%llx) pread failed\n", page_no);
		bpt->errno = -1;
		return -1;
	}

	__sync_add_and_fetch(&bpt->iostat.reads, 1);
	return 0;
}

bpt_pageno_t bpt_newpage(bpt_handle h, struct bpt_page *page)
{
	struct bplustree *bpt;
	bpt_pageno_t new_page;

	bpt = (struct bplustree *)h;

	if (bpt_mappage(bpt, bpt->alloc, PAGE_ALLOC)) {
		goto out;
	}

	/* Try empty chain first
	 * otherwise allocate new empty page
	 */
	new_page = bpt_getpageno(bpt->alloc[1].right);
	if (new_page) {
		if (bpt_mappage(bpt, bpt->temp, new_page)) {
			goto out;
		}
		bpt_putpageno(bpt->alloc[1].right,
			      bpt_getpageno(bpt->temp->right));
		LOG("reuse free page(%llx)\n", new_page);
	} else {
		/* Alloc page always point to the tail page. */
		new_page = bpt_getpageno(bpt->alloc->right);
		bpt_putpageno(bpt->alloc->right, new_page+1);
		LOG("allocating new page(%llx)\n", new_page);
	}

	/* Persist the page allocation */
	if (bpt_updatepage(bpt, bpt->alloc, PAGE_ALLOC)) {
		goto out;
	}

	/* Persist current page to new page */
	if (bpt_updatepage(bpt, page, new_page)) {
		goto out;
	}

	return new_page;

 out:
	return 0;
}

int bpt_freepage(bpt_handle h, bpt_pageno_t page_no)
{
	struct bplustree *bpt;

	bpt = (struct bplustree *)h;

	/* Retrieve the page allocaction info */
	if (bpt_mappage(bpt, bpt->alloc, PAGE_ALLOC)) {
		goto out;
	}

	/* Retrieve the specifed page data into temp page */
	if (bpt_mappage(bpt, bpt->temp, page_no)) {
		goto out;
	}

	/* Insert the page to be freed into the empty chain
	 * in second alloc page.
	 * alloc[1] -> page_no -> ...  -> free page -> 0
	 */
	bpt_putpageno(bpt->temp->right,
		      bpt_getpageno(bpt->alloc[1].right));
	bpt_putpageno(bpt->alloc[1].right, page_no);
	bpt->temp->free = 1;

	/* Persistent page changes */
	if (bpt_updatepage(bpt, bpt->alloc, PAGE_ALLOC)) {
		goto out;
	}
	if (bpt_updatepage(bpt, bpt->temp, page_no)) {
		goto out;
	}
	
	LOG("page(%llx) freed\n", page_no);

 out:
	return bpt->errno;
}

unsigned int bpt_findslot(bpt_handle h, unsigned char *key,
			  unsigned int len)
{
	int slot;
	int low, high;
	struct bplustree *bpt;

	bpt = (struct bplustree *)h;
	low = 1;	// slot index start from 1
	high = bpt->page->count;

	if (bpt_getpageno(bpt->page->right)) {
		/* If next page exists, this page has no stopper
		 * key, so high index should be count+1
		 */
		high++;
	}

	/* Do binary search to find the key */
	while (high > low) {
		slot = low + ((high - low) / 2);
		if (keycmp(keyptr(bpt->page, slot), key, len) < 0) {
			low = slot + 1;
		} else {
			high = slot;
		}
	}

	return (high > bpt->page->count) ? 0 : high;
}

unsigned int bpt_loadpage(bpt_handle h, unsigned char *key,
			  unsigned int len, bpt_level level)
{
	struct bplustree *bpt;
	bpt_pageno_t page_no;
	unsigned int slot;
	unsigned char drill = 0xFF;

	bpt = (struct bplustree *)h;

	page_no = PAGE_ROOT;

	do {
		bpt->page_no = page_no;

		/* Retrieve the page data */
		if (bpt_mappage(bpt, bpt->page, bpt->page_no)) {
			LOG("map page(%llx) failed\n", bpt->page_no);
			return 0;
		}

		if (bpt->page->level != drill) {
			if (bpt->page_no != PAGE_ROOT) {
				LOG("non-root page(%llx)\n", bpt->page_no);
				bpt->errno = -1;
				return 0;
			}
			
			drill = bpt->page->level;
		}

		/* Find the key on page at this level and descend
		 * to requested level.
		 */
		if (!bpt->page->kill) {
			slot = bpt_findslot(bpt, key, len);
			if (slot) {
				/* Current level is the requested level,
				 * just return slot number
				 */
				if (drill == level) {
					return slot;
				}

				/* Skip all dead slots */
				while (slotptr(bpt->page, slot)->dead) {
					if (slot < bpt->page->count) {
						slot++;
						continue;
					} else {
						goto nextpage;
					}
				}

				/* Descend to next level */
				page_no = bpt_getpageno(slotptr(bpt->page, slot)->page_no);
				drill--;
				continue;
			}
		}

		/* Or slide into next page */
 nextpage:
		page_no = bpt_getpageno(bpt->page->right);
	} while (page_no);

	LOG("key not found\n");
	bpt->errno = -1;
	return 0;
}

unsigned int bpt_cleanpage(bpt_handle h, unsigned len,
			   unsigned int slot)
{
	struct bplustree *bpt;
	struct bpt_page *page;
	struct bpt_key *key;
	unsigned int max;
	unsigned int size;
	unsigned int newslot;
	unsigned int i, count;
	unsigned int next;

	bpt = (struct bplustree *)h;
	page = bpt->page;
	max = page->count;
	newslot = slot;
	size = (max+1) * sizeof(struct bpt_slot) + sizeof(*page) + len + 1;
	
	/* There is enough space for the key and its slot, just return */
	if (page->min >= size) {
		return slot;
	}
	
	/* Skip cleanup if nothing to reclaim */
	if (!page->dirty) {
		return 0;
	}

	memcpy(bpt->frame, page, bpt->page_size);
	memset(page+1, 0, bpt->page_size - sizeof(*page));
	next = bpt->page_size;
	page->active = 0;

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
		memcpy(((unsigned char *)page) + next, key, key->len + 1);

		/* Copy slot */
		memcpy(slotptr(page, count)->page_no,
		       slotptr(bpt->frame, i)->page_no,
		       PAGE_NUM_BYTES);
		if (!(slotptr(page, count)->dead = slotptr(bpt->frame, i)->dead)) {
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

int bpt_splitroot(bpt_handle h, unsigned char *leftkey,
		  bpt_pageno_t page_no2)
{
	struct bplustree *bpt;
	struct bpt_page *root;
	bpt_pageno_t right;
	unsigned int next;

	bpt = (struct bplustree *)h;
	root = bpt->page;
	next = bpt->page_size;

	/* Make a copy of current root page */
	if (!(right = bpt_newpage(bpt, root))) {
		goto out;
	}

	memset(root+1, 0, bpt->page_size - sizeof(*root));

	/* Insert first key on new root page and link old root
	 * page as left child
	 */
	next -= leftkey[0] + 1;
	memcpy(((unsigned char *)root) + next, leftkey, leftkey[0] + 1);
	bpt_putpageno(slotptr(root, 1)->page_no, right);
	slotptr(root, 1)->offset = next;

	/* Insert stopper key and link new page as right child */
	next -= 3;
	((unsigned char *)root)[next] = 2;
	((unsigned char *)root)[next+1] = 0xFF;
	((unsigned char *)root)[next+2] = 0xFF;
	bpt_putpageno(slotptr(root, 2)->page_no, page_no2);
	slotptr(root, 2)->offset = next;

	bpt_putpageno(root->right, 0);
	root->min = next;
	root->count = 2;
	root->active = 2;
	root->level++;

	/* Persist root page changes */
	if (bpt_updatepage(bpt, root, bpt->page_no)) {
		goto out;
	}

	LOG("root splitted, page_no2(%llx)\n", page_no2);

 out:
	return bpt->errno;
}

int bpt_splitpage(bpt_handle h)
{
	struct bplustree *bpt;
	struct bpt_page *page;
	struct bpt_key *key;
	unsigned int max;
	unsigned int count, i;
	unsigned int next;
	bpt_pageno_t page_no, right;
	bpt_level level;
	unsigned char fencekey[257];
	unsigned char rightkey[257];

	bpt = (struct bplustree *)h;
	page = bpt->page;
	page_no = bpt->page_no;
	level = page->level;

	/* Split higher half of keys to bpt->frame */
	memset(bpt->frame, 0, bpt->page_size);
	max = page->count;

	for (i = max/2 + 1, count = 0, next = bpt->page_size; i <= max; i++) {
		count++;
		key = keyptr(page, i);
		next -= (key->len + 1);
		/* Copy key */
		memcpy(((unsigned char *)bpt->frame) + next, key, key->len + 1);
		/* Copy slot */
		memcpy(slotptr(bpt->frame, count)->page_no,
		       slotptr(page, i)->page_no,
		       PAGE_NUM_BYTES);
		if (!(slotptr(bpt->frame, count)->dead = slotptr(page, i)->dead)) {
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
	if (page_no > PAGE_ROOT) {
		memcpy(bpt->frame->right, page->right, PAGE_NUM_BYTES);
	}

	/* Allocate a new page and write frame to it */
	if (!(right = bpt_newpage(bpt, bpt->frame))) {
		goto out;
	}

	/* Update lower half in old page */
	memcpy(bpt->frame, page, bpt->page_size);
	memset(page+1, 0, bpt->page_size - sizeof(*page));
	page->dirty = 0;
	page->active = 0;

	for (i = 1, count = 0, next = bpt->page_size; i <= max/2; i++) {
		count++;
		key = keyptr(bpt->frame, i);
		next -= (key->len + 1);
		/* Copy key */
		memcpy((unsigned char *)page + next, key, key->len + 1);
		/* Copy slot */
		memcpy(slotptr(page, count)->page_no,
		       slotptr(bpt->frame, i)->page_no,
		       PAGE_NUM_BYTES);
		slotptr(page, count)->offset = next;
		page->active++;
	}

	/* Remember fence key for old page */
	memcpy(fencekey, key, key->len + 1);

	bpt_putpageno(page->right, right);
	page->min = next;
	page->count = count;

	/* If current page is root page, split it */
	if (page_no == PAGE_ROOT) {
		bpt_splitroot(bpt, fencekey, right);
		goto out;
	}

	/* Persist left node */
	if (bpt_updatepage(bpt, page, page_no)) {
		goto out;
	}

	/* Insert new fence for left half */
	if (bpt_insertkey(bpt, &fencekey[1], fencekey[0], level+1, page_no)) {
		goto out;
	}

	/* Update fence for right half to new page */
	if (bpt_insertkey(bpt, &rightkey[1], rightkey[0], level+1, right)) {
		goto out;
	}

	LOG("page(%llx) splitted, new sibling(%llx)\n", page_no, right);

 out:
	return bpt->errno;
}

int bpt_insertkey(bpt_handle h, unsigned char *key,
		  unsigned int len, bpt_level level,
		  bpt_pageno_t page_no)
{
	struct bplustree *bpt;
	struct bpt_key *ptr;
	struct bpt_page *page;
	unsigned int slot;
	unsigned int i;

	bpt = (struct bplustree *)h;

	while (1) {
		slot = bpt_loadpage(bpt, key, len, level);
		if (slot) {
			ptr = keyptr(bpt->page, slot);
		} else {
			LOG("failed to load page, level(%d), page_no(%llx)\n",
			    level, page_no);
			if (bpt->errno == 0) {
				bpt->errno = -1;
			}
			goto out;
		}

		/* If key already exists, update page number
		 * and return.
		 */
		page = bpt->page;

		if (keycmp(ptr, key, len) == 0) {
			if (slotptr(page, slot)->dead) {
				page->active++;
			}
			slotptr(page, slot)->dead = 0;
			bpt_putpageno(slotptr(page, slot)->page_no, page_no);
			if (bpt_updatepage(bpt, bpt->page, bpt->page_no)) {
				goto out;
			}
			LOG("key updated, level(%d)\n", level);
			bpt->errno = 0;
			goto out;
		}

		/* Check whether page has enough space to reclaim */
		slot = bpt_cleanpage(bpt, len, slot);
		if (slot) {
			break;
		}

		/* Not enough space for the key, do page split */
		if (bpt_splitpage(bpt)) {
			goto out;
		}
	}

	/* First copy the key into the page */
	page->min -= (len + 1);
	((unsigned char *)page)[page->min] = len;
	memcpy((unsigned char *)page + page->min + 1, key, len);

	/* Then insert new entry into the slot array */
	for (i = slot; i < page->count; i++) {
		if (slotptr(page, i)->dead) {
			break;
		}
	}

	if (i == page->count) {
		i++;
		page->count++;	// No dead slot can be reused
	}

	page->active++;

	for ( ; i > slot; i--) {
		*slotptr(page, i) = *slotptr(page, i - 1);
	}

	bpt_putpageno(slotptr(page, slot)->page_no, page_no);
	slotptr(page, slot)->offset = page->min;
	slotptr(page, slot)->dead = 0;

	if (bpt_updatepage(bpt, bpt->page, bpt->page_no)) {
		goto out;
	}

 out:
	return bpt->errno;
}

bpt_pageno_t bpt_findkey(bpt_handle h, unsigned char *key, unsigned int len)
{
	unsigned int slot;
	struct bplustree *bpt;
	struct bpt_key *ptr;
	bpt_pageno_t page_no;

	bpt = (struct bplustree *)h;
	page_no = 0;

	slot = bpt_loadpage(bpt, key, len, 0);
	if (slot) {
		/* If key exists return page number, otherwise return 0. */
		ptr = keyptr(bpt->page, slot);
		if (ptr->len == len && !memcmp(ptr->key, key, len)) {
			page_no = bpt_getpageno(slotptr(bpt->page, slot)->page_no);
		}
	}

	return page_no;
}

int bpt_fixfence(bpt_handle h, bpt_pageno_t page_no, bpt_level level)
{
	struct bplustree *bpt;
	struct bpt_key *ptr;
	unsigned char leftkey[257];
	unsigned char rightkey[257];

	bpt = (struct bplustree *)h;

	ptr = keyptr(bpt->page, bpt->page->count);
	memcpy(rightkey, ptr, ptr->len + 1);

	memset(slotptr(bpt->page, bpt->page->count), 0,
	       sizeof(struct bpt_slot));
	bpt->page->count--;
	bpt->page->dirty = 1;

	ptr = keyptr(bpt->page, bpt->page->count);
	memcpy(leftkey, ptr, ptr->len + 1);

	if (bpt_updatepage(bpt, bpt->page, page_no)) {
		goto out;
	}

	if (bpt_insertkey(bpt, &leftkey[1], leftkey[0], level+1, page_no)) {
		goto out;
	}

	if (bpt_deletekey(bpt, &rightkey[1], rightkey[0], level+1)) {
		goto out;
	}

 out:
	return bpt->errno;
}

int bpt_collapseroot(bpt_handle h, struct bpt_page *root)
{
	struct bplustree *bpt;
	bpt_pageno_t child;
	unsigned int i;

	bpt = (struct bplustree *)h;

	/* Find child entry and promote to new root */
	do {
		for (i = 1; i <= root->count; i++) {
			if (!slotptr(root, i)->dead) {
				break;
			}
		}

		child = bpt_getpageno(slotptr(root, i)->page_no);
		if (bpt_mappage(bpt, bpt->temp, child)) {
			goto out;
		}

		memcpy(root, bpt->temp, bpt->page_size);

		if (bpt_updatepage(bpt, root, PAGE_ROOT)) {
			goto out;
		}

		if (bpt_freepage(bpt, child)) {
			goto out;
		}
	} while ((root->level > 1) && (root->active == 1));

	LOG("root collapsed, child(%llx) freed\n", child);

 out:
	return bpt->errno;
}

int bpt_deletekey(bpt_handle h, unsigned char *key,
		  unsigned int len, bpt_level level)
{
	struct bplustree *bpt;
	struct bpt_key *ptr;
	unsigned int slot;
	unsigned int i;
	bpt_pageno_t right, page_no;
	boolean_t fence, found, dirty;
	unsigned char lowerkey[257];
	unsigned char higherkey[257];

	bpt = (struct bplustree *)h;

	slot = bpt_loadpage(bpt, key, len, level);
	if (slot) {
		ptr = keyptr(bpt->page, slot);
	} else {
		goto out;
	}

	fence = (slot == bpt->page->count);

	found = (keycmp(ptr, key, len) == 0);
	if (found) {
		found = !slotptr(bpt->page, slot)->dead;
		if (found) {
			dirty = slotptr(bpt->page, slot)->dead = 1;
			bpt->page->dirty = 1;
			bpt->page->active--;

			if (!fence) {
				for (i = slot; i < bpt->page->count; i++) {
					*slotptr(bpt->page, i) =
						*slotptr(bpt->page, i+1);
				}
				bpt->page->count--;
				memset(slotptr(bpt->page, i), 0,
				       sizeof(struct bpt_slot));
			}
		}
	}

	right = bpt_getpageno(bpt->page->right);
	page_no = bpt->page_no;

	/* Did we delete a fence key in an upper level? */
	if (dirty && level && bpt->page->active && fence) {
		if (bpt_fixfence(bpt, page_no, level)) {
			goto out;
		}
		bpt->errno = 0;
		goto out;
	}

	/* Is this a collapsed root? */
	if ((level > 1) &&
	    (page_no == PAGE_ROOT) &&
	    (bpt->page->active == 1)) {
		if (bpt_collapseroot(bpt, bpt->page)) {
			goto out;
		}
		bpt->errno = 0;
		goto out;
	}

	/* Return if page is not empty */
	if (bpt->page->active) {
		if (dirty && bpt_updatepage(bpt, bpt->page, page_no)) {
			goto out;
		}
		bpt->errno = 0;
		goto out;
	}

	/* Cache a copy of fence key in order to find parent */
	ptr = keyptr(bpt->page, bpt->page->count);
	memcpy(lowerkey, ptr, ptr->len + 1);

	/* Pull contents of next page into current empty page */
	if (bpt_mappage(bpt, bpt->temp, right)) {
		goto out;
	}
	if (bpt->temp->kill) {
		LOG("page(%llx) killed\n", right);
		bpt->errno = -1;
		goto out;
	}
	memcpy(bpt->page, bpt->temp, bpt->page_size);

	ptr = keyptr(bpt->temp, bpt->temp->count);
	memcpy(higherkey, ptr, ptr->len + 1);

	/* Mark right page as deleted */
	bpt_putpageno(bpt->temp->right, page_no);
	bpt->temp->kill = 1;

	/* Persist current page and right page */
	if (bpt_updatepage(bpt, bpt->page, page_no)) {
		goto out;
	}
	if (bpt_updatepage(bpt, bpt->temp, right)) {
		goto out;
	}

	/* Insert new higher key to upper level */
	if (bpt_insertkey(bpt, &higherkey[1], higherkey[0], level+1, page_no)) {
		goto out;
	}

	/* Delete old lower key from upper level */
	if (bpt_deletekey(bpt, &lowerkey[1], lowerkey[0], level+1)) {
		goto out;
	}

	/* Free right page since it was moved to current page */
	if (bpt_freepage(bpt, right)) {
		goto out;
	}

 out:
	return bpt->errno;
}

struct bpt_key *bpt_key(bpt_handle h, unsigned int slot)
{
	struct bplustree *bpt;
	
	bpt = (struct bplustree *)h;
	
	return keyptr(bpt->cursor, slot);
}

unsigned int bpt_firstkey(bpt_handle h, unsigned char *key, unsigned int len)
{
	struct bplustree *bpt;
	unsigned int slot;

	bpt = (struct bplustree *)h;
	
	slot = bpt_loadpage(bpt, key, len, 0);
	if (slot) {
		memcpy(bpt->cursor, bpt->page, bpt->page_size);
	} else {
		return 0;
	}

	bpt->cursor_page = bpt->page_no;

	return slot;
}

unsigned int bpt_nextkey(bpt_handle h, unsigned int slot)
{
	struct bplustree *bpt;
	bpt_pageno_t right;

	bpt = (struct bplustree *)h;
	
	do {
		right = bpt_getpageno(bpt->cursor->right);
		
		for ( slot = slot+1; slot <= bpt->cursor->count; slot++) {
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
		if (bpt_mappage(bpt, bpt->page, right)) {
			return 0;
		}

		memcpy(bpt->cursor, bpt->page, bpt->page_size);

		slot = 0;
	} while (1);

	bpt->errno = 0;
	return 0;
}

void bpt_getiostat(bpt_handle h, struct bpt_iostat *iostat)
{
	struct bplustree *bpt;

	bpt = (struct bplustree *)h;
	*iostat = bpt->iostat;
}

#ifdef _UNITTEST

void dump_key(unsigned char *key, unsigned int len)
{
	unsigned int i;

	for (i = 0; i < len; i++) {
		printf("%c", key[i]);
	}
	printf(" ");
}

void dump_keys_in_page(struct bpt_page *page)
{
	int i;
	struct bpt_key *k;
	unsigned char stopper[] = {0xFF, 0xFF};
	
	for (i = 1; i <= page->count; i++) {
		if (slotptr(page, i)->dead) {
			continue;
		}
		k = keyptr(page, i);
		if (keycmp(k, stopper, sizeof(stopper)) == 0) {
			printf(";");
			continue;
		}
		
		dump_key(k->key, k->len);
	}
}

void dump_page(struct bpt_page *page)
{
	printf("---------- bplustree page info -----------\n");
	printf(" count  : %d\n", page->count);
	printf(" active : %d\n", page->active);
	printf(" level  : %d\n", page->level);
	printf(" min    : %d\n", page->min);
	printf(" right  : %llx\n", bpt_getpageno(page->right));
	printf(" keys   : ");
	dump_keys_in_page(page);
	printf("\n");
	printf("------------------------------------------\n");
}

int main(int argc, char *argv[])
{
	int rc = 0;
	bpt_handle h = NULL;
	struct bplustree *bpt = NULL;
	struct bpt_key *k = NULL;
	char *key1 = "test1";
	char *key2 = "test2";
	char *key3 = "test3";
	unsigned int key1_len = strlen(key1);
	unsigned int key2_len = strlen(key2);
	unsigned int key3_len = strlen(key3);
	bpt_pageno_t page_no = PAGE_ROOT;
	int i;
	char key[5];
	unsigned int key_len = sizeof(key) - 1;
	int ret = 0;
	unsigned int slot;

	h = bpt_open("bpt.dat", 9);
	if (h == NULL) {
		fprintf(stderr, "Failed to open bplustree!\n");
		goto out;
	}

	bpt = (struct bplustree *)h;
	
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

	page_no = PAGE_ROOT + 1;
	rc = bpt_mappage(bpt, bpt->temp, page_no);
	if (rc != 0) {
		fprintf(stderr, "Failed to map page 0x%llx\n", page_no);
		goto out;
	}

	dump_page(bpt->temp);

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

	page_no = bpt_findkey(bpt, (unsigned char *)key2, key2_len);
	if (page_no != 0) {
		fprintf(stderr, "Deleted key found: %s->0x%llx\n", key2, page_no);
		goto out;
	}

	rc = bpt_deletekey(bpt, (unsigned char *)key3, key3_len, 0);
	if (rc != 0) {
		fprintf(stderr, "Failed to delete key: %s\n", key3);
		goto out;
	}

	page_no = bpt_findkey(bpt, (unsigned char *)key3, key3_len);
	if (page_no != 0) {
		fprintf(stderr, "Deleted key found: %s->0x%llx\n", key3, page_no);
		goto out;
	}

	printf("Current page:\n");
	dump_page(bpt->page);

	for (i = 10; i < 64; i++) {
		ret = sprintf(key, "%04d", i);
		assert(ret == key_len);
		rc = bpt_insertkey(bpt, (unsigned char *)key, key_len, 0, i);
		if (rc != 0) {
			fprintf(stderr, "Failed to insert key: %s\n", key);
			goto out;
		}
	}

	ret = sprintf(key, "%04d", 36);
	assert(ret == key_len);
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

	i = 0;
	do {
		k = bpt_key(bpt, slot);
		dump_key(k->key, k->len);
		
		if (++i > 20) {
			printf("\n");
			break;
		}
		slot = bpt_nextkey(bpt, slot);
	} while(slot);

	for (i = 63; i >= 10; i--) {
		ret = sprintf(key, "%04d", i);
		assert(ret == key_len);
		rc = bpt_deletekey(bpt, (unsigned char *)key, key_len, 0);
		if (rc != 0) {
			fprintf(stderr, "Failed to delete key: %s\n", key);
			goto out;
		}
	}
	
 out:
	if (h) {
		bpt_close(h);
	}
	return rc;
}

#endif	/* _UNITTEST */
