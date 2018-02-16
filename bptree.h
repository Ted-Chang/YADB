#ifndef __BPTREE_H__
#define __BPTREE_H__

#ifndef TRUE
#define TRUE	1
#endif

#ifndef FALSE
#define FALSE	0
#endif

typedef void * bpt_handle;
typedef unsigned char bpt_level;
typedef unsigned long long bpt_pageno_t;
typedef unsigned char boolean_t;

bpt_handle bpt_open(const char *name, unsigned int page_bits);
void bpt_close(bpt_handle h);
unsigned int bpt_firstkey(bpt_handle h, unsigned char *key, unsigned int len);
unsigned int bpt_nextkey(bpt_handle h, unsigned int slot);

#endif	/* __BPTREE_H__ */
