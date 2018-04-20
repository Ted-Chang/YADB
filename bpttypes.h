#ifndef __BPTTYPES_H__
#define __BPTTYPES_H__

#ifndef TRUE
#define TRUE	1
#endif

#ifndef FALSE
#define FALSE	0
#endif

#ifndef BOOL
typedef unsigned char bool_t;
#endif	/* BOOL */

typedef void * bptree_t;
typedef unsigned char bpt_level_t;
typedef unsigned long long pageno_t;

#endif	/* __BPTTYPES_H__ */
