#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <stdio.h>
#include "lib/kernel/hash.h"
#include "threads/synch.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "userprog/process.h"

/* Frame size is the same as page size in order to not lose any information
  about the page when it is loaded to and from main memory. */
#define FRAME_SIZE PGSIZE

/*
    The frame table contains one entry for each frame that contains a user page.
    Each entry in the frame table contains a pointer to the page, if any, that
    currently occupies it.
 */
struct frame
{
  void *frame_addr;           /* The kernel address of the frame */
  void *page_addr;            /* The virtual address of the page */
  struct hash_elem hash_elem; /* To add frame to frame_table */

  // sharing
  struct list pages; /* A list of the pages that share this frame. */

  // eviction
  struct thread *t;           /* Thread of process that owns frame */
  struct list_elem list_elem; /* To add frame to last_used */
};

/* Lock for frame_table */
struct lock frame_lock;

/* Initialiser */
void frame_table_init(void);

/* Table operations */
void *frame_alloc(enum palloc_flags, void *);

/* Memory operations */
void free_kernel_page(void *);
void frame_table_destroy(void);

void check_dirty_mmap(void *);
struct frame *frame_find_from_page(struct page *);
void frame_push_page(void *, struct page *);
struct frame *frame_lookup_by_frameptr(void *);

#endif /* vm/frame.h */