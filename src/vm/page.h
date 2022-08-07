#ifndef VM_PAGE_H
#define VM_PAGE_H

#include "lib/kernel/hash.h"
#include "threads/synch.h"
#include "filesys/off_t.h"

/* The various states a page can be*/
enum page_status
{
    EXEC,
    MMAP,
    SWAP,
    STACK,
    EMPTY
};

/* Page in the supplementary page table */
struct page
{
    void *virtual_address;      /* Address of page */
    struct hash_elem hash_elem; /* Used to add page to supplemental page table */
    enum page_status status;    /* Status of this page */

    struct metadata *metadata; /* Metadata about cursor for lazy loading */

    struct list_elem shared_frame; /* List elem for adding pages to shared page list in frame structure */
};

/* Data exclusively for executables */
struct metadata
{
    bool writable;          /* Flag that states if executable is writable or read only */
    off_t cursor;           /* Current position of the cursor in the file */
    size_t page_read_bytes; /* Stores number of bytes to read from file */
    struct file *file;      /* Pointer to file that is to be loaded */
};

/* Public function signatures */
void sp_table_init(struct hash *);
void sp_table_destroy(struct hash *);
void sp_table_add_page(void *, struct metadata *, enum page_status);
void sp_table_remove_page(void *);
struct page *sp_table_get_page(struct hash *, void *);
void sp_table_update_status(struct hash *, void *, enum page_status);

struct metadata *create_metadata(bool, off_t, size_t, struct file *);

#endif /* vm/page.h */
