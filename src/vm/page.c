#include <stdio.h>
#include "page.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "userprog/process.h"

/* Private static function signatures */
static unsigned page_hash(const struct hash_elem *, void *UNUSED);
static bool page_less(const struct hash_elem *, const struct hash_elem *, void *UNUSED);
static void sp_table_free_page(struct hash_elem *, void *UNUSED);

/* Initialises page and corresponding lock */
void sp_table_init(struct hash *sptable)
{
    hash_init(sptable, page_hash, page_less, NULL);
}

/* Frees memory allocated to supplementary page table and all remaining pages */
void sp_table_destroy(struct hash *sptable)
{
    hash_destroy(sptable, &sp_table_free_page);
}

/* Adds page into supplementary page table */
void sp_table_add_page(void *address, struct metadata *metadata, enum page_status pstatus)
{
    struct hash *sptable = &thread_current()->process->sp_table;
    struct page *new_page = malloc(sizeof(struct page));
    if (new_page == NULL)
    {
        PANIC("Memory allocation for page failed");
    }
    new_page->virtual_address = address;
    new_page->status = pstatus;
    new_page->metadata = metadata;

    hash_insert(sptable, &new_page->hash_elem);
}

/* Removes page from supplementary page table */
void sp_table_remove_page(void *address)
{
    struct hash *sptable = &thread_current()->process->sp_table;

    struct page this;
    this.virtual_address = address;

    struct hash_elem *this_delete = hash_delete(sptable, &this.hash_elem);
    sp_table_free_page(this_delete, NULL);
}

/* Given all of metadata's fields mallocs a metadata struct and returns its pointer */
struct metadata *create_metadata(bool writable, off_t cursor, size_t page_read_bytes, struct file *f)
{
    struct metadata *metadata = malloc(sizeof(struct metadata));

    if (!metadata)
        PANIC("create metadata, allocaiton failed");

    metadata->writable = writable;
    metadata->cursor = cursor;
    metadata->page_read_bytes = page_read_bytes;
    metadata->file = f;

    return metadata;
}

/* Given a pointer updates its status */
void sp_table_update_status(struct hash *sp_table, void *addr, enum page_status status)
{
    struct page *p = sp_table_get_page(sp_table, addr);
    if (p)
        p->status = status;
}

/* Frees memory allocated to an element of the supplmentary page table */
static void
sp_table_free_page(struct hash_elem *e, void *aux UNUSED)
{
    struct page *page_to_free = hash_entry(e, struct page, hash_elem);
    /* Free metadata */
    if (page_to_free)
        free(page_to_free->metadata);
    /* Free page */
    free(page_to_free);
}

/* Returns page at given address in given table, NULL if not found */
struct page *
sp_table_get_page(struct hash *sptable, void *address)
{

    struct page this;
    this.virtual_address = address;

    struct hash_elem *found_this = hash_find(sptable, &this.hash_elem);
    if (found_this)
    {
        return hash_entry(found_this, struct page, hash_elem);
    }
    return NULL;
}

/* Hashes page to be added into supplmentary page table */
static unsigned
page_hash(const struct hash_elem *e, void *aux UNUSED)
{
    struct page *page = hash_entry(e, struct page, hash_elem);
    return hash_bytes(&page->virtual_address, sizeof(page->virtual_address));
}

/* Compares virtual address of two pages */
static bool
page_less(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED)
{
    struct page *pa = hash_entry(a, struct page, hash_elem);
    struct page *pb = hash_entry(b, struct page, hash_elem);
    return pa->virtual_address < pb->virtual_address;
}
