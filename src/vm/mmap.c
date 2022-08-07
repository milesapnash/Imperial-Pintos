#include <stdio.h>
#include "mmap.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "userprog/syscall.h"
#include "frame.h"

static void free_map_elem(struct hash_elem *, void *UNUSED);
static unsigned mapping_hash(const struct hash_elem *, void *UNUSED);
static bool mapping_less(const struct hash_elem *, const struct hash_elem *, void *UNUSED);

/* Initialises given mmap table. */
void mmap_table_init(struct hash *mmap_table)
{
  hash_init(mmap_table, mapping_hash, mapping_less, NULL);
}

/* Frees resources allocated to given mmap table. */
void mmap_table_destroy(struct hash *mmap_table)
{
  hash_destroy(mmap_table, &free_map_elem);
}

/* Unmaps each mapping in a threads mmap table. */
static void
free_map_elem(struct hash_elem *e, void *aux UNUSED)
{
  struct mapping *m = hash_entry(e, struct mapping, hash_elem);
  munmap(m->mapid);
}

/* Adds new mapping to given mmap table. */
void mmap_table_add_mapping(struct hash *mmap_table, mapid_t id, void *start_addr, void *end_addr, struct file *f)
{
  struct mapping *new_mapping = malloc(sizeof(struct mapping));
  if (new_mapping == NULL)
  {
    PANIC("Memory allocation for mapping failed");
  }

  new_mapping->mapid = id;
  new_mapping->start_addr = start_addr;
  new_mapping->end_addr = end_addr;
  new_mapping->file = f;

  hash_insert(mmap_table, &new_mapping->hash_elem);
}

/* Removes mapping from given mmap table and frees allocated resources. */
void mmap_remove_mapping(struct hash *mmap_table, struct mapping *m)
{
  void *page_addr = m->start_addr;
  while (page_addr <= m->end_addr)
  {
    check_dirty_mmap(pagedir_get_page(thread_current()->pagedir, page_addr));

    sp_table_remove_page(page_addr);
    page_addr += PGSIZE;
  }

  if (hash_delete(mmap_table, &m->hash_elem))
  {
    free(m);
  }
}

/* Returns mapping corresponding to given mapid. */
struct mapping *
mmap_table_get_mapping(struct hash *mmap_table, mapid_t id)
{
  struct mapping this;
  this.mapid = id;
  struct hash_elem *found_elem = hash_find(mmap_table, &this.hash_elem);
  if (found_elem)
  {
    return hash_entry(found_elem, struct mapping, hash_elem);
  }
  return NULL;
}

/* Checks if there are any pages mapped in the interval a mapping
   is seeking to use. */
bool pages_mapped_between(void *start, void *end)
{
  while (start <= end)
  {
    struct page *p = sp_table_get_page(&current_process_record()->sp_table, start);
    if (p)
    {
      return true;
    }
    start += PGSIZE;
  }
  return false;
}

/* Hashes mapping to be added into mmap table. */
static unsigned
mapping_hash(const struct hash_elem *e, void *aux UNUSED)
{
  struct mapping *mmap = hash_entry(e, struct mapping, hash_elem);
  return (unsigned)mmap->mapid;
}

/* Compares mapids of two mappings. */
static bool
mapping_less(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED)
{
  struct mapping *ma = hash_entry(a, struct mapping, hash_elem);
  struct mapping *mb = hash_entry(b, struct mapping, hash_elem);
  return ma->mapid < mb->mapid;
}