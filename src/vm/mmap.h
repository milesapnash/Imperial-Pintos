#ifndef VM_MMAP_H
#define VM_MMAP_H

#include "lib/kernel/hash.h"
#include "filesys/file.h"

typedef int mapid_t;

/* Records each mapping made by a thread */
struct mapping
{
    mapid_t mapid;              /* Mapid attributed to this mapping. */
    struct file *file;          /* File opened by mapping. */
    void *start_addr;           /* Start virtual address of the file. */
    void *end_addr;             /* End virtual address of the file. */
    struct hash_elem hash_elem; /* Hash element for mmap table. */
};

void mmap_table_init(struct hash *);
void mmap_table_destroy(struct hash *);

void mmap_table_add_mapping(struct hash *, mapid_t, void *, void *, struct file *);
void mmap_remove_mapping(struct hash *, struct mapping *);
struct mapping *mmap_table_get_mapping(struct hash *, mapid_t);

bool pages_mapped_between(void *, void *);

#endif /* vm/mmap.h */