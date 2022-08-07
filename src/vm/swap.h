#ifndef VM_SWAP_H
#define VM_SWAP_H

#include "lib/kernel/hash.h"

/* Records the pages allocated to slots of the swap space */
struct swap_page
{
    void *v_address;            /* Virtual address of page. */
    struct hash_elem hash_elem; /* To add these to hash table. */
    size_t index;               /* Index of the slot this page occupies. */
};

void swap_table_init(void);
void swap_table_destroy(void);

void swap_store(void *, void *);
void swap_load(void *, void *);
void swap_free(void *);

#endif /* vm/swap.h */