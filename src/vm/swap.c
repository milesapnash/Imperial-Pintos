#include <stdio.h>
#include <bitmap.h>
#include "swap.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "threads/malloc.h"
#include "devices/block.h"

#define PAGE_SECTORS (PGSIZE / BLOCK_SECTOR_SIZE)

static void swap_page_free(struct hash_elem *, void *UNUSED);
static unsigned swap_page_hash(const struct hash_elem *, void *UNUSED);
static bool swap_page_less(const struct hash_elem *, const struct hash_elem *, void *UNUSED);

/* Stores information relating to swap table. */
struct swap_table
{
    struct hash table;          /* Hash of swap_page virtual adresses. */
    struct lock lock;           /* Lock to ensure thread-safe access of table. */
    struct block *swap_space;   /* Disk block for swap space. */
    struct bitmap *taken_slots; /* Records slots of swap space currently taken by pages. */
};

/* Global swap table. */
static struct swap_table swap_t;

/* Initialises swap table. */
void swap_table_init(void)
{
    hash_init(&swap_t.table, swap_page_hash, swap_page_less, NULL);
    lock_init(&swap_t.lock);
    swap_t.swap_space = block_get_role(BLOCK_SWAP);
    size_t slots = block_size(swap_t.swap_space) / PAGE_SECTORS;
    swap_t.taken_slots = bitmap_create(slots);
}

/* Hashes swap_page to be added into swap table. */
static unsigned
swap_page_hash(const struct hash_elem *e, void *aux UNUSED)
{
    struct swap_page *page = hash_entry(e, struct swap_page, hash_elem);
    return hash_bytes(&page->v_address, sizeof(page->v_address));
}

/* Compares virtual address of two swap_pages. */
static bool
swap_page_less(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED)
{
    struct swap_page *pa = hash_entry(a, struct swap_page, hash_elem);
    struct swap_page *pb = hash_entry(b, struct swap_page, hash_elem);
    return pa->v_address < pb->v_address;
}

/* Frees resources allocated to swap table. */
void swap_table_destroy(void)
{
    hash_destroy(&swap_t.table, &swap_page_free);
    bitmap_destroy(swap_t.taken_slots);
}

/* Frees resources allocated to swap page. */
static void
swap_page_free(struct hash_elem *e, void *aux UNUSED)
{
    struct swap_page *sp = hash_entry(e, struct swap_page, hash_elem);
    bitmap_reset(swap_t.taken_slots, sp->index);
    free(sp);
}

/* Stores frame at k_address into swap space.
   RAM -> SWAP SPACE */
void swap_store(void *p_address, void *k_address)
{
    struct swap_page *new_page = malloc(sizeof(struct swap_page));
    if (new_page == NULL)
    {
        PANIC("UNABLE TO ALLOCATE MEMORY FOR SWAP SLOT");
    }

    lock_acquire(&swap_t.lock);

    size_t new_index = bitmap_scan_and_flip(swap_t.taken_slots, 0, 1, false);
    if (new_index == BITMAP_ERROR)
    {
        PANIC("SWAP SPACE FULL");
    }

    new_page->index = new_index;
    new_page->v_address = p_address;

    struct hash_elem *equal_elements = hash_insert(&swap_t.table, &new_page->hash_elem);
    if (equal_elements)
    {
        PANIC("THIS PAGE IS ALREADY IN SWAP SPACE");
    }

    for (int i = 0; i < PAGE_SECTORS; i++)
    {
        block_write(swap_t.swap_space, (new_index * PAGE_SECTORS) + i, k_address + (BLOCK_SECTOR_SIZE * i));
    }

    lock_release(&swap_t.lock);
}

/* Loads swap block of p_address from swap space into k_address.
   SWAP SPACE -> RAM */
void swap_load(void *p_address, void *k_address)
{
    struct swap_page remove_page;
    remove_page.v_address = p_address;

    lock_acquire(&swap_t.lock);

    struct hash_elem *page_found = hash_find(&swap_t.table, &remove_page.hash_elem);
    if (page_found == NULL)
    {
        PANIC("PAGE NOT IN SWAP SPACE");
    }

    size_t index = hash_entry(page_found, struct swap_page, hash_elem)->index;

    if (!bitmap_test(swap_t.taken_slots, index))
    {
        PANIC("NO PAGE AT INDEX");
    }

    bitmap_reset(swap_t.taken_slots, index);
    hash_delete(&swap_t.table, page_found);

    for (int i = 0; i < PAGE_SECTORS; i++)
    {
        block_read(swap_t.swap_space, (index * PAGE_SECTORS) + i, k_address + (BLOCK_SECTOR_SIZE * i));
    }

    lock_release(&swap_t.lock);
}

/* Frees page in swap space of p_address. */
void swap_free(void *p_address)
{
    struct swap_page remove_page;
    remove_page.v_address = p_address;

    lock_acquire(&swap_t.lock);

    struct hash_elem *remove_e = hash_delete(&swap_t.table, &remove_page.hash_elem);
    if (!remove_e)
    {
        PANIC("THIS PAGE IS NOT IN SWAP SPACE");
    }

    swap_page_free(remove_e, NULL);

    lock_release(&swap_t.lock);
}
