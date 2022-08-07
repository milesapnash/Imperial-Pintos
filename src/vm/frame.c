#include "frame.h"
#include "swap.h"
#include "page.h"
#include "userprog/syscall.h"
#include "userprog/pagedir.h"

/* Hash maps of frame elements */
static struct hash frame_table;

/* List of frames ordered by last use for eviction */
static struct list last_used;

/* Private frame funcitons */

struct frame *frame_lookup_by_frameptr(void *);
static void frame_evict(struct frame *);
static struct frame *frame_select_eviction(void);
static unsigned frame_hash(const struct hash_elem *, void *);
static void frame_free(struct frame *);
static bool frame_less(const struct hash_elem *, const struct hash_elem *, void *);
static void write_dirty_mmap(struct frame *f, struct page *p);
static void destructor(struct hash_elem *, void *);

/* ------- Public Functions ------- */

/* Initialises hash table and lock */
void frame_table_init(void)
{
    hash_init(&frame_table, frame_hash, frame_less, NULL);
    lock_init(&frame_lock);
    list_init(&last_used);
}

/* Returns the kernel page that the user page is mapped to. If no such
   frame exists, implements eviction policy to get a new frame */
void *frame_alloc(enum palloc_flags flags, void *user_pointer)
{
    lock_acquire(&frame_lock);
    void *kvaddr = palloc_get_page(flags);
    struct frame *f;
    if (kvaddr == NULL)
    {
        /* No frames available, so eviction policy is implemented*/
        f = frame_select_eviction();
        if (f == NULL)
        {
            frame_table_destroy();
            PANIC("Eviction unsuccessfull");
        }
        frame_evict(f);
    }
    else
    {
        /* Create new frame and add into frame table */
        f = malloc(sizeof(struct frame));
        f->frame_addr = kvaddr;
        hash_insert(&frame_table, &f->hash_elem);
    }

    f->page_addr = user_pointer;
    f->t = thread_current();
    list_init(&f->pages); /* initialising the list of shared pages */

    list_push_front(&last_used, &f->list_elem);

    lock_release(&frame_lock);
    return f->frame_addr;
}

/* given a kernel address from a frame, and a page pushes the page onto the list of shared pages */
void frame_push_page(void *kaddr, struct page *p)
{
    struct frame *f = frame_lookup_by_frameptr(kaddr);
    if (f)
        list_push_back(&f->pages, &p->shared_frame);
    else
        PANIC("could not find a frame for given address [%p]", kaddr);
}

/* given a page, tries to find a frame that shares similar pages */
struct frame *frame_find_from_page(struct page *p)
{
    /* it is only possible for read only pages to be shared */
    ASSERT(!p->metadata->writable);
    struct hash_iterator it;
    lock_acquire(&frame_lock);
    hash_first(&it, &frame_table);
    while (hash_next(&it))
    {
        struct frame *f = hash_entry(hash_cur(&it), struct frame, hash_elem);
        if (!list_empty(&f->pages))
        {
            /* look at the first page and decide whether the pages that already share the frame
                match the data that you're trying to find */
            struct metadata *shared_metadata = list_entry(list_begin(&f->pages), struct page, shared_frame)->metadata;
            struct metadata *lookup_metadata = p->metadata;
            bool match = true;
            match &= (shared_metadata->cursor == lookup_metadata->cursor);
            match &= (shared_metadata->page_read_bytes == lookup_metadata->page_read_bytes);
            match &= (shared_metadata->file == lookup_metadata->file);

            if (match)
                return f;
        }
    }
    lock_release(&frame_lock);
    return NULL;
}

/* Frees the frame, and removes from the hash table */
void frame_free(struct frame *frame)
{
    lock_acquire(&frame_lock);
    struct hash_elem *elem = hash_find(&frame_table, &frame->hash_elem);
    if (elem != NULL)
    {
        /* delete the frame from the hash table */
        hash_delete(&frame_table, &frame->hash_elem);
        /* free the frame */
        palloc_free_page(frame->frame_addr);
        /* removes from list of last used */
        list_remove(&frame->list_elem);
        /* free the frame structure */
        free(frame);
    }
    lock_release(&frame_lock);
}

/* Frees a frame by frame_pointer */
void free_kernel_page(void *frame_pointer)
{
    struct frame *f = frame_lookup_by_frameptr(frame_pointer);
    if (f)
        frame_free(f);
}

/* Destroys the contents of the hash table */
void frame_table_destroy()
{
    /* For each frame that is still in the hash map: free */
    hash_destroy(&frame_table, &destructor);
}

void check_dirty_mmap(void *f_addr)
{
    struct frame this;
    this.frame_addr = f_addr;
    struct hash_elem *e = hash_find(&frame_table, &this.hash_elem);
    if (e)
    {
        struct frame *found_this = hash_entry(e, struct frame, hash_elem);
        struct page *p = sp_table_get_page(&found_this->t->process->sp_table, found_this->page_addr);
        write_dirty_mmap(found_this, p);
    }
}

/* Iterate over the hash and return the first frame that matches the kernel virtual
    address frame_ptr. Otherwise return NULL */
struct frame *frame_lookup_by_frameptr(void *frame_ptr)
{
    struct frame this;
    this.frame_addr = frame_ptr;

    lock_acquire(&frame_lock);
    struct hash_elem *match = hash_find(&frame_table, &this.hash_elem);

    if (match)
    {
        struct frame *return_frame = hash_entry(match, struct frame, hash_elem);
        lock_release(&frame_lock);
        return return_frame;
    }

    lock_release(&frame_lock);
    return NULL;
}

/* ------- Helper Functions ------- */

/* ------- Frame eviction ------- */

static struct frame *
frame_select_eviction()
{
    if (!list_empty(&last_used))
    {
        return list_entry(list_pop_back(&last_used), struct frame, list_elem);
    }
    return NULL;
}

/* Tries to evict a frame from the table and if successful, removes it
    from the frame_table, otherwise returns null */
static void
frame_evict(struct frame *f)
{
    /* no pages to evict */
    if (list_empty(&f->pages))
        return;

    struct page *p = list_entry(list_pop_front(&f->pages), struct page, shared_frame);

    switch (p->status)
    {
    case MMAP:
        write_dirty_mmap(f, p);
        break;
    case STACK:
    case EXEC:
        swap_store(f->page_addr, f->frame_addr);
        pagedir_clear_page(f->t->pagedir, f->page_addr);

        /* set each page's status to SWAP */
        p->status = SWAP;
        for (struct list_elem *e = list_begin(&f->pages); e != list_end(&f->pages); e = list_remove(e))
            list_entry(e, struct page, shared_frame)->status = SWAP;

        break;
    default: /* SWAP, EMPTY */
        PANIC("INVALID PAGE STATUS");
    }
}

static void
write_dirty_mmap(struct frame *f, struct page *p)
{
    if (pagedir_is_dirty(f->t->pagedir, f->page_addr))
    {
        lock_acquire(&lock_filesys);
        file_seek(p->metadata->file, p->metadata->cursor);
        file_write(p->metadata->file, f->frame_addr, p->metadata->page_read_bytes);
        lock_release(&lock_filesys);
    }
    pagedir_clear_page(f->t->pagedir, f->page_addr);
}

/* ------- Hashing functions ------- */

/* Returns hash value corresponding to frame address */
static unsigned frame_hash(const struct hash_elem *e, void *aux UNUSED)
{
    const struct frame *frame = hash_entry(e, struct frame, hash_elem);
    return hash_bytes(&frame->frame_addr, sizeof frame->frame_addr);
}

/* Returns if frame of elem a comes before frame of elem b */
static bool frame_less(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED)
{
    struct frame *fa = hash_entry(a, struct frame, hash_elem);
    struct frame *fb = hash_entry(b, struct frame, hash_elem);
    return fa->frame_addr < fb->frame_addr;
}

/* hash_action_func to be used in frame_table_destory */
static void destructor(struct hash_elem *e, void *aux UNUSED)
{
    frame_free(hash_entry(e, struct frame, hash_elem));
}