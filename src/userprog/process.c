#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "process.h"
#include "lib/kernel/list.h"
#ifdef VM
#include "vm/frame.h"
#include "vm/page.h"
#endif

static int arg_parsing(char *file, char **argv);
static void stack_push_all(struct intr_frame *if_, char **argv, int argc);

static thread_func start_process NO_RETURN;
static bool load(const char *cmdline, void (**eip)(void), void **esp);

struct process_record *get_process_record_child(struct thread *parent, tid_t child_tid);
static void process_record_init(struct thread *parent, tid_t tid);
void free_process_record(struct process_record *record);
void children_can_terminate(struct thread *parent);

/* Records details of loads */
struct process_load
{
  int argc;                    /* Number of arguments passed */
  char **argv;                 /* Array of arguments */
  char *file_name;             /* Name of file */
  bool load_success;           /* Flags if load was successful */
  struct semaphore check_load; /* Used to block parent until load finished */
};

/*-------------------PROCESS FUNCTIONS-------------------*/

/* Free the current process's resources. */
void process_exit(void)
{
  uint32_t *pd;
  struct thread *cur = thread_current();
  struct process_record *cur_record = cur->process;

  lock_acquire(&cur_record->free_lock);

  int exit_status = cur_record->exit_status;
  // if the parent has already exited, we no longer need the child
  // hence we free the record
  if (cur_record->parent_exited)
  {
    free(cur_record);
  }
  else
  {
    // if the parent hasn't exited then set status to exit
    cur_record->exited = true;
    sema_up(&cur_record->check_exit);
  }
  lock_release(&cur_record->free_lock);

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL)
  {
    /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
    cur->pagedir = NULL;
    pagedir_activate(NULL);
    pagedir_destroy(pd);
  }

  // Output message
  printf("%s: exit(%d)\n", cur->name, exit_status);

  children_can_terminate(cur);
}

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t process_execute(const char *file_name)
{
  char *fn_copy;
  tid_t tid;
  struct thread *parent = thread_current();
  struct process_load info;
  sema_init(&info.check_load, 0);

  ASSERT(strlen(file_name) < PGSIZE);

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page(0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy(fn_copy, file_name, PGSIZE);

  info.file_name = fn_copy;

  info.argv = palloc_get_page(0);
  if (info.argv == NULL)
  {
    // print error message, memory allocation for passing arguments failed
    PANIC("Page allocation for program arguments failed");
  }

  info.argc = arg_parsing(info.file_name, info.argv);

  /* trying to open executable*/
  struct file *file = filesys_open(info.argv[0]);
  if (!file)
  {
    return TID_ERROR;
  }
  file_close(file);

  /* Create a new thread to execute only the runnable a.k.a. the first argument of file name */
  tid = thread_create(info.argv[0], PRI_DEFAULT, start_process, &info);

  if (tid == TID_ERROR)
  {
    palloc_free_page(fn_copy);
    return TID_ERROR;
  }

  process_record_init(parent, tid);

  sema_down(&info.check_load);

  if (!info.load_success)
  {
    return TID_ERROR;
  }

  return tid;
}

/* Waits for thread TID to die and returns its exit status.
 * If it was terminated by the kernel (i.e. killed due to an exception),
 * returns -1.
 * If TID is invalid or if it was not a child of the calling process, or if
 * process_wait() has already been successfully called for the given TID,
 * returns -1 immediately, without waiting. */
int process_wait(tid_t child_tid)
{
  struct thread *parent = thread_current();
  struct process_record *child_record = get_process_record_child(parent, child_tid);

  if (child_record == NULL || child_record->waited)
  {
    return -1;
  }

  child_record->waited = true;

  sema_down(&child_record->check_exit);

  return child_record->exit_status;
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void process_activate(void)
{
  struct thread *t = thread_current();

  /* Activate thread's page tables. */
  pagedir_activate(t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update();
}

/* -------------------STRUCT HELPER FUNCTIONS------------------- */

void close_all_thread_files(struct thread *t)
{
  while (!list_empty(&t->open_files))
  {
    struct list_elem *e = list_pop_front(&t->open_files);
    struct thread_file *this = list_entry(e, struct thread_file, elem);
    file_close(this->file);
    free(this);
  }
}

void children_can_terminate(struct thread *parent)
{
  while (!list_empty(&parent->child_processes))
  {
    struct list_elem *e = list_pop_front(&parent->child_processes);
    struct process_record *child_record = list_entry(e, struct process_record, elem);

    lock_acquire(&child_record->free_lock);

    child_record->parent_exited = true;

    if (child_record->exited)
    {
      lock_release(&child_record->free_lock);
      free(child_record);
    }
    else
      lock_release(&child_record->free_lock);
  }
}

/* Allocates memory for the process_record */
static void
process_record_init(struct thread *parent, tid_t tid)
{
  struct process_record *child_record = malloc(sizeof(struct process_record));
  if (child_record == NULL)
  {
    thread_exit();
  }

  enum intr_level old_level = intr_disable();

  child_record->pid = tid;
  sema_init(&child_record->check_exit, 0);
  lock_init(&child_record->free_lock);
  child_record->waited = false;
  child_record->exited = false;

  child_record->parent_exited = false;

  list_push_back(&parent->child_processes, &child_record->elem);

  thread_search(tid)->process = child_record;

#ifdef VM
  mmap_table_init(&child_record->mmap_table);
  sp_table_init(&child_record->sp_table);
#endif

  intr_set_level(old_level);
}

/* Returns process_record of current thread. */
struct process_record *
current_process_record(void)
{
  return thread_current()->process;
}

/* Returns the corresponding process_record to the input tid,
   NULL if no such record exists */
struct process_record *
get_process_record_child(struct thread *parent, tid_t child_tid)
{
  struct list_elem *elem;
  if (!list_empty(&parent->child_processes))
    for (elem = list_front(&parent->child_processes); elem != list_tail(&parent->child_processes); elem = list_next(elem))
    {
      struct process_record *this = list_entry(elem, struct process_record, elem);
      if (child_tid == this->pid)
      {
        return this;
      }
    };
  return NULL;
}

/*-------------------STACK-------------------*/

static int
arg_parsing(char *str, char **argv)
{
  char *delim = " ";
  char *saveptr;
  char *tok_content;
  int argc = 0;

  for (tok_content = strtok_r(str, delim, &saveptr); tok_content != NULL; tok_content = strtok_r(NULL, delim, &saveptr))
  {
    argv[argc++] = tok_content;
  }

  /* returns number of arguments */
  return argc;
}

static void
try_decrement_stack(void **esp, int *bytes_remaining, int to_decrement)
{
  *bytes_remaining -= to_decrement;
  if (*bytes_remaining < 0)
  {
    PANIC("Command line arguments are too long. Overflow will occur.");
  }
  *esp -= to_decrement;
}

static void
stack_push_all(struct intr_frame *if_, char **argv, int argc)
{
  int bytes_remaining = PGSIZE;

  /* Push arguments' values in stack */
  for (int i = argc - 1; i >= 0; i--)
  {
    /* Get the length of each argument + '\0' */
    int len = strlen(argv[i]) + 1;
    /* Decrement by the length of argument to push in stack */
    try_decrement_stack(&if_->esp, &bytes_remaining, len);
    strlcpy(if_->esp, argv[i], len);
    /* Remember the stack address of the argument's value */
    argv[i] = if_->esp;
  }

  /* Decrement by integer address % 4 - to round up to multiple of sizeof(uint32_t) */
  try_decrement_stack(&if_->esp, &bytes_remaining, ((uint32_t)if_->esp) % 4);

  /* Push pointers to arguments in stack
     Typecast void pointer if_esp to corresponding addresses with (TYPE *). */
  for (int i = argc; i >= 0; i--)
  {
    try_decrement_stack(&if_->esp, &bytes_remaining, sizeof(char *));
    if (i == argc)
    {
      *(uint8_t *)if_->esp = (uint8_t)0;
    }
    else
    {
      *(char **)if_->esp = (char *)argv[i];
    }
  }

  /* Push address to start of array */
  try_decrement_stack(&if_->esp, &bytes_remaining, sizeof(char **));
  *((char **)if_->esp) = (if_->esp + sizeof(char **));

  /* Push number of program arguments */
  try_decrement_stack(&if_->esp, &bytes_remaining, sizeof(int));
  *(int *)if_->esp = argc;

  /* Push fake return address */
  try_decrement_stack(&if_->esp, &bytes_remaining, sizeof(void *));
  *(void **)if_->esp = (void (*)())0;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process(void *load_info)
{
  struct process_load *info = load_info;
  struct intr_frame if_;

  /* Initialize interrupt frame and load executable. */
  memset(&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  info->load_success = load(info->argv[0], &if_.eip, &if_.esp);

  // pushing arguments onto stack
  stack_push_all(&if_, info->argv, info->argc);
  palloc_free_page(info->argv);

  /* If load failed, quit. */
  palloc_free_page(info->file_name);

  sema_up(&info->check_load);

  if (!info->load_success)
    thread_exit();

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile("movl %0, %%esp; jmp intr_exit"
               :
               : "g"(&if_)
               : "memory");

  NOT_REACHED();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in // printf(). */
#define PE32Wx PRIx32 /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32 /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32 /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16 /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
{
  unsigned char e_ident[16];
  Elf32_Half e_type;
  Elf32_Half e_machine;
  Elf32_Word e_version;
  Elf32_Addr e_entry;
  Elf32_Off e_phoff;
  Elf32_Off e_shoff;
  Elf32_Word e_flags;
  Elf32_Half e_ehsize;
  Elf32_Half e_phentsize;
  Elf32_Half e_phnum;
  Elf32_Half e_shentsize;
  Elf32_Half e_shnum;
  Elf32_Half e_shstrndx;
};

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
{
  Elf32_Word p_type;
  Elf32_Off p_offset;
  Elf32_Addr p_vaddr;
  Elf32_Addr p_paddr;
  Elf32_Word p_filesz;
  Elf32_Word p_memsz;
  Elf32_Word p_flags;
  Elf32_Word p_align;
};

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL 0           /* Ignore. */
#define PT_LOAD 1           /* Loadable segment. */
#define PT_DYNAMIC 2        /* Dynamic linking info. */
#define PT_INTERP 3         /* Name of dynamic loader. */
#define PT_NOTE 4           /* Auxiliary info. */
#define PT_SHLIB 5          /* Reserved. */
#define PT_PHDR 6           /* Program header table. */
#define PT_STACK 0x6474e551 /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1 /* Executable. */
#define PF_W 2 /* Writable. */
#define PF_R 4 /* Readable. */

static bool setup_stack(void **esp);
static bool validate_segment(const struct Elf32_Phdr *, struct file *);
static bool load_segment(struct file *file, off_t ofs, uint8_t *upage,
                         uint32_t read_bytes, uint32_t zero_bytes,
                         bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool load(const char *file_name, void (**eip)(void), void **esp)
{
  struct thread *t = thread_current();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create();
  if (t->pagedir == NULL)
    goto done;
  process_activate();

  /* Open executable file. */
  file = filesys_open(file_name);
  if (file == NULL)
  {
    printf("load: %s: open failed\n", file_name);
    goto done;
  }

  /* lock the executable from being written to */
  file_deny_write(file);
  t->executable = file;

  /* Read and verify executable header. */
  if (file_read(file, &ehdr, sizeof ehdr) != sizeof ehdr || memcmp(ehdr.e_ident, "\177ELF\1\1\1", 7) || ehdr.e_type != 2 || ehdr.e_machine != 3 || ehdr.e_version != 1 || ehdr.e_phentsize != sizeof(struct Elf32_Phdr) || ehdr.e_phnum > 1024)
  {
    printf("load: %s: error loading executable\n", file_name);
    goto done;
  }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++)
  {
    struct Elf32_Phdr phdr;

    if (file_ofs < 0 || file_ofs > file_length(file))
      goto done;
    file_seek(file, file_ofs);

    if (file_read(file, &phdr, sizeof phdr) != sizeof phdr)
      goto done;
    file_ofs += sizeof phdr;
    switch (phdr.p_type)
    {
    case PT_NULL:
    case PT_NOTE:
    case PT_PHDR:
    case PT_STACK:
    default:
      /* Ignore this segment. */
      break;
    case PT_DYNAMIC:
    case PT_INTERP:
    case PT_SHLIB:
      goto done;
    case PT_LOAD:
      if (validate_segment(&phdr, file))
      {
        bool writable = (phdr.p_flags & PF_W) != 0;
        uint32_t file_page = phdr.p_offset & ~PGMASK;
        uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
        uint32_t page_offset = phdr.p_vaddr & PGMASK;
        uint32_t read_bytes, zero_bytes;
        if (phdr.p_filesz > 0)
        {
          /* Normal segment.
                     Read initial part from disk and zero the rest. */
          read_bytes = page_offset + phdr.p_filesz;
          zero_bytes = (ROUND_UP(page_offset + phdr.p_memsz, PGSIZE) - read_bytes);
        }
        else
        {
          /* Entirely zero.
                     Don't read anything from disk. */
          read_bytes = 0;
          zero_bytes = ROUND_UP(page_offset + phdr.p_memsz, PGSIZE);
        }
        if (!load_segment(file, file_page, (void *)mem_page,
                          read_bytes, zero_bytes, writable))
          goto done;
      }
      else
        goto done;
      break;
    }
  }

  /* Set up stack. */
  if (!setup_stack(esp))
    goto done;

  /* Start address. */
  *eip = (void (*)(void))ehdr.e_entry;

  success = true;

done:
  /* We arrive here whether the load is successful or not. */

  /* "To deny writes to a process's executable, you must keep it open as long as the process is still running" */
  if (!success)
    file_close(file);
  return success;
}

/* load() helpers. */
static bool install_page(void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment(const struct Elf32_Phdr *phdr, struct file *file)
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
    return false;

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off)file_length(file))
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz)
    return false;

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;

  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr((void *)phdr->p_vaddr))
    return false;
  if (!is_user_vaddr((void *)(phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment(struct file *file, off_t ofs, uint8_t *upage,
             uint32_t read_bytes, uint32_t zero_bytes, bool writable)
{
  ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT(pg_ofs(upage) == 0);
  ASSERT(ofs % PGSIZE == 0);

#ifdef VM
  /* storing current position of the cursor */
  off_t cursor = ofs;
#endif

  while (read_bytes > 0 || zero_bytes > 0)
  {
    /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
    size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
    size_t page_zero_bytes = PGSIZE - page_read_bytes;
#ifdef VM
    struct metadata *metadata = NULL;
    struct page *p = sp_table_get_page(&thread_current()->process->sp_table, upage);
    /* If there exists an entry already for this address, then, due to an overlap we only need to update the values
       Hence either retrieve the existing metadata or malloc a chunk of memory to act as new metadata */
    if (p != NULL)
      metadata = p->metadata;
    else
    {
      metadata = malloc(sizeof(struct metadata));

      if (!metadata)
        return false;

      /* setting writable to false so that || operator works as required */
      metadata->writable = false;
    }
    /* insert meta data about the state of the cursor and number of bits
       to read and zero out at the end */

    metadata->writable = writable || metadata->writable;
    metadata->cursor = cursor;
    metadata->page_read_bytes = page_read_bytes;
    metadata->file = file;

    /* Only add the page if it was not already in the suppplemental page table. */
    if (p == NULL)
      sp_table_add_page(upage, metadata, page_read_bytes == 0 ? EMPTY : EXEC);

    /* Advance. */
    cursor += page_read_bytes; /* advancing cursor by amount read in this iterration */
#else
    /* Check if virtual page already allocated */
    struct thread *t = thread_current();
    uint8_t *kpage = pagedir_get_page(t->pagedir, upage);

    if (kpage == NULL)
    {

      /* Get a new page of memory. */
      kpage = palloc_get_page(PAL_USER);
      if (kpage == NULL)
      {
        return false;
      }

      /* Add the page to the process's address space. */
      if (!install_page(upage, kpage, writable))
      {
        palloc_free_page(kpage);
        return false;
      }
    }

    /* Load data into the page. */
    if (file_read(file, kpage, page_read_bytes) != (int)page_read_bytes)
    {
      palloc_free_page(kpage);
      return false;
    }
    memset(kpage + page_read_bytes, 0, page_zero_bytes);
#endif
    read_bytes -= page_read_bytes; /* how many bytes left to read from file */
    zero_bytes -= page_zero_bytes; /* how many zeros to add to the end of the page */
    upage += PGSIZE;               /* address for next virtual page */
  }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack(void **esp)
{
  uint8_t *kpage;
  bool success = false;
#ifdef VM
  uint8_t *upage = ((uint8_t *)PHYS_BASE) - PGSIZE;
  kpage = frame_alloc(PAL_USER | PAL_ZERO, upage);
#else
  kpage = palloc_get_page(PAL_USER | PAL_ZERO);
#endif
  if (kpage != NULL)
  {
    success = install_page(((uint8_t *)PHYS_BASE) - PGSIZE, kpage, true);

    if (success)
    {
      *esp = PHYS_BASE;
#ifdef VM
      sp_table_add_page(upage, NULL, STACK);
#endif
    }
    else
    {
#ifdef VM
      free_kernel_page(kpage);
#else
      palloc_free_page(kpage);
#endif
    }
  }
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page(void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page(t->pagedir, upage) == NULL && pagedir_set_page(t->pagedir, upage, kpage, writable));
}