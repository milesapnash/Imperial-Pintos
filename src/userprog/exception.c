#include "userprog/exception.h"
#include <inttypes.h>
#include <stdio.h>
#include "userprog/gdt.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "process.h"
#include "threads/vaddr.h"
#include "pagedir.h"
#include "string.h"
#include "filesys/file.h"
#include "vm/page.h"
#include "vm/frame.h"
#include "vm/swap.h"
#include "threads/thread.h"

#define PUSH_FAULT 4
#define PUSHA_FAULT 32
#define ULIMIT (1 << 23) /* 8MB */

/* Number of page faults processed. */
static long long page_fault_cnt;

static void kill(struct intr_frame *);

/* page fault handling */
static void page_fault(struct intr_frame *);

#ifdef VM
static void *handle_page_fault(struct intr_frame *, void *);

/* Loading pages */
static void *load_executable_page(struct page *);
static void *load_empty_page(struct page *);
static void *load_from_swap_table(struct page *);

/* stack growth handling */
static bool stack_access(void *, void *);
static void *stack_grow(void *);
#endif

/* Registers handlers for interrupts that can be caused by user
   programs.

   In a real Unix-like OS, most of these interrupts would be
   passed along to the user process in the form of signals, as
   described in [SV-386] 3-24 and 3-25, but we don't implement
   signals.  Instead, we'll make them simply kill the user
   process.

   Page faults are an exception.  Here they are treated the same
   way as other exceptions, but this will need to change to
   implement virtual memory.

   Refer to [IA32-v3a] section 5.15 "Exception and Interrupt
   Reference" for a description of each of these exceptions. */
void exception_init(void)
{
   /* These exceptions can be raised explicitly by a user program,
     e.g. via the INT, INT3, INTO, and BOUND instructions.  Thus,
     we set DPL==3, meaning that user programs are allowed to
     invoke them via these instructions. */
   intr_register_int(3, 3, INTR_ON, kill, "#BP Breakpoint Exception");
   intr_register_int(4, 3, INTR_ON, kill, "#OF Overflow Exception");
   intr_register_int(5, 3, INTR_ON, kill, "#BR BOUND Range Exceeded Exception");

   /* These exceptions have DPL==0, preventing user processes from
     invoking them via the INT instruction.  They can still be
     caused indirectly, e.g. #DE can be caused by dividing by
     0.  */
   intr_register_int(0, 0, INTR_ON, kill, "#DE Divide Error");
   intr_register_int(1, 0, INTR_ON, kill, "#DB Debug Exception");
   intr_register_int(6, 0, INTR_ON, kill, "#UD Invalid Opcode Exception");
   intr_register_int(7, 0, INTR_ON, kill, "#NM Device Not Available Exception");
   intr_register_int(11, 0, INTR_ON, kill, "#NP Segment Not Present");
   intr_register_int(12, 0, INTR_ON, kill, "#SS Stack Fault Exception");
   intr_register_int(13, 0, INTR_ON, kill, "#GP General Protection Exception");
   intr_register_int(16, 0, INTR_ON, kill, "#MF x87 FPU Floating-Point Error");
   intr_register_int(19, 0, INTR_ON, kill, "#XF SIMD Floating-Point Exception");

   /* Most exceptions can be handled with interrupts turned on.
     We need to disable interrupts for page faults because the
     fault address is stored in CR2 and needs to be preserved. */
   intr_register_int(14, 0, INTR_OFF, page_fault, "#PF Page-Fault Exception");
}

/* Prints exception statistics. */
void exception_print_stats(void)
{
   printf("Exception: %lld page faults\n", page_fault_cnt);
}

/* Handler for an exception (probably) caused by a user process. */
static void
kill(struct intr_frame *f)
{
   /* This interrupt is one (probably) caused by a user process.
     For example, the process might have tried to access unmapped
     virtual memory (a page fault).  For now, we simply kill the
     user process.  Later, we'll want to handle page faults in
     the kernel.  Real Unix-like operating systems pass most
     exceptions back to the process via signals, but we don't
     implement them. */

   /* The interrupt frame's code segment value tells us where the
     exception originated. */
   switch (f->cs)
   {
   case SEL_UCSEG:
      /* User's code segment, so it's a user exception, as we
         expected.  Kill the user process.  */
      printf("%s: dying due to interrupt %#04x (%s).\n",
             thread_name(), f->vec_no, intr_name(f->vec_no));
      intr_dump_frame(f);
      /* setting exit status */
      thread_current()->process->exit_status = -1;
      thread_exit();

   case SEL_KCSEG:
      /* Kernel's code segment, which indicates a kernel bug.
         Kernel code shouldn't throw exceptions.  (Page faults
         may cause kernel exceptions--but they shouldn't arrive
         here.)  Panic the kernel to make the point.  */
      intr_dump_frame(f);
      PANIC("Kernel bug - unexpected interrupt in kernel");

   default:
      /* Some other code segment?
         Shouldn't happen.  Panic the kernel. */
      printf("Interrupt %#04x (%s) in unknown segment %04x\n",
             f->vec_no, intr_name(f->vec_no), f->cs);
      PANIC("Kernel bug - this shouldn't be possible!");
   }
}

/* Page fault handler.  This is a skeleton that must be filled in
   to implement virtual memory.  Some solutions to task 2 may
   also require modifying this code.

   At entry, the address that faulted is in CR2 (Control Register
   2) and information about the fault, formatted as described in
   the PF_* macros in exception.h, is in F's error_code member.  The
   example code here shows how to parse that information.  You
   can find more information about both of these in the
   description of "Interrupt 14--Page Fault Exception (#PF)" in
   [IA32-v3a] section 5.15 "Exception and Interrupt Reference". */
static void
page_fault(struct intr_frame *f)
{
   void *fault_addr; /* Fault address. */

   /* Obtain faulting address, the virtual address that was
     accessed to cause the fault.  It may point to code or to
     data.  It is not necessarily the address of the instruction
     that caused the fault (that's f->eip).
     See [IA32-v2a] "MOV--Move to/from Control Registers" and
     [IA32-v3a] 5.15 "Interrupt 14--Page Fault Exception
     (#PF)". */
   asm("movl %%cr2, %0"
       : "=r"(fault_addr));

   /* Turn interrupts back on (they were only off so that we could
     be assured of reading CR2 before it changed). */
   intr_enable();

   /* Count page faults. */
   page_fault_cnt++;

   void *new_kpage = NULL;
#ifdef VM
   new_kpage = handle_page_fault(f, fault_addr);
#endif
   bool user = (f->error_code & PF_U) != 0; /* True: access by user, false: access by kernel. */

   if (new_kpage == NULL)
   {
      if (!user)
      {
         f->eip = (void *)f->eax;
         f->eax = -1;
         return;
      }
      kill(f);
   }
}

#ifdef VM
static void *
handle_page_fault(struct intr_frame *f, void *fault_addr)
{
   /* Determine cause. */
   bool not_present = (f->error_code & PF_P) == 0; /* True: not-present page, false: writing r/o page. */

   /* If page fault is caused by writing to a read only page then kill the process */
   if (!not_present)
      return NULL;

   /* check if valid memory reference */
   if (is_kernel_vaddr(fault_addr))
      return NULL;

   /* Check and deal with stack access */
   if (stack_access(f->esp, fault_addr))
   {
      return stack_grow(pg_round_down(fault_addr));
   }

   void *addr = pg_round_down(fault_addr);
   UNUSED void *offset = (void *)pg_ofs(fault_addr);

   struct thread *curr = thread_current();

   /* extracting page from the supplmentary page table */
   struct page *p = sp_table_get_page(&curr->process->sp_table, addr);

   /* if the supplementary page table does not contain the fault address kill the process*/
   if (!p)
      return NULL;

   struct frame *shared_frame = NULL;

   if (!p->metadata->writable)
      shared_frame = frame_find_from_page(p);

   /* If we have found a frame that is shared by similar pages (i.e. same metadata)
      then set the entry in the page table to point to the frame */
   if (shared_frame)
   {
      /* update the page table */
      pagedir_set_page(curr->pagedir, addr, shared_frame->frame_addr, p->metadata->writable);
      list_push_back(&shared_frame->pages, &p->shared_frame);
      return shared_frame->frame_addr;
   }

   /* Obtain a frame to store the page */
   /* Fetch the data into the frame, by reading it from the file system or swap, zeroing it */
   /* Point the page table entry for the faulting virtual address to the frame. */
   void *kpage = NULL;
   switch (p->status)
   {
   case EXEC:
   case MMAP:
      kpage = load_executable_page(p);
      break;
   case EMPTY:
      kpage = load_empty_page(p);
      break;
   case SWAP:
      kpage = load_from_swap_table(p);
      break;
   default:
      PANIC("Page fault: Invalid page status");
   }

   ASSERT(kpage != NULL);

   /* update the page table */
   pagedir_set_page(curr->pagedir, addr, kpage, p->metadata->writable);

   return kpage;
}

/* Given a page that is to be loaded from a swap space, return the address of the frame */
static void *
load_from_swap_table(struct page *p)
{
   /* allocate a new frame to load data into*/
   void *kpage = frame_alloc(PAL_USER, p->virtual_address);
   frame_push_page(kpage, p);

   /* load from swap space (Disk) into main memory (RAM) */
   swap_load(p->virtual_address, kpage);

   return kpage;
}

/* Given a page that is to be loaded with zeros, returns the address of the frame */
static void *
load_empty_page(struct page *p)
{
   ASSERT(p->status == EMPTY);

   /* Get a new frame and set page to zeros */
   void *kpage = frame_alloc(PAL_USER | PAL_ZERO, p->virtual_address);
   frame_push_page(kpage, p);

   return kpage;
}

/* Given a page, loads it into a frame and returns the address of the frame */
static void *
load_executable_page(struct page *p)
{
   ASSERT(p->status == EXEC || MMAP);

   /* extracting metadata from load_segment */
   size_t page_read_bytes = p->metadata->page_read_bytes;
   size_t page_zero_bytes = PGSIZE - page_read_bytes;

   ASSERT((page_read_bytes + page_zero_bytes) % PGSIZE == 0);
   ASSERT(pg_ofs(p->virtual_address) == 0);

   /* allocating a new frame to read the page data into */
   void *kpage = frame_alloc(PAL_USER, p->virtual_address);
   frame_push_page(kpage, p);

   /* Load data into the page. */
   off_t bytes_written = file_read_at(p->metadata->file, kpage, page_read_bytes, p->metadata->cursor);
   ASSERT(bytes_written != 0);

   /* Zero out the rest of the page */
   memset(kpage + page_read_bytes, 0, page_zero_bytes);

   return kpage;
}

static bool stack_access(void *esp, void *addr)
{
   return is_user_vaddr(addr) &&                       /* The fault address is a virtual address */
          (addr >= esp - PUSHA_FAULT) &&               /* Tries to write below the stack pointer */
          (PHYS_BASE - pg_round_down(addr)) <= ULIMIT; /* Does not exceed the stack size limit of 8MB */
}

static void *stack_grow(void *vaddr)
{
   /* Add to supplementary page table */
   /* metadata is set to null becuase we're not loading an executable */

   /* Creates new page */
   void *kpage = frame_alloc(PAL_USER | PAL_ZERO, vaddr);

   pagedir_set_page(thread_current()->pagedir, pg_round_down(vaddr), kpage, true);

   sp_table_add_page(vaddr, NULL, STACK);
   return kpage;
}
#endif