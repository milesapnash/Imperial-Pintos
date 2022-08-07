#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/vaddr.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "devices/input.h"
#include "process.h"
#include <string.h>
#include "devices/shutdown.h"
#include "pagedir.h"
#include "threads/malloc.h"

#define PTR_SIZE 4
#define MAX_SYSCALL_INDEX 14

static int get_user(const uint8_t *uaddr);
static void get_arg(void *esp, int pos, void *dst);
static bool is_valid_buffer(const void *, const int);
static void syscall_handler(struct intr_frame *f);
static void exit(int exit_status);
static void acquire_filesys(void);
static void release_filesys(void);
static struct thread_file *get_thread_file(int fd);
static int next_available_fd(void);
static mapid_t next_available_mapid(void);

static void (*syscall_functions[MAX_SYSCALL_INDEX])(void *esp, uint32_t *eax);
static void sys_halt(void *esp UNUSED, uint32_t *eax UNUSED);
static void sys_exit(void *esp, uint32_t *eax UNUSED);
static void sys_exec(void *esp, uint32_t *eax);
static void sys_wait(void *esp, uint32_t *eax);
static void sys_create(void *esp, uint32_t *eax);
static void sys_remove(void *esp, uint32_t *eax);
static void sys_open(void *esp, uint32_t *eax);
static void sys_filesize(void *esp, uint32_t *eax);
static void sys_read(void *esp, uint32_t *eax);
static void sys_write(void *esp, uint32_t *eax);
static void sys_seek(void *esp, uint32_t *eax UNUSED);
static void sys_tell(void *esp, uint32_t *eax);
static void sys_close(void *esp, uint32_t *eax UNUSED);
static void sys_mmap(void *esp, uint32_t *eax);
static void sys_munmap(void *esp, uint32_t *eax UNUSED);

/* Reads a byte at user virtual address UADDR.
   UADDR must be below PHYS_BASE.
   Returns the byte value if successful, -1 if a segfault
   occurred. */
static int
get_user(const uint8_t *uaddr)
{
  int result;
  asm("movl $1f, %0; movzbl %1, %0; 1:"
      : "=&a"(result)
      : "m"(*uaddr));
  return result;
}

static bool
check_pointer(const void *ptr)
{
  for (int i = 0; i < PTR_SIZE; i++, ptr++)
  {
    if (!is_user_vaddr(ptr))
      return false;
    if (get_user((uint8_t *)ptr) == -1)
      return false;
  }
  return true;
}

/* Checks if the contents of buffer are all within the user space */
static bool is_valid_buffer(const void *buffer, const off_t size)
{
  return check_pointer(buffer) && check_pointer(buffer + size);
}

/* Sets the value of the given variable to that of the
   corresponding argument in the intr_frame. */
static void
get_arg(void *esp, int pos, void *dst)
{
  const void *p = esp + (pos + 1) * PTR_SIZE; /*  position 0 is fake return address */

  for (int i = 0; i < PTR_SIZE; i++)
  {
    if (!is_user_vaddr(p + i))
      exit(-1);
    int byte_data = get_user(p + i);
    if (byte_data == -1)
      exit(-1);
    *((uint8_t *)dst + i) = byte_data;
  }
}

/* Returns the next available fd for the current process. */
static int
next_available_fd(void)
{
  struct thread *cur = thread_current();
  int fd = cur->current_fd;
  cur->current_fd++;
  return fd;
}

/* Returns the next available mapid for the current process. */
static mapid_t
next_available_mapid(void)
{
  struct thread *cur = thread_current();
  mapid_t mapid = cur->current_mapid;
  cur->current_mapid++;
  return mapid;
}

/* Returns corresponding process_file for fd, NULL if no such file exists. */
static struct thread_file *
get_thread_file(int fd)
{
  struct thread *cur = thread_current();

  if (fd < FIRST_AVAILABLE_FD || fd > cur->current_fd)
  {
    return NULL;
  }

  struct list_elem *elem;
  if (!list_empty(&cur->open_files))
    for (elem = list_front(&cur->open_files); elem != list_end(&cur->open_files); elem = list_next(elem))
    {
      struct thread_file *this = list_entry(elem, struct thread_file, elem);
      if (fd == this->fd)
      {
        return this;
      }
    };
  return NULL;
}

/* Initialises syscall handler and functions. */
void syscall_init(void)
{
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");

  syscall_functions[SYS_HALT] = &sys_halt;
  syscall_functions[SYS_EXIT] = &sys_exit;
  syscall_functions[SYS_EXEC] = &sys_exec;
  syscall_functions[SYS_WAIT] = &sys_wait;
  syscall_functions[SYS_CREATE] = &sys_create;
  syscall_functions[SYS_REMOVE] = &sys_remove;
  syscall_functions[SYS_OPEN] = &sys_open;
  syscall_functions[SYS_FILESIZE] = &sys_filesize;
  syscall_functions[SYS_READ] = &sys_read;
  syscall_functions[SYS_WRITE] = &sys_write;
  syscall_functions[SYS_SEEK] = &sys_seek;
  syscall_functions[SYS_TELL] = &sys_tell;
  syscall_functions[SYS_CLOSE] = &sys_close;
  syscall_functions[SYS_MMAP] = &sys_mmap;
  syscall_functions[SYS_MUNMAP] = &sys_munmap;

  lock_init(&lock_filesys);
}

/* Acquires filesystem lock. */
static void
acquire_filesys(void)
{
  lock_acquire(&lock_filesys);
}

/* Releases filesystem lock. */
static void
release_filesys(void)
{
  lock_release(&lock_filesys);
}

/* Calls function corresponding to syscall_number. */
static void
syscall_handler(struct intr_frame *f)
{
  
  ASSERT(f != NULL);

  if (!check_pointer(f->esp))
    exit(-1);

  int syscall_num = *(int *)f->esp;

  syscall_functions[syscall_num](f->esp, &f->eax);
}

/* Terminates Pintos. */
static void
sys_halt(void *esp UNUSED, uint32_t *eax UNUSED)
{
  shutdown_power_off();
}

/* Exits with specified status. */
static void
exit(int exit_status)
{
  current_process_record()->exit_status = exit_status;
  thread_exit();
}

/* Terminates current user program. */
static void
sys_exit(void *esp, uint32_t *eax UNUSED)
{
  int status;
  get_arg(esp, 0, &status);
  exit(status);
}

/* Runs given executable as child process. */
static void
sys_exec(void *esp, uint32_t *eax)
{
  const char *cmd_line;
  get_arg(esp, 0, &cmd_line);

  if (!check_pointer(cmd_line))
    exit(-1);

  *eax = process_execute(cmd_line);
}

/* Waits for child process pid. */
static void
sys_wait(void *esp, uint32_t *eax)
{
  pid_t pid;
  get_arg(esp, 0, &pid);

  *eax = process_wait(pid);
}

/* Creates a new file. */
static void
sys_create(void *esp, uint32_t *eax)
{
  const char *file;
  unsigned initial_size;
  get_arg(esp, 0, &file);
  get_arg(esp, 1, &initial_size);

  if (!check_pointer(file))
    exit(-1);

  acquire_filesys();
  *eax = filesys_create(file, (off_t)initial_size);
  release_filesys();
}

/* Deletes specified file. */
static void
sys_remove(void *esp, uint32_t *eax)
{
  const char *file;
  get_arg(esp, 0, &file);

  if (!check_pointer(file))
    exit(-1);

  acquire_filesys();
  *eax = filesys_remove(file);
  release_filesys();
}

/* Opens specified file. */
static void
sys_open(void *esp, uint32_t *eax)
{
  const char *file;
  int fd = -1;
  get_arg(esp, 0, &file);

  if (!check_pointer(file))
    exit(-1);

  acquire_filesys();

  struct file *new_file = filesys_open(file);
  if (new_file != NULL)
  {
    fd = next_available_fd();

    struct thread_file *new_t_file = malloc(sizeof(struct thread_file));

    if (new_t_file == NULL)
      exit(-1);

    new_t_file->fd = fd;
    new_t_file->file = new_file;

    list_push_back(&thread_current()->open_files, &new_t_file->elem);
  }
  release_filesys();

  *eax = fd;
}

/* Returns size of open file. */
static void
sys_filesize(void *esp, uint32_t *eax)
{
  int fd;
  get_arg(esp, 0, &fd);

  acquire_filesys();

  struct thread_file *t_file = get_thread_file(fd);
  if (t_file == NULL)
    exit(-1);

  *eax = file_length(t_file->file);

  release_filesys();
}

/* Reads bytes from open file. */
static void sys_read(void *esp, uint32_t *eax)
{
  int fd;
  void *buffer;
  off_t size;
  get_arg(esp, 0, &fd);
  get_arg(esp, 1, &buffer);
  get_arg(esp, 2, &size);

  if (!is_valid_buffer(buffer, size))
    exit(-1);

  acquire_filesys();

  if (fd == STDIN_FILENO)
  {
    for (int i = 0; i < size; i++)
    {
      *((char *)buffer + i) = input_getc();
    }
    *eax = size;
  }
  else
  {
    struct thread_file *t_file = get_thread_file(fd);
    if (t_file == NULL)
      exit(-1);

    *eax = (int)file_read(t_file->file, buffer, size);
  }
  release_filesys();
}

/* Writes bytes to open file. */
static void
sys_write(void *esp, uint32_t *eax)
{
  int fd;
  const void *buffer;
  unsigned size;
  get_arg(esp, 0, &fd);
  get_arg(esp, 1, &buffer);
  get_arg(esp, 2, &size);

  if (!is_valid_buffer(buffer, size))
    exit(-1);

  acquire_filesys();
  if (fd == STDOUT_FILENO)
  {
    putbuf(buffer, size);
    *eax = size;
  }
  else
  {
    struct thread_file *t_file = get_thread_file(fd);
    if (t_file == NULL)
      exit(-1);

    *eax = (int)file_write(t_file->file, buffer, size);
  }
  release_filesys();
}

/* Changes position of next byte to be read/written in open file. */
static void
sys_seek(void *esp, uint32_t *eax UNUSED)
{
  int fd;
  unsigned position;
  get_arg(esp, 0, &fd);
  get_arg(esp, 1, &position);

  acquire_filesys();

  struct thread_file *t_file = get_thread_file(fd);
  if (t_file == NULL)
    exit(-1);

  file_seek(t_file->file, position);

  release_filesys();
}

/* Returns position of next byte to be read/written in open file. */
static void
sys_tell(void *esp, uint32_t *eax)
{
  int fd;
  get_arg(esp, 0, &fd);

  acquire_filesys();

  struct thread_file *t_file = get_thread_file(fd);
  if (t_file == NULL)
    exit(-1);

  *eax = (unsigned)file_tell(t_file->file);

  release_filesys();
}

/* Closes open file fd. */
static void
sys_close(void *esp, uint32_t *eax UNUSED)
{
  int fd;
  get_arg(esp, 0, &fd);

  struct thread_file *t_file = get_thread_file(fd);
  if (t_file == NULL)
    exit(-1);

  acquire_filesys();
  file_close(t_file->file);
  release_filesys();
  list_remove(&t_file->elem);
  free(t_file);
}

/* Maps file fd into process virtual address space. */
static void
sys_mmap(void *esp, uint32_t *eax)
{

  int fd;
  void *addr;
  get_arg(esp, 0, &fd);
  get_arg(esp, 1, &addr);

  /* Ensures that address is a valid pointer */
  if (!is_user_vaddr(addr))
    exit(-1);

  struct thread_file *t_file = get_thread_file(fd);
  /* Ensures that there is a thread_file corresponding to
     fd, that a valid fd has been provided, that the address is not
     0 and that the address is page aligned */
  if (!t_file || addr == 0 || !page_aligned(addr))
  {
    *eax = -1;
    return;
  }

  acquire_filesys();
  off_t length = file_length(t_file->file);
  release_filesys();

  /*Ensures file length is greater than 0 and that there
    are no files mapped in betweeen */
  if (length == 0 || pages_mapped_between(addr, addr + length))
  {
    *eax = -1;
    return;
  }

  acquire_filesys();
  struct file *f = file_reopen(t_file->file);
  release_filesys();

  int new_mapid = next_available_mapid();
  struct thread *curr = thread_current();
  int page_addr = 0;

  while (page_addr < length)
  {
    /* How many pages to read */
    size_t page_read_bytes = (length - page_addr) < PGSIZE ? (length - page_addr) : PGSIZE;

    struct metadata *metadata = create_metadata(true, page_addr, page_read_bytes, f);
    sp_table_add_page(addr + page_addr, metadata, MMAP);

    /* Incrementing cursor */
    page_addr += page_read_bytes;
  }
  
  mmap_table_add_mapping(&curr->process->mmap_table, new_mapid, addr, addr + page_addr, f);

  *eax = new_mapid;
}

/* Unmaps mapping designated by id. */
void 
munmap(mapid_t id)
{
  struct process_record *pr = current_process_record();
  struct mapping *m = mmap_table_get_mapping(&pr->mmap_table, id);

  if (m)
  {
    struct file *f = m->file;

    mmap_remove_mapping(&pr->mmap_table, m);

    acquire_filesys();
    file_close(f);
    release_filesys();
  }
}

static void
sys_munmap(void *esp, uint32_t *eax UNUSED)
{
  mapid_t id;
  get_arg(esp, 0, &id);
  munmap(id);
}