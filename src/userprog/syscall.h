#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "vm/mmap.h"

/* Process identifier. */
typedef int pid_t;
#define PID_ERROR ((pid_t)-1)

struct lock lock_filesys;

void syscall_init(void);
void munmap(mapid_t);

#endif /* userprog/syscall.h */
