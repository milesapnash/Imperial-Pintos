#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "threads/synch.h"
#include "vm/page.h"

/* Records details of a thread
   for when it has been exited */
struct process_record
{
    int pid;                     /* PID of record thread */
    int exit_status;             /* Thread exit status */
    struct list_elem elem;       /* Used to add process to list of child processes */
    struct semaphore check_exit; /* Used to block parent until child finishes */
    struct lock free_lock;
    bool waited;        /* Used to track if process has been waited on */
    bool parent_exited; /* Used to track if parent thread has exited */
    bool exited;        /* Used to track if record thread has exited */
#ifdef VM
    struct hash mmap_table; /* Hash table of memory mappings for this process  */
    struct hash sp_table;   /* Supplemental page hash table for the process */
#endif
};

tid_t process_execute(const char *);
int process_wait(tid_t);
void process_exit(void);
void process_activate(void);
struct process_record *current_process_record(void);
void close_all_thread_files(struct thread *);

#endif /* userprog/process.h */
