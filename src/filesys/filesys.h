#ifndef FILESYS_FILESYS_H
#define FILESYS_FILESYS_H

#include <stdbool.h>
#include "filesys/off_t.h"

/* Sectors of system file inodes. */
#define FREE_MAP_SECTOR 0       /* Free map file inode sector. */
#define ROOT_DIR_SECTOR 1       /* Root directory file inode sector. */

/* Block device that contains the file system. */
extern struct block *fs_device;

/* 
    Limitations:
        > No internal synchronization. Cncurrent access will interfere with one 
        another. You should use synchroniztion to ensure that only one process
        at a time is executing file system code. No finer- grained 
        synchronisation is expected.
        > File size is fixed at creation time. The root directory is 
        represented as a file, so the number of files that may be 
        created is also limited. 
        > File data is allocated as a single extent, that is, data in a single 
        file must occupy a contiguous range of sectors on disk. External 
        fragmentation can therefore become a serious problem as a file system
        is used over time
        > No Subdirectories
        > File names are limited to 14 characters
        > A system crash mid-operation may corrupt the disk in a way that 
        cannot be repaired automatically. There is no file system repair tool 
        anyway.
*/

void filesys_init (bool format);
void filesys_done (void);
bool filesys_create (const char *name, off_t initial_size);
struct file *filesys_open (const char *name);
bool filesys_remove (const char *name);

#endif /* filesys/filesys.h */
