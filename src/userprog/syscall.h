#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#define MAX_BUF_SIZE 100

#include <list.h>

#include "threads/synch.h"
#include "filesys/file.h"

void syscall_init (void);

struct lock file_lock;    //lock created for file system operations synchronizations

struct file_descriptor{
    int fd;    						// File descriptor identifier    (> 2 since 0, 1,and represent standard I/O streams)
    struct list_elem fdesc_elem;    			// list_elem to use as a reference in a list
    struct file *fdesc_file;    			// pointer to file referenced by the current file descriptor
};

void system_exit(int exit_status);
#endif /* userprog/syscall.h */

