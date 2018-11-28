#include <list.h>
#include "threads/synch.h"

#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#define MAX_BUF_SIZE 100

struct file_descriptor{
    int fd;               // File descriptor identifier    (> 2 since 0, 1,and represent standard I/O streams)
    struct list_elem fd_elem;     // list_elem to use as a reference in a list
    struct file *file;          // pointer to file referenced by the current file descriptor
    struct fd_buf *fd_buf;        // fd buffer for piped file I/O 
};

struct fd_buf{
    int rw_count;           // count to check how many streams are open (0, 1, 2)
    char fd_buffer[MAX_BUF_SIZE];   // buffer used to exchange messages in piped mode
    struct lock fd_buffer_lock;     // lock to synchronize the fd_buffer
    int buf_start, buf_end;       // start and end indexes to fd_buffer array
};

void syscall_init (void);

#endif /* userprog/syscall.h */