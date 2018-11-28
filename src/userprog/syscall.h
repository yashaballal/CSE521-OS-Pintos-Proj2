#inclule <list.h>

#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

struct fd {
  int fd;
  struct file *f;
  struct list_elem fd_elem;
};

void syscall_init (void);

#endif /* userprog/syscall.h */
