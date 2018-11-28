#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <list.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/shutdown.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "threads/malloc.h"

#define WORD_SIZE sizeof(void *)
#define MAX_ARGS_COUNT 3

struct lock filesys_lock;
static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
	int* stack_pointer = f->esp;
	int syscall_num = *stack_pointer;
	void *args_refs[MAX_ARGS_COUNT];

	for(int i=0; i<MAX_ARGS_COUNT; i++){
		args_refs[i] = stack_pointer + (i+1);
	}
	//printf("LC: Inside syscall handler - arguments captured\n");

	switch(syscall_num){
		case SYS_HALT:
		    shutdown_power_off();
			break;

		case SYS_EXIT:
		{
			/*The argument to exit is an integer pointer*/
			/*if(!(is_user_vaddr(args_refs[0])))
			{
				thread_current()->exec_status = -1;
				break;
			}*/
			int status = *((int *) args_refs[0]);
	        thread_current()->exec_status = status;
	        printf("%s: exit(%d)\n", thread_current()->name, status);
		    thread_exit();
			break;
		}
		case SYS_EXEC:
			break;

		case SYS_WAIT:
			break;

		case SYS_CREATE:
			break;

		case SYS_REMOVE:
			break;

		case SYS_OPEN:
		{
		      struct file_descriptor *fdesc = (struct file_descriptor *) malloc(sizeof(struct file_descriptor));
		      char *file_name = *((char **) args_refs[0]);
  			  /*if(file_name == NULL)
    		  {
    		  	/*To notify that the thread has failed to the parent process*/
    		  	 //thread_current()->exec_status = -1;
    		  	 /* Pintos system call handler returns a value to the user program by 
    		  	 modifying the eax register*/
    		  	 //f->eax = -1;
    		  //}	

  			  lock_acquire(&filesys_lock);
  			  struct file *file_n = filesys_open(file_name);
  			  lock_release(&filesys_lock);

  			  if( file_n == NULL)
  			  {
  			  	 thread_current()->exec_status = -1;
  			  	 f->eax = -1;
  			  	 break;
  			  }

  			  /*Need to maintain a list of the files opened by the thread*/	
  			  fdesc->fd = thread_current()->fd_counter;
  			  thread_current()->fd_counter++;
  			  fdesc->f = file_n;
  			  list_push_back(&thread_current()->fd_list, &fdesc->fd_elem);
  			  f->eax = fdesc->fd;
  			break;
        }
		case SYS_FILESIZE:
			break;

		case SYS_READ:
			printf("LC: Inside read syscall\n");
			break;

		case SYS_WRITE:
			{
				//printf("LC: Inside write syscall\n");
				int fd = *((int*)args_refs[0]);
				void* buf = (void*)(*((int*)args_refs[1]));
				unsigned size = *((unsigned*)args_refs[2]);
	  			//printf("fd - %d \n buf - %s \nsize - %d\n", fd, buf, size);
	  			if(fd == 1){
					putbuf(buf, size);
					f->eax = buf;
				}
			}
			break;

		case SYS_SEEK:
			break;

		case SYS_TELL:
			break;

		case SYS_CLOSE:
			break;


	}

	/*if(thread_current()->exec_status == -1 )
	{
		f->eax = -1;
		thread_exit();
	}*/

  // printf ("system call!\n");
  // thread_exit ();
}
