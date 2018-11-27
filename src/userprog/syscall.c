#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/shutdown.h"

#define WORD_SIZE sizeof(void *)
#define MAX_ARGS_COUNT 3

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
			break;

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

  // printf ("system call!\n");
  // thread_exit ();
}
