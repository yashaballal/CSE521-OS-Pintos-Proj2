#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

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
	int i;
	void *args[MAX_ARGS_COUNT];

	for(i=0; i<MAX_ARGS_COUNT; i++){
		args[i] = stack_pointer + WORD_SIZE * i;
		printf("%s\n", args[i]);
	}

	switch(syscall_num){
		case SYS_HALT:
			break;

		case SYS_EXIT:
			break;

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
			break;

		case SYS_WRITE:
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
