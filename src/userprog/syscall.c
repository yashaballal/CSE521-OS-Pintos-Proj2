#include "userprog/syscall.h"
#include <stdio.h>
#include <list.h>
#include <syscall-nr.h>

#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/shutdown.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "devices/input.h"
#include "threads/malloc.h"

#define MAX_ARGS_COUNT 3
#define STDOUT_LIMIT 100    // setting a limit of bytes to be written

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&file_lock);
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
			{
				char* arg_fileName = *((char *)args_refs[0]);
				unsigned arg_size = *((unsigned*)args_refs[1]);

				if(arg_fileName == NULL){
					printf("LC : File name is null\n");
					f->eax = -1;
					break;
				}

				lock_acquire(&file_lock);
				f->eax = filesys_create(arg_fileName, arg_size);
				lock_release(&file_lock);

			}
			break;

		case SYS_REMOVE:
			break;

		case SYS_OPEN:
			{
				char* arg_fileName = *((char *)args_refs[0]);
				//printf("LC: File name : %s\n",arg_fileName);
				if(arg_fileName == NULL){
					printf("LC : File name is null\n");
					f->eax = -1;
					break;
				}

				lock_acquire(&file_lock);
				struct file *opened_file = filesys_open(arg_fileName);
				lock_release(&file_lock);

				if(f == NULL){
					printf("LC: There was an error in opening the file");
					f->eax = -1;
					break;
				}

				struct thread *cur = thread_current();
				struct file_descriptor *fdesc = malloc(sizeof(struct file_descriptor));
				fdesc->fd = cur->fd_counter;
				(cur->fd_counter)++;
				fdesc->fdesc_file = opened_file;
				fdesc->fdesc_fd_buf = NULL;    // nothing in buffer when the file is opened
				list_push_back(&cur->fd_list, &fdesc->fdesc_elem);
				f->eax = fdesc->fd;
			}	
			break;
			

		case SYS_FILESIZE:
			break;

		case SYS_READ:
			{
				//printf("LC: Inside read syscall\n");
				int arg_fd = *((int*)args_refs[0]);
				char* arg_buf = (char*)(*((int*)args_refs[1]));
				unsigned arg_size = *((unsigned*)args_refs[2]);

				if(arg_fd == 1){
					//write operation is invalid in read syscall
					f->eax = -1;
				}
				else if(arg_fd == 0){
					//standard input read
					f->eax = input_getc();
				}
				else{

				}
			}
			break;

		case SYS_WRITE:
			{
				//printf("LC: Inside write syscall\n");
				int arg_fd = *((int*)args_refs[0]);
				char* arg_buf = (char*)(*((int*)args_refs[1]));
				unsigned arg_size = *((unsigned*)args_refs[2]);
	  			//printf("fd - %d \n buf - %s \nsize - %d\n", arg_fd, arg_buf, arg_size);

	  			if(arg_fd == 0){
	  				// read operation is invalid in write syscall
	  				f->eax = -1;
	  			}
	  			else if(arg_fd == 1){
	  				//console write
	  				if(arg_size > STDOUT_LIMIT){
	  					putbuf(arg_buf, STDOUT_LIMIT);
						f->eax = STDOUT_LIMIT;
	  				}
	  				else{
	  					putbuf(arg_buf, arg_size);
	  					f->eax = arg_size;
	  				}
					
				}
				else{
					//child-parent buffer write
					f->eax = 0;
					struct list_elem *elem;
					struct thread *cur = thread_current();
					for(elem = list_begin(&cur->fd_list); elem != list_end(&cur->fd_list); elem = list_next(elem)){
						struct file_descriptor *fdesc = list_entry(elem, struct file_descriptor, fdesc_elem);
						if(fdesc->fd == arg_fd){
							if(fdesc->fdesc_fd_buf == NULL && !(fdesc->fdesc_file->deny_write)){
								f->eax = file_write(fdesc->fdesc_file, arg_buf, arg_size);
							}
							else{
								//if the buffer contains data
								int i = 0;
								lock_acquire(&fdesc->fdesc_fd_buf->fd_buffer_lock);
								while (i < arg_size && fdesc->fdesc_fd_buf->buf_end != MAX_BUF_SIZE) {
						          fdesc->fdesc_fd_buf->fd_buffer[fdesc->fdesc_fd_buf->buf_end] = arg_buf[i];
						          fdesc->fdesc_fd_buf->buf_end++;
						          i++;
						        }
								lock_release(&fdesc->fdesc_fd_buf->fd_buffer_lock);
								f->eax = i;
							}
							break;    // break the for loop
						}
					}
					

				}
			}
			break;

		case SYS_SEEK:
			break;

		case SYS_TELL:
			break;

		case SYS_CLOSE:
			break;


		default:
			printf("LC: SYSCALL did not match any of the cases\n");
			break;
	}

  // printf ("system call!\n");
  // thread_exit ();
}
