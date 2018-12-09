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
#include "threads/vaddr.h"

#define MAX_ARGS_COUNT 3
#define STDOUT_LIMIT 100    // setting an arbitrary limit of bytes to be written

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

    //printf("f->esp : %s    valid?:%d\n",f->esp, is_user_vaddr(f->esp));

    if(!(is_user_vaddr(f->esp)) || pagedir_get_page(thread_current()->pagedir, f->esp) == NULL)
	{
		printf("LC: Found an invalid stack pointer\n");
		f->eax = -1;
		system_exit(-1);
	}
	
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
				//printf("Enter sys exit\n");
				int status = *((int *) args_refs[0]);
				if(status < -1){
					status = -1;
				}
				system_exit(status);
			}
			break;

		case SYS_EXEC:
			{
				//printf("LC : Inside exec \n");
				char* copy_var;
				char* exec_prog = *((char **)args_refs[0]);
				//printf("LC: exec_prog : %s\n", exec_prog);

				
				copy_var = malloc(strlen(exec_prog) + 1);
				strlcpy(copy_var, exec_prog, PGSIZE);
				//printf("LC: Copy var created - %s\n",copy_var);

				char* save_ptr;
				copy_var = strtok_r(copy_var, " ", &save_ptr);
				//printf("Token : %s\n", copy_var);
				//printf("LC : Here");
				
				lock_acquire(&file_lock);
				struct file *opened_file = filesys_open(copy_var);

				if(opened_file == NULL){
					//printf("LC: There was an error in opening the file");
					f->eax = -1;
				}
				else{
					f->eax = process_execute(exec_prog);
				}
				file_close(opened_file);
				lock_release(&file_lock);
			}
			break;

		case SYS_WAIT:
			{
				int status = *((int *) args_refs[0]);
				f->eax = process_wait(status);
			}
			break;

		case SYS_CREATE:
			{
				char* arg_fileName = *((char **)args_refs[0]);
				unsigned arg_size = *((unsigned*)args_refs[1]);

				if(arg_fileName == NULL){
					//printf("LC : File name is null\n");
					f->eax = -1;
					system_exit(-1);
				}

				lock_acquire(&file_lock);
				f->eax = filesys_create(arg_fileName, arg_size);
				lock_release(&file_lock);

			}
			break;

		case SYS_REMOVE:
			{
				char* arg_fileName = *((char **)args_refs[0]);

				if(arg_fileName == NULL){
					//printf("LC : File name is null\n");
					f->eax = -1;
					system_exit(-1);
				}

				lock_acquire(&file_lock);
				f->eax = filesys_remove(arg_fileName);
				lock_release(&file_lock);
			}
			break;

		case SYS_OPEN:
			{
				char* arg_fileName = *((char **)args_refs[0]);
				//printf("LC: File name : %s\n",arg_fileName);
				if(arg_fileName == NULL){
					//printf("LC : File name is null\n");
					f->eax = -1;
					break;
				}

				lock_acquire(&file_lock);
				struct file *opened_file = filesys_open(arg_fileName);
				lock_release(&file_lock);

				if(opened_file == NULL){
					//printf("LC: There was an error in opening the file");
					f->eax = -1;
				        break;
				}

				struct thread *cur = thread_current();
				struct file_descriptor *fdesc = malloc(sizeof(struct file_descriptor));
                                fdesc->fd = cur->fd_counter;
				(cur->fd_counter)++;
				fdesc->fdesc_file = opened_file;
				//printf("LC: Before push\n");
				list_push_back(&cur->fd_list, &fdesc->fdesc_elem);
				//printf("LC: After push\n");
				f->eax = fdesc->fd;
			}	
			break;
			

		case SYS_FILESIZE:
			{
				f->eax = 0;
				int f_desc = *((int*)args_refs[0]);
				struct thread *curr_thread = thread_current();
				struct list_elem *e;

				for(e=list_begin(&curr_thread->fd_list);e!=list_end(&curr_thread->fd_list);e=list_next(e))
				{
					struct file_descriptor *f_curr = list_entry(e, struct file_descriptor,fdesc_elem);
					if(f_curr->fd==f_desc)
					{
						f->eax = file_length(f_curr->fdesc_file);
						break;
					}						
				}
			}
			break;

		case SYS_READ:
			{
				//printf("LC: Inside read syscall\n");
				int arg_fd = *((int*)args_refs[0]);
				char* arg_buf = (char*)(*((int*)args_refs[1]));
				unsigned arg_size = *((unsigned*)args_refs[2]);

				if(!(is_user_vaddr(arg_buf))){
					f->eax = -1;
					system_exit(-1);
				}
				else{
					if(arg_fd == 1){
						//write operation is invalid in read syscall
						f->eax = -1;
					}
					else if(arg_fd == 0){
						//standard input read
						for(int i=0;i<arg_size ;i++)
							arg_buf[i] = input_getc();
						f->eax = arg_size;
					}
					else{
						// file read
						f->eax = -1;    //the file descriptor was not found in the fd_list
						struct list_elem *elem;
						struct thread *cur = thread_current();
						for(elem = list_begin(&cur->fd_list); elem != list_end(&cur->fd_list); elem = list_next(elem)){
							struct file_descriptor *fdesc = list_entry(elem, struct file_descriptor, fdesc_elem);
							if(fdesc->fd == arg_fd){
								if(!(fdesc->fdesc_file->deny_write)){
									lock_acquire(&file_lock);
									f->eax = file_read(fdesc->fdesc_file, arg_buf, arg_size);
									lock_release(&file_lock);
								}
								break;    // break the for loop
							}
						}
					}
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

				if(!(is_user_vaddr(arg_buf))){
					f->eax = -1;
					system_exit(-1);
				}
				else{
					if(arg_fd == 0){
		  				// read operation is invalid in write syscall
		  				f->eax = -1;
		  			}
		  			else if(arg_fd == 1){
		  				// console write
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
						// file write
						f->eax = -1;    //the file descriptor was not found in the fd_list
						struct list_elem *elem;
						struct thread *cur = thread_current();
						for(elem = list_begin(&cur->fd_list); elem != list_end(&cur->fd_list); elem = list_next(elem)){
							struct file_descriptor *fdesc = list_entry(elem, struct file_descriptor, fdesc_elem);
							if(fdesc->fd == arg_fd){
								if(!(fdesc->fdesc_file->deny_write)){
									lock_acquire(&file_lock);
									f->eax = file_write(fdesc->fdesc_file, arg_buf, arg_size);
									lock_release(&file_lock);
								}
								break;    // break the for loop
							}
						}
					}
				}
			}
			break;

		case SYS_SEEK:
			{
				int f_desc = *((int *)args_refs[0]);
				unsigned new_pos = *((unsigned *) args_refs[1]);

				struct thread *curr_thread = thread_current();
				struct list_elem *e;
				for(e=list_begin(&curr_thread->fd_list);e!=list_end(&curr_thread->fd_list);e=list_next(e))
					{
						struct file_descriptor *f_curr = list_entry(e, struct file_descriptor,fdesc_elem);
						if(f_curr->fd==f_desc)
							{
								file_seek(f_curr->fdesc_file,new_pos);
								return;
							}
					}
			}
			break;

		case SYS_TELL:
			{
				int f_desc = *((int *)args_refs[0]);

				struct thread *curr_thread = thread_current();

				struct list_elem *e;

				for(e=list_begin(&curr_thread->fd_list);e!=list_end(&curr_thread->fd_list);e=list_next(e))

					{
						struct file_descriptor *f_curr = list_entry(e, struct file_descriptor,fdesc_elem);
						if(f_curr->fd==f_desc)
						{
							f->eax = f_curr->fdesc_file->pos;
							break;
						}						
					}
				f->eax = -1;
			}

			break;

		case SYS_CLOSE:
			{
				int f_desc = *((int *)args_refs[0]);

				struct thread *curr_thread = thread_current();

				struct list_elem *e;

				for(e=list_begin(&curr_thread->fd_list);e!=list_end(&curr_thread->fd_list);e=list_next(e))

					{
						struct file_descriptor *f_curr = list_entry(e, struct file_descriptor,fdesc_elem);

						if(f_curr->fd==f_desc)

							{
								list_remove(e);
								file_close(f_curr->fdesc_file);
							}
						free(f_curr);
						break;
					}
			}
			break;


		default:
		{
			printf("LC: SYSCALL did not match any of the cases\n");
			system_exit(-1);
		}
			break;
	}
  // printf ("system call!\n");
  // thread_exit ();
}

void system_exit(int exit_status){
    //printf("LC: Inside system_exit()\n");
    //printf("status = %d\n",exit_status);
    thread_current()->exec_status = exit_status;
    printf("%s: exit(%d)\n", thread_current()->name, exit_status);
    thread_exit();
}
