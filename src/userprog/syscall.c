#include "userprog/syscall.h"
#include "userprog/process.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/malloc.h"
#include "devices/shutdown.h"

#define STDOUT 1
#define STDIN 0
#define SUCCESS 0
#define ERROR -1

#define FILE_SYNC_BARRIER lock_acquire(&fileops_sync);
#define FILE_SYNC_BARRIER_END lock_release(&fileops_sync);

static void syscall_handler (struct intr_frame *);
int find_file_from_fd(int , struct open_file_info **);
struct lock fileops_sync;

bool check_pointer(void* ptr);
bool check_buffer(void *buffer, int size);

void
syscall_init (void) 
{
  lock_init(&fileops_sync);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  int syscall_number=-1;
  uint32_t *esp_top = f->esp;

  if(!check_pointer((void *)esp_top))
    exit(ERROR);
  syscall_number = *esp_top++;

  switch(syscall_number)
  {
    case SYS_WRITE: if(!check_pointer((void *)esp_top+1))
                      exit(ERROR);
                    f->eax = write((int)(*esp_top), (void *)(*(esp_top+1)), (unsigned) *(esp_top+2) );
                    break;
    case SYS_EXIT: if(!check_pointer((void *)esp_top))
                     exit(ERROR);
                   exit(*esp_top);
                   break;
    case SYS_OPEN: if(!check_pointer((void *)esp_top))
                     exit(ERROR);
                   f->eax = open((const char *) *esp_top);
                   break;
    case SYS_CLOSE: close((int) *esp_top);
                   break;
    case SYS_READ: f->eax = read((int)(*esp_top), (void *)(*(esp_top+1)), (unsigned) *(esp_top+2) );
                   break;
    case SYS_WAIT: f->eax = wait((int)*esp_top);
                   break;
    case SYS_HALT: halt();
                   break;
    case SYS_EXEC: if(!check_pointer(esp_top))
                     exit(ERROR);
                   f->eax = exec((const char *) *esp_top);
                   break;
    case SYS_CREATE: f->eax = create((const char *) *esp_top, (unsigned) *(esp_top+1));
                     break;
    case SYS_REMOVE: f->eax = remove((const char *) *esp_top);
                     break;
    case SYS_FILESIZE: f->eax = filesize((int) *esp_top);
                       break;
    case SYS_SEEK: seek((int)*esp_top, (unsigned) *(esp_top+1));
                   break;
    case SYS_TELL: f->eax = tell((int)*esp_top);
                   break;
  }
}

/* Function to find the open file information
 * Arguments: file descriptor (fd), pointer to open_file_info
 * Matching file information stored in file_info argument
 *
 * Mapping file descriptor integers to file structure
 * Each thread maintains an open_file list in the thread 
 * structure, traverse the list, and find the open file 
 * with the passed fd.
 * If such a file is found, return SUCCESS(0) and store result
 * in file_info, else return -1
 */
int find_file_from_fd(int fd, struct open_file_info **file_info)
{
  struct thread *t = thread_current();
  struct list_elem *iter;
  struct open_file_info *temp;


  for(iter = list_begin(&t->open_file); iter != list_end(&t->open_file);
      iter = list_next(iter))
  {
    temp = list_entry(iter, struct open_file_info, elem);
    if(temp->fd == fd)
    {
      *file_info = temp;
      return SUCCESS;
    }
  }
    return ERROR;
}

/*
 * Exit system call
 *
 * Exit performs
 * 1. Orphaning any child thread: For each child thread
 * is_parent_alive in thread_info set to false, and child
 * is removed from the parents child list. If the child is
 * dead parent frees any memory allocated to child threads
 * thread_info
 * 2. Signalling exit status to parent thread: If the 
 * Parent thread is alive, change child status to dead 
 * is_alive=false, and write exit status to memory
 * If the parent is terminated, free any memory associated
 * to the child process
 * 3. Closing open files: For each thread, close all open
 * files that have not been closed by the user program
 *
 * finally thread_exit is called, thus terminating the thread
 */
void exit(int status)
{
  struct thread *t=thread_current();
  struct thread_info *i = t->info, *temp;
  struct open_file_info *free_files;
  struct list_elem *e;
  printf("%s: exit(%d)\n", t->name, status);
  for (e = list_begin (&i->child_list); e != list_end (&i->child_list);)
  {
    temp = list_entry (e, struct thread_info, elem);
    temp->is_parent_alive = false;
    if(!temp->is_alive)
    {
      e = list_remove(&temp->elem);
      free(temp);
    }
    else
      e = list_next(e);
  }
  if(i->is_parent_alive)
  {
    i->is_alive = false;
    i->exit_status = status;
    sema_up(&i->wait_sem);
  }
  else
  {
    list_remove(&i->elem);
    free(i);
  }

  //Freeing files
  for (e = list_begin (&t->open_file); e != list_end (&t->open_file);)
  {
    free_files = list_entry(e, struct open_file_info, elem);
    file_close(free_files->fp);
    e = list_remove(&free_files->elem);
    free(free_files);
  }
  thread_exit ();
}

/* Write syscall
 * Writes size number of items from buffer to the file
 * associated with fd
 *
 * if fd is STDOUT write to console
 * for fd>=2 find the file related to it, and write
 * returns the number of bytes successfully written
 * returns an error in case of invalid buffer,
 * invalid fd, NULL buffer
 */
int write(int fd, void *buffer, unsigned size)
{
  struct open_file_info *file_info = NULL;

  if(buffer == NULL)
  {
    return ERROR;
  }
  if(!check_buffer((void *) buffer, size))
  {
    exit(ERROR);
  }

  if(fd == STDOUT)
  {
    putbuf((char *)buffer, size);
    return size;
  }
  else if(fd == STDIN)
    return ERROR;

  if(find_file_from_fd(fd, &file_info) < 0)
  {
    return ERROR;
  }
    FILE_SYNC_BARRIER 
    size = file_write(file_info->fp, buffer, size);
    FILE_SYNC_BARRIER_END
  
  return size;
}

/* Read syscall
 * Read size number of items from buffer to the file
 * associated with fd
 *
 * if fd is STDIN read from console
 * for fd>=2 find the file related to it, and read 
 * returns the number of bytes successfully read 
 * returns an error in case of invalid buffer,
 * invalid fd, NULL buffer
 */
int read(int fd, void *buffer, unsigned size)
{

  struct open_file_info *file_info = NULL;
  int iter;

  if(buffer == NULL)
    return ERROR;
  
  if(!check_buffer(buffer, size))
    exit(ERROR);

  if(fd == STDIN)
  {
    for(iter = 0; iter<size; iter++)
      //TODO
      //buffer[iter]=input_getc();
    return size;
  }
  else if(fd == STDOUT)
    return ERROR;

  if(find_file_from_fd(fd, &file_info) < 0)
    return ERROR;

  size = file_read(file_info->fp, buffer, size);

  return size;
}
/* Open syscall
 * Argument: A pointer containing the name
 * of the file to be opened
 * Function opens the file, stores the file pointer,
 * file descriptor in an open_file_info structure
 * and adds it to the list of open files for the
 * process
 * Return value: value of the file descriptor assigned
 * to the file
 * returns an error in case of an invalid file/file_open
 * error
 */
int open(const char *file_name)
{
  struct thread *t= thread_current();
  struct open_file_info *f1 = (struct open_file_info*) 
                                  malloc(sizeof(struct open_file_info));

  if(!check_pointer((void *) file_name))
    exit(ERROR);
    

  if(file_name == NULL)
  {
    free(f1);
    return ERROR;
  }
  f1->fp = filesys_open(file_name);

  if(f1->fp == NULL)
  {
    free(f1);
    return ERROR;
  }

  f1->fd = (t->fd)++;

  list_push_back(&t->open_file, &f1->elem);
  return f1->fd;
}
/* Close systemcall
 * Argument: File descriptor(fd)
 * closes the file associated to the file descriptor
 * The function finds the file associated to the file
 * descriptor and closes it, the file is then removed
 * from the open file list and the open_file_info structure
 * is freed
 */
void close(int fd)
{
  struct open_file_info *file_info ;//= (struct open_file_info *) 
                                    //      malloc(sizeof(struct open_file_info));

  if(find_file_from_fd(fd, &file_info) == SUCCESS)
  {
    FILE_SYNC_BARRIER
    file_close(file_info->fp);
    FILE_SYNC_BARRIER_END

    list_remove(&file_info->elem);
    free(file_info);
  }
}
/* Wait syscall
 * Arguments: child_pid for which the process waits
 * The function waits for the child process to exit
 * and returns the exit status of the child thread
 */
int wait(int pid)
{
  int ret = process_wait(pid);
  return ret;
}
/* Halt systemcall
 * Shuts down the kernel
 */
void halt()
{
  shutdown_power_off();
}
/* Exec syscall
 * Arguments: file name for the file to be executed
 * Function calls process_execute to execute
 */
int exec(const char *file_name)
{
  int pid;
  if(!check_pointer((void *)file_name))
    exit(ERROR);
  pid = process_execute(file_name);
  return pid;
}
/* Create syscall
 * Arguments: pointer containing the file to be created,
 * unsigned value of the initial size of the file
 * creates a file in the filesystem and returns true,
 * if successfully created, ERROR otherwise
 */
bool create(const char *file, unsigned initial_size)
{
  int ret;
  if(file == NULL)
    exit(ERROR);

  if(!check_pointer((void *)file))
    exit(ERROR);

  FILE_SYNC_BARRIER
  ret = filesys_create(file, initial_size);
  FILE_SYNC_BARRIER_END

  return ret;
}
/* Remove syscall
 * Arguments: pointer containing the file to be removed
 * Function removes the file from the filesystem
 * returns true if the file was successfully removed
 */
bool remove(const char *file)
{
  bool ret;

  FILE_SYNC_BARRIER
    ret = filesys_remove(file);
  FILE_SYNC_BARRIER_END

  return ret;
}

/* seek syscall
 * Arguments: file descriptor(int), position in file to seek to
 * Function advances the file pointer to the position passed,
 * File is found from the open list from the fd.
 */
void seek(int fd, unsigned position)
{
  struct open_file_info *file_info = NULL;

  if(!find_file_from_fd(fd, &file_info))
  {
    file_seek(file_info->fp, position);
  }
}
/* tell syscall
 * Arguments: file descriptor
 * Function returns the current position of the file pointer
 */
unsigned tell(int fd)
{
  int position;
  struct open_file_info *file_info = NULL;

  if(!find_file_from_fd(fd, &file_info))
  {
    position = file_tell(file_info->fp);
  }
  return position;
}
/* filesize syscall
 * Arguments: file descriptor
 * Function returns the size of the file associated to the
 * file descriptor
 */
int filesize(int fd)
{
  struct open_file_info *file_info = NULL;

  if(find_file_from_fd(fd, &file_info) < 0)
    return ERROR;
  return file_length(file_info->fp);
}
/*
 * Checks if the pointer is in user space
 * Checks if the pointer is mapped to a page
 * returns false if any of the conditions fail
 */
bool check_pointer(void* ptr)
{
  if(!is_user_vaddr(ptr))
  {
    return false;
  }
  if(pagedir_get_page(thread_current()->pagedir, ptr) == NULL)
  {
    return false;
  }
  return true;
}
/*
 * Checks if the entire buffer is in user space
 * Checks if the entire buffer is mapped to a page
 * returns false if any of the conditions fail
 */
bool check_buffer(void *buffer, int size)
{
  int iter=size;
  void *buffer_test = buffer;
  uint32_t *pagedir = thread_current()->pagedir;
  for(iter = 0; iter<size-1; iter++)
  {
    buffer_test++;
    if(!is_user_vaddr(buffer_test))
    {
      return false;
    }
    if(pagedir_get_page(pagedir, buffer_test) == NULL)
    {
      return false;
    }
  }
  return true;
}
