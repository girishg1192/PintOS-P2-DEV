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

static void syscall_handler (struct intr_frame *);
int find_file_from_fd(int , struct open_file_info **);

bool check_pointer(void* ptr);
bool check_buffer(void *buffer, int size);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  int syscall_number=-1;
  uint32_t *esp_top = f->esp;

  //hex_dump(0, f->esp, PHYS_BASE - f->esp, true);

  if(!check_pointer(esp_top))
    exit(ERROR);
  syscall_number = *esp_top++;

  switch(syscall_number)
  {
    case SYS_WRITE: f->eax = write((int)(*esp_top), (void *)(*(esp_top+1)), (unsigned) *(esp_top+2) );
                    break;
    case SYS_EXIT: if(!check_pointer(esp_top))
                     exit(ERROR);
                   exit(*esp_top);
                   break;
    case SYS_OPEN: if(!check_pointer(esp_top))
                     exit(ERROR);
                   f->eax = open((const char *) *esp_top);
                   break;
    case SYS_CLOSE: //if(!check_pointer(esp_top));
                     // exit(-1);
                    close(*esp_top);
                    break;
    case SYS_READ: f->eax = read((int)(*esp_top), (void *)(*(esp_top+1)), (unsigned) *(esp_top+2) );
                   break;
    case SYS_WAIT: f->eax = wait(*esp_top);
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
    case SYS_FILESIZE: f->eax = filesize(*esp_top);
                       break;
    case SYS_SEEK: seek(*esp_top, (unsigned) *(esp_top+1));
                   break;
    case SYS_TELL: f->eax = tell(esp_top);
                   break;
  }
}

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

void exit(int status)
{
  struct thread *t=thread_current();
  struct thread_info *i = t->info, *temp;
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
  process_exit();
  thread_exit ();
}

int write(int fd, void *buffer, unsigned size)
{
  struct open_file_info *file_info = NULL;

  if(buffer == NULL)
  {
    return ERROR;
  }
  
  if(!check_buffer(buffer, size))
    exit(ERROR);

  if(fd == STDOUT)
  {
    putbuf((char *)buffer, size);
    return size;
  }
//  else if(fd == STDIN)
//    return ERROR;

  if(find_file_from_fd(fd, &file_info) < 0)
  {
    return ERROR;
  }

  size = file_write(file_info->fp, buffer, size);

  return size;
}

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

int open(const char *file_name)
{
  struct thread *t= thread_current();
  struct open_file_info *f1 = (struct open_file_info*) 
                                  malloc(sizeof(struct open_file_info));

  /*if(!is_user_vaddr(file_name))
  {
    return ERROR;
  }
  */
  if(!check_pointer((void *) file_name))
    exit(ERROR);
    

  if(file_name == NULL)
    return ERROR;
  f1->fp = filesys_open(file_name);
  if(f1->fp == NULL)
    return ERROR;

  f1->fd = (t->fd)++;

  //printf("f1->fd = %d 0x%x\n", f1->fd, f1->fp);
  list_push_back(&t->open_file, &f1->elem);
  return f1->fd;
}

void close(int fd)
{
  struct open_file_info *file_info ;//= (struct open_file_info *) 
                                    //      malloc(sizeof(struct open_file_info));

  //printf("fd = %d 0x%x\n", fd, file_info);

  if(find_file_from_fd(fd, &file_info) == SUCCESS)
  {
    file_close(file_info->fp);
    list_remove(&file_info->elem);
    free(file_info);
  }
}

int wait(int pid)
{
  int ret = process_wait(pid);
  return ret;
}
void halt()
{
  shutdown_power_off();
}
int exec(const char *file_name)
{
  int pid;
  if(!check_pointer(file_name))
    exit(ERROR);
  pid = process_execute(file_name);
  return pid;
  //TODO
  //sem_down( thread_current()->child->sem
}
bool create(const char *file, unsigned initial_size)
{
  int ret;
  if(file == NULL || initial_size < 0)
    exit(ERROR);

  if(!check_pointer(file))
    exit(ERROR);
  ret = filesys_create(file, initial_size);
  return ret;
}
bool remove(const char *file)
{
  //const char *file = (const char *)(*(++esp));
  return false;
}

void seek(int fd, unsigned position)
{

  struct open_file_info *file_info = NULL;

  if(find_file_from_fd(fd, &file_info) > 0)
  {
    file_seek(file_info, position);
  }
  //
}
unsigned tell(uint32_t *esp)
{
  //
}

int filesize(int fd)
{
  struct open_file_info *file_info = NULL;

  if(find_file_from_fd(fd, &file_info) < 0)
    return ERROR;
  return file_length(file_info->fp);

}

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
