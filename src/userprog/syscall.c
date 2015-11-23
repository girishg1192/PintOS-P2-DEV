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

#define STDOUT 1
#define STDIN 0
#define SUCCESS 0
#define ERROR -1

static void syscall_handler (struct intr_frame *);
int find_file_from_fd(int , struct open_file_info *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  int syscall_number;
  uint32_t *esp_top = f->esp;

  //hex_dump(0, f->esp, PHYS_BASE - f->esp, true);

  syscall_number = *esp_top;
//printf("arg = %d\n", syscall_number);
  switch(syscall_number)
  {
    case SYS_WRITE: f->eax = write(esp_top);
                    break;
    case SYS_EXIT: exit(esp_top);
                   break;
    case SYS_OPEN: f->eax = open(esp_top);
                   break;
    case SYS_CLOSE: close(esp_top);
                    break;
    case SYS_READ: f->eax = read(esp_top);
                    break;
    case SYS_WAIT: break;
  }
}

int find_file_from_fd(int fd, struct open_file_info *file_info)
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
      file_info = temp;
      return SUCCESS;
    }
  }
    return ERROR;
}  

void exit(uint32_t* esp)
{
  int ret;
  struct thread *t=thread_current();
  struct thread_info *i = t->info, *temp;
  struct list_elem *e;
  char *file_name, *tempa;
  esp++;
  ret = *esp;
  printf("%s: exit(%d)\n", t->name, ret);
  for (e = list_begin (&i->child_list); e != list_end (&i->child_list);
      e = list_next (e))
  {
    temp = list_entry (e, struct thread_info, elem);
    temp->is_parent_alive = false;
    if(!temp->is_alive)
    {
      free(temp);
    }
  }
  if(i->is_parent_alive)
  {
    i->is_alive = false;
    i->exit_status = ret;
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

int write(uint32_t *esp)
{
  int fd=*(++esp);
  void *buffer = (void *)(*(++esp));
  unsigned size = *(++esp);

  struct open_file_info *file_info = NULL;

  if(fd == STDOUT)
  {
    putbuf((char *)buffer, size);
    return size;
  }
  else if(fd == STDIN)
    return ERROR;

  if(find_file_from_fd(fd, file_info) < 0)
    return ERROR;

  size = file_write(file_info->fp, buffer, size);

  return size;
}

int read(uint32_t *esp)
{
  int fd=*(++esp);
  void *buffer = (void *)(*(++esp));
  unsigned size = *(++esp);

  struct open_file_info *file_info = NULL;

  if(fd == STDIN)
  {
    putbuf((char *)buffer, size);
    return size;
  }
  else if(fd == STDOUT)
    return ERROR;

  if(find_file_from_fd(fd, file_info) < 0)
    return ERROR;

  size = file_read(file_info->fp, buffer, size);

  return size;
}

int open(uint32_t *esp)
{
  struct thread *t= thread_current();
  struct open_file_info *f1 = (struct open_file_info*) 
                                  malloc(sizeof(struct open_file_info));
  char *file_name = (char *)(*(++esp));

  //printf("%d file_name = %s\n", t->fd, file_name);
  f1->fp = filesys_open(file_name);
  if(f1->fp == NULL)
    return ERROR;

  f1->fd = (t->fd)++;

  list_push_back(&(t->open_file), &(f1->elem));
  return f1->fd;
}

void close(uint32_t *esp)
{
  int fd = *(++esp);
  struct open_file_info *file_info= NULL;

  if(find_file_from_fd(fd, file_info) == SUCCESS)
  {
    file_close(file_info->fp);
    list_remove(&file_info->elem);
    free(file_info);
  }
}

int wait(uint32_t *esp)
{
  int pid = *(++esp);
  int ret = process_wait(pid);
  //printf("ret stat %d", ret);
  return ret;
}
