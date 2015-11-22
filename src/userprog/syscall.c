#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

static void syscall_handler (struct intr_frame *);

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

  //printf("\nesp= 0x%x\n%d\n", f->esp, PHYS_BASE - f->esp);
//  hex_dump(0, f->esp, PHYS_BASE - f->esp, true);

  syscall_number = *esp_top;
//printf("0x%x value=%d\n", esp_top, *esp_top);
  //printf("arg = %d\n", syscall_number);
  switch(syscall_number)
  {
    case SYS_WRITE: syscall_write(esp_top);
                    break;
    case SYS_EXIT: syscall_exit(esp_top);
                   break;
  }
//  printf ("system call!\n");
}

void syscall_exit(int* esp)
{
  struct thread *t=thread_current();
  esp++;
  int return_value = *esp;
  printf("%s exit(%d)\n", t->name, *esp);
  thread_exit ();
}

void syscall_write(int *esp)
{
  int fd=*(++esp);
  void *buffer = (void *)(*(++esp));
  char *start;
  unsigned size = *(++esp);

//  for(start = buffer; start < buffer + size ; start)
//    printf("%c", (char *)buffer);

  if(fd)
    putbuf((char *)buffer, size);

  //printf("\n%d 0x%x %d\n", fd, buffer, size);
}
