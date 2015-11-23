#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stdint.h>

void syscall_init (void);

//Syscall implementation
void exit(uint32_t *);
int write(uint32_t *);
int read(uint32_t *);
int open(uint32_t *);
void close(uint32_t *);
int wait(uint32_t *);
//int find_file_from_fd(int fd, struct open_file_info *file_info);

#endif /* userprog/syscall.h */
