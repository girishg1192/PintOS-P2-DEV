#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stdint.h>
#include <stdbool.h>

void syscall_init (void);

//Syscall implementation
void exit(int);
int write(int , void *, unsigned);
int read(int, void *, unsigned);
int open(const char *);
void close(int);
int wait(int);
void halt();
int exec(const char *);
bool create(const char *, unsigned );
bool remove(const char *);
int filesize(int);
void seek(int,unsigned);
unsigned tell(uint32_t*);

//int find_file_from_fd(int fd, struct open_file_info *file_info);

#endif /* userprog/syscall.h */
