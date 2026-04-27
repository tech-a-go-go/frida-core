#ifndef __SUNDAY_SYSCALL_H__
#define __SUNDAY_SYSCALL_H__

#ifndef NOLIBC
# include <unistd.h>
#endif
#include <sys/syscall.h>

#define sunday_syscall_0(n)          sunday_syscall_4 (n, 0, 0, 0, 0)
#define sunday_syscall_1(n, a)       sunday_syscall_4 (n, a, 0, 0, 0)
#define sunday_syscall_2(n, a, b)    sunday_syscall_4 (n, a, b, 0, 0)
#define sunday_syscall_3(n, a, b, c) sunday_syscall_4 (n, a, b, c, 0)

ssize_t sunday_syscall_4 (size_t n, size_t a, size_t b, size_t c, size_t d);

#endif
