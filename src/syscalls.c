#include <stdint.h>
#include <sys/syscall.h>

#include "syscalls.h"

int errno = 0;

/* Architecture-specific definitions */
#ifdef __x86_64__
# define SA_RESTORER                                0x04000000

# define SYSCALL0(num)                              ({ unsigned long long _ret; asm volatile ("syscall\n\t" : "=a"(_ret) : "0"(num) : "memory", "cc", "r11", "cx"); (_ret); })
# define SYSCALL1(num, a1)                          ({ unsigned long long _ret; register __typeof__(a1) _a1 asm ("rdi") = a1; asm volatile ("syscall\n\t" : "=a"(_ret) : "0"(num), "r"(_a1) : "memory", "cc", "r11", "cx"); (_ret); })
# define SYSCALL2(num, a1, a2)                      ({ unsigned long long _ret; register __typeof__(a1) _a1 asm ("rdi") = a1; register __typeof__(a2) _a2 asm ("rsi") = a2; asm volatile ("syscall\n\t" : "=a"(_ret) : "0"(num), "r"(_a1), "r"(_a2) : "memory", "cc", "r11", "cx"); (_ret); })
# define SYSCALL3(num, a1, a2, a3)                  ({ unsigned long long _ret; register __typeof__(a1) _a1 asm ("rdi") = a1; register __typeof__(a2) _a2 asm ("rsi") = a2; register __typeof__(a3) _a3 asm ("rdx") = a3; asm volatile ("syscall\n\t" : "=a"(_ret) : "0"(num), "r"(_a1), "r"(_a2), "r"(_a3) : "memory", "cc", "r11", "cx"); (_ret); })
# define SYSCALL4(num, a1, a2, a3, a4)              ({ unsigned long long _ret; register __typeof__(a1) _a1 asm ("rdi") = a1; register __typeof__(a2) _a2 asm ("rsi") = a2; register __typeof__(a3) _a3 asm ("rdx") = a3; register __typeof__(a4) _a4 asm ("r10") = a4; asm volatile ("syscall\n\t" : "=a"(_ret) : "0"(num), "r"(_a1), "r"(_a2), "r"(_a3), "r"(_a4) : "memory", "cc", "r11", "cx"); (_ret); })
# define SYSCALL5(num, a1, a2, a3, a4, a5)          ({ unsigned long long _ret; register __typeof__(a1) _a1 asm ("rdi") = a1; register __typeof__(a2) _a2 asm ("rsi") = a2; register __typeof__(a3) _a3 asm ("rdx") = a3; register __typeof__(a4) _a4 asm ("r10") = a4; register __typeof__(a5) _a5 asm ("r8") = a5; asm volatile ("syscall\n\t" : "=a"(_ret) : "0"(num), "r"(_a1), "r"(_a2), "r"(_a3), "r"(_a4), "r"(_a5) : "memory", "cc", "r11", "cx"); (_ret); })
# define SYSCALL6(num, a1, a2, a3, a4, a5, a6)      ({ unsigned long long _ret; register __typeof__(a1) _a1 asm ("rdi") = a1; register __typeof__(a2) _a2 asm ("rsi") = a2; register __typeof__(a3) _a3 asm ("rdx") = a3; register __typeof__(a4) _a4 asm ("r10") = a4; register __typeof__(a5) _a5 asm ("r8") = a5; register __typeof__(a6) _a6 asm ("r9") = a6; asm volatile ("syscall\n\t" : "=a"(_ret) : "0"(num), "r"(_a1), "r"(_a2), "r"(_a3), "r"(_a4), "r"(_a5), "r"(_a6) : "memory", "cc", "r11", "cx"); (_ret); })
#else
# error "Unsupported architecture!"
#endif

#define SET_ERRNO(x)                                ({intptr_t r = (intptr_t)x; if (r < 0 && r > -4096) { errno = r & 4095; r = -1; } (__typeof__(x))r; })

int my_arch_prctl(int code, unsigned long addr) {
    return SET_ERRNO(SYSCALL2(SYS_arch_prctl, code, addr));
}

int my_close(int fd) {
    return SET_ERRNO(SYSCALL1(SYS_close, fd));
}

int my_fstat(int fd, struct stat *buf) {
    return SET_ERRNO(SYSCALL2(SYS_fstat, fd, buf));
}

pid_t my_getpid() {
    return SET_ERRNO(SYSCALL0(SYS_getpid));
}

pid_t my_gettid() {
    return SET_ERRNO(SYSCALL0(SYS_gettid));
}

void *my_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
    return SET_ERRNO((void *)SYSCALL6(SYS_mmap, addr, length, prot, flags, fd, offset));
}

int my_mprotect(void *addr, size_t len, int prot) {
    return SET_ERRNO(SYSCALL3(SYS_mprotect, addr, len, prot));
}

int my_munmap(void *addr, size_t length) {
    return SET_ERRNO(SYSCALL2(SYS_munmap, addr, length));
}

int my_openat(int dirfd, const char *pathname, int flags, mode_t mode) {
    return SET_ERRNO(SYSCALL4(SYS_openat, dirfd, pathname, flags, mode));
}

int my_tgkill(int tgid, int tid, int sig) {
    return SET_ERRNO(SYSCALL3(SYS_tgkill, tgid, tid, sig));
}

int my_rt_sigaction(int signum, const struct kernel_sigaction *act, struct kernel_sigaction *old_act, size_t set_sz) {
    return SET_ERRNO(SYSCALL4(SYS_rt_sigaction, signum, act, old_act, set_sz));
}

ssize_t my_write(int fd, const void *buf, size_t count) {
    return SET_ERRNO(SYSCALL3(SYS_write, fd, buf, count));
}
