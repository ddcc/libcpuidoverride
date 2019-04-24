#ifndef __SYSCALLS_H__
#define __SYSCALLS_H__

#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>

#ifdef __x86_64__
struct kernel_sigaction {
  __sighandler_t k_sa_handler;
  unsigned long sa_flags;
  void (*sa_restorer) (void);
  sigset_t sa_mask;
};
#else
# error "Unsupported architecture!"
#endif

int my_arch_prctl(int code, unsigned long addr);

int my_close(int fd);

int my_fstat(int fd, struct stat *buf);

pid_t my_getpid();

pid_t my_gettid();

void *my_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);

int my_mprotect(void *addr, size_t len, int prot);

int my_munmap(void *addr, size_t length);

int my_openat(int dirfd, const char *pathname, int flags, mode_t mode);

int my_tgkill(int tgid, int tid, int sig);

int my_rt_sigaction(int signum, const struct kernel_sigaction *act, struct kernel_sigaction *old_act, size_t set_sz);

ssize_t my_write(int fd, const void *buf, size_t count);

#endif /* __SYSCALLS_H__ */
