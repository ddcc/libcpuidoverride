#include <signal.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "library.h"
#include "syscalls.h"

extern const char **envp;

#ifdef __x86_64__
# define STRINGIFY_(x)                              #x
# define STRINGIFY(x)                               STRINGIFY_(x)

# define SA_RESTORER                                0x04000000

/* See RESTORE2 in glibc/sysdeps/unix/sysv/linux/<arch>/sigaction.c */
void __restore_rt();

__asm__ ("\n\
    .global __restore_rt\n\
    .type __restore_rt,@function\n\
__restore_rt:\n\
    mov $" STRINGIFY(SYS_rt_sigreturn) ", %eax\n\
    syscall\n\
");
#else
# error "Unsupported architecture!"
#endif

void my_abort() {
    // FIXME: Unblock SIGABRT
    my_tgkill(my_getpid(), my_gettid(), SIGABRT);
}

const char *my_getenv(const char *name) {
    const char **env = envp;

    while (*env) {
        if (!my_strcmp(*env, name)) {
            size_t len = my_strlen(name);
            if ((*env)[len] == '=')
                return &(*env)[len + 1];
        }

        ++env;
    }

    return NULL;
}

int my_memcmp(const void *ptr1, const void *ptr2, size_t sz) {
    for (unsigned int i = 0; i < sz; ++i) {
        const uint8_t p1 = ((const uint8_t *)ptr1)[i], p2 = ((const uint8_t *)ptr2)[i];
        if (p1 != p2)
            return p1 < p2 ? -1 : 1;
    }

    return 0;
}

int my_putchar(int character) {
    uint8_t c = character;

    if (my_write(STDOUT_FILENO, &c, 1) < 0)
        return EOF;

    return character;
}

int my_puts(const char *str) {
    if (my_write(STDOUT_FILENO, str, my_strlen(str)) < 0)
        return EOF;

    if (my_putchar('\n') == EOF)
        return EOF;

    return 1;
}

int my_sigaction(int signum, const struct sigaction *act, struct sigaction *old_act) {
    struct kernel_sigaction kact, kold_act;

    if (act) {
        kact.k_sa_handler = act->sa_handler;
#ifdef __x86_64__
        kact.sa_flags = act->sa_flags | SA_RESTORER;
        kact.sa_restorer = __restore_rt;
#else
        kact.sa_flags = act->sa_flags;
#endif /* __x86_64__ */
        kact.sa_mask = act->sa_mask;
    }

    /* Note: Documentation says to use sizeof(sigset_t) = 128, but this will result in -EINVAL */
    /* See __libc_sigaction in glibc/sysdeps/unix/sysv/linux/sigaction.c */
    int ret = my_rt_sigaction(signum, &kact, old_act ? &kold_act : NULL, NSIG / 8);

    if (ret && old_act) {
        old_act->sa_handler = kold_act.k_sa_handler;
#ifdef __x86_64__
        old_act->sa_flags = kold_act.sa_flags & ~SA_RESTORER;
#else
        old_act->sa_flags = kold_act.sa_flag;
#endif /* __x86_64__ */
        old_act->sa_mask = kold_act.sa_mask;
    }

    return ret;
}

int my_strcmp(const char *str1, const char *str2) {
    char c1, c2;

    while ((c1 = *str1++) && (c2 = *str2++)) {
        if (c1 != c2)
            return c1 < c2 ? -1 : 1;
    }

    return 0;
}

size_t my_strlen(const char *str) {
    size_t sz = 0;

    while (*str++)
        ++sz;

    return sz;
}

void my_strncpy(char *dst, const char *src, size_t sz) {
    int done = 0;

    for (unsigned int i = 0; i < sz; ++i) {
        if (!done) {
            const char c = src[i];
            done = !c;
            dst[i] = c;
        } else
            dst[i] = '\0';
    }
}
