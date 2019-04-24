#ifndef __STDLIB_H__
#define __STDLIB_H__

#include <signal.h>
#include <stdio.h>

void my_abort();

const char *my_getenv(const char *name);

int my_memcmp(const void *ptr1, const void *ptr2, size_t sz);

int my_putchar(int character);

int my_puts(const char *str);

int my_sigaction(int signum, const struct sigaction *act, struct sigaction *old_act);

int my_strcmp(const char *str1, const char *str2);

size_t my_strlen(const char *str);

void my_strncpy(char *dst, const char *src, size_t sz);

#endif /* __STDLIB_H__ */
