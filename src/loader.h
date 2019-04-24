#ifndef __LOADER_H__
#define __LOADER_H__

#include <elf.h>
#include <stdbool.h>

/* Architecture-specific definitions */
/* See linux/Documentation/x86/x86_64/mm.txt */
#ifdef __x86_64__
#define ELF_INTERPRETER                             "/lib64/ld-linux-x86-64.so.2"

# define GET_RANDOM_BASE(x)                         ((*(uint64_t *)x) & 0x7fffffffffffUL)
# define GET_ELF_MACHINE(x)                         ((x) == EM_X86_64)
typedef Elf64_Addr Elf_Addr;
typedef Elf64_Off Elf_Off;
typedef Elf64_Word Elf_Word;
typedef Elf64_Xword Elf_Xword;
typedef Elf64_auxv_t Elf_auxv_t;
typedef Elf64_Ehdr Elf_Ehdr;
typedef Elf64_Phdr Elf_Phdr;
#elif defined(__i386__)
#define ELF_INTERPRETER                             "/lib/ld-linux.so.2"

# define GET_RANDOM_BASE(x)                         ((*(uint32_t *)x) & 0xc0000000)
# define GET_ELF_MACHINE(x)                         ((x) == EM_386 || (x) == EM_486)
typedef Elf32_Addr Elf_Addr;
typedef Elf32_Off Elf_Off;
typedef Elf32_Word Elf_Word;
typedef Elf32_Word Elf_Xword;
typedef Elf32_auxv_t Elf_auxv_t;
typedef Elf32_Ehdr Elf_Ehdr;
typedef Elf32_Phdr Elf_Phdr;
#else
# error "Unsupported architecture!"
#endif

#define ALIGN(a, x)                                 ((a) & ~(unsigned long)((x) - 1))
#define ALIGN_UP(a, x)                              ALIGN((a) + (x) - 1, (x))

/* Workaround for older non-4.17+ kernels */
#ifndef MAP_FIXED_NOREPLACE
# define MAP_FIXED_NOREPLACE                        MAP_FIXED
#endif /* MAP_FIXED_NOREPLACE */

/* Arbitrary fallback virtual address for mapping the actual interpreter */
#define FALLBACK_LOADER_BASE                        0xa0000000

void elf_stack_parse(Elf_Addr *stack);

void elf_auxv_parse(unsigned int *page_sz, uint8_t **rand);

int elf_ehdr_validate(const Elf_Ehdr *ehdr, bool exec);

Elf_Off elf_phdr_interpreter(const Elf_Phdr *phdr, unsigned int num_phdr);

int elf_phdr_flags_prot(Elf_Word flags);

void elf_phdr_load(const Elf_Phdr *phdr, unsigned int num_phdr, int fd, unsigned long base, void *stack, unsigned int page_sz);

bool parse_executable(const char *executable, char *interp);

void *parse_interpreter(const char *interp, void *stack, const uint8_t *rand, unsigned int page_sz);

#endif /* __LOADER_H__ */
