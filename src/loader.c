#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>

#include <sys/mman.h>

#include "cpuid.h"
#include "library.h"
#include "loader.h"
#include "syscalls.h"

int argc;
const char **argv, **envp;
const Elf_auxv_t *auxv;

/* Architecture-specific definitions */
/* See RTLD_START in glibc/sysdeps/<arch>/dl-machine.h */
#ifdef __x86_64__
__asm__ ("\n\
    .global _start\n\
    .type _start,@function\n\
_start:\n\
    mov %rsp, %rdi\n\
    call loader_init\n\
    jmp *%rax\n\
");
#else
# error "Unsupported architecture!"
#endif

/* Parse the stack set up by the kernel ELF loader */
/* See create_elf_tables in linux/fs/binfmt_elf.c */
void elf_stack_parse(Elf_Addr *stack) {
    int argc = stack[0];
    argv = (const char **)&stack[1];
    envp = (const char **)&stack[1 + argc + 1];
    while (*envp++) { };
    auxv = (Elf_auxv_t *)envp;
    envp = (const char **)&stack[1 + argc + 1];
}

/* Parse the auxiliary vector and PT_INTERP program header */
void elf_auxv_parse(unsigned int *page_sz, uint8_t **rand) {
    while (auxv && auxv->a_type != AT_NULL) {
        if (auxv->a_type == AT_PAGESZ) {
            *page_sz = auxv->a_un.a_val;
        } else if (auxv->a_type == AT_RANDOM) {
            *rand = (uint8_t *)auxv->a_un.a_val;
        }

        ++auxv;
    }
}

/* Validate the ELF header */
int elf_ehdr_validate(const Elf_Ehdr *ehdr, bool exec) {
    return !my_memcmp(ehdr->e_ident, ELFMAG, SELFMAG) && ((exec && ehdr->e_type == ET_EXEC) || ehdr->e_type == ET_DYN) && GET_ELF_MACHINE(ehdr->e_machine) && ehdr->e_ehsize == sizeof(Elf_Ehdr) && ehdr->e_phentsize == sizeof(Elf_Phdr);
}

/* Fetch the interpreter offset from the ELF program header PT_INTERP */
Elf_Off elf_phdr_interpreter(const Elf_Phdr *phdr, unsigned int num_phdr) {
    for (unsigned int i = 0; i < num_phdr; ++i) {
        if (phdr[i].p_type == PT_INTERP)
            return phdr[i].p_offset;
    }

    return 0;
}

/* Convert the ELF segment flags into mmap access permissions */
int elf_phdr_flags_prot(Elf_Word flags) {
    return (flags & PF_R ? PROT_READ : PROT_NONE) | (flags & PF_W ? PROT_WRITE : PROT_NONE) | (flags & PF_X ? PROT_EXEC : PROT_NONE);
}

/* Load all ELF program header PT_LOAD into memory, and handle executable stack from program header PT_GNU_STACK */
void elf_phdr_load(const Elf_Phdr *phdr, unsigned int num_phdr, int fd, unsigned long base, void *stack, unsigned int page_sz) {
    /* See executable_stack in linux/fs/binfmt_elf.c */
    unsigned int stack_prot = PF_R | PF_W | PF_X;

    for (unsigned int i = 0; i < num_phdr; ++i) {
        if (phdr[i].p_type == PT_LOAD) {
            /* Map in the page from the file */
            void *addr = my_mmap((void *)(ALIGN(base + phdr[i].p_vaddr, page_sz)), phdr[i].p_filesz, elf_phdr_flags_prot(phdr[i].p_flags), MAP_FIXED_NOREPLACE | MAP_PRIVATE, fd, ALIGN(phdr[i].p_offset, page_sz));
            if (addr == MAP_FAILED) {
                my_puts("Failed to map page from file!");
                my_abort();
            }

            /* Map in additional anonymous pages, if necessary */
            /* See load_elf_binary in linux/fs/binfmt_elf.c */
            if (phdr[i].p_memsz > phdr[i].p_filesz) {
                void *addr = my_mmap((void *)(ALIGN_UP(base + phdr[i].p_vaddr + phdr[i].p_filesz, page_sz)), phdr[i].p_memsz - phdr[i].p_filesz, elf_phdr_flags_prot(phdr[i].p_flags), MAP_FIXED_NOREPLACE | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
                if (addr == MAP_FAILED) {
                    my_puts("Failed to map anonymous page!");
                    my_abort();
                }
            }
        } else if (phdr[i].p_type == PT_GNU_STACK) {
            stack_prot = phdr[i].p_flags;
        }
    }

    /* Set the stack executable if necessary */
    if (stack_prot & PF_X) {
        if (my_mprotect((void *)ALIGN((uintptr_t)stack, page_sz), page_sz, elf_phdr_flags_prot(stack_prot)) < 0) {
            my_puts("Failed to set stack permissions!");
            my_abort();
        }
    }
}

/* Open the executable and fetch the interpreter */
bool parse_executable(const char *executable, char *interp) {
    bool ret = false;

    /* Open the executable */
    int fd = my_openat(AT_FDCWD, executable, O_RDONLY, 0);
    if (fd < 0) {
        my_puts("Failed to open executable!");
        return ret;
    }

    /* Get the size of the executable */
    struct stat sb;
    if (my_fstat(fd, &sb) < 0) {
        my_puts("Failed to get executable size!");
        goto out_fd;
    }

    /* Map the executable into memory */
    void *addr = my_mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (addr == MAP_FAILED) {
        my_puts("Failed to map executable into memory!");
        goto out_fd;
    }

    /* Validate the executable as an executable */
    if (!elf_ehdr_validate((const Elf_Ehdr *)addr, 1)) {
        my_puts("Failed to validate executable ELF header!");
        goto out_mmap;
    }

    /* Get the interpreter offset */
    Elf_Off interp_off = elf_phdr_interpreter((const Elf_Phdr *)((uintptr_t)addr + ((const Elf_Ehdr *)addr)->e_phoff), ((const Elf_Ehdr *)addr)->e_phnum);
    if (interp_off) {
        my_strncpy(interp, (const char *)((uintptr_t)addr + interp_off), PATH_MAX - 1);
        interp[PATH_MAX - 1] = '\0';
    }

    ret = true;
    /* Cleanup */
out_mmap:
    my_munmap(addr, sb.st_size);
out_fd:
    my_close(fd);

    return ret;
}

/* Parse the interpreter, load it into memory, and return the entry point */
void *parse_interpreter(const char *interp, void *stack, const uint8_t *rand, unsigned int page_sz) {
    void *ep = NULL;

    /* Open the interpreter */
    int fd = my_openat(0, interp, O_RDONLY, 0);
    if (fd < 0) {
        my_puts("Failed to open interpreter!");
        return ep;
    }

    /* Get the size of the interpreter */
    struct stat sb;
    if (my_fstat(fd, &sb) < 0) {
        my_puts("Failed to get interpreter size!");
        goto out_fd;
    }

    /* Map the interpreter into memory */
    void *addr = my_mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (addr == MAP_FAILED) {
        my_puts("Failed to map interpreter into memory!");
        goto out_fd;
    }

    /* Validate the interpreter as a library */
    if (!elf_ehdr_validate((const Elf_Ehdr *)addr, 0)) {
        my_puts("Failed to validate interpreter ELF header!");
        goto out_mmap;
    }

    /* Re-map the interpreter, at a (preferably) randomized base address, with correct permissions for each segment, and an executable stack (if necessary) */
    /* Note: Cannot map everything RWX, so must map each segment individually */
    unsigned long base = ALIGN(rand ? GET_RANDOM_BASE(rand) : FALLBACK_LOADER_BASE, page_sz);
    elf_phdr_load((const Elf_Phdr *)((uintptr_t)addr + ((const Elf_Ehdr *)addr)->e_phoff), ((const Elf_Ehdr *)addr)->e_phnum, fd, base, stack, page_sz);

    /* Compute the entry point */
    ep = (void *)(base + ((const Elf_Ehdr *)addr)->e_entry);

    /* Cleanup */
out_mmap:
    my_munmap(addr, sb.st_size);
out_fd:
    my_close(fd);

    return ep;
}

/* Called when executed as a dynamic loader */
void *loader_init(void *stack) {
    /* Parse the stack set up by the kernel's ELF executable loader */
    elf_stack_parse((Elf_Addr *)stack);

    /* Get the page size and some random bytes */
    uint8_t *rand = NULL;
    unsigned int page_sz = 4096;
    elf_auxv_parse(&page_sz, &rand);

    /* Open the executable and parse out the actual interpreter */
    // char interp[PATH_MAX];
    // if (!parse_executable(argv[0], interp))
    //     my_abort();

    /* Open the interpreter, load it into memory, and return the entry point */
    void *ep = parse_interpreter(ELF_INTERPRETER, stack, rand, page_sz);
    // void *ep = parse_interpreter(interp, stack, rand, page_sz);
    if (!ep)
        my_abort();

    /* Enable CPUID hooking */
    if (!hook_cpuid())
        my_abort();

    return ep;
}
