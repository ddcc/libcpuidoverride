#define _GNU_SOURCE

#include <sched.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

#include <asm/prctl.h>
#include <sys/prctl.h>
#include <sys/ucontext.h>

#include "cpuid.h"
#include "library.h"
#include "syscalls.h"

/* List of disabled CPUID features */
feature_t disabled;
/* Previous signal handler */
struct sigaction old_handler;

void get_features(feature_t *disabled) {
    /* Mark feature disabled if environment variable defined */
#define FEATURE(name, leaf, subleaf, reg, bit)      if (my_getenv("NO_" #name)) { disabled->name = 1; my_puts("Overriding feature " #name "!"); }
#define FEATURE2(name, leaf, subleaf, reg, bit)     /* nothing */
#include "cpuid.inc"
#undef FEATURE2
#undef FEATURE
}

void sigsegv_handler(int signal, siginfo_t *info, void *ucontext) {
    /* Check if CPUID was executed */
    const uint8_t *ip = (const uint8_t *)GET_REGISTER(ucontext, IP);
    if (info->si_code == SI_KERNEL && ip[0] == CPUID_INSN0 && ip[1] == CPUID_INSN1) {
        unsigned int AX, BX, CX, DX;
        greg_t leaf = GET_REGISTER(ucontext, AX), subleaf = GET_REGISTER(ucontext, CX);

        my_puts("Intercepted call to CPUID!");

        // FIXME: May be racy. Either pre-cache CPUID values, or clone a child to retrieve the actual value
        /* Disable CPUID faulting */
        if (my_arch_prctl(ARCH_SET_CPUID, 1) < 0) {
            my_puts("Failed to disable CPUID faulting!");
            my_abort();
        }

        /* Obtain the actual CPUID */
        __cpuid_count(leaf, subleaf, AX, BX, CX, DX);

        /* Mask off anything that should be disabled */
        int subleaf_valid = SUBLEAF_LEAVES(leaf);

#define FEATURE(name, lf, slf, reg, bit)            if (lf == leaf && (!subleaf_valid || slf == subleaf) && disabled.name) { reg &= ~(bit); my_puts("Hiding feature " #name "!"); }
#define FEATURE2(name, leaf, subleaf, reg, bit)     FEATURE(name, leaf, subleaf, reg, bit)
#include "cpuid.inc"
#undef FEATURE2
#undef FEATURE

        /* Emulate the behavior of CPUID */
        GET_REGISTER(ucontext, IP) += 2;
        GET_REGISTER(ucontext, AX) = AX;
        GET_REGISTER(ucontext, BX) = BX;
        GET_REGISTER(ucontext, CX) = CX;
        GET_REGISTER(ucontext, DX) = DX;

        /* Re-enable CPUID faulting */
        if (my_arch_prctl(ARCH_SET_CPUID, 0) < 0) {
            my_puts("Failed to re-enable CPUID faulting!");
            my_abort();
        }
    } else {
        /* Call the previous signal handler */
        if (old_handler.sa_flags & SA_SIGINFO && old_handler.sa_sigaction)
            old_handler.sa_sigaction(signal, info, ucontext);
        else if (old_handler.sa_handler)
            old_handler.sa_handler(signal);
        else {
            /* Disable this signal handler */
            struct sigaction new = {
                .sa_handler = SIG_DFL,
                .sa_flags = SA_SIGINFO,
            };
            if (my_sigaction(SIGSEGV, &new, NULL) < 0) {
                my_puts("Failed to change SIGSEGV signal handler!");
                my_abort();
            }

            /* Signal is fatal, so just re-raise it */
            my_tgkill(my_getpid(), my_gettid(), SIGSEGV);
        }
    }
}

int hook_cpuid() {
    /* Determine which CPUID features should be disabled */
    get_features(&disabled);

    /* Set the signal handler for SIGSEGV */
    struct sigaction new = {
        .sa_sigaction = sigsegv_handler,
        .sa_flags = SA_SIGINFO,
    };
    if (my_sigaction(SIGSEGV, &new, &old_handler) < 0) {
        my_puts("Failed to register SIGSEGV handler!");
        return 0;
    }

    /* Enable CPUID faulting */
    if (my_arch_prctl(ARCH_SET_CPUID, 0) < 0) {
        my_puts("Failed to enable CPUID faulting!");
        return 0;
    }

    return 1;
}
