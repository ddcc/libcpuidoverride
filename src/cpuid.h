#ifndef __CPUID_H__
#define __CPUID_H__

#include <cpuid.h>
#include <stdbool.h>

/* Access to registers from context */
#ifdef __x86_64__
# define GET_REGISTER(uctx, reg)                    ((ucontext_t *)uctx)->uc_mcontext.gregs[REG_R##reg]
#elif defined(__i386__)
# define GET_REGISTER(uctx, reg)                    ((ucontext_t *)uctx)->uc_mcontext.gregs[REG_E##reg]
#else
# error "Unsupported architecture!"
#endif

/* Define feature bits for compatibility with older GCC versions */
#ifdef __GNUC__
# if GCC_VERSION < 80100
#  define bit_AVX512VBMI2                           (1 << 6)
#  define bit_AVX512VNNI                            (1 << 11)
#  define bit_AVX512BITALG                          (1 << 12)
# endif /* GCC_VERSION < 8.1.0 */
#endif /* __GNUC__ */

/* Raw values of the CPUID instruction */
#define CPUID_INSN0                                 0x0f
#define CPUID_INSN1                                 0xa2

/* Leaves that contain subleaves */
#define SUBLEAF_LEAVES(x)                           ((x) == 0x04 || (x) == 0x07 || (x) == 0x0b || (x) == 0x0d || (x) == 0x0f || (x) == 0x10 || (x) == 0x12 || (x) == 0x14 || (x) == 0x17 || (x) == 0x18 || (x) == 0x1f)

/* Structure of supported features */
typedef struct {
#define FEATURE(name, leaf, subleaf, reg, bit)      bool name;
#define FEATURE2(name, leaf, subleaf, reg, bit)     /* nothing */
#include "cpuid.inc"
#undef FEATURE2
#undef FEATURE
} feature_t;

int hook_cpuid();

#endif /* __CPUID_H__ */
