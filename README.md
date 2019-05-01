# libcpuidoverride

A shim dynamic loader for overriding CPUID, using processor support for CPUID faulting on Ivy Bridge+, and the Linux kernel support for `ARCH_GET_CPUID` / `ARCH_SET_CPUID` subfunctions on 4.12+. This was implemented using a shim dynamic loader instead of e.g. `LD_PRELOAD`, because glibc 2.26+ performs CPU feature detection within the dynamic loader itself, which is too early to intercept with `LD_PRELOAD`.

Writeup: https://www.dcddcc.com/blog/2019-05-01-processor-cpuid-faulting-and-dynamic-loader-interposing.html

Supported CPUID features: `SSE`, `SSE2`, `SSE3`, `SSSE3`, `SSE41`, `SSE42`, `AVX`, `AVX2`, `AVX512`.

## Usage

```
cp <binary> <patch_binary>
patchelf --set-interpreter <absolute path>/libcpuidoverride.so <patch_binary>
NO_<feature>=1 <patch_binary>
```

For example, to disable AVX2 for the `cpuid` binary:

```
cp `which cpuid` patched_cpuid
patchelf --set-interpreter `pwd`/libcpuidoverride.so patched_cpuid
NO_AVX2=1 patched_cpuid
```

Alternatively, build with `-Wl,--dynamic-linker=<absolute path>/libcpuidoverride.so`.
