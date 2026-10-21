// SPDX-License-Identifier: MIT
// One-shot console report. APFS symbols are resolved, never called.
#include <dlfcn.h>
#include <stdio.h>
#include <sys/utsname.h>
#include <unistd.h>
#ifdef __APPLE__
#include <sys/mount.h>
#endif

int main(void)
{
    int failed = 0;
    struct utsname kernel;
    const char *symbols[] = {
        "APFSContainerResize",
        "APFSContainerResizeEx",
        "APFSContainerGetMinimalSize",
    };

    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    puts("A13_UART_PROBE_BEGIN");
    printf("euid=%u\n", (unsigned)geteuid());
    if (uname(&kernel) == 0) {
        printf("kernel=%s release=%s machine=%s\n", kernel.sysname, kernel.release,
               kernel.machine);
    } else {
        perror("uname");
        failed = 1;
    }
#ifdef __APPLE__
    struct statfs *mounts;
    int count = getmntinfo(&mounts, MNT_NOWAIT);
    printf("mounts=%d\n", count);
    if (count <= 0)
        failed = 1;
    for (int i = 0; i < count; i++)
        printf("mount source=%s target=%s type=%s flags=%#lx\n", mounts[i].f_mntfromname,
               mounts[i].f_mntonname, mounts[i].f_fstypename, (unsigned long)mounts[i].f_flags);
#else
    puts("mount snapshot unavailable on non-Darwin host test");
#endif
    void *framework = dlopen("/System/Library/PrivateFrameworks/APFS.framework/APFS",
                             RTLD_LAZY | RTLD_LOCAL);
    if (!framework) {
        printf("APFS_LOAD_FAILED: %s\n", dlerror());
        failed = 1;
    } else {
        puts("APFS_LOAD_OK");
        for (unsigned i = 0; i < sizeof(symbols) / sizeof(symbols[0]); i++) {
            dlerror();
            void *symbol = dlsym(framework, symbols[i]);
            const char *error = dlerror();
            printf("APFS_SYMBOL %s %s\n", symbols[i], symbol && !error ? "present" : "missing");
            if (!symbol || error)
                failed = 1;
        }
        dlclose(framework);
    }
    printf("A13_UART_PROBE_END status=%d\n", failed);
    return failed;
}
