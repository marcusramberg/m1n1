// SPDX-License-Identifier: MIT
// Fake loader returns fatal function pointers: resolving is allowed, calling is not.
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#define main probe_main
#define dlopen test_dlopen
#define dlsym test_dlsym
#define dlerror test_dlerror
#define dlclose test_dlclose
#include "a13_uart_probe.c"
#undef main

static int mode;
static unsigned lookups;
static char *loader_error;

static void forbidden_call(void)
{
    abort();
}

void *test_dlopen(const char *path, int flags)
{
    assert(strcmp(path, "/System/Library/PrivateFrameworks/APFS.framework/APFS") == 0);
    assert(flags == (RTLD_LAZY | RTLD_LOCAL));
    if (mode == 1) {
        loader_error = "test: framework absent";
        return NULL;
    }
    return &mode;
}

void *test_dlsym(void *handle, const char *name)
{
    assert(handle == &mode);
    assert(strcmp(name, "APFSContainerResize") == 0 ||
           strcmp(name, "APFSContainerResizeEx") == 0 ||
           strcmp(name, "APFSContainerGetMinimalSize") == 0);
    lookups++;
    if (mode == 2 && strcmp(name, "APFSContainerGetMinimalSize") == 0) {
        loader_error = "test: symbol absent";
        return NULL;
    }
    return (void *)forbidden_call;
}

char *test_dlerror(void)
{
    char *result = loader_error;
    loader_error = NULL;
    return result;
}

int test_dlclose(void *handle)
{
    assert(handle == &mode);
    return 0;
}

int main(void)
{
    assert(probe_main() == 0);
    assert(lookups == 3);
    mode = 1;
    assert(probe_main() == 1);
    assert(lookups == 3);
    mode = 2;
    assert(probe_main() == 1);
    assert(lookups == 6);
    puts("PASS: resolves only; missing framework/symbol fail closed; no APFS function called");
    return 0;
}
