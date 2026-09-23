/*
 * antidbg_bypass.c -- illustrative LD_PRELOAD shim that defeats part2's ptrace
 * and /proc/self/status checks, so you can run it under a debugger.
 *
 *   cc -shared -fPIC -o antidbg_bypass.so tools/antidbg_bypass.c -ldl
 *   LD_PRELOAD=./antidbg_bypass.so gdb ./part2      # use `hbreak`, not `break`
 *
 * Then, for the remaining checks, use HARDWARE breakpoints (gdb `hbreak` / DR
 * registers) so no 0xCC is written into .text (defeats the self-checksum and the
 * INT3 scan), and don't single-step the timed region (run to a breakpoint past
 * it) so the rdtsc window stays small. The reference solver avoids all of this
 * by simply running part2 with no debugger attached -- every check then passes.
 *
 * This is a standard, well-documented technique; it is provided so the author
 * can confirm each check is bypassable by a real method, not a fragile hack.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdarg.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

/* 1) ptrace(PTRACE_TRACEME) always "succeeds". */
long ptrace(int request, ...) { (void)request; return 0; }

/* 2) spoof /proc/self/status so TracerPid is always 0. We create a sanitized
 *    temp copy on first access and redirect opens of the real path to it. */
static const char *fake_status(void) {
    static char path[64];
    if (path[0]) return path;
    strcpy(path, "/tmp/fakestatus_XXXXXX");
    int fd = mkstemp(path);
    if (fd < 0) { path[0] = 0; return NULL; }
    dprintf(fd, "Name:\tpart2\nState:\tR (running)\nTracerPid:\t0\n");
    close(fd);
    return path;
}

static int wants_status(const char *p) {
    return p && strstr(p, "/proc/") && strstr(p, "/status");
}

int openat(int dirfd, const char *path, int flags, ...) {
    static int (*real)(int, const char *, int, ...);
    if (!real) real = dlsym(RTLD_NEXT, "openat");
    mode_t mode = 0;
    if (flags & O_CREAT) { va_list ap; va_start(ap, flags); mode = va_arg(ap, int); va_end(ap); }
    if (wants_status(path)) { const char *f = fake_status(); if (f) path = f; }
    return real(dirfd, path, flags, mode);
}

int open(const char *path, int flags, ...) {
    static int (*real)(const char *, int, ...);
    if (!real) real = dlsym(RTLD_NEXT, "open");
    mode_t mode = 0;
    if (flags & O_CREAT) { va_list ap; va_start(ap, flags); mode = va_arg(ap, int); va_end(ap); }
    if (wants_status(path)) { const char *f = fake_status(); if (f) path = f; }
    return real(path, flags, mode);
}
