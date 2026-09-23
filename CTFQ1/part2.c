/*
 * part2.c -- CTF Q1, Part 2: anti-debug wrapper around an encrypted part3.
 *
 * A self-contained crackme (NOT malware): it decrypts an embedded, AES-128-CBC
 * encrypted copy of the Part 3 binary using a key supplied on stdin, but only
 * if a sequence of anti-debugging checks all pass. Each check is a real,
 * documented technique with a documented bypass (see NOTES.md):
 *
 *   1. ptrace(PTRACE_TRACEME) self-attach          (fails if already traced)
 *   2. /proc/self/status TracerPid != 0            (a tracer is attached)
 *   3. rdtsc timing window                         (single-stepping is slow)
 *   4. FNV-1a self-checksum of guarded_func()'s .text vs a baked baseline
 *   5. count of 0xCC (INT3) bytes in guarded_func() vs the pristine count
 *
 * On ANY failed check we DO NOT exit; we XOR the in-memory key with a fixed
 * garbage constant, so decryption still runs but yields garbage. Success is
 * detected by checking the decrypted data starts with the ELF magic.
 *
 * The expected key is embedded only in obfuscated form (k2_obf ^ k2_mask); a
 * solver recovers it by static RE. Build patches g_guard_len / g_guard_ck /
 * g_guard_cc after compiling (two-pass), since they live in .data and thus do
 * not perturb the .text region they describe.
 *
 * Build: cc -O1 -no-pie -fno-pic -o part2 part2.c -lcrypto   (then patch guards)
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/ptrace.h>
#include <openssl/evp.h>

#include "part2_gen.h"   /* enc_blob[], enc_blob_len, k2_obf[16], k2_mask[16],
                            keycorrupt_garbage[16], part2_flag_enc[], part2_flag_len */

/* Patched by the build after compilation (kept in .data via nonzero inits). */
volatile uint32_t g_guard_len = 0xA1B2C3D4u;
volatile uint64_t g_guard_ck  = 0x0123456789ABCDEFull;
volatile uint32_t g_guard_cc  = 0xDEADBEEFu;

/* Deliberately generous: it must flag single-stepping (which turns a ~100k-iter
 * loop into seconds -> many billions of cycles) while never false-tripping on a
 * clean run, including under CPU emulation (x86 on Apple Silicon via Docker).
 * Overridable at build time with -DP2_TSC_THRESHOLD=... */
#ifndef P2_TSC_THRESHOLD
#define P2_TSC_THRESHOLD 5000000000ULL
#endif

/* Guarded region: pure arithmetic, no calls / no global refs, so its compiled
 * bytes are position-independent and identical on disk and in memory. */
__attribute__((noinline, used))
uint32_t guarded_func(const unsigned char *key, int n) {
    uint32_t h = 0x811c9dc5u;
    for (int i = 0; i < n; i++) {
        h ^= key[i];
        h *= 16777619u;
        h ^= (h >> 13);
    }
    return h;
}

static uint64_t fnv1a(const unsigned char *p, uint32_t n) {
    uint64_t h = 1469598103934665603ULL;
    for (uint32_t i = 0; i < n; i++) { h ^= p[i]; h *= 1099511628211ULL; }
    return h;
}

static uint64_t rdtsc(void) {
    uint32_t lo, hi;
    __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

/* ---- individual checks: return 1 if a debugger/tamper is indicated ---- */
static int chk_ptrace(void) {
    if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1) return 1;   /* already traced */
    return 0;
}

static int chk_status(void) {
    int fd = open("/proc/self/status", O_RDONLY);
    if (fd < 0) return 0;
    char buf[4096];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return 0;
    buf[n] = 0;
    char *p = strstr(buf, "TracerPid:");
    if (!p) return 0;
    return atoi(p + 10) != 0;
}

static int chk_timing(void) {
    uint64_t t0 = rdtsc();
    volatile uint64_t s = 0;
    for (int i = 0; i < 100000; i++) s += (uint64_t)i * i;
    uint64_t t1 = rdtsc();
    return (t1 - t0) > P2_TSC_THRESHOLD;
}

static int chk_checksum(void) {
    return fnv1a((const unsigned char *)&guarded_func, g_guard_len) != g_guard_ck;
}

static int chk_int3(void) {
    const unsigned char *p = (const unsigned char *)&guarded_func;
    uint32_t c = 0;
    for (uint32_t i = 0; i < g_guard_len; i++) if (p[i] == 0xCC) c++;
    return c != g_guard_cc;
}

/*
 * debug_dump_flag() -- leftover debug helper from bring-up. Not called by
 * main() any more. (Decoy: prints a flag that is NOT the real one. Reachable
 * only if you invoke it directly, e.g.  gdb -ex 'call debug_dump_flag()'.)
 */
__attribute__((used))
void debug_dump_flag(void) {
    puts("flag{PART2_d3bug_dump_n0t_th3_fl4g}");
}

static int aes_cbc_dec(const unsigned char *key, const unsigned char *iv,
                       const unsigned char *ct, int ctlen,
                       unsigned char *out, int *outlen) {
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    if (!c) return 0;
    int l1 = 0, l2 = 0, ok = 0;
    if (EVP_DecryptInit_ex(c, EVP_aes_128_cbc(), NULL, key, iv) == 1 &&
        EVP_DecryptUpdate(c, out, &l1, ct, ctlen) == 1 &&
        EVP_DecryptFinal_ex(c, out + l1, &l2) == 1) {
        *outlen = l1 + l2;
        ok = 1;
    }
    EVP_CIPHER_CTX_free(c);
    return ok;
}

static int hex2bin(const char *h, unsigned char *out, int n) {
    for (int i = 0; i < n; i++) {
        unsigned v;
        if (sscanf(h + 2 * i, "%2x", &v) != 1) return 0;
        out[i] = (unsigned char)v;
    }
    return 1;
}

int main(void) {
    char line[128];
    if (!fgets(line, sizeof(line), stdin)) { fprintf(stderr, "no key\n"); return 2; }
    size_t ln = strlen(line);
    while (ln && (line[ln - 1] == '\n' || line[ln - 1] == '\r')) line[--ln] = 0;
    if (ln < 32) { fprintf(stderr, "need 32 hex chars (16-byte key)\n"); return 2; }

    unsigned char key[16];
    if (!hex2bin(line, key, 16)) { fprintf(stderr, "bad hex key\n"); return 2; }

    int bad = 0;
    bad |= chk_ptrace();
    bad |= chk_status();
    bad |= chk_timing();
    bad |= chk_checksum();
    bad |= chk_int3();
    if (bad)
        for (int i = 0; i < 16; i++) key[i] ^= keycorrupt_garbage[i];

    const unsigned char *iv = enc_blob;
    const unsigned char *ct = enc_blob + 16;
    int ctlen = (int)enc_blob_len - 16;

    unsigned char *out = malloc(ctlen + 16);
    if (!out) return 3;
    int outlen = 0;

    if (aes_cbc_dec(key, iv, ct, ctlen, out, &outlen) &&
        outlen >= 4 && memcmp(out, "\x7f""ELF", 4) == 0) {
        char tmpl[] = "/tmp/part3_XXXXXX";
        int fd = mkstemp(tmpl);
        if (fd >= 0) {
            if (write(fd, out, outlen) != outlen) { /* best effort */ }
            fchmod(fd, 0755);
            close(fd);
        }
        printf("[+] anti-debug OK, decryption OK -> %s\n", tmpl);
        /* de-obfuscate PART2 flag with the (correct) key */
        unsigned char f[256];
        for (unsigned i = 0; i < part2_flag_len && i < sizeof(f) - 1; i++)
            f[i] = part2_flag_enc[i] ^ key[i % 16] ^ (unsigned char)((i * 7) & 0xff);
        f[part2_flag_len] = 0;
        printf("%s\n", f);
        free(out);
        return 0;
    }

    /* failure: help a legitimate solver confirm their extracted key without
     * revealing it, and keep the obfuscated-key material referenced. */
    unsigned char k2[16];
    for (int i = 0; i < 16; i++) k2[i] = k2_obf[i] ^ k2_mask[i];
    printf("[-] decryption failed (wrong key or a debugger was detected)\n");
    printf("[i] expected-key fingerprint: %08x\n", guarded_func(k2, 16));
    free(out);
    return 1;
}
