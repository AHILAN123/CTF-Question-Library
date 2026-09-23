/*
 * part3.c -- CTF Q1, Part 3: the final keygen.
 *
 * Reads a candidate password (argv[1] or stdin), runs it through a hand-rolled,
 * position-dependent checksum (rotate / xor with a running accumulator / add a
 * rotating constant -- NOT a standard algorithm), and compares the result to an
 * embedded target. On a match it de-obfuscates and prints the real flag; the
 * flag itself is never stored in the clear, so `strings` will not reveal it.
 *
 * The checksum is deliberately invertible left-to-right, so a solver who
 * reverses the routine can recover the password directly (see reference_solver).
 *
 * Build: cc -O1 -o part3 part3.c   (symbols kept so the challenge is reversible)
 */
#include <stdio.h>
#include <string.h>

#define P3_L 12

/* Constants are plain globals (not static) so they are easy to locate when
 * reversing -- recovering the password is about inverting the MATH, not about
 * finding a hidden string. */
unsigned char p3_params[4] = {0x5a /*SEED*/, 3 /*ROT*/, 1 /*R0*/, 4 /*NK*/};
unsigned char p3_K[4]      = {0x1f, 0x2b, 0x3d, 0x47};
unsigned char p3_target[P3_L] = {
    0xb3, 0xed, 0x04, 0x13, 0xc6, 0xc5, 0xd5, 0x24, 0x78, 0x4d, 0x2a, 0x0c
};

#define P3_FLAG_LEN 41
unsigned char p3_flag_enc[P3_FLAG_LEN] = {
    0x01,0x5b,0x03,0x16,0x54,0x1d,0x34,0x13,0x58,0x78,0x71,0x04,0x07,0x05,
    0x6a,0x52,0x31,0x29,0x4d,0x99,0x8b,0x83,0xad,0xe3,0xa7,0xac,0xb9,0xb2,
    0x84,0xd0,0xe0,0xf6,0xe5,0xfd,0xf0,0xe7,0xe9,0x47,0x55,0x11,0x56
};

static unsigned char rotl8(unsigned char b, int r) {
    r &= 7;
    return r ? (unsigned char)((b << r) | (b >> (8 - r))) : b;
}

/* out[i] = ( rotl(in[i], (i*ROT+R0)&7) ^ acc ) + K[i%NK];  acc += in[i] */
static void checksum(const unsigned char *in, unsigned char *out) {
    unsigned char acc = p3_params[0];
    int rot = p3_params[1], r0 = p3_params[2], nk = p3_params[3];
    for (int i = 0; i < P3_L; i++) {
        unsigned char x = rotl8(in[i], (i * rot + r0) & 7);
        x ^= acc;
        x = (unsigned char)(x + p3_K[i % nk]);
        out[i] = x;
        acc = (unsigned char)(acc + in[i]);
    }
}

static void print_flag(const unsigned char *pw) {
    unsigned char f[P3_FLAG_LEN + 1];
    for (int i = 0; i < P3_FLAG_LEN; i++)
        f[i] = p3_flag_enc[i] ^ pw[i % P3_L] ^ (unsigned char)((i * 7) & 0xff);
    f[P3_FLAG_LEN] = 0;
    printf("%s\n", f);
}

/*
 * legacy_check() -- LEFTOVER from an earlier revision. No longer called from
 * main(); kept only so old test harnesses still link. (Decoy: prints a flag
 * that looks real but is not. Reachable via e.g.  gdb -ex 'call legacy_check()')
 */
__attribute__((used))
void legacy_check(void) {
    puts("flag{PART3_l3gacy_p4th_n0t_r34l}");
}

int main(int argc, char **argv) {
    unsigned char in[P3_L + 2];
    char buf[256];
    const char *src = NULL;

    if (argc >= 2) {
        src = argv[1];
    } else {
        if (!fgets(buf, sizeof(buf), stdin)) return 2;
        size_t n = strlen(buf);
        while (n && (buf[n - 1] == '\n' || buf[n - 1] == '\r')) buf[--n] = 0;
        src = buf;
    }
    if (strlen(src) != P3_L) {
        fprintf(stderr, "part3: password must be %d chars\n", P3_L);
        return 1;
    }
    memcpy(in, src, P3_L);

    unsigned char out[P3_L];
    checksum(in, out);
    if (memcmp(out, p3_target, P3_L) == 0) {
        print_flag(in);
        return 0;
    }
    puts("Access denied.");
    return 1;
}
