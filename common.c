/*
 * common.c - Shared utilities for revtool
 */

#include "common.h"

int g_no_color = 0;

file_t *file_open(const char *path) {
    file_t *f = calloc(1, sizeof(file_t));
    if (!f) {
        fprintf(stderr, "%sError: calloc failed: %s%s\n", c(C_RED), strerror(errno), c(C_RESET));
        return NULL;
    }
    f->path = path;
    f->fd = open(path, O_RDONLY);
    if (f->fd < 0) {
        fprintf(stderr, "%sError: Cannot open '%s': %s%s\n", c(C_RED), path, strerror(errno), c(C_RESET));
        free(f);
        return NULL;
    }
    struct stat st;
    if (fstat(f->fd, &st) < 0) {
        fprintf(stderr, "%sError: fstat failed on '%s': %s%s\n", c(C_RED), path, strerror(errno), c(C_RESET));
        close(f->fd);
        free(f);
        return NULL;
    }
    f->size = st.st_size;
    if (f->size == 0) {
        f->data = NULL;
        return f;
    }
    f->data = mmap(NULL, f->size, PROT_READ, MAP_PRIVATE, f->fd, 0);
    if (f->data == MAP_FAILED) {
        fprintf(stderr, "%sError: mmap failed on '%s': %s%s\n", c(C_RED), path, strerror(errno), c(C_RESET));
        close(f->fd);
        free(f);
        return NULL;
    }
    return f;
}

void file_close(file_t *f) {
    if (!f) return;
    if (f->data && f->data != MAP_FAILED) {
        munmap(f->data, f->size);
    }
    if (f->fd >= 0) {
        close(f->fd);
    }
    free(f);
}

double calc_entropy(const uint8_t *data, size_t len) {
    if (len == 0) return 0.0;
    size_t counts[256] = {0};
    for (size_t i = 0; i < len; i++) {
        counts[data[i]]++;
    }
    double ent = 0.0;
    for (int i = 0; i < 256; i++) {
        if (counts[i] == 0) continue;
        double p = (double)counts[i] / (double)len;
        ent -= p * log2(p);
    }
    return ent;
}

const char *entropy_color(double ent) {
    if (g_no_color) return "";
    if (ent > 7.5) return C_BRIGHT_RED;
    if (ent > 6.5) return C_BRIGHT_YELLOW;
    if (ent > 5.0) return C_YELLOW;
    return C_GREEN;
}

/*  MD5 Implementation (standalone, RFC 1321)  */

typedef struct {
    uint32_t state[4];
    uint32_t count[2];
    uint8_t buffer[64];
} md5_ctx_t;

#define MD5_F(x,y,z) (((x) & (y)) | ((~x) & (z)))
#define MD5_G(x,y,z) (((x) & (z)) | ((y) & (~z)))
#define MD5_H(x,y,z) ((x) ^ (y) ^ (z))
#define MD5_I(x,y,z) ((y) ^ ((x) | (~z)))
#define MD5_ROTATE_LEFT(x,n) (((x) << (n)) | ((x) >> (32-(n))))
#define MD5_FF(a,b,c,d,x,s,ac) { (a) += MD5_F(b,c,d) + (x) + (ac); (a) = MD5_ROTATE_LEFT(a,s); (a) += (b); }
#define MD5_GG(a,b,c,d,x,s,ac) { (a) += MD5_G(b,c,d) + (x) + (ac); (a) = MD5_ROTATE_LEFT(a,s); (a) += (b); }
#define MD5_HH(a,b,c,d,x,s,ac) { (a) += MD5_H(b,c,d) + (x) + (ac); (a) = MD5_ROTATE_LEFT(a,s); (a) += (b); }
#define MD5_II(a,b,c,d,x,s,ac) { (a) += MD5_I(b,c,d) + (x) + (ac); (a) = MD5_ROTATE_LEFT(a,s); (a) += (b); }

static void md5_transform(uint32_t state[4], const uint8_t block[64]) {
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t x[16];
    memcpy(x, block, 64);
    MD5_FF(a,b,c,d,x[0],7,0xd76aa478); MD5_FF(d,a,b,c,x[1],12,0xe8c7b756);
    MD5_FF(c,d,a,b,x[2],17,0x242070db); MD5_FF(b,c,d,a,x[3],22,0xc1bdceee);
    MD5_FF(a,b,c,d,x[4],7,0xf57c0faf); MD5_FF(d,a,b,c,x[5],12,0x4787c62a);
    MD5_FF(c,d,a,b,x[6],17,0xa8304613); MD5_FF(b,c,d,a,x[7],22,0xfd469501);
    MD5_FF(a,b,c,d,x[8],7,0x698098d8); MD5_FF(d,a,b,c,x[9],12,0x8b44f7af);
    MD5_FF(c,d,a,b,x[10],17,0xffff5bb1); MD5_FF(b,c,d,a,x[11],22,0x895cd7be);
    MD5_FF(a,b,c,d,x[12],7,0x6b901122); MD5_FF(d,a,b,c,x[13],12,0xfd987193);
    MD5_FF(c,d,a,b,x[14],17,0xa679438e); MD5_FF(b,c,d,a,x[15],22,0x49b40821);
    MD5_GG(a,b,c,d,x[1],5,0xf61e2562); MD5_GG(d,a,b,c,x[6],9,0xc040b340);
    MD5_GG(c,d,a,b,x[11],14,0x265e5a51); MD5_GG(b,c,d,a,x[0],20,0xe9b6c7aa);
    MD5_GG(a,b,c,d,x[5],5,0xd62f105d); MD5_GG(d,a,b,c,x[10],9,0x02441453);
    MD5_GG(c,d,a,b,x[15],14,0xd8a1e681); MD5_GG(b,c,d,a,x[4],20,0xe7d3fbc8);
    MD5_GG(a,b,c,d,x[9],5,0x21e1cde6); MD5_GG(d,a,b,c,x[14],9,0xc33707d6);
    MD5_GG(c,d,a,b,x[3],14,0xf4d50d87); MD5_GG(b,c,d,a,x[8],20,0x455a14ed);
    MD5_GG(a,b,c,d,x[13],5,0xa9e3e905); MD5_GG(d,a,b,c,x[2],9,0xfcefa3f8);
    MD5_GG(c,d,a,b,x[7],14,0x676f02d9); MD5_GG(b,c,d,a,x[12],20,0x8d2a4c8a);
    MD5_HH(a,b,c,d,x[5],4,0xfffa3942); MD5_HH(d,a,b,c,x[8],11,0x8771f681);
    MD5_HH(c,d,a,b,x[11],16,0x6d9d6122); MD5_HH(b,c,d,a,x[14],23,0xfde5380c);
    MD5_HH(a,b,c,d,x[1],4,0xa4beea44); MD5_HH(d,a,b,c,x[4],11,0x4bdecfa9);
    MD5_HH(c,d,a,b,x[7],16,0xf6bb4b60); MD5_HH(b,c,d,a,x[10],23,0xbebfbc70);
    MD5_HH(a,b,c,d,x[13],4,0x289b7ec6); MD5_HH(d,a,b,c,x[0],11,0xeaa127fa);
    MD5_HH(c,d,a,b,x[3],16,0xd4ef3085); MD5_HH(b,c,d,a,x[6],23,0x04881d05);
    MD5_HH(a,b,c,d,x[9],4,0xd9d4d039); MD5_HH(d,a,b,c,x[12],11,0xe6db99e5);
    MD5_HH(c,d,a,b,x[15],16,0x1fa27cf8); MD5_HH(b,c,d,a,x[2],23,0xc4ac5665);
    MD5_II(a,b,c,d,x[0],6,0xf4292244); MD5_II(d,a,b,c,x[7],10,0x432aff97);
    MD5_II(c,d,a,b,x[14],15,0xab9423a7); MD5_II(b,c,d,a,x[5],21,0xfc93a039);
    MD5_II(a,b,c,d,x[12],6,0x655b59c3); MD5_II(d,a,b,c,x[3],10,0x8f0ccc92);
    MD5_II(c,d,a,b,x[10],15,0xffeff47d); MD5_II(b,c,d,a,x[1],21,0x85845dd1);
    MD5_II(a,b,c,d,x[8],6,0x6fa87e4f); MD5_II(d,a,b,c,x[15],10,0xfe2ce6e0);
    MD5_II(c,d,a,b,x[6],15,0xa3014314); MD5_II(b,c,d,a,x[13],21,0x4e0811a1);
    MD5_II(a,b,c,d,x[4],6,0xf7537e82); MD5_II(d,a,b,c,x[11],10,0xbd3af235);
    MD5_II(c,d,a,b,x[2],15,0x2ad7d2bb); MD5_II(b,c,d,a,x[9],21,0xeb86d391);
    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    memset(x, 0, sizeof(x));
}

static void md5_init(md5_ctx_t *ctx) {
    ctx->count[0] = ctx->count[1] = 0;
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xefcdab89;
    ctx->state[2] = 0x98badcfe;
    ctx->state[3] = 0x10325476;
}

static void md5_update(md5_ctx_t *ctx, const uint8_t *input, size_t len) {
    size_t i, idx = (ctx->count[0] >> 3) & 0x3F;
    ctx->count[0] += (uint32_t)(len << 3);
    if (ctx->count[0] < (len << 3)) ctx->count[1]++;
    ctx->count[1] += (uint32_t)(len >> 29);
    size_t partLen = 64 - idx;
    if (len >= partLen) {
        memcpy(&ctx->buffer[idx], input, partLen);
        md5_transform(ctx->state, ctx->buffer);
        for (i = partLen; i + 63 < len; i += 64) {
            md5_transform(ctx->state, &input[i]);
        }
        idx = 0;
    } else {
        i = 0;
    }
    memcpy(&ctx->buffer[idx], &input[i], len - i);
}

static void md5_final(uint8_t digest[16], md5_ctx_t *ctx) {
    uint8_t bits[8];
    uint32_t high = ctx->count[1], low = ctx->count[0];
    for (int i = 0; i < 8; i++) {
        bits[i] = (uint8_t)((i < 4 ? low : high) >> ((i & 3) << 3));
    }
    uint8_t padding[64];
    size_t idx = (ctx->count[0] >> 3) & 0x3F;
    size_t padLen = (idx < 56) ? (56 - idx) : (120 - idx);
    memset(padding, 0, 64);
    padding[0] = 0x80;
    md5_update(ctx, padding, padLen);
    md5_update(ctx, bits, 8);
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            digest[i*4+j] = (uint8_t)(ctx->state[i] >> (j*8));
        }
    }
    memset(ctx, 0, sizeof(*ctx));
}

/*  SHA1 Implementation (standalone, FIPS 180-1)  */

typedef struct {
    uint32_t state[5];
    uint32_t count[2];
    uint8_t buffer[64];
} sha1_ctx_t;

#define SHA1_ROTL(x,n) (((x) << (n)) | ((x) >> (32-(n))))

static void sha1_transform(sha1_ctx_t *ctx, const uint8_t data[64]) {
    uint32_t w[80];
    for (int i = 0; i < 16; i++) {
        w[i] = ((uint32_t)data[i*4] << 24) | ((uint32_t)data[i*4+1] << 16) |
               ((uint32_t)data[i*4+2] << 8) | data[i*4+3];
    }
    for (int i = 16; i < 80; i++) {
        w[i] = SHA1_ROTL(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
    }
    uint32_t a = ctx->state[0], b = ctx->state[1], c = ctx->state[2];
    uint32_t d = ctx->state[3], e = ctx->state[4];
    for (int i = 0; i < 20; i++) {
        uint32_t t = SHA1_ROTL(a,5) + ((b & c) | (~b & d)) + e + w[i] + 0x5a827999;
        e = d; d = c; c = SHA1_ROTL(b,30); b = a; a = t;
    }
    for (int i = 20; i < 40; i++) {
        uint32_t t = SHA1_ROTL(a,5) + (b ^ c ^ d) + e + w[i] + 0x6ed9eba1;
        e = d; d = c; c = SHA1_ROTL(b,30); b = a; a = t;
    }
    for (int i = 40; i < 60; i++) {
        uint32_t t = SHA1_ROTL(a,5) + ((b & c) | (b & d) | (c & d)) + e + w[i] + 0x8f1bbcdc;
        e = d; d = c; c = SHA1_ROTL(b,30); b = a; a = t;
    }
    for (int i = 60; i < 80; i++) {
        uint32_t t = SHA1_ROTL(a,5) + (b ^ c ^ d) + e + w[i] + 0xca62c1d6;
        e = d; d = c; c = SHA1_ROTL(b,30); b = a; a = t;
    }
    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c;
    ctx->state[3] += d; ctx->state[4] += e;
}

static void sha1_init(sha1_ctx_t *ctx) {
    ctx->state[0] = 0x67452301; ctx->state[1] = 0xEFCDAB89;
    ctx->state[2] = 0x98BADCFE; ctx->state[3] = 0x10325476;
    ctx->state[4] = 0xC3D2E1F0;
    ctx->count[0] = ctx->count[1] = 0;
}

static void sha1_update(sha1_ctx_t *ctx, const uint8_t *data, size_t len) {
    size_t i = 0, j = ctx->count[0] & 63;
    ctx->count[0] += (uint32_t)len;
    if (ctx->count[0] < len) ctx->count[1]++;
    for (; i < len && j < 64; i++, j++) ctx->buffer[j] = data[i];
    if (j == 64) {
        sha1_transform(ctx, ctx->buffer);
        for (; i + 63 < len; i += 64) sha1_transform(ctx, &data[i]);
        j = 0;
    }
    for (; i < len; i++, j++) ctx->buffer[j] = data[i];
}

static void sha1_final(uint8_t digest[20], sha1_ctx_t *ctx) {
    uint8_t finalcount[8];
    for (int i = 0; i < 8; i++) {
        finalcount[i] = (uint8_t)((i < 4 ? ctx->count[1] : ctx->count[0]) >> ((3-(i&3))*8));
    }
    uint8_t c = 0x80;
    sha1_update(ctx, &c, 1);
    while ((ctx->count[0] & 63) != 56) {
        c = 0; sha1_update(ctx, &c, 1);
    }
    sha1_update(ctx, finalcount, 8);
    for (int i = 0; i < 20; i++) {
        digest[i] = (uint8_t)(ctx->state[i>>2] >> ((3-(i&3))*8));
    }
}

/*  SHA-256 Implementation (standalone, FIPS 180-4)  */

typedef struct {
    uint32_t state[8];
    uint64_t bitcount;
    uint8_t buffer[64];
    size_t buflen;
} sha256_ctx_t;

static const uint32_t sha256_k[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

#define SHA256_CH(x,y,z)  (((x) & (y)) ^ (~(x) & (z)))
#define SHA256_MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SHA256_SIG0(x)    (SHA256_ROTR(x,2) ^ SHA256_ROTR(x,13) ^ SHA256_ROTR(x,22))
#define SHA256_SIG1(x)    (SHA256_ROTR(x,6) ^ SHA256_ROTR(x,11) ^ SHA256_ROTR(x,25))
#define SHA256_ep0(x)     (SHA256_ROTR(x,7) ^ SHA256_ROTR(x,18) ^ ((x) >> 3))
#define SHA256_ep1(x)     (SHA256_ROTR(x,17) ^ SHA256_ROTR(x,19) ^ ((x) >> 10))
#define SHA256_ROTR(x,n)  (((x) >> (n)) | ((x) << (32-(n))))

static void sha256_transform(sha256_ctx_t *ctx, const uint8_t data[64]) {
    uint32_t m[64];
    for (int i = 0; i < 16; i++) {
        m[i] = ((uint32_t)data[i*4] << 24) | ((uint32_t)data[i*4+1] << 16) |
               ((uint32_t)data[i*4+2] << 8) | data[i*4+3];
    }
    for (int i = 16; i < 64; i++) {
        m[i] = SHA256_ep1(m[i-2]) + m[i-7] + SHA256_ep0(m[i-15]) + m[i-16];
    }
    uint32_t a = ctx->state[0], b = ctx->state[1], c = ctx->state[2], d = ctx->state[3];
    uint32_t e = ctx->state[4], f = ctx->state[5], g = ctx->state[6], h = ctx->state[7];
    for (int i = 0; i < 64; i++) {
        uint32_t t1 = h + SHA256_SIG1(e) + SHA256_CH(e,f,g) + sha256_k[i] + m[i];
        uint32_t t2 = SHA256_SIG0(a) + SHA256_MAJ(a,b,c);
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

static void sha256_init(sha256_ctx_t *ctx) {
    ctx->state[0] = 0x6a09e667; ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372; ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f; ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab; ctx->state[7] = 0x5be0cd19;
    ctx->bitcount = 0;
    ctx->buflen = 0;
}

static void sha256_update(sha256_ctx_t *ctx, const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        ctx->buffer[ctx->buflen++] = data[i];
        ctx->bitcount += 8;
        if (ctx->buflen == 64) {
            sha256_transform(ctx, ctx->buffer);
            ctx->buflen = 0;
        }
    }
}

static void sha256_final(uint8_t digest[32], sha256_ctx_t *ctx) {
    size_t padlen = (ctx->buflen < 56) ? (56 - ctx->buflen) : (120 - ctx->buflen);
    uint8_t padding[128];
    padding[0] = 0x80;
    for (size_t i = 1; i < padlen; i++) padding[i] = 0;
    uint64_t total_bits = ctx->bitcount;
    uint8_t len_bytes[8];
    for (int i = 7; i >= 0; i--) {
        len_bytes[i] = total_bits & 0xFF;
        total_bits >>= 8;
    }
    sha256_update(ctx, padding, padlen);
    sha256_update(ctx, len_bytes, 8);
    for (int i = 0; i < 32; i++) {
        digest[i] = (uint8_t)(ctx->state[i>>2] >> ((3-(i&3))*8));
    }
}

/*  Hash wrapper  */

void calc_hashes(const uint8_t *data, size_t len, hashes_t *out) {
    md5_ctx_t md5;
    md5_init(&md5);
    md5_update(&md5, data, len);
    uint8_t md5_digest[16];
    md5_final(md5_digest, &md5);
    for (int i = 0; i < 16; i++) {
        sprintf(&out->md5[i*2], "%02x", md5_digest[i]);
    }
    out->md5[32] = '\0';

    sha1_ctx_t sha1;
    sha1_init(&sha1);
    sha1_update(&sha1, data, len);
    uint8_t sha1_digest[20];
    sha1_final(sha1_digest, &sha1);
    for (int i = 0; i < 20; i++) {
        sprintf(&out->sha1[i*2], "%02x", sha1_digest[i]);
    }
    out->sha1[40] = '\0';

    sha256_ctx_t sha256;
    sha256_init(&sha256);
    sha256_update(&sha256, data, len);
    uint8_t sha256_digest[32];
    sha256_final(sha256_digest, &sha256);
    for (int i = 0; i < 32; i++) {
        sprintf(&out->sha256[i*2], "%02x", sha256_digest[i]);
    }
    out->sha256[64] = '\0';
}

const char *identify_magic(const uint8_t *data, size_t len) {
    if (len < 4) return "Too small";
    if (memcmp(data, ELFMAG, 4) == 0) return "ELF Executable";
    if (data[0] == 'M' && data[1] == 'Z') return "DOS/PE Executable";
    if (len >= 4 && data[0] == 0xCA && data[1] == 0xFE && data[2] == 0xBA && data[3] == 0xBE)
        return "Java Class / Mach-O Universal";
    if (len >= 4 && data[0] == 0xCF && data[1] == 0xFA && data[2] == 0xED && data[3] == 0xFE)
        return "Mach-O 64-bit (little-endian)";
    if (len >= 2 && data[0] == 0x4c && data[1] == 0x01) return "Windows COFF (i386)";
    if (len >= 2 && data[0] == 0x64 && data[1] == 0x86) return "Windows COFF (x64)";
    if (len >= 4 && memcmp(data, "\x89PNG", 4) == 0) return "PNG Image";
    if (len >= 3 && memcmp(data, "GIF", 3) == 0) return "GIF Image";
    if (len >= 2 && data[0] == 0xFF && data[1] == 0xD8) return "JPEG Image";
    if (len >= 4 && memcmp(data, "PK\x03\x04", 4) == 0) return "ZIP Archive";
    if (len >= 4 && memcmp(data, "Rar!", 4) == 0) return "RAR Archive";
    if (len >= 2 && data[0] == 0x1f && data[1] == 0x8b) return "GZIP Compressed";
    if (len >= 3 && memcmp(data, "\x52\x49\x46\x46", 4) == 0) return "RIFF Container";
    return "Unknown / Raw Binary";
}
