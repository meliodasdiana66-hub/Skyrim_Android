/* Read a PE32+ file in place and map it as data. Prints metadata only.
   Does not call the entry point, bind imports, or modify the file.
*/
#include "pe_data.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint32_t rotr(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }

static void sha256(const uint8_t *data, size_t len, uint8_t out[32]) {
    static const uint32_t k[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };
    uint32_t h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a;
    uint32_t h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;
    size_t blocks = (len + 8) / 64 + 1;
    size_t total = blocks * 64;
    uint8_t *buf = calloc(1, total);
    size_t b, i;
    uint64_t bits;
    if (buf == NULL) {
        memset(out, 0, 32);
        return;
    }
    memcpy(buf, data, len);
    buf[len] = 0x80;
    bits = (uint64_t)len * 8;
    for (i = 0; i < 8; i++)
        buf[total - 1 - i] = (uint8_t)(bits >> (8 * i));
    for (b = 0; b < blocks; b++) {
        uint32_t w[64];
        uint32_t a = h0, c = h1, d = h2, e = h3, f = h4, g = h5, hh = h6, p = h7;
        for (i = 0; i < 16; i++)
            w[i] = ((uint32_t)buf[b * 64 + i * 4] << 24) | ((uint32_t)buf[b * 64 + i * 4 + 1] << 16) |
                   ((uint32_t)buf[b * 64 + i * 4 + 2] << 8) | buf[b * 64 + i * 4 + 3];
        for (i = 16; i < 64; i++) {
            uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
            uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }
        for (i = 0; i < 64; i++) {
            uint32_t S1 = rotr(f, 6) ^ rotr(f, 11) ^ rotr(f, 25);
            uint32_t ch = (f & g) ^ (~f & hh);
            uint32_t t1 = p + S1 + ch + k[i] + w[i];
            uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            uint32_t maj = (a & c) ^ (a & d) ^ (c & d);
            uint32_t t2 = S0 + maj;
            p = hh; hh = g; g = f; f = e + t1; e = d; d = c; c = a; a = t1 + t2;
        }
        h0 += a; h1 += c; h2 += d; h3 += e; h4 += f; h5 += g; h6 += hh; h7 += p;
    }
    free(buf);
    {
        uint32_t hs[8] = {h0, h1, h2, h3, h4, h5, h6, h7};
        for (i = 0; i < 8; i++) {
            out[i * 4] = (uint8_t)(hs[i] >> 24);
            out[i * 4 + 1] = (uint8_t)(hs[i] >> 16);
            out[i * 4 + 2] = (uint8_t)(hs[i] >> 8);
            out[i * 4 + 3] = (uint8_t)hs[i];
        }
    }
}

static int hex_eq(const uint8_t digest[32], const char *hex) {
    char got[65];
    size_t i;
    if (hex == NULL || strlen(hex) != 64)
        return 0;
    for (i = 0; i < 32; i++)
        sprintf(got + i * 2, "%02x", digest[i]);
    got[64] = 0;
    for (i = 0; i < 64; i++) {
        char a = got[i];
        char b = hex[i];
        if (b >= 'A' && b <= 'F')
            b = (char)(b - 'A' + 'a');
        if (a != b)
            return 0;
    }
    return 1;
}

int main(int argc, char **argv) {
    const char *path = NULL;
    const char *expect = NULL;
    FILE *fp;
    long sz;
    uint8_t *file;
    uint8_t digest[32];
    PeImage *image = NULL;
    int i, rc;
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--exe") == 0 && i + 1 < argc)
            path = argv[++i];
        else if (strcmp(argv[i], "--expect-sha256") == 0 && i + 1 < argc)
            expect = argv[++i];
        else {
            fprintf(stderr, "usage: pe_data_map --exe FILE [--expect-sha256 HEX]\n");
            return 2;
        }
    }
    if (path == NULL)
        return 2;
    fp = fopen(path, "rb");
    if (fp == NULL) {
        fprintf(stderr, "not a file\n");
        return 1;
    }
    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return 1;
    }
    sz = ftell(fp);
    if (sz < 0 || (unsigned long)sz > PE_MAX_IMAGE) {
        fclose(fp);
        fprintf(stderr, "file exceeds the 64 MiB cap\n");
        return 2;
    }
    rewind(fp);
    file = malloc((size_t)sz);
    if (file == NULL || fread(file, 1, (size_t)sz, fp) != (size_t)sz) {
        free(file);
        fclose(fp);
        return 1;
    }
    fclose(fp);
    sha256(file, (size_t)sz, digest);
    if (expect != NULL && !hex_eq(digest, expect)) {
        free(file);
        fprintf(stderr, "sha256 mismatch\n");
        return 3;
    }
    rc = pe_load_data(file, (size_t)sz, NULL, 1, &image);
    free(file);
    if (rc != PE_OK || image == NULL) {
        fprintf(stderr, "pe data map failed\n");
        return 2;
    }
    if (image->entry_called || image->imports_bound || guest_host_executable(image->mem)) {
        pe_image_destroy(image);
        fprintf(stderr, "refusing an executable mapping\n");
        return 2;
    }
    printf("{\n");
    printf("  \"tool\": \"pe-data-map\",\n");
    printf("  \"mapped\": true,\n");
    printf("  \"entryCalled\": false,\n");
    printf("  \"importsBound\": false,\n");
    printf("  \"hostExecutable\": false,\n");
    printf("  \"imageBase\": %llu,\n", (unsigned long long)image->image_base);
    printf("  \"sizeOfImage\": %u,\n", image->size_of_image);
    printf("  \"addressOfEntryPoint\": %u,\n", image->entry_rva);
    printf("  \"sectionCount\": %d,\n", image->section_count);
    printf("  \"importCount\": %d,\n", image->import_count);
    printf("  \"unresolvedImports\": %d,\n", image->import_count);
    printf("  \"relocationsApplied\": %d,\n", image->relocations_applied);
    printf("  \"note\": \"Data pages only. The entry point was not called and the file was not modified.\"\n");
    printf("}\n");
    pe_image_destroy(image);
    return 0;
}
