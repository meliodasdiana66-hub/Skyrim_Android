/* Print bound guest tokens. Does not call the entry point or write the file. */
#include "ae_iat.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    FILE *fp;
    long sz;
    uint8_t *file;
    PeImage *image = NULL;
    AeRegistry *registry = NULL;
    AeBindReport report;
    int i;
    if (argc != 2)
        return 2;
    fp = fopen(argv[1], "rb");
    if (fp == NULL)
        return 1;
    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return 1;
    }
    sz = ftell(fp);
    rewind(fp);
    file = malloc((size_t)sz);
    if (file == NULL || fread(file, 1, (size_t)sz, fp) != (size_t)sz) {
        free(file);
        fclose(fp);
        return 1;
    }
    fclose(fp);
    {
        int rc = pe_load_unsealed(file, (size_t)sz, NULL, 1, &image);
        if (rc != PE_OK) {
            free(file);
            fprintf(stderr, "load failed %d\n", rc);
            return 2;
        }
    }
    free(file);
    memset(&report, 0, sizeof report);
    if (ae_registry_from_image(image, &registry) != AE_OK || ae_bind_iat(image, registry, &report) != AE_OK) {
        fprintf(stderr, "bind refused\n");
        ae_registry_destroy(registry);
        pe_image_destroy(image);
        return 2;
    }
    guest_seal(image->mem);
    printf("{\"entryCalled\":false,\"importsBound\":true,\"hostExecutable\":%s,\"modeled\":%d,\"traps\":%d,\"slots\":[",
           guest_host_executable(image->mem) ? "true" : "false", report.modeled, report.traps);
    for (i = 0; i < registry->count; i++) {
        uint8_t raw[8];
        uint64_t token = 0;
        int b;
        if (guest_read(image->mem, image->imports[i].iat_rva, raw, 8) != GUEST_OK) {
            pe_image_destroy(image);
            ae_registry_destroy(registry);
            return 2;
        }
        for (b = 0; b < 8; b++)
            token |= (uint64_t)raw[b] << (8 * b);
        printf("%s{\"rva\":%u,\"token\":\"0x%llx\",\"name\":\"%s\",\"modeled\":%s}",
               i ? "," : "", image->imports[i].iat_rva, (unsigned long long)token,
               registry->items[i].name, registry->items[i].modeled ? "true" : "false");
    }
    printf("]}\n");
    ae_registry_destroy(registry);
    pe_image_destroy(image);
    return 0;
}
