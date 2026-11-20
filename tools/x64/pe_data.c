#include "pe_data.h"

#include <stdlib.h>
#include <string.h>

enum {
    PE_SCN_EXECUTE = 0x20000000,
    PE_SCN_READ = 0x40000000,
    PE_SCN_WRITE = 0x80000000
};

static uint16_t u16(const uint8_t *p) {
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static uint32_t u32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t u64(const uint8_t *p) {
    uint64_t value = 0;
    int i;
    for (i = 0; i < 8; i++)
        value |= (uint64_t)p[i] << (8 * i);
    return value;
}

static int in_file(size_t file_len, uint32_t off, uint32_t size) {
    return size == 0 || (off <= file_len && size <= file_len - off);
}

static int copy_name(const uint8_t *file, size_t file_len, uint32_t rva,
                     const uint32_t *sec_va, const uint32_t *sec_raw, const uint32_t *sec_n,
                     int nsec, char *dst) {
    int s, i;
    for (s = 0; s < nsec; s++) {
        if (rva < sec_va[s] || rva >= sec_va[s] + sec_n[s])
            continue;
        {
            uint32_t off = sec_raw[s] + (rva - sec_va[s]);
            if (!in_file(file_len, off, 1))
                return PE_ERR_FORMAT;
            for (i = 0; i < PE_NAME - 1; i++) {
                if (!in_file(file_len, off + (uint32_t)i, 1))
                    return PE_ERR_FORMAT;
                dst[i] = (char)file[off + (uint32_t)i];
                if (dst[i] == 0)
                    return dst[0] ? PE_OK : PE_ERR_FORMAT;
                if ((unsigned char)dst[i] < 0x20 || (unsigned char)dst[i] > 0x7e)
                    return PE_ERR_FORMAT;
            }
            return PE_ERR_FORMAT;
        }
    }
    return PE_ERR_FORMAT;
}

void pe_image_destroy(PeImage *image) {
    if (image == NULL)
        return;
    guest_destroy(image->mem);
    free(image);
}

int pe_load_data(const uint8_t *file, size_t file_len, const uint64_t *new_base,
                 int host_read_only, PeImage **out) {
    uint32_t e_lfanew, opt, size_of_image, entry, nrva, nsec, optsize;
    uint64_t preferred;
    int i;
    PeImage *image;
    uint32_t sec_va[96], sec_vsize[96], sec_raw[96], sec_rawsz[96], sec_file[96], sec_chars[96];
    if (out == NULL)
        return PE_ERR_FORMAT;
    *out = NULL;
    if (file == NULL || file_len < 0x40 || file_len > PE_MAX_IMAGE || file[0] != 'M' || file[1] != 'Z')
        return PE_ERR_FORMAT;
    e_lfanew = u32(file + 0x3C);
    if (e_lfanew < 0x40 || !in_file(file_len, e_lfanew, 24))
        return PE_ERR_FORMAT;
    if (memcmp(file + e_lfanew, "PE\0\0", 4) != 0)
        return PE_ERR_FORMAT;
    if (u16(file + e_lfanew + 4) != 0x8664)
        return PE_ERR_FORMAT;
    nsec = u16(file + e_lfanew + 6);
    optsize = u16(file + e_lfanew + 20);
    if (nsec > 96 || optsize < 240 || !in_file(file_len, e_lfanew + 24, optsize))
        return PE_ERR_FORMAT;
    opt = e_lfanew + 24;
    if (u16(file + opt) != 0x20B)
        return PE_ERR_FORMAT;
    entry = u32(file + opt + 16);
    preferred = u64(file + opt + 24);
    size_of_image = u32(file + opt + 56);
    nrva = u32(file + opt + 108);
    if (size_of_image == 0 || size_of_image > PE_MAX_IMAGE || nrva > 16)
        return PE_ERR_RANGE;
    if (optsize < 112 + nrva * 8)
        return PE_ERR_FORMAT;
    if (!in_file(file_len, opt + optsize, nsec * 40))
        return PE_ERR_FORMAT;
    for (i = 0; i < (int)nsec; i++) {
        const uint8_t *sec = file + opt + optsize + (uint32_t)i * 40;
        uint32_t va = u32(sec + 12);
        uint32_t vsize = u32(sec + 8);
        uint32_t raw = u32(sec + 20);
        uint32_t rawsz = u32(sec + 16);
        if (vsize > size_of_image || va > size_of_image - vsize)
            return PE_ERR_RANGE;
        if (rawsz != 0 && !in_file(file_len, raw, rawsz > vsize ? vsize : rawsz))
            return PE_ERR_RANGE;
        sec_va[i] = va;
        sec_vsize[i] = vsize;
        sec_raw[i] = raw;
        sec_rawsz[i] = rawsz;
        sec_file[i] = rawsz < vsize ? rawsz : vsize;
        sec_chars[i] = u32(sec + 36);
        {
            int prev;
            for (prev = 0; prev < i; prev++) {
                uint32_t other = sec_va[prev];
                uint32_t other_end = other + sec_vsize[prev];
                if (vsize != 0 && sec_vsize[prev] != 0 && va < other_end && other < va + vsize)
                    return PE_ERR_RANGE;
            }
        }
    }
    image = calloc(1, sizeof *image);
    if (image == NULL)
        return PE_ERR_NOMEM;
    image->mem = guest_create();
    if (image->mem == NULL) {
        free(image);
        return PE_ERR_NOMEM;
    }
    image->preferred_base = preferred;
    image->image_base = new_base != NULL ? *new_base : preferred;
    image->size_of_image = size_of_image;
    image->entry_rva = entry;
    image->entry_called = 0;
    image->imports_bound = 0;
    image->section_count = (int)nsec;
    for (i = 0; i < (int)nsec; i++) {
        uint32_t copy = sec_rawsz[i] < sec_vsize[i] ? sec_rawsz[i] : sec_vsize[i];
        int perms = GUEST_PERM_READ;
        int rc;
        if (sec_vsize[i] == 0)
            continue;
        if (!host_read_only && (sec_chars[i] & PE_SCN_WRITE))
            perms |= GUEST_PERM_WRITE;
        rc = guest_map(image->mem, sec_va[i], sec_vsize[i], perms,
                       copy ? file + sec_raw[i] : NULL, copy);
        if (rc != GUEST_OK) {
            pe_image_destroy(image);
            return rc == GUEST_ERR_NOMEM ? PE_ERR_NOMEM : PE_ERR_RANGE;
        }
        if (sec_chars[i] & PE_SCN_EXECUTE) {
            if (guest_set_logical_execute(image->mem, sec_va[i], sec_vsize[i], 1) != GUEST_OK) {
                pe_image_destroy(image);
                return PE_ERR_RANGE;
            }
        }
    }
    if (new_base != NULL && *new_base != preferred && nrva > 5) {
        uint32_t reloc_rva = u32(file + opt + 112 + 5 * 8);
        uint32_t reloc_size = u32(file + opt + 112 + 5 * 8 + 4);
        int s;
        const uint8_t *reloc = NULL;
        if (reloc_rva != 0 && reloc_size != 0) {
            if (reloc_size > PE_MAX_IMAGE) {
                pe_image_destroy(image);
                return PE_ERR_RANGE;
            }
            for (s = 0; s < (int)nsec; s++) {
                if (reloc_rva >= sec_va[s] && reloc_size <= sec_vsize[s] &&
                    reloc_rva - sec_va[s] <= sec_vsize[s] - reloc_size &&
                    reloc_rva - sec_va[s] < sec_rawsz[s] &&
                    sec_rawsz[s] - (reloc_rva - sec_va[s]) >= reloc_size) {
                    reloc = file + sec_raw[s] + (reloc_rva - sec_va[s]);
                    break;
                }
            }
            if (reloc == NULL) {
                pe_image_destroy(image);
                return PE_ERR_RELOC;
            }
            if (guest_apply_dir64(image->mem, reloc, reloc_size, (*new_base - preferred) & 0xFFFFFFFFFFFFFFFFULL) != GUEST_OK) {
                pe_image_destroy(image);
                return PE_ERR_RELOC;
            }
            image->relocations_applied = 1;
        }
    }
    if (nrva > 1) {
        uint32_t imp_rva = u32(file + opt + 112 + 8);
        uint32_t imp_size = u32(file + opt + 112 + 12);
        uint32_t cursor = imp_rva;
        if (imp_rva != 0 && imp_size >= 20) {
            if (imp_size > 20 * PE_MAX_IMPORTS) {
                pe_image_destroy(image);
                return PE_ERR_RANGE;
            }
            while (image->import_count < PE_MAX_IMPORTS) {
                uint32_t desc_off = 0;
                int s, found = 0;
                uint32_t oft, name_rva, ft;
                for (s = 0; s < (int)nsec; s++) {
                    if (cursor >= sec_va[s] && cursor + 20 <= sec_va[s] + sec_rawsz[s] &&
                        cursor + 20 >= cursor) {
                        desc_off = sec_raw[s] + (cursor - sec_va[s]);
                        found = in_file(file_len, desc_off, 20);
                        break;
                    }
                }
                if (!found)
                    break;
                oft = u32(file + desc_off);
                name_rva = u32(file + desc_off + 12);
                ft = u32(file + desc_off + 16);
                if (oft == 0 && name_rva == 0 && ft == 0)
                    break;
                {
                    PeImport *row = &image->imports[image->import_count];
                    uint32_t thunk_rva = oft ? oft : ft;
                    int rc = copy_name(file, file_len, name_rva, sec_va, sec_raw, sec_file, (int)nsec, row->dll);
                    if (rc != PE_OK) {
                        pe_image_destroy(image);
                        return rc;
                    }
                    if (thunk_rva != 0) {
                        uint32_t thunk_off = 0;
                        int located = 0;
                        uint64_t thunk;
                        for (s = 0; s < (int)nsec; s++) {
                            if (thunk_rva >= sec_va[s] && thunk_rva + 8 <= sec_va[s] + sec_rawsz[s]) {
                                thunk_off = sec_raw[s] + (thunk_rva - sec_va[s]);
                                located = in_file(file_len, thunk_off, 8);
                                break;
                            }
                        }
                        if (!located) {
                            pe_image_destroy(image);
                            return PE_ERR_FORMAT;
                        }
                        thunk = u64(file + thunk_off);
                        if (thunk & 0x8000000000000000ULL) {
                            row->name[0] = '#';
                            row->name[1] = 0;
                        } else {
                            rc = copy_name(file, file_len, (uint32_t)thunk + 2, sec_va, sec_raw, sec_file,
                                           (int)nsec, row->name);
                            if (rc != PE_OK) {
                                pe_image_destroy(image);
                                return rc;
                            }
                        }
                    }
                    row->iat_rva = ft;
                    row->resolved = 0;
                    image->import_count++;
                }
                cursor += 20;
                if (cursor < imp_rva || cursor - imp_rva >= imp_size)
                    break;
            }
        }
    }
    if (guest_host_executable(image->mem) != 0) {
        pe_image_destroy(image);
        return PE_ERR_RANGE;
    }
    *out = image;
    return PE_OK;
}
