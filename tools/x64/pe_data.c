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
                     int nsec, char *dst, size_t cap) {
    int s;
    size_t i;
    for (s = 0; s < nsec; s++) {
        if (rva < sec_va[s] || rva >= sec_va[s] + sec_n[s])
            continue;
        {
            uint32_t off = sec_raw[s] + (rva - sec_va[s]);
            for (i = 0; i < cap; i++) {
                unsigned char ch;
                if (!in_file(file_len, off + (uint32_t)i, 1) ||
                    rva + (uint32_t)i >= sec_va[s] + sec_n[s])
                    return PE_ERR_FORMAT;
                ch = file[off + (uint32_t)i];
                if (ch == 0) {
                    dst[i] = 0;
                    return i > 0 ? PE_OK : PE_ERR_FORMAT;
                }
                if (ch < 0x20 || ch > 0x7e)
                    return PE_ERR_FORMAT;
                dst[i] = (char)ch;
            }
            if (!in_file(file_len, off + (uint32_t)cap, 1) ||
                rva + (uint32_t)cap >= sec_va[s] + sec_n[s])
                return PE_ERR_FORMAT;
            if (file[off + (uint32_t)cap] == 0) {
                dst[cap] = 0;
                return PE_OK;
            }
            return PE_ERR_NAME;
        }
    }
    return PE_ERR_FORMAT;
}

void pe_image_destroy(PeImage *image) {
    if (image == NULL)
        return;
    guest_destroy(image->mem);
    free(image->imports);
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
            if (guest_loader_reloc(image->mem, reloc, reloc_size, (*new_base - preferred) & 0xFFFFFFFFFFFFFFFFULL) != GUEST_OK) {
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
        PeImport *rows = NULL;
        int symbols = 0, dlls = 0;
        if (imp_rva != 0 && imp_size >= 20) {
            if (imp_size > 20u * PE_MAX_DLLS) {
                pe_image_destroy(image);
                return PE_ERR_RANGE;
            }
            rows = calloc(PE_MAX_SYMBOLS, sizeof *rows);
            if (rows == NULL) {
                pe_image_destroy(image);
                return PE_ERR_NOMEM;
            }
            while (cursor >= imp_rva && cursor - imp_rva + 20 <= imp_size) {
                uint32_t desc_off = 0, oft, name_rva, ft, step;
                int s, found = 0, rc;
                char dll[PE_DLL_NAME + 1];
                for (s = 0; s < (int)nsec; s++) {
                    if (cursor >= sec_va[s] && cursor + 20 <= sec_va[s] + sec_file[s] && cursor + 20 >= cursor) {
                        desc_off = sec_raw[s] + (cursor - sec_va[s]);
                        found = in_file(file_len, desc_off, 20);
                        break;
                    }
                }
                if (!found) {
                    free(rows);
                    pe_image_destroy(image);
                    return PE_ERR_FORMAT;
                }
                oft = u32(file + desc_off);
                name_rva = u32(file + desc_off + 12);
                ft = u32(file + desc_off + 16);
                if (oft == 0 && name_rva == 0 && ft == 0)
                    break;
                if (dlls >= PE_MAX_DLLS) {
                    free(rows);
                    pe_image_destroy(image);
                    return PE_ERR_RANGE;
                }
                rc = copy_name(file, file_len, name_rva, sec_va, sec_raw, sec_file, (int)nsec, dll, PE_DLL_NAME);
                if (rc != PE_OK) {
                    free(rows);
                    pe_image_destroy(image);
                    return rc;
                }
                step = 0;
                for (;;) {
                    uint32_t name_rva_thunk = (oft ? oft : ft) + step * 8;
                    uint32_t iat_rva = (ft ? ft : oft) + step * 8;
                    uint64_t name_thunk = 0, iat_thunk = 0;
                    int name_ok = 0, iat_ok = 0;
                    if (oft == 0 && ft == 0)
                        break;
                    if (step >= PE_MAX_SYMBOLS || symbols >= PE_MAX_SYMBOLS) {
                        free(rows);
                        pe_image_destroy(image);
                        return PE_ERR_RANGE;
                    }
                    if (name_rva_thunk + 8 < name_rva_thunk || iat_rva + 8 < iat_rva) {
                        free(rows);
                        pe_image_destroy(image);
                        return PE_ERR_FORMAT;
                    }
                    for (s = 0; s < (int)nsec; s++) {
                        if (oft && name_rva_thunk >= sec_va[s] && name_rva_thunk + 8 <= sec_va[s] + sec_file[s]) {
                            uint32_t off = sec_raw[s] + (name_rva_thunk - sec_va[s]);
                            if (!in_file(file_len, off, 8))
                                break;
                            name_thunk = u64(file + off);
                            name_ok = 1;
                        }
                        if (ft && iat_rva >= sec_va[s] && iat_rva + 8 <= sec_va[s] + sec_file[s]) {
                            uint32_t off = sec_raw[s] + (iat_rva - sec_va[s]);
                            if (!in_file(file_len, off, 8))
                                break;
                            iat_thunk = u64(file + off);
                            iat_ok = 1;
                        }
                    }
                    if (oft && !name_ok) {
                        free(rows);
                        pe_image_destroy(image);
                        return PE_ERR_FORMAT;
                    }
                    if (ft && !iat_ok) {
                        free(rows);
                        pe_image_destroy(image);
                        return PE_ERR_FORMAT;
                    }
                    if (!oft)
                        name_thunk = iat_thunk;
                    if ((name_thunk == 0) != ((ft ? iat_thunk : name_thunk) == 0)) {
                        free(rows);
                        pe_image_destroy(image);
                        return PE_ERR_FORMAT;
                    }
                    if (name_thunk == 0)
                        break;
                    {
                        PeImport *row = &rows[symbols];
                        memcpy(row->dll, dll, PE_DLL_NAME + 1);
                        row->resolved = 0;
                        row->iat_rva = ft ? iat_rva : name_rva_thunk;
                        if (name_thunk & 0x8000000000000000ULL) {
                            row->by_ordinal = 1;
                            row->ordinal = (uint16_t)name_thunk;
                            row->name[0] = 0;
                        } else {
                            rc = copy_name(file, file_len, (uint32_t)name_thunk + 2, sec_va, sec_raw, sec_file,
                                           (int)nsec, row->name, PE_SYMBOL_NAME);
                            if (rc != PE_OK) {
                                free(rows);
                                pe_image_destroy(image);
                                return rc;
                            }
                            row->by_ordinal = 0;
                            row->ordinal = 0;
                        }
                        symbols++;
                        step++;
                    }
                }
                dlls++;
                cursor += 20;
            }
            if (symbols == 0) {
                free(rows);
                rows = NULL;
            } else {
                PeImport *shrunk = realloc(rows, (size_t)symbols * sizeof *rows);
                if (shrunk != NULL)
                    rows = shrunk;
            }
            image->imports = rows;
            image->dll_count = dlls;
            image->symbol_count = symbols;
            image->import_count = symbols;
        }
    }
    guest_seal(image->mem);
    if (guest_host_executable(image->mem) != 0) {
        pe_image_destroy(image);
        return PE_ERR_RANGE;
    }
    *out = image;
    return PE_OK;
}
