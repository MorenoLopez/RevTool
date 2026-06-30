/*
 * elf.c - ELF file parser and printer
 */

#include "common.h"

static uint16_t read_u16(const uint8_t *data, int lsb, size_t off) {
    if (lsb)
        return data[off] | (data[off+1] << 8);
    return (data[off] << 8) | data[off+1];
}

static uint32_t read_u32(const uint8_t *data, int lsb, size_t off) {
    if (lsb)
        return ((uint32_t)data[off]) | ((uint32_t)data[off+1] << 8) |
               ((uint32_t)data[off+2] << 16) | ((uint32_t)data[off+3] << 24);
    return ((uint32_t)data[off] << 24) | ((uint32_t)data[off+1] << 16) |
           ((uint32_t)data[off+2] << 8) | data[off+3];
}

static uint64_t read_u64(const uint8_t *data, int lsb, size_t off) {
    uint64_t lo = read_u32(data, lsb, off);
    uint64_t hi = read_u32(data, lsb, off + 4);
    return lsb ? (lo | (hi << 32)) : ((lo << 32) | hi);
}

static const char *elf_type_name(uint16_t type) {
    switch (type) {
        case 0: return "ET_NONE";
        case 1: return "ET_REL";
        case 2: return "ET_EXEC";
        case 3: return "ET_DYN";
        case 4: return "ET_CORE";
        default: return "Unknown";
    }
}

static const char *elf_machine_name(uint16_t machine) {
    switch (machine) {
        case EM_386: return "Intel 80386";
        case EM_X86_64: return "x86-64";
        case EM_ARM: return "ARM";
        case EM_AARCH64: return "AArch64";
        default: return "Unknown";
    }
}

static const char *elf_class_name(uint8_t cls) {
    if (cls == ELFCLASS32) return "ELF32";
    if (cls == ELFCLASS64) return "ELF64";
    return "Unknown";
}

static const char *elf_endian_name(uint8_t data) {
    if (data == ELFDATA2LSB) return "Little Endian";
    if (data == ELFDATA2MSB) return "Big Endian";
    return "Unknown";
}

static const char *phdr_type_name(uint32_t type) {
    switch (type) {
        case 0: return "NULL";
        case 1: return "LOAD";
        case 2: return "DYNAMIC";
        case 3: return "INTERP";
        case 4: return "NOTE";
        case 5: return "SHLIB";
        case 6: return "PHDR";
        case 7: return "TLS";
        case 0x6474e550: return "GNU_EH_FRAME";
        case 0x6474e551: return "GNU_STACK";
        case 0x6474e552: return "GNU_RELRO";
        default: return "UNKNOWN";
    }
}

static const char *shdr_type_name(uint32_t type) {
    switch (type) {
        case 0: return "NULL";
        case 1: return "PROGBITS";
        case 2: return "SYMTAB";
        case 3: return "STRTAB";
        case 4: return "RELA";
        case 5: return "HASH";
        case 6: return "DYNAMIC";
        case 7: return "NOTE";
        case 8: return "NOBITS";
        case 9: return "REL";
        case 11: return "DYNSYM";
        case 14: return "INIT_ARRAY";
        case 15: return "FINI_ARRAY";
        case 16: return "PREINIT_ARRAY";
        case 17: return "GROUP";
        case 18: return "SYMTAB_SHNDX";
        case 0x6ffffff6: return "GNU_HASH";
        case 0x6fffffff: return "VERDEF";
        case 0x6ffffffe: return "VERNEED";
        default: return "UNKNOWN";
    }
}

static void print_elf_info(const uint8_t *data, size_t size, int is_64, int lsb) {
    uint16_t e_type, e_machine, e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx;
    uint32_t e_version, e_flags;
    (void)e_version; (void)e_flags; (void)e_ehsize; (void)e_phentsize; (void)e_shentsize;
    uint64_t e_entry, e_phoff, e_shoff;

    if (is_64) {
        e_type = read_u16(data, lsb, 16);
        e_machine = read_u16(data, lsb, 18);
        e_version = read_u32(data, lsb, 20);
        e_entry = read_u64(data, lsb, 24);
        e_phoff = read_u64(data, lsb, 32);
        e_shoff = read_u64(data, lsb, 40);
        e_flags = read_u32(data, lsb, 48);
        e_ehsize = read_u16(data, lsb, 52);
        e_phentsize = read_u16(data, lsb, 54);
        e_phnum = read_u16(data, lsb, 56);
        e_shentsize = read_u16(data, lsb, 58);
        e_shnum = read_u16(data, lsb, 60);
        e_shstrndx = read_u16(data, lsb, 62);
    } else {
        e_type = read_u16(data, lsb, 16);
        e_machine = read_u16(data, lsb, 18);
        e_version = read_u32(data, lsb, 20);
        e_entry = read_u32(data, lsb, 24);
        e_phoff = read_u32(data, lsb, 28);
        e_shoff = read_u32(data, lsb, 32);
        e_flags = read_u32(data, lsb, 36);
        e_ehsize = read_u16(data, lsb, 40);
        e_phentsize = read_u16(data, lsb, 42);
        e_phnum = read_u16(data, lsb, 44);
        e_shentsize = read_u16(data, lsb, 46);
        e_shnum = read_u16(data, lsb, 48);
        e_shstrndx = read_u16(data, lsb, 50);
    }

    printf("\n%s%sELF Header:%s\n", c(C_BOLD), c(C_RESET), c(C_RESET));
    printf("  Magic:      ");
    for (int i = 0; i < 16; i++) printf("%02x ", data[i]);
    printf("\n");
    printf("  Class:      %s%s%s\n", c(C_GREEN), elf_class_name(data[EI_CLASS]), c(C_RESET));
    printf("  Endianness: %s\n", elf_endian_name(data[EI_DATA]));
    printf("  Type:       %s%s%s\n", c(C_YELLOW), elf_type_name(e_type), c(C_RESET));
    printf("  Machine:    %s%s%s\n", c(C_MAGENTA), elf_machine_name(e_machine), c(C_RESET));
    printf("  Entry:      %s0x%08lx%s\n", c(C_BRIGHT_CYAN), (unsigned long)e_entry, c(C_RESET));
    printf("  Phdr off:   %s0x%08lx%s (%u entries)\n", c(C_BRIGHT_BLUE), (unsigned long)e_phoff, c(C_RESET), e_phnum);
    printf("  Shdr off:   %s0x%08lx%s (%u entries)\n", c(C_BRIGHT_BLUE), (unsigned long)e_shoff, c(C_RESET), e_shnum);

    /* Program Headers */
    if (e_phoff > 0 && e_phnum > 0) {
        printf("\n%s%sProgram Headers:%s\n", c(C_BOLD), c(C_RESET), c(C_RESET));
        printf("%-16s %10s %12s %12s %10s %10s %5s %6s\n",
               "Type", "Offset", "VirtAddr", "PhysAddr", "FileSize", "MemSize", "Flags", "Align");
        printf("-------------------------------------------------------------------------------------\n");
        for (int i = 0; i < e_phnum; i++) {
            size_t off = e_phoff + i * e_phentsize;
            uint32_t p_type, p_flags = 0;
            uint64_t p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align;
            p_type = read_u32(data, lsb, off);
            if (is_64) {
                p_flags = read_u32(data, lsb, off + 4);
                p_offset = read_u64(data, lsb, off + 8);
                p_vaddr = read_u64(data, lsb, off + 16);
                p_paddr = read_u64(data, lsb, off + 24);
                p_filesz = read_u64(data, lsb, off + 32);
                p_memsz = read_u64(data, lsb, off + 40);
                p_align = read_u64(data, lsb, off + 48);
            } else {
                p_offset = read_u32(data, lsb, off + 4);
                p_vaddr = read_u32(data, lsb, off + 8);
                p_paddr = read_u32(data, lsb, off + 12);
                p_filesz = read_u32(data, lsb, off + 16);
                p_memsz = read_u32(data, lsb, off + 20);
                p_flags = read_u32(data, lsb, off + 24);
                p_align = read_u32(data, lsb, off + 28);
            }
            char flags[4] = "   ";
            if (p_flags & 1) flags[2] = 'X';
            if (p_flags & 2) flags[1] = 'W';
            if (p_flags & 4) flags[0] = 'R';
            printf("%-16s %010lx %012lx %012lx %010lx %010lx %5s %06lx\n",
                   phdr_type_name(p_type), (unsigned long)p_offset, (unsigned long)p_vaddr,
                   (unsigned long)p_paddr, (unsigned long)p_filesz, (unsigned long)p_memsz,
                   flags, (unsigned long)p_align);
        }
    }

    /* Section Headers */
    if (e_shoff > 0 && e_shnum > 0) {
        printf("\n%s%sSection Headers:%s\n", c(C_BOLD), c(C_RESET), c(C_RESET));
        printf("%4s %-18s %-12s %10s %8s %8s %7s %6s\n",
               "[Nr]", "Name", "Type", "Address", "Offset", "Size", "EntSize", "Flags");
        printf("------------------------------------------------------------------------------------------\n");

        /* Read string table */
        size_t strtab_off = 0, strtab_size = 0;
        if (e_shstrndx < e_shnum) {
            size_t soff = e_shoff + e_shstrndx * e_shentsize;
            if (is_64) {
                strtab_off = read_u64(data, lsb, soff + 24);
                strtab_size = read_u64(data, lsb, soff + 32);
            } else {
                strtab_off = read_u32(data, lsb, soff + 16);
                strtab_size = read_u32(data, lsb, soff + 20);
            }
        }

        for (int i = 0; i < e_shnum && i < 256; i++) {
            size_t off = e_shoff + i * e_shentsize;
            uint32_t sh_name = read_u32(data, lsb, off);
            uint32_t sh_type = read_u32(data, lsb, off + 4);
            uint64_t sh_flags, sh_addr, sh_offset, sh_size, sh_entsize;
            (void)sh_entsize;
            if (is_64) {
                sh_flags = read_u64(data, lsb, off + 8);
                sh_addr = read_u64(data, lsb, off + 16);
                sh_offset = read_u64(data, lsb, off + 24);
                sh_size = read_u64(data, lsb, off + 32);
                sh_entsize = read_u64(data, lsb, off + 56);
            } else {
                sh_flags = read_u32(data, lsb, off + 8);
                sh_addr = read_u32(data, lsb, off + 12);
                sh_offset = read_u32(data, lsb, off + 16);
                sh_size = read_u32(data, lsb, off + 20);
                sh_entsize = read_u32(data, lsb, off + 36);
            }

            char name_buf[32] = "<invalid>";
            if (strtab_off > 0 && sh_name < strtab_size) {
                size_t ns = strtab_off + sh_name;
                size_t ne = ns;
                while (ne < size && data[ne] != '\0') ne++;
                size_t nlen = ne - ns;
                if (nlen > 0 && nlen < sizeof(name_buf)) {
                    memcpy(name_buf, &data[ns], nlen);
                    name_buf[nlen] = '\0';
                }
            }

            char flags[8] = "";
            int fi = 0;
            if (sh_flags & 0x001) flags[fi++] = 'W';
            if (sh_flags & 0x002) flags[fi++] = 'A';
            if (sh_flags & 0x004) flags[fi++] = 'X';
            flags[fi] = '\0';

            printf("[%2d] %-18s %-12s %010lx %08lx %08lx %07lx %6s\n",
                   i, name_buf, shdr_type_name(sh_type),
                   (unsigned long)sh_addr, (unsigned long)sh_offset,
                   (unsigned long)sh_size, (unsigned long)sh_entsize, flags);
        }
    }
}

int cmd_elf(int argc, char **argv) {
    const char *path = NULL;

    for (int i = 2; i < argc; i++) {
        if (argv[i][0] != '-') {
            path = argv[i];
        }
    }
    if (!path) {
        fprintf(stderr, "Usage: %s elf <file>\n", TOOL_NAME);
        return 1;
    }

    file_t *f = file_open(path);
    if (!f) return 1;

    if (f->size < 64 || memcmp(f->data, ELFMAG, 4) != 0) {
        fprintf(stderr, "%sError: Not a valid ELF file%s\n", c(C_RED), c(C_RESET));
        file_close(f);
        return 1;
    }

    int is_64 = (f->data[EI_CLASS] == ELFCLASS64);
    int lsb = (f->data[EI_DATA] == ELFDATA2LSB);
    print_elf_info(f->data, f->size, is_64, lsb);

    file_close(f);
    return 0;
}
