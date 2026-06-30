/*
 * pe.c - PE/COFF file parser and printer
 */

#include "common.h"

static uint16_t r_u16(const uint8_t *d, size_t o) { return d[o] | (d[o+1] << 8); }
static uint32_t r_u32(const uint8_t *d, size_t o) { return ((uint32_t)d[o]) | ((uint32_t)d[o+1]<<8) | ((uint32_t)d[o+2]<<16) | ((uint32_t)d[o+3]<<24); }
static uint64_t r_u64(const uint8_t *d, size_t o) { return (uint64_t)r_u32(d,o) | ((uint64_t)r_u32(d,o+4) << 32); }

static const char *machine_name(uint16_t m) {
    switch (m) {
        case 0x014c: return "x86 (I386)";
        case 0x8664: return "x64 (AMD64)";
        case 0x01c0: return "ARM";
        case 0xaa64: return "ARM64";
        default: return "Unknown";
    }
}

static const char *subsystem_name(uint16_t s) {
    switch (s) {
        case 1: return "NATIVE";
        case 2: return "WINDOWS_GUI";
        case 3: return "WINDOWS_CUI";
        case 5: return "OS2_CUI";
        case 7: return "POSIX_CUI";
        case 9: return "WINDOWS_CE_GUI";
        case 10: return "EFI_APPLICATION";
        case 14: return "XBOX";
        case 16: return "BOOT_APPLICATION";
        default: return "Unknown";
    }
}

int cmd_pe(int argc, char **argv) {
    const char *path = NULL;

    for (int i = 2; i < argc; i++) {
        if (argv[i][0] != '-') {
            path = argv[i];
        }
    }
    if (!path) {
        fprintf(stderr, "Usage: %s pe <file>\n", TOOL_NAME);
        return 1;
    }

    file_t *f = file_open(path);
    if (!f) return 1;

    if (f->size < 64) {
        fprintf(stderr, "%sError: File too small%s\n", c(C_RED), c(C_RESET));
        file_close(f);
        return 1;
    }
    if (r_u16(f->data, 0) != IMAGE_DOS_SIGNATURE) {
        fprintf(stderr, "%sError: Not a valid PE file (missing MZ)%s\n", c(C_RED), c(C_RESET));
        file_close(f);
        return 1;
    }

    uint32_t lfanew = r_u32(f->data, 60);
    if (lfanew + 4 >= f->size || r_u32(f->data, lfanew) != IMAGE_NT_SIGNATURE) {
        fprintf(stderr, "%sError: Invalid PE signature%s\n", c(C_RED), c(C_RESET));
        file_close(f);
        return 1;
    }

    uint32_t coff_off = lfanew + 4;
    uint16_t machine = r_u16(f->data, coff_off);
    uint16_t num_sections = r_u16(f->data, coff_off + 2);
    uint32_t time_date = r_u32(f->data, coff_off + 4);
    uint32_t symtab = r_u32(f->data, coff_off + 8);
    uint32_t num_syms = r_u32(f->data, coff_off + 12);
    uint16_t opt_hdr_size = r_u16(f->data, coff_off + 16);
    uint16_t characteristics = r_u16(f->data, coff_off + 18);

    uint32_t opt_off = coff_off + 20;
    uint16_t magic = r_u16(f->data, opt_off);
    int is_pe32plus = (magic == 0x20b);

    uint32_t entry_point = r_u32(f->data, opt_off + 16);
    uint64_t image_base;
    uint32_t subsystem, checksum;
    uint64_t stack_reserve, stack_commit, heap_reserve, heap_commit;

    if (is_pe32plus) {
        image_base = r_u64(f->data, opt_off + 24);
        subsystem = r_u16(f->data, opt_off + 68);
        checksum = r_u32(f->data, opt_off + 64);
        stack_reserve = r_u64(f->data, opt_off + 72);
        stack_commit = r_u64(f->data, opt_off + 80);
        heap_reserve = r_u64(f->data, opt_off + 88);
        heap_commit = r_u64(f->data, opt_off + 96);
    } else {
        image_base = r_u32(f->data, opt_off + 28);
        subsystem = r_u16(f->data, opt_off + 68);
        checksum = r_u32(f->data, opt_off + 64);
        stack_reserve = r_u32(f->data, opt_off + 72);
        stack_commit = r_u32(f->data, opt_off + 76);
        heap_reserve = r_u32(f->data, opt_off + 80);
        heap_commit = r_u32(f->data, opt_off + 84);
    }

    printf("\n%s%sDOS Header:%s\n", c(C_BOLD), c(C_RESET), c(C_RESET));
    printf("  Magic:       %s0x%04x (MZ)%s\n", c(C_CYAN), IMAGE_DOS_SIGNATURE, c(C_RESET));
    printf("  lfanew:      0x%08x\n", lfanew);

    printf("\n%s%sCOFF Header:%s\n", c(C_BOLD), c(C_RESET), c(C_RESET));
    printf("  Machine:     %s%s%s\n", c(C_MAGENTA), machine_name(machine), c(C_RESET));
    printf("  Sections:    %u\n", num_sections);
    printf("  Timestamp:   %u\n", time_date);
    printf("  SymbolTable: 0x%08x (%u symbols)\n", symtab, num_syms);
    printf("  OptHdrSize:  %u\n", opt_hdr_size);
    printf("  Characteristics: 0x%04x\n", characteristics);

    printf("\n%s%sOptional Header:%s\n", c(C_BOLD), c(C_RESET), c(C_RESET));
    printf("  Magic:       %s\n", is_pe32plus ? "PE32+" : "PE32");
    printf("  Entry Point: %s0x%08x%s\n", c(C_BRIGHT_CYAN), entry_point, c(C_RESET));
    printf("  Image Base:  0x%08lx\n", (unsigned long)image_base);
    printf("  Subsystem:   %s\n", subsystem_name(subsystem));
    printf("  Stack Reserve: %lu\n", (unsigned long)stack_reserve);
    printf("  Stack Commit:  %lu\n", (unsigned long)stack_commit);
    printf("  Heap Reserve:  %lu\n", (unsigned long)heap_reserve);
    printf("  Heap Commit:   %lu\n", (unsigned long)heap_commit);
    printf("  Checksum:    0x%08x\n", checksum);

    /* Section Table */
    if (num_sections > 0 && num_sections < 256) {
        uint32_t sect_off = coff_off + 20 + opt_hdr_size;
        printf("\n%s%sSection Table:%s\n", c(C_BOLD), c(C_RESET), c(C_RESET));
        printf("%-12s %10s %10s %10s %10s %s\n",
               "Name", "VirtSize", "VirtAddr", "RawSize", "RawAddr", "Characteristics");
        printf("------------------------------------------------------------------------------------------\n");
        for (int i = 0; i < num_sections; i++) {
            size_t soff = sect_off + i * 40;
            if (soff + 40 > f->size) break;
            char name[9] = {0};
            memcpy(name, &f->data[soff], 8);
            uint32_t vsize = r_u32(f->data, soff + 8);
            uint32_t vaddr = r_u32(f->data, soff + 12);
            uint32_t rsize = r_u32(f->data, soff + 16);
            uint32_t raddr = r_u32(f->data, soff + 20);
            uint32_t ch = r_u32(f->data, soff + 36);

            char flags[32] = "";
            int fi = 0;
            if (ch & 0x20) { strcat(flags, "CODE "); fi++; }
            if (ch & 0x40) { strcat(flags, "IDATA "); fi++; }
            if (ch & 0x80) { strcat(flags, "UDATA "); fi++; }
            if (ch & 0x20000000) { strcat(flags, "EXEC "); fi++; }
            if (ch & 0x40000000) { strcat(flags, "READ "); fi++; }
            if (ch & 0x80000000) { strcat(flags, "WRITE "); fi++; }

            printf("%-12s %010x %010x %010x %010x %s\n",
                   name, vsize, vaddr, rsize, raddr, flags);
        }
    }

    file_close(f);
    return 0;
}
