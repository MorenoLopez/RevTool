/*
 * disasm.c - Disassembly engine using Capstone (optional)
 * Falls back to raw hex dump if Capstone is not available.
 */

#include "common.h"

/* Try to use Capstone if available */
#if defined(USE_CAPSTONE)
#include <capstone/capstone.h>
#endif

static void print_hex_fallback(const uint8_t *data, size_t offset, size_t len, int width) {
    printf("%s[Capstone not available - showing hex dump]%s\n\n", c(C_YELLOW), c(C_RESET));
    for (size_t row = 0; row < len; row += width) {
        printf("%s%08zx%s  ", c(C_BRIGHT_BLUE), offset + row, c(C_RESET));
        size_t j;
        for (j = 0; j < (size_t)width && row + j < len; j++) {
            uint8_t b = data[row + j];
            const char *col = c(C_WHITE);
            if (b == 0) col = c(C_DIM);
            else if (b < 32 || b > 126) col = c(C_CYAN);
            printf("%s%02x%s ", col, b, c(C_RESET));
        }
        for (; j < (size_t)width; j++) printf("   ");
        printf(" |");
        for (j = 0; j < (size_t)width && row + j < len; j++) {
            uint8_t b = data[row + j];
            printf("%c", (b >= 32 && b <= 126) ? b : '.');
        }
        printf("|\n");
    }
}

#if defined(USE_CAPSTONE)

static int do_capstone_disasm(const uint8_t *data, size_t len, const char *arch, size_t base_addr, int max_insns) {
    csh handle;
    cs_arch csarch;
    cs_mode csmode;

    if (strcmp(arch, "x86") == 0) { csarch = CS_ARCH_X86; csmode = CS_MODE_32; }
    else if (strcmp(arch, "x64") == 0) { csarch = CS_ARCH_X86; csmode = CS_MODE_64; }
    else if (strcmp(arch, "arm") == 0) { csarch = CS_ARCH_ARM; csmode = CS_MODE_ARM; }
    else if (strcmp(arch, "arm64") == 0) { csarch = CS_ARCH_ARM64; csmode = CS_MODE_LITTLE_ENDIAN; }
    else {
        fprintf(stderr, "%sUnknown architecture: %s%s\n", c(C_RED), arch, c(C_RESET));
        return 1;
    }

    if (cs_open(csarch, csmode, &handle) != CS_ERR_OK) {
        print_hex_fallback(data, base_addr, len, 16);
        return 0;
    }
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    cs_insn *insn;
    size_t count = cs_disasm(handle, data, len, base_addr, max_insns, &insn);
    if (count == 0) {
        printf("%sNo instructions decoded.%s\n", c(C_YELLOW), c(C_RESET));
        cs_close(&handle);
        return 0;
    }

    printf("%10s  %-20s %-12s %s\n", "Address", "Bytes", "Mnemonic", "Operands");
    printf("----------------------------------------------------------------------\n");
    for (size_t i = 0; i < count; i++) {
        char bytes[64] = "";
        int blen = 0;
        for (int j = 0; j < insn[i].size && j < 12; j++) {
            blen += snprintf(bytes + blen, sizeof(bytes) - blen, "%02x ", insn[i].bytes[j]);
        }
        printf("%s0x%08lx%s  %s%-20s%s %s%-12s%s %s\n",
               c(C_BRIGHT_BLUE), (unsigned long)insn[i].address, c(C_RESET),
               c(C_CYAN), bytes, c(C_RESET),
               c(C_BRIGHT_YELLOW), insn[i].mnemonic, c(C_RESET),
               insn[i].op_str);
    }
    cs_free(insn, count);
    cs_close(&handle);
    return 0;
}

#else

static int do_capstone_disasm(const uint8_t *data, size_t len, const char *arch, size_t base_addr, int max_insns) {
    (void)arch;
    (void)max_insns;
    print_hex_fallback(data, base_addr, len, 16);
    return 0;
}

#endif

int cmd_disasm(int argc, char **argv) {
    const char *path = NULL;
    const char *arch = "x64";
    size_t offset = 0;
    size_t size = 4096;
    int count = 50;
    size_t base = 0x1000;

    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-a") == 0 && i + 1 < argc) {
            arch = argv[++i];
        } else if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            offset = strtoul(argv[++i], NULL, 0);
        } else if (strcmp(argv[i], "-s") == 0 && i + 1 < argc) {
            size = strtoul(argv[++i], NULL, 0);
        } else if (strcmp(argv[i], "-n") == 0 && i + 1 < argc) {
            char *end;
            long val = strtol(argv[++i], &end, 0);
            if (*end != '\0' || val <= 0) {
                fprintf(stderr, "%sError: -n requires a positive integer%s\n", c(C_RED), c(C_RESET));
                return 1;
            }
            count = (int)val;
        } else if (strcmp(argv[i], "-b") == 0 && i + 1 < argc) {
            base = strtoul(argv[++i], NULL, 0);
        } else if (!path) {
            path = argv[i];
        }
    }
    if (!path) {
        fprintf(stderr, "Usage: %s disasm <file> [-a arch] [-o offset] [-s size] [-n count] [-b base]\n", TOOL_NAME);
        return 1;
    }

    file_t *f = file_open(path);
    if (!f) return 1;
    if (offset >= f->size) {
        fprintf(stderr, "%sError: Offset beyond file size%s\n", c(C_RED), c(C_RESET));
        file_close(f);
        return 1;
    }
    if (offset + size > f->size) size = f->size - offset;

    printf("\n%s%sDisassembly:%s %s%s%s [%s] @ 0x%08lx\n",
           c(C_BOLD), c(C_RESET), c(C_RESET), c(C_CYAN), path, c(C_RESET), arch, (unsigned long)base);
    printf("%s\n", "======================================================================");

    int ret = do_capstone_disasm(f->data + offset, size, arch, base, count);
    file_close(f);
    return ret;
}
