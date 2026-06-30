/*
 * revtool.c - Binary Reverse Engineering Toolkit
 * Main entry point and command dispatch.
 */

#include "common.h"

static void usage(const char *prog) {
    printf("\n%s%sBinary Reverse Engineering Toolkit v%s%s\n\n",
           c(C_BRIGHT_CYAN), c(C_BOLD), VERSION, c(C_RESET));
    printf("%sUsage:%s %s <command> [options] <file>\n\n", c(C_BOLD), c(C_RESET), prog);
    printf("%sCommands:%s\n", c(C_BOLD), c(C_RESET));
    printf("  %-12s Show file metadata, magic bytes, hashes, and entropy\n", "info");
    printf("  %-12s Hex dump with colorized output and ASCII sidebar\n", "hex");
    printf("  %-12s Extract printable strings (ASCII/UTF-16LE)\n", "strings");
    printf("  %-12s Parse and display ELF headers, sections, and symbols\n", "elf");
    printf("  %-12s Parse and display PE headers, sections, and imports\n", "pe");
    printf("  %-12s Scan file for high-entropy regions (packing/encryption)\n", "entropy");
    printf("  %-12s Disassemble code sections (x86/x64/ARM)\n", "disasm");
    printf("  %-12s Run all analysis modules\n", "scan");
    printf("\n%sGlobal Options:%s\n", c(C_BOLD), c(C_RESET));
    printf("  --no-color   Disable colored output\n");
    printf("  -h, --help   Show this help message\n");
    printf("  -v, --version Show version\n");
    printf("\n%sExamples:%s\n", c(C_BOLD), c(C_RESET));
    printf("  %s info /bin/ls\n", prog);
    printf("  %s info -f /bin/ls          # Full ELF/PE analysis\n", prog);
    printf("  %s hex -n 256 /bin/ls       # Show 256 bytes\n", prog);
    printf("  %s hex -o 0x1000 -n 64 file.bin\n", prog);
    printf("  %s strings -n 8 /bin/ls     # Strings min 8 chars\n", prog);
    printf("  %s elf /bin/ls              # ELF headers\n", prog);
    printf("  %s pe malware.exe           # PE headers\n", prog);
    printf("  %s entropy -t 7.0 /bin/ls  # Entropy scan\n", prog);
    printf("  %s disasm -a x64 file.bin   # Disassemble x64 code\n", prog);
    printf("  %s disasm -a x86 -o 0x400 -s 512 -b 0x400 file.bin\n", prog);
    printf("  %s scan /bin/ls             # Full scan\n", prog);
    printf("\n");
}

int main(int argc, char **argv) {
    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    /*
     * Pre-process argv to extract global flags.
     * Build a new argv with flags removed so subcommands
     * see argv[1] as the command and argv[2] as the file.
     */
    char **new_argv = calloc(argc + 1, sizeof(char *));
    if (!new_argv) {
        perror("calloc");
        return 1;
    }
    int new_argc = 0;
    const char *cmd = NULL;

    new_argv[new_argc++] = argv[0];  /* program name */

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--no-color") == 0) {
            g_no_color = 1;
            continue;  /* skip this flag in new_argv */
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            free(new_argv);
            return 0;
        } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--version") == 0) {
            printf("%s version %s\n", TOOL_NAME, VERSION);
            free(new_argv);
            return 0;
        }
        /* Not a global flag; keep it */
        if (!cmd && argv[i][0] != '-') {
            cmd = argv[i];
        }
        new_argv[new_argc++] = argv[i];
    }
    new_argv[new_argc] = NULL;

    if (!cmd || new_argc < 2) {
        usage(new_argv[0]);
        free(new_argv);
        return 1;
    }

    int ret;
    if (strcmp(cmd, "info") == 0) {
        ret = cmd_info(new_argc, new_argv);
    } else if (strcmp(cmd, "hex") == 0) {
        ret = cmd_hexdump(new_argc, new_argv);
    } else if (strcmp(cmd, "strings") == 0) {
        ret = cmd_strings(new_argc, new_argv);
    } else if (strcmp(cmd, "elf") == 0) {
        ret = cmd_elf(new_argc, new_argv);
    } else if (strcmp(cmd, "pe") == 0) {
        ret = cmd_pe(new_argc, new_argv);
    } else if (strcmp(cmd, "entropy") == 0) {
        ret = cmd_entropy(new_argc, new_argv);
    } else if (strcmp(cmd, "disasm") == 0) {
        ret = cmd_disasm(new_argc, new_argv);
    } else if (strcmp(cmd, "scan") == 0) {
        ret = cmd_scan(new_argc, new_argv);
    } else {
        fprintf(stderr, "%sUnknown command: '%s'%s\n", c(C_RED), cmd, c(C_RESET));
        usage(new_argv[0]);
        free(new_argv);
        return 1;
    }
    free(new_argv);
    return ret;
}
