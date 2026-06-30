/*
 * info.c - File information display
 */

#include "common.h"

static void print_elf_summary(const char *path);
static void print_pe_summary(const char *path);

int cmd_info(int argc, char **argv) {
    const char *path = NULL;
    int full = 0;

    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-f") == 0 || strcmp(argv[i], "--full") == 0) {
            full = 1;
        } else if (!path) {
            path = argv[i];
        }
    }
    if (!path) {
        fprintf(stderr, "Usage: %s info <file> [-f]\n", TOOL_NAME);
        return 1;
    }

    file_t *f = file_open(path);
    if (!f) return 1;

    hashes_t hashes;
    calc_hashes(f->data, f->size, &hashes);
    double ent = calc_entropy(f->data, f->size);
    const char *magic = identify_magic(f->data, f->size);

    printf("\n%s%sFile Information%s\n", c(C_BOLD), c(C_RESET), c(C_RESET));
    printf("%s\n", "============================================================");
    printf("  File:        %s%s%s\n", c(C_BRIGHT_CYAN), path, c(C_RESET));
    printf("  Size:        %s%zu%s bytes (%.2f KB)\n", c(C_GREEN), f->size, c(C_RESET), f->size / 1024.0);
    printf("  Type:        %s%s%s\n", c(C_YELLOW), magic, c(C_RESET));
    printf("  Entropy:     %s%.4f%s/8.00 %s(high=packed/encrypted)%s\n",
           entropy_color(ent), ent, c(C_RESET), c(C_DIM), c(C_RESET));
    printf("\n%s%sHashes:%s\n", c(C_BOLD), c(C_RESET), c(C_RESET));
    printf("  MD5:         %s\n", hashes.md5);
    printf("  SHA1:        %s\n", hashes.sha1);
    printf("  SHA256:      %s\n", hashes.sha256);

    if (ent > 7.0) {
        printf("\n%s%s WARNING: High entropy detected! File may be packed or encrypted. %s\n",
               c(C_BG_RED), c(C_WHITE), c(C_RESET));
    }

    if (full) {
        if (strncmp(magic, "ELF", 3) == 0) {
            file_close(f);
            print_elf_summary(path);
            return 0;
        } else if (strncmp(magic, "DOS/PE", 6) == 0) {
            file_close(f);
            print_pe_summary(path);
            return 0;
        }
    }

    file_close(f);
    return 0;
}

/* Quick ELF summary for info -f */
static void print_elf_summary(const char *path) {
    extern int cmd_elf(int argc, char **argv);
    char *args[] = { (char*)TOOL_NAME, (char*)"elf", (char*)path, NULL };
    cmd_elf(3, args);
}

/* Quick PE summary for info -f */
static void print_pe_summary(const char *path) {
    extern int cmd_pe(int argc, char **argv);
    char *args[] = { (char*)TOOL_NAME, (char*)"pe", (char*)path, NULL };
    cmd_pe(3, args);
}
