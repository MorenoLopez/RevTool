/*
 * common.h - Binary Reverse Engineering Toolkit
 * Shared definitions, structures, and function prototypes.
 */

#ifndef REVTOOL_COMMON_H
#define REVTOOL_COMMON_H

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <errno.h>
#include <math.h>
#include <ctype.h>
#include <time.h>
#include <stdbool.h>

#define VERSION     "1.0.0"
#define TOOL_NAME   "revtool"

/*  Terminal Colors  */

#define C_RESET         "\033[0m"
#define C_BOLD          "\033[1m"
#define C_DIM           "\033[2m"
#define C_RED           "\033[31m"
#define C_GREEN         "\033[32m"
#define C_YELLOW        "\033[33m"
#define C_BLUE          "\033[34m"
#define C_MAGENTA       "\033[35m"
#define C_CYAN          "\033[36m"
#define C_WHITE         "\033[37m"
#define C_BRIGHT_RED    "\033[91m"
#define C_BRIGHT_GREEN  "\033[92m"
#define C_BRIGHT_YELLOW "\033[93m"
#define C_BRIGHT_BLUE   "\033[94m"
#define C_BRIGHT_MAGENTA "\033[95m"
#define C_BRIGHT_CYAN   "\033[96m"
#define C_BG_RED        "\033[41m"
#define C_BG_GREEN      "\033[42m"
#define C_BG_YELLOW     "\033[43m"
#define C_BG_BLUE       "\033[44m"

extern int g_no_color;

static inline const char *c(const char *name) {
    if (g_no_color) return "";
    return name;
}

/*  File Handle  */

typedef struct {
    const char *path;
    uint8_t *data;
    size_t size;
    int fd;
} file_t;

/*  Hash Results  */

typedef struct {
    char md5[33];
    char sha1[41];
    char sha256[65];
} hashes_t;

/*  ELF Structures (reconstructed for independence)  */

#define ELFMAG          "\177ELF"
#define EI_CLASS        4
#define EI_DATA         5
#define ELFCLASS32      1
#define ELFCLASS64      2
#define ELFDATA2LSB     1
#define ELFDATA2MSB     2
#define EM_386          3
#define EM_X86_64       62
#define EM_ARM          40
#define EM_AARCH64      183

/*  PE Structures  */

#define IMAGE_DOS_SIGNATURE     0x5A4D
#define IMAGE_NT_SIGNATURE      0x00004550
#define IMAGE_FILE_MACHINE_I386 0x014c
#define IMAGE_FILE_MACHINE_AMD64 0x8664

/*  Function Prototypes  */

/* common.c */
void banner(void);
file_t *file_open(const char *path);
void file_close(file_t *f);
double calc_entropy(const uint8_t *data, size_t len);
const char *entropy_color(double ent);
void calc_hashes(const uint8_t *data, size_t len, hashes_t *out);
const char *identify_magic(const uint8_t *data, size_t len);

/* hexdump.c */
int cmd_hexdump(int argc, char **argv);

/* strings.c */
int cmd_strings(int argc, char **argv);

/* elf.c */
int cmd_elf(int argc, char **argv);

/* pe.c */
int cmd_pe(int argc, char **argv);

/* entropy.c */
int cmd_entropy(int argc, char **argv);

/* disasm.c */
int cmd_disasm(int argc, char **argv);

/* info.c */
int cmd_info(int argc, char **argv);

/* scan.c */
int cmd_scan(int argc, char **argv);

#endif /* REVTOOL_COMMON_H */
