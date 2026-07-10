# Makefile for revtool - Binary Reverse Engineering Toolkit

CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra -Wpedantic -std=c11
LDFLAGS ?= -lm

# Optional: Enable Capstone disassembly engine
# Usage: make USE_CAPSTONE=1 CAPSTONE_CFLAGS="..." CAPSTONE_LDFLAGS="..."
ifdef USE_CAPSTONE
    CFLAGS  += -DUSE_CAPSTONE $(CAPSTONE_CFLAGS)
    LDFLAGS += $(CAPSTONE_LDFLAGS) -lcapstone
endif

# Optional: Enable debug build
ifdef DEBUG
    CFLAGS = -g -O0 -Wall -Wextra -Wpedantic -std=c11 -fsanitize=address
    LDFLAGS = -lm -fsanitize=address
endif

TARGET  = revtool
SRCS    = revtool.c common.c hexdump.c strings.c elf.c pe.c entropy.c disasm.c info.c scan.c
OBJS    = $(SRCS:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $@ $(LDFLAGS)

%.o: %.c common.h
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS)

fclean: clean
	rm -f $(TARGET)

install: $(TARGET)
	install -Dm755 $(TARGET) /usr/local/bin/$(TARGET)

uninstall:
	rm -f /usr/local/bin/$(TARGET)

test: $(TARGET)
	@echo "=== Testing revtool ==="
	@./$(TARGET) --version
	@./$(TARGET) --help
	@echo ""
	@echo "Test info on /bin/ls:"
	@./$(TARGET) info /bin/ls | head -20
	@echo ""
	@echo "Test hex on /bin/ls:"
	@./$(TARGET) hex -n 64 /bin/ls
	@echo ""
	@echo "Test strings on /bin/ls:"
	@./$(TARGET) strings -n 10 /bin/ls | head -10
	@echo ""
	@echo "Test entropy on /bin/ls:"
	@./$(TARGET) entropy /bin/ls | head -15
	@echo ""
	@echo "Test ELF on /bin/ls:"
	@./$(TARGET) elf /bin/ls | head -25

# Build with Capstone support
capstone:
	$(MAKE) clean
	$(MAKE) USE_CAPSTONE=1

# Debug build
debug:
	$(MAKE) clean
	$(MAKE) DEBUG=1

.PHONY: all clean install uninstall test
