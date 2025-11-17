CC ?= gcc
CFLAGS ?= -std=gnu99 -O0 -g
LDFLAGS ?=
LIBS ?=

# 32-bit architecture (targeting i386 for this challenge)
CFLAGS += -m32

# Disable stack protector (focus on heap exploitation)
CFLAGS += -fno-stack-protector

# Enable PIE (Position Independent Executable)
CFLAGS += -pie -fPIE

# Enable Full RELRO (Read-Only Relocations)
LDFLAGS += -Wl,-z,relro,-z,now

# NX is enabled by default (non-executable stack)

ALL := target

.PHONY: all
all: $(ALL)

target: decimal_labyrinth_v2.c flag.h
	$(CC) $(CFLAGS) -o $@ decimal_labyrinth_v2.c $(LDFLAGS) $(LIBS)
	checksec --file $@ || true

.PHONY: clean
clean:
	$(RM) -f $(ALL)


