/*
 * Decimal Labyrinth - House of Einherjar CTF Challenge
 * Numogram-themed heap exploitation challenge for glibc 2.27
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include "flag.h"

#define NUM_ZONES 10
#define MAX_OPS 30

const char* ZONE_NAMES[NUM_ZONES] = {
    "Lemurian", "Katak", "Sukugool", "Djinn", "Kattaku",
    "Sukuport", "Dubbe", "Djunana", "Ixix", "Oddubb"
};

const size_t ZONE_SIZES[NUM_ZONES] = {
    0x100, 0x180, 0x100, 0x180, 0x100,
    0x100, 0x100, 0x100, 0x100, 0x120
};

typedef struct {
    void (*execute)(void);
    uint64_t id;
    char data[256];
} Executor;

typedef struct {
    uint8_t number;
    uint8_t twin;
    char name[16];
    char data[0x80];
} Zone;

void* zones[NUM_ZONES] = {NULL};
bool exists[NUM_ZONES] = {false};
int corrupted = -1;
bool freed_one = false;
int ops = 0;
Executor* exec = NULL;

void win(void) {
    puts("\n[RETROCAUSAL BREACH ACHIEVED]");
    printf("%s\n", FLAG);
    exit(0);
}

void safe_exit(void) {
    puts("[Timeline collapsed safely]");
    exit(0);
}

void banner(void) {
    puts("═══════════════════════════════════════════════");
    puts(" DECIMAL LABYRINTH v0.NULL");
    puts(" Ten Zones. Five Syzygies. Three Time-Systems.");
    puts("═══════════════════════════════════════════════\n");
}

void menu(void) {
    printf("\n[Operations: %d/%d]\n", ops, MAX_OPS);
    puts("1. Manifest Zone");
    puts("2. Inscribe Data");
    puts("3. View Zone");
    puts("4. Corrupt Zone");
    puts("5. Liberate Zone");
    puts("6. Execute Timeline");
    puts("0. Exit");
    printf("> ");
}

int read_int(void) {
    char buf[32];
    if (fgets(buf, sizeof(buf), stdin) == NULL) return -1;
    return atoi(buf);
}

void read_data(char* buf, size_t size) {
    if (fgets(buf, size, stdin) == NULL) {
        buf[0] = '\0';
        return;
    }
    size_t len = strlen(buf);
    if (len > 0 && buf[len-1] == '\n') buf[len-1] = '\0';
}

void manifest_zone(void) {
    printf("Zone number (0-9): ");
    int n = read_int();

    if (n < 0 || n >= NUM_ZONES) {
        puts("[Invalid zone]");
        return;
    }
    if (exists[n]) {
        puts("[Zone already exists]");
        return;
    }

    size_t size = ZONE_SIZES[n];
    void* ptr = malloc(size);
    if (!ptr) {
        puts("[Allocation failed]");
        return;
    }

    memset(ptr, 0, size);
    zones[n] = ptr;
    exists[n] = true;

    if (n == 9) {
        exec = (Executor*)ptr;
        exec->execute = safe_exit;
        exec->id = 0x0909090909090909ULL;
        strcpy(exec->data, "Timeline Executor");
    } else {
        Zone* z = (Zone*)ptr;
        z->number = n;
        z->twin = 9 - n;
        strncpy(z->name, ZONE_NAMES[n], sizeof(z->name)-1);
    }

    printf("[Zone %d (%s) manifested at %p]\n", n, ZONE_NAMES[n], ptr);
}

void inscribe_data(void) {
    printf("Zone number (0-9): ");
    int n = read_int();

    if (n < 0 || n >= NUM_ZONES || !exists[n]) {
        puts("[Zone does not exist]");
        return;
    }

    if (n == 9) {
        puts("[Cannot inscribe to Zone 9]");
        return;
    }

    Zone* z = (Zone*)zones[n];

    // Read length first to support binary data
    printf("Data length: ");
    int len = read_int();

    if (len < 0) {
        puts("[Invalid length]");
        return;
    }

    // Determine max length based on corruption status
    // Need enough space to overflow and reach subsequent chunks
    int max_len = (corrupted == n) ? 0x400 : 0x80;
    if (len > max_len) {
        printf("[Length too large, max is 0x%x]\n", max_len);
        return;
    }

    printf("Data (max %d bytes): ", max_len);

    // Read binary data directly without strlen
    char input[0x200];
    size_t bytes_read = fread(input, 1, len, stdin);

    if (bytes_read != (size_t)len) {
        puts("[Failed to read data]");
        return;
    }

    if (corrupted == n) {
        puts("[Overflow enabled - writing with extra bytes]");
    }

    memcpy(z->data, input, len);

    printf("[Data inscribed to Zone %d]\n", n);
}

void view_zone(void) {
    printf("Zone number (0-9): ");
    int n = read_int();

    if (n < 0 || n >= NUM_ZONES || !exists[n]) {
        puts("[Zone does not exist]");
        return;
    }

    printf("\n[Zone %d - %s]\n", n, ZONE_NAMES[n]);
    printf("[Address: %p]\n", zones[n]);

    if (n == 9) {
        Executor* e = (Executor*)zones[n];
        printf("[Execute ptr: %p]\n", (void*)e->execute);
        printf("[ID: 0x%lx]\n", e->id);
        printf("[Data: %s]\n", e->data);
    } else {
        Zone* z = (Zone*)zones[n];
        printf("[Number: %d, Twin: %d]\n", z->number, z->twin);
        printf("[Name: %s]\n", z->name);
        printf("[Data: %.64s%s]\n", z->data, strlen(z->data) > 64 ? "..." : "");
    }
}

void corrupt_zone(void) {
    printf("Zone number (0-9): ");
    int n = read_int();

    if (n < 0 || n >= NUM_ZONES || !exists[n]) {
        puts("[Zone does not exist]");
        return;
    }
    if (n == 9) {
        puts("[Cannot corrupt Zone 9]");
        return;
    }
    if (corrupted >= 0 && corrupted != n) {
        printf("[Zone %d already corrupted]\n", corrupted);
        return;
    }

    corrupted = n;
    printf("[Zone %d corruption enabled - overflow allowed]\n", n);
}

void liberate_zone(void) {
    printf("Zone number (0-9): ");
    int n = read_int();

    if (n < 0 || n >= NUM_ZONES || !exists[n]) {
        puts("[Zone does not exist]");
        return;
    }
    if (n == 0 || n == 9) {
        printf("[Cannot liberate Zone %d]\n", n);
        return;
    }
    if (freed_one) {
        puts("[Already liberated a zone]");
        return;
    }

    printf("[Liberating Zone %d...]\n", n);
    free(zones[n]);
    freed_one = true;

    puts("[Liberation complete - backward consolidation may have occurred]");
}

void execute_timeline(void) {
    if (!exists[9]) {
        puts("[Zone 9 not manifested]");
        return;
    }

    puts("\n[Executing Timeline...]");
    exec->execute();
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);

    banner();

    while (ops < MAX_OPS) {
        menu();
        int choice = read_int();
        ops++;

        switch(choice) {
            case 1: manifest_zone(); break;
            case 2: inscribe_data(); break;
            case 3: view_zone(); break;
            case 4: corrupt_zone(); break;
            case 5: liberate_zone(); break;
            case 6: execute_timeline(); break;
            case 0:
                puts("[Exiting...]");
                return 0;
            default:
                puts("[Invalid]");
                ops--;
        }
    }

    puts("\n[Operation limit reached]");
    if (exists[9]) execute_timeline();
    return 0;
}
