/* Intentional native defects. This file is never part of a release build. */
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static volatile uint64_t racy_value;
static pthread_barrier_t barrier;

static void *race_worker(void *unused) {
    (void)unused;
    pthread_barrier_wait(&barrier);
    for (uint64_t i = 0; i < 10000; ++i) racy_value = i;
    return NULL;
}

static void *leak_worker(void *unused) {
    (void)unused;
    volatile unsigned char *bytes = malloc(65537);
    if (!bytes) abort();
    bytes[0] = 42;
    bytes[65536] = 7;
    /* Intentionally lose the only pointer when this thread exits. */
    return NULL;
}

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    if (strcmp(argv[1], "good") == 0) {
        unsigned char *bytes = malloc(256);
        if (!bytes) abort();
        memset(bytes, 7, 256);
        volatile unsigned char value = bytes[255];
        free(bytes);
        if (value != 7) abort();
        puts("sanitizer-good-control-complete");
        return 0;
    }
    if (strcmp(argv[1], "address") == 0) {
        volatile uint64_t *pointer = malloc(sizeof(uint64_t));
        if (!pointer) abort();
        *pointer = 42;
        free((void *)pointer);
        return (int)*pointer; /* Intentional use after free. */
    }
    pthread_t thread;
    if (strcmp(argv[1], "thread") == 0) {
        if (pthread_barrier_init(&barrier, NULL, 2) != 0) abort();
        if (pthread_create(&thread, NULL, race_worker, NULL) != 0) abort();
        race_worker(NULL);
        pthread_join(thread, NULL);
        pthread_barrier_destroy(&barrier);
        return 0;
    }
    if (strcmp(argv[1], "leak") == 0) {
        if (pthread_create(&thread, NULL, leak_worker, NULL) != 0) abort();
        pthread_join(thread, NULL);
        return 0;
    }
    return 2;
}
