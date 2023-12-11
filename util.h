#ifndef UTIL_H
#define UTIL_H

#include <stdio.h>
#include <stdint.h>
#include <unistd.h>

/* flags for debug */
//#define ENABLE_HEXDUMP
//#define ENABLE_HDRDUMP
//#define ENABLE_NDCACHEDUMP
//#define ENABLE_FIBDUMP

#define ENNABLE_PRINT_ERROR
//#define ENNABLE_PRINT_WARNIG
#define ENNABLE_PRINT_INFO
//#define ENNABLE_PRINT_DEBUG

#ifndef MAX
#define MAX(x, y) ((x) > (y) ? (x) : (y))
#endif
#ifndef MIN
#define MIN(x, y) ((x) < (y) ? (x) : (y))
#endif

#define countof(x) ((sizeof(x) / sizeof(*x)))
#define tailof(x) (x + countof(x))
#define indexof(x, y) (((uintptr_t)y - (uintptr_t)x) / sizeof(*y))

#define timeval_add_usec(x, y)         \
    do {                               \
        (x)->tv_sec += y / 1000000;    \
        (x)->tv_usec += y % 1000000;   \
        if ((x)->tv_usec >= 1000000) { \
            (x)->tv_sec += 1;          \
            (x)->tv_usec -= 1000000;   \
        }                              \
    } while(0);

#define timespec_add_nsec(x, y)           \
    do {                                  \
        (x)->tv_sec += y / 1000000000;    \
        (x)->tv_nsec += y % 1000000000;   \
        if ((x)->tv_nsec >= 1000000000) { \
            (x)->tv_sec += 1;             \
            (x)->tv_nsec -= 1000000000;   \
        }                                 \
    } while(0);

#ifdef ENNABLE_PRINT_ERROR
#define errorf(...) lprintf(stderr, 'E', __FILE__, __LINE__, __func__, __VA_ARGS__)
#else
#define errorf(...)
#endif
#ifdef ENNABLE_PRINT_WARNING
#define warnf(...) lprintf(stderr, 'W', __FILE__, __LINE__, __func__, __VA_ARGS__)
#else
#define warnf(...)
#endif
#ifdef ENNABLE_PRINT_INFO
#define infof(...) lprintf(stderr, 'I', __FILE__, __LINE__, __func__, __VA_ARGS__)
#else
#define infof(...)
#endif
#ifdef ENNABLE_PRINT_DEBUG
#define debugf(...) lprintf(stderr, 'D', __FILE__, __LINE__, __func__, __VA_ARGS__)
#else
#define debugf(...)
#endif

#ifdef ENABLE_HEXDUMP
#define debugdump(...) hexdump(stderr, __VA_ARGS__)
#else
#define debugdump(...)
#endif

extern int
lprintf(FILE *fp, int level, const char *file, int line, const char *func, const char *fmt, ...);
extern void
hexdump(FILE *fp, const void *data, size_t size);

struct queue_entry;

struct queue_head {
    struct queue_entry *head;
    struct queue_entry *tail;
    unsigned int num;
};

extern void
queue_init(struct queue_head *queue);
extern void *
queue_push(struct queue_head *queue, void *data);
extern void *
queue_pop(struct queue_head *queue);
extern void *
queue_peek(struct queue_head *queue);
extern void
queue_foreach(struct queue_head *queue, void (*func)(void *arg, void *data), void *arg);

extern uint16_t
hton16(uint16_t h);
extern uint16_t
ntoh16(uint16_t n);
extern uint32_t
hton32(uint32_t h);
extern uint32_t
ntoh32(uint32_t n);

extern uint16_t
cksum16(uint16_t *addr, uint16_t count, uint32_t init);

#endif
