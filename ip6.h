#ifndef IP6_H
#define IP6_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "net.h"

#define IP_VERSION_IPV6 6

#define IPV6_HDR_SIZE 40

#define IPV6_TOTAL_SIZE_MAX UINT16_MAX /* maximum value of uint16 */
#define IPV6_PAYLOAD_SIZE_MAX (IPV6_TOTAL_SIZE_MAX - IPV6_HDR_SIZE)

#define IPV6_ADDR_LEN       16
#define IPV6_ADDR_LEN16     8
#define IPV6_ADDR_LEN32     4
#define IPV6_ADDR_STR_LEN   40  /* "dddd:dddd:dddd:dddd:dddd:dddd:dddd:dddd\0" */

typedef struct {
    union {
        uint8_t __addr8[16];
        uint16_t __addr16[8];
        uint32_t __addr32[4];
    } ip6_aun;
#define addr8   ip6_aun.__addr8
#define addr16  ip6_aun.__addr16
#define addr32  ip6_aun.__addr32
} ip6_addr_t;

extern int
ip6_addr_pton(const char *p, ip6_addr_t *n);
extern char *
ip6_addr_ntop(const ip6_addr_t n, char *p, size_t size);

char *
ip6_protocol_name(uint8_t type);

extern int
ip6_init(void);

#endif