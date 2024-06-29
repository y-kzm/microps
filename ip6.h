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

#define IPV6_ADDR(a, b, c, d, e, f, g, h) \
  {{{ \
    (a >> 8) & 0xff, a & 0xff, \
    (b >> 8) & 0xff, b & 0xff, \
    (c >> 8) & 0xff, c & 0xff, \
    (d >> 8) & 0xff, d & 0xff, \
    (e >> 8) & 0xff, e & 0xff, \
    (f >> 8) & 0xff, f & 0xff, \
    (g >> 8) & 0xff, g & 0xff, \
    (h >> 8) & 0xff, h & 0xff  \
  }}}
#define IPV6_ADDR_COMP(addr1, addr2, size) (memcmp((addr1)->addr8, (addr2)->addr8, size) == 0)
#define IPV6_ADDR_COPY(addr1, addr2, size) (memcpy((addr1)->addr8, (addr2)->addr8, size))

#define IPV6_ADDR_LEN       16
#define IPV6_ADDR_LEN16     8
#define IPV6_ADDR_LEN32     4
#define IPV6_ADDR_STR_LEN   40  /* "dddd:dddd:dddd:dddd:dddd:dddd:dddd:dddd\0" */

#define IPV6_PROTOCOL_HOPOPT   0x00
#define IPV6_PROTOCOL_TCP      0x06
#define IPV6_PROTOCOL_UDP      0x11
#define IPV6_PROTOCOL_IPV6     0x29
#define IPV6_PROTOCOL_ROUTING  0x2b
#define IPV6_PROTOCOL_FRAGMENT 0x2c
#define IPV6_PROTOCOL_ICMPV6   0x3a
#define IPV6_PROTOCOL_NONE     0x3b
#define IPV6_PROTOCOL_DSTOPT   0x3c

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

#define IPV6_ADDR_SCOPE_INTFACELOCAL 0x01
#define IPV6_ADDR_SCOPE_LINKLOCAL    0x02
#define IPV6_ADDR_SCOPE_SITELOCAL    0x05 /* deprecated */
#define IPV6_ADDR_SCOPE_ORGLOCAL     0x08
#define IPV6_ADDR_SCOPE_GLOBAL       0x0e

#define IPV6_IFACE_ANYCAST      0x01
#define IPV6_IFACE_TENTATIVE    0x02
#define IPV6_IFACE_DUPLICATED   0x04
#define IPV6_IFACE_DETACHED     0x08
#define IPV6_IFACE_DEPRECATED   0x10
#define IPV6_IFACE_NODAD        0x20
#define IPV6_IFACE_AUTOCONF     0x40
#define IPV6_IFACE_TEMPORARY    0x80

struct ip6_iface {
    struct net_iface iface;
    struct ip6_iface *next;
    ip6_addr_t addr;
    ip6_addr_t netmask;
    uint8_t prefixlen;
    uint32_t scope;
    uint8_t state;
};

extern int
ip6_addr_pton(const char *p, ip6_addr_t *n);
extern char *
ip6_addr_ntop(const ip6_addr_t n, char *p, size_t size);

char *
ip6_protocol_name(uint8_t type);

extern int
ip6_init(void);

#endif