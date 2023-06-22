#ifndef IP6_H
#define IP6_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "net.h"

#define IP_VERSION_IPV6 6

#define IPV6_HDR_LEN 40

#define IPV6_ADDR_LEN       16
#define IPV6_ADDR8_LEN      16
#define IPV6_ADDR16_LEN     8
#define IPV6_ADDR32_LEN     4
#define IPV6_ADDR_STR_MAX_LEN 40 /* "ddd:ddd:ddd:ddd:ddd:ddd:ddd:ddd\0" */

typedef struct {
    union {
        uint8_t __addr8[16];
        uint16_t __addr16[8];
        uint32_t __addr32[4];
    } __addr;
#define addr8   __addr.__addr8
#define addr16  __addr.__addr16
#define addr32  __addr.__addr32
} ip6_addr_t;

struct ip6_iface {
    struct net_iface iface;
    struct ip6_iface *next;
    ip6_addr_t unicast;
    ip6_addr_t prefix;
    // uint8_t prefixlen;
    // uint32_t scope_id;
};

int
ip6_addr_pton(const char *p, ip6_addr_t *n);
char *
ip6_addr_ntop(const ip6_addr_t n, char *p, size_t size);

void
ip6_dump(const uint8_t *data, size_t len);

struct ip6_iface *
ip6_iface_alloc(const char *unicast, const char *prefix);
int
ip6_iface_register(struct net_device *dev, struct ip6_iface *iface);
struct ip6_iface *
ip6_iface_select(ip6_addr_t addr);

int
ip6_init(void);

#endif