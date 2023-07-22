#ifndef IP6_H
#define IP6_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "net.h"

#define IP_VERSION_IPV6 6

#define IPV6_HDR_SIZE 40
#define IPV6_TOTAL_SIZE_MAX UINT16_MAX      /* maximum value of uint16 */
#define IPV6_PAYLOAD_SIZE_MAX (IPV6_TOTAL_SIZE_MAX - IPV6_HDR_SIZE)

/* protpcpl number */
#define IP_PROTOCOL_ICMPV6  58  /* 0x3a */

#define IPV6_ADDR_STR_LEN   40      /* "dddd:dddd:dddd:dddd:dddd:dddd:dddd:dddd\0" */
#define IPV6_ADDR(x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15, x16) {{{ \
    x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15, x16 }}}

typedef struct {
    union {
        uint8_t __addr8[16];
        uint16_t __addr16[8];
    } __addr;
#define addr8   __addr.__addr8
#define addr16  __addr.__addr16
} ip6_addr_t;

#define IPV6_ADDR_LEN       16
#define IPV6_ADDR_LEN16     8
#define IPV6_ADDR_LEN32     4

struct ip6_iface {
    struct net_iface iface;
    struct ip6_iface *next;
    ip6_addr_t unicast;
    ip6_addr_t prefix;
    uint8_t prefixlen;
    uint32_t scope_id;
};

struct ip6_hdr {
    union {
		uint32_t ip6_un_flow;	    /* ver(4) tc(8) flow-ID(20) */
		uint8_t ip6_un_vfc;	        /* ver(4) tc(8) */
	} ip6_un;
    uint16_t ip6_plen;	            /* payload length */
	uint8_t  ip6_nxt;	            /* next header */
	uint8_t  ip6_hlim;	            /* hop limit */
    ip6_addr_t ip6_src;
    ip6_addr_t ip6_dst;
#define ip6_vfc		ip6_un.ip6_un_vfc
#define ip6_flow	ip6_un.ip6_un_flow
};

struct ip6_pseudo_hdr {
    ip6_addr_t src;
    ip6_addr_t dst;
    uint32_t len;       /* upper-layer packet length */
    uint8_t zero[3];
    uint8_t nxt;
};

extern const ip6_addr_t IPV6_ADDR_ANY;
extern const ip6_addr_t IPV6_SOLICITED_NODE_ADDR_PREFIX;
#define IPV6_SOLICITED_NODE_ADDR_PREFIX_LEN 104


extern int
ip6_addr_pton(const char *p, ip6_addr_t *n);
extern char *
ip6_addr_ntop(const ip6_addr_t n, char *p, size_t size);

extern void
ip6_dump(const uint8_t *data, size_t len);

extern struct ip6_iface *
ip6_iface_alloc(const char *unicast, const char *prefix);
extern int
ip6_iface_register(struct net_device *dev, struct ip6_iface *iface);
extern struct ip6_iface *
ip6_iface_select(ip6_addr_t addr);

extern ssize_t
ip6_output(uint8_t next, const uint8_t *data, size_t len, ip6_addr_t src, ip6_addr_t dst);

extern int
ip6_protocol_register(const char *name, uint8_t type, void (*handler)(const uint8_t *data, size_t len, ip6_addr_t src, ip6_addr_t dst, struct ip6_iface *iface));

extern int
ip6_init(void);

#endif