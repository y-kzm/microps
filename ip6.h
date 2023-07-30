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
#define IPV6_ADDR_STR_LEN   40 /* "dddd:dddd:dddd:dddd:dddd:dddd:dddd:dddd\0" */
#define IPV6_ADDR(x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15, x16) {{{ \
    x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15, x16 }}}

/* address checking macros */
#define IS_IP6ADDR_MULTICAST(ip6addr) (ip6addr.addr8[0] == 0xff)
#define IPV6_SOLICITED_NODE_ADDR_PREFIX_LEN 104

/* protpcpl number (next header) */
/* see https://www.iana.org/assignments/protocol-numbers/protocol-numbers.txt */
#define IPV6_NEXT_HOP_BY_HOP    0x00 
#define IPV6_NEXT_TCP           0x06
#define IPV6_NEXT_UDP           0x11
#define IPV6_NEXT_IPV6          0x29 
#define IPV6_NEXT_ROUTING       0x2b 
#define IPV6_NEXT_FRAGMENT      0x2c 
#define IPV6_NEXT_ICMPV6        0x3a 
#define IPV6_NEXT_NO_NEXT       0x3b 
#define IPV6_NEXT_DEST_OPT      0x3c

/* typedef uint8_t[16] ip6_addr_t */
typedef struct {
    union {
        uint8_t __addr8[16];
        uint16_t __addr16[8];
    } __addr;
#define addr8   __addr.__addr8
#define addr16  __addr.__addr16
} ip6_addr_t;

struct ip6_iface {
    struct net_iface iface;
    struct ip6_iface *next;
    ip6_addr_t unicast;
    ip6_addr_t prefix; // TODO: 7/30
    uint8_t prefixlen;
    uint32_t scope_id;
};

struct ip6_hdr {
    union {
		uint32_t ip6_un_flow; /* ver(4) tc(8) flow-ID(20) */
		uint8_t ip6_un_vfc;	  /* ver(4) tc(8) */
	} ip6_un;
    uint16_t ip6_plen;  /* payload length */
	uint8_t  ip6_nxt;	/* next header */
	uint8_t  ip6_hlim;  /* hop limit */
    ip6_addr_t ip6_src;
    ip6_addr_t ip6_dst;
#define ip6_vfc		ip6_un.ip6_un_vfc
#define ip6_flow	ip6_un.ip6_un_flow
};

/* for compute checksum */
struct ip6_pseudo_hdr {
    ip6_addr_t src;
    ip6_addr_t dst;
    uint32_t len; /* upper-layer packet length */
    uint8_t zero[3];
    uint8_t nxt;
};

/* IPv6 addresses */
extern const ip6_addr_t IPV6_UNSPECIFIED_ADDR;
extern const ip6_addr_t IPV6_SOLICITED_NODE_ADDR_PREFIX;

extern int
ip6_addr_pton(const char *p, ip6_addr_t *n);
extern char *
ip6_addr_ntop(const ip6_addr_t n, char *p, size_t size);

extern void 
ip6_get_solicit_node_maddr(const ip6_addr_t ip6addr, ip6_addr_t *solicit_node_maddr);

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