#ifndef IP6_H
#define IP6_H

#include <stdio.h>
#include <string.h>
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
#define IPV6_ENDPOINT_STR_LEN (IPV6_ADDR_STR_LEN + 8)  /* [xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx]:yyyyy\0 */
#define IPV6_ADDR(x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15, x16) {{{ \
    x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15, x16 }}}

/* macros for address checking */
#define IPV6_ADDR_EQUAL(addr1, addr2) (memcmp((addr1)->addr8, (addr2)->addr8, IPV6_ADDR_LEN) == 0)
#define IPV6_ADDR_COPY(addr1, addr2, prefixlen) (memcpy((addr1)->addr8, (addr2)->addr8, prefixlen))
#define IPV6_ADDR_MASK(addr1, addr2, masked)  {                          \
        (masked)->addr32[0] = (addr1)->addr32[0] & (addr2)->addr32[0]; \
        (masked)->addr32[1] = (addr1)->addr32[1] & (addr2)->addr32[1]; \
        (masked)->addr32[2] = (addr1)->addr32[2] & (addr2)->addr32[2]; \
        (masked)->addr32[3] = (addr1)->addr32[3] & (addr2)->addr32[3]; \
    }
#define IPV6_ADDR_IS_MULTICAST(ip6addr) ((ip6addr)->addr8[0] == 0xff)
#define IPV6_ADDR_IS_UNSPECIFIED(ip6addr) (memcmp((ip6addr)->addr8, &IPV6_UNSPECIFIED_ADDR, IPV6_ADDR_LEN) == 0)
#define IPV6_ADDR_IS_LOOPBACK(ip6addr) IPV6_ADDR_EQUAL(ip6addr, &IPV6_LOOPBACK_ADDR)
#define IPV6_ADDR_IS_LINKLOCAL(ip6addr) ((ip6addr)->addr8[0] == 0xfe && ((ip6addr)->addr8[1] & 0xc0) == 0x80)
#define IPV6_ADDR_IS_SITELOCAL(ip6addr) ((ip6addr)->addr8[0] == 0xfe && ((ip6addr)->addr8[1] & 0xc0) == 0xc0)
#define IPV6_ADDR_MC_SCOPE(ip6addr) ((ip6addr)->addr8[1] & 0x0f)

/* ipv6 address scope */
#define IPV6_ADDR_SCOPE_INTFACELOCAL 0x01
#define IPV6_ADDR_SCOPE_LINKLOCAL	 0x02
#define IPV6_ADDR_SCOPE_SITELOCAL	 0x05 /* deprecated */ 
#define IPV6_ADDR_SCOPE_ORGLOCAL	 0x08
#define IPV6_ADDR_SCOPE_GLOBAL		 0x0e

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
        uint8_t __u6_addr8[16];
        uint16_t __u6_addr16[8];
        uint32_t __u6_addr32[4];
    } __addr_un;
#define addr8   __addr_un.__u6_addr8
#define addr16  __addr_un.__u6_addr16
#define addr32  __addr_un.__u6_addr32
// TODO: s6_*
} ip6_addr_t;

/* ip6_iface state flags */
#define IPV6_IFACE_ANYCAST		0x01
#define IPV6_IFACE_TENTATIVE	0x02	
#define IPV6_IFACE_DUPLICATED	0x04
#define IPV6_IFACE_DETACHED	    0x08
#define IPV6_IFACE_DEPRECATED	0x10
#define IPV6_IFACE_NODAD		0x20
#define IPV6_IFACE_AUTOCONF	    0x40
#define IPV6_IFACE_TEMPORARY	0x80	

struct ip6_iface {
    struct net_iface iface;
    struct ip6_iface *next; /* unicast */
    struct {
        int running;
        int rdns;
    } slaac;  /* SLAAC context */
    struct {
        ip6_addr_t addr;
        ip6_addr_t netmask;
        uint8_t prefixlen;
        uint32_t scope;
        uint8_t state;      /* use with auto-generated addresses */
    } ip6_addr_ctx;
#define ip6_addr ip6_addr_ctx    
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
#define ip6_vfc	 ip6_un.ip6_un_vfc
#define ip6_flow ip6_un.ip6_un_flow    
};

/* for checksum calculation */
struct ip6_pseudo_hdr {
    ip6_addr_t src;
    ip6_addr_t dst;
    uint32_t len;       /* upper-layer packet length */
    uint8_t zero[3];
    uint8_t nxt;
};

/* IPv6 addresses */
extern const ip6_addr_t IPV6_UNSPECIFIED_ADDR;
extern const ip6_addr_t IPV6_SOLICITED_NODE_ADDR_PREFIX;
extern const ip6_addr_t IPV6_LOOPBACK_ADDR;
extern const ip6_addr_t IPV6_LINK_LOCAL_ALL_ROUTERS_ADDR;
extern const ip6_addr_t IPV6_MULTICAST_ADDR_PREFIX;

#define IPV6_SOLICITED_NODE_ADDR_PREFIX_LEN     104
#define IPV6_MULTICAST_ADDR_PREFIX_LEN          8
#define IPV6_LINK_LOCAL_ADDR_PREFIX_LEN         10

extern int
ip6_addr_pton(const char *p, ip6_addr_t *n);
extern char *
ip6_addr_ntop(const ip6_addr_t n, char *p, size_t size);
extern void 
ip6_addr_create_solicit_mcastaddr(const ip6_addr_t ip6addr, ip6_addr_t *solicited_node_mcaddr);
extern void
ip6_addr_create_globaladdr(const uint8_t *eui64, const ip6_addr_t prefix, const uint8_t prefixlen, ip6_addr_t *ip6addr);

extern struct ip6_iface *
ip6_rule_addr_select(const ip6_addr_t dst);

extern void
ip6_dump(const uint8_t *data, size_t len);

extern int
ip6_route_set_default_gateway(struct ip6_iface *iface, const char *gateway);
extern int
ip6_route_set_multicast(struct ip6_iface *iface);
extern struct ip6_iface *
ip6_route_get_iface(ip6_addr_t dst);

extern struct ip6_iface *
ip6_iface_alloc(const char *addr, const uint8_t prefixlen, int enable);
extern int
ip6_iface_register(struct net_device *dev, struct ip6_iface *iface);
extern struct ip6_iface *
ip6_iface_select(ip6_addr_t addr);

extern ssize_t
ip6_output(uint8_t next, const uint8_t *data, size_t len, ip6_addr_t src, ip6_addr_t dst);

extern int
ip6_protocol_register(const char *name, uint8_t type, void (*handler)(const uint8_t *data, size_t len, ip6_addr_t src, ip6_addr_t dst, struct ip6_iface *iface));
extern struct ip6_iface *
ip6_iface_init(struct net_device *dev);

extern int
ip6_init(void);

#endif