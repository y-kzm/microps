#ifndef ND6_H
#define ND6_H

#include <stdint.h>

#include "ether.h"
#include "ip6.h"
#include "icmp6.h"

#define ND6_RESOLVE_ERROR      -1
#define ND6_RESOLVE_INCOMPLETE  0
#define ND6_RESOLVE_FOUND       1

struct nd_neighbor_solicit {
    struct icmp6_hdr hdr;
    ip6_addr_t target;
    /* options follow. */
#define nd_ns_type		hdr.icmp6_type
#define nd_ns_code		hdr.icmp6_code
#define nd_ns_sum		hdr.icmp6_sum
#define nd_ns_reserved	hdr.icmp6_flag_reserved
};

struct nd_neighbor_adv {
    struct icmp6_hdr hdr;
    ip6_addr_t target;
    /* options follow. */
#define nd_na_type		hdr.icmp6_type
#define nd_na_code		hdr.icmp6_code
#define nd_na_sum		hdr.icmp6_sum
#define nd_na_reserved	hdr.icmp6_flag_reserved
};

#define ND_NA_FLAG_ROUTER		0x80000000
#define ND_NA_FLAG_SOLICITED	0x40000000
#define ND_NA_FLAG_OVERRIDE		0x20000000

/* not used */
struct nd_opt {
	u_int8_t	nd_opt_type;
	u_int8_t	nd_opt_len;
    union {
        uint8_t lladdr[ETHER_ADDR_LEN];
    } nd_opt_un;
#define nd_opt_lladdr nd_opt_un.lladdr
};

#define ND_OPT_SOURCE_LINKADDR		1
#define ND_OPT_TARGET_LINKADDR		2
#define ND_OPT_PREFIX_INFORMATION	3
#define ND_OPT_REDIRECTED_HEADER	4
#define ND_OPT_MTU			        5

struct nd_lladdr_opt {
    uint8_t type;
    uint8_t len;  
    uint8_t lladdr[ETHER_ADDR_LEN];
};

extern int
nd6_resolve(struct ip6_iface *iface, ip6_addr_t ip6addr, uint8_t *lladdr);

extern void
nd6_ns_input(const uint8_t *data, size_t len, ip6_addr_t src, ip6_addr_t dst, struct ip6_iface *iface);
extern int
nd6_ns_output(struct ip6_iface *iface, const ip6_addr_t target);

extern void
nd6_na_input(const uint8_t *data, size_t len, ip6_addr_t src, ip6_addr_t dst, struct ip6_iface *iface);
extern int
nd6_na_output(uint8_t type, uint8_t code, uint32_t flags, const uint8_t *data, size_t len, ip6_addr_t src, ip6_addr_t dst, const ip6_addr_t target, const void *lladdr);

#endif