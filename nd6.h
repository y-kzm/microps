#ifndef ND6_H
#define ND6_H

#include <stdint.h>

#include "ether.h"
#include "ip6.h"
#include "icmp6.h"

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
struct nd_opt_hdr {
	u_int8_t	nd_opt_type;
	u_int8_t	nd_opt_len;
	/* options follow. */
};

#define ND_OPT_SOURCE_LINKADDR		1
#define ND_OPT_TARGET_LINKADDR		2
#define ND_OPT_PREFIX_INFORMATION	3
#define ND_OPT_REDIRECTED_HEADER	4
#define ND_OPT_MTU			        5

// TODO: support other options
struct nd_lladdr_opt {
    uint8_t type;
    uint8_t len;  
    uint8_t lladdr[ETHER_ADDR_LEN];
};






extern void
nd6_ns_input(const uint8_t *data, size_t len, ip6_addr_t src, ip6_addr_t dst, struct ip6_iface *iface);

extern int
nd6_na_output(uint8_t type, uint8_t code, uint32_t flags, const uint8_t *data, size_t len, ip6_addr_t src, ip6_addr_t dst, const ip6_addr_t target, const void *lladdr);

#endif