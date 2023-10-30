#ifndef ND6_H
#define ND6_H

#include <stdint.h>

#include "ether.h"
#include "ip6.h"
#include "icmp6.h"

#define ND6_RESOLVE_ERROR      -1
#define ND6_RESOLVE_INCOMPLETE  0
#define ND6_RESOLVE_FOUND       1

struct nd_router_solicit {
    struct icmp6_hdr hdr;
    /* options follow. */
#define nd_rs_type		hdr.icmp6_type
#define nd_rs_code		hdr.icmp6_code
#define nd_rs_sum		hdr.icmp6_sum
#define nd_rs_reserved	hdr.icmp6_flag_reserved
};

#define ND6_RA_FLG_ISSET(x, y) ((x & 0xfc) & (y) ? 1 : 0)

#define ND6_RA_FLG_MGMT     0x80  // Management address configuration
#define ND6_RA_FLG_OTHER    0x40  // Other configuration
#define ND6_RA_FLG_HOME     0x20  // Home agent
#define ND6_RA_FLG_PRF      0x18  // Default router preference
#define ND6_RA_FLG_PROXY    0x04  // Proxy 

struct nd_router_adv {
    uint8_t	nd_ra_type;
	uint8_t	nd_ra_code;	    
	uint16_t nd_ra_sum;	
    uint8_t cur_hlim;
    uint8_t nd_ra_flg;
    uint16_t lifetime;        // router life time
    uint32_t reachable_time;  // reachable time
    uint32_t retransmit_time; // retransmit time
    /* options follow. */
};

struct nd_neighbor_solicit {
    struct icmp6_hdr hdr;
    ip6_addr_t target;
    /* options follow. */
#define nd_ns_type		hdr.icmp6_type
#define nd_ns_code		hdr.icmp6_code
#define nd_ns_sum		hdr.icmp6_sum
#define nd_ns_reserved	hdr.icmp6_flag_reserved
};

#define ND6_NA_FLG_ISSET(x, y) ((x & 0xe0000000) & (y) ? 1 : 0)

#define ND6_NA_FLAG_ROUTER		0x80000000
#define ND6_NA_FLAG_SOLICITED	0x40000000
#define ND6_NA_FLAG_OVERRIDE	0x20000000

struct nd_neighbor_adv {
    uint8_t	nd_na_type;
	uint8_t	nd_na_code;	    
	uint16_t nd_na_sum;	
    uint32_t nd_na_flg;
    ip6_addr_t target;
    /* options follow. */
};

struct nd_opt_hdr {
	u_int8_t type;
	u_int8_t len;
    /* options follow. */
};

/* ndp options */
#define ND_OPT_SOURCE_LINKADDR		1
#define ND_OPT_TARGET_LINKADDR		2
#define ND_OPT_PREFIX_INFORMATION	3
#define ND_OPT_REDIRECTED_HEADER	4
#define ND_OPT_MTU			        5

struct nd_opt_lladdr {
    uint8_t lladdr[ETHER_ADDR_LEN];
};

#define ND6_RA_PI_FLG_ISSET(x, y) ((x & 0xe0) & (y) ? 1 : 0)

#define ND6_RA_PI_FLG_LINK 0x80
#define ND6_RA_PI_FLG_AUTO 0x40
#define ND6_RA_PI_FLG_RTR  0x20

struct nd_opt_prefixinfo {
    uint8_t prefixlen;
    uint8_t flg;
    uint32_t valid_time;
    uint32_t preferred_time;
	uint32_t reserved2;
	ip6_addr_t prefix;
} __attribute__((__packed__));

struct nd_opt_redirect {
    // TODO: not supported
};

struct nd_opt_mtu {
    // TODO: not supported
};

extern int
nd6_resolve(struct ip6_iface *iface, ip6_addr_t ip6addr, uint8_t *lladdr);

extern void
nd6_options_dump(const uint8_t *options, size_t len);
extern void *
nd6_options(const uint8_t *options, size_t len, uint8_t type);

extern int
nd6_rs_output(struct ip6_iface *iface);

extern void
nd6_ra_input(const uint8_t *data, size_t len, ip6_addr_t src, ip6_addr_t dst, struct ip6_iface *iface);

extern void
nd6_ns_input(const uint8_t *data, size_t len, ip6_addr_t src, ip6_addr_t dst, struct ip6_iface *iface);
extern int
nd6_ns_output(struct ip6_iface *iface, const ip6_addr_t target);

extern void
nd6_na_input(const uint8_t *data, size_t len, ip6_addr_t src, ip6_addr_t dst, struct ip6_iface *iface);
extern int
nd6_na_output(uint8_t type, uint8_t code, uint32_t flags, const uint8_t *data, size_t len, ip6_addr_t src, ip6_addr_t dst, const ip6_addr_t target, const void *lladdr);

extern int 
nd6_init(void);

#endif