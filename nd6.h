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

struct nd_router_adv {
    uint8_t	nd_ra_type;
	uint8_t	nd_ra_code;	    
	uint16_t nd_ra_sum;	
    uint8_t cur_hlim;
#if defined(_CPU_BIG_ENDIAN)
    uint8_t m   : 1;
    uint8_t o   : 1;
    uint8_t h   : 1;
    uint8_t prf : 2;
    uint8_t p   : 1;  
    uint8_t reserved : 2;
#else
    uint8_t reserved : 2;
    uint8_t p   : 1; // Proxy 
    uint8_t prf : 2; // Default router preference
    uint8_t h   : 1; // Home agent
    uint8_t o   : 1; // Other configuration
    uint8_t m   : 1; // Management address configuration
#endif
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

struct nd_neighbor_adv {
    struct icmp6_hdr hdr;
    ip6_addr_t target;
    /* options follow. */
#define nd_na_type		hdr.icmp6_type
#define nd_na_code		hdr.icmp6_code
#define nd_na_sum		hdr.icmp6_sum
#define nd_na_reserved	hdr.icmp6_flag_reserved
};

// TODO: 定義だけ
#define ND_NA_FLAG_ROUTER		0x80000000
#define ND_NA_FLAG_SOLICITED	0x40000000
#define ND_NA_FLAG_OVERRIDE		0x20000000

/* not used */
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

struct nd_opt_prefixinfo {
    uint8_t prefixlen;
#if defined(_CPU_BIG_ENDIAN)
    uint8_t l : 1;
    uint8_t a : 1;
    uint8_t r : 1;
    uint8_t reserved : 5;
#else
    uint8_t reserved : 5;
    uint8_t r : 1; // Router address
    uint8_t a : 1; // Autonomous address-configuration
    uint8_t l : 1; // On-link
#endif 
    uint32_t valid_time;
    uint32_t preferred_time;
	uint32_t reserved2;
	ip6_addr_t prefix;
} __attribute__((__packed__));

struct nd_opt_redirect {
    // TODO: 
};

struct nd_opt_mtu {
    // TODO: 
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