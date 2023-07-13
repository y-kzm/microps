#ifndef ND6_H
#define ND6_H

#include <stdint.h>

#include "ether.h"
#include "ip6.h"
#include "icmp6.h"

struct nd_neighbor_solicit {
    struct icmp6_hdr hdr;
    ip6_addr_t target;
    uint8_t options[0];
};

/*
struct nd_opt_hdr {
    uint8_t type;
    uint8_t len; 
    uint8_t options[0];
};
*/

struct nd_lladdr_opt {
    uint8_t type;
    uint8_t len;  
    uint8_t lladdr[ETHER_ADDR_LEN];
};

/*
struct nd_opt_hdr {
    uint8_t type;
    uint8_t len;
    union {

    } nd_opt_un;
};
*/





extern void
nd6_ns_input(const uint8_t *data, size_t len, ip6_addr_t src, ip6_addr_t dst, struct ip6_iface *iface);

#endif