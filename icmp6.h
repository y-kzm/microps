#ifndef ICMP6_H
#define ICMP6_H

#include <stddef.h>
#include <stdint.h>

#include "ip6.h"

/* for error messages */
#define ICMPV6_TYPE_DEST_UNREACH    1
#define ICMPV6_TYPE_TOO_BIG         2 
#define ICMPV6_TYPE_TIME_EXCEEDED   3
#define ICMPV6_TYPE_PARAM_PROBLEM   4

/* for informational messages */
#define ICMPV6_TYPE_ECHO_REQUEST    128
#define ICMPV6_TYPE_ECHO_REPLY      129
#define ICMPV6_TYPE_ROUTER_SOL      133
#define ICMPV6_TYPE_ROUTER_ADV      134
#define ICMPV6_TYPE_NEIGHBOR_SOL    135
#define ICMPV6_TYPE_NEIGHBOR_ADV    136
#define ICMPV6_TYPE_REDIRECT        137

extern int
icmp6_output(uint8_t type, uint8_t code, const uint8_t *data, size_t len, ip6_addr_t src, ip6_addr_t dst);

extern int
icmp6_init(void);

#endif