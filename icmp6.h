#ifndef ICMP6_H
#define ICMP6_H

#include <stddef.h>
#include <stdint.h>

#define ICMPV6_HDR_SIZE 8
#define ICMPV6_BUFSIZ IPV6_PAYLOAD_SIZE_MAX

/* error messages */
#define ICMPV6_TYPE_DEST_UNREACH    1
#define ICMPV6_TYPE_TOO_BIG         2 
#define ICMPV6_TYPE_TIME_EXCEEDED   3
#define ICMPV6_TYPE_PARAM_PROBLEM   4

/* informational messages */
#define ICMPV6_TYPE_ECHO_REQUEST    128
#define ICMPV6_TYPE_ECHO_REPLY      129
#define ICMPV6_TYPE_ROUTER_SOL      133
#define ICMPV6_TYPE_ROUTER_ADV      134
#define ICMPV6_TYPE_NEIGHBOR_SOL    135
#define ICMPV6_TYPE_NEIGHBOR_ADV    136
#define ICMPV6_TYPE_REDIRECT        137

struct icmp6_hdr {
	uint8_t	icmp6_type;	    
	uint8_t	icmp6_code;	    
	uint16_t icmp6_sum;	   
    uint32_t icmp6_flag_reserved;
};

struct icmp6_echo {
    uint8_t icmp6_type;
    uint8_t icmp6_code;
    uint16_t icmp6_sum;
    uint16_t icmp6_id;
    uint16_t icmp6_seq;
};

extern void 
icmp6_dump(const uint8_t *data, size_t len);

extern void
icmp6_input(const uint8_t *data, size_t len, ip6_addr_t src, ip6_addr_t dst, struct ip6_iface *iface);

extern int 
icmp6_output(uint8_t type, uint8_t code, uint32_t flags, const uint8_t*data, size_t len, ip6_addr_t src, ip6_addr_t dst);

extern int
icmp6_init(void);

#endif