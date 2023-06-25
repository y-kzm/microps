#include <stdio.h>
#include <stdint.h>

#include "util.h"
#include "ip.h"
#include "ip6.h"
#include "icmp6.h"

struct icmp6_hdr {
	uint8_t	icmp6_type;	    /* type field */
	uint8_t	icmp6_code;	    /* code field */
	uint16_t icmp6_sum;	    /* checksum field */
    uint8_t icmp6_values[];
/*
    union {
        uint32_t icmp6_un_values32[1]; 
        uint16_t icmp6_un_values16[2]; 
        uint8_t icmp6_un_values8[4]; 
    } icmp6_vlaues_un;
#define icmp6_values32  icmp6_values_un.icmp6_un_values32
#define icmp6_values16  icmp6_values_un.icmp6_un_values16
#define icmp6_values8   icmp6_values_un.icmp6_un_values8
*/
};

struct icmp6_echo {
    uint8_t icmp6_type;
    uint8_t icmp6_code;
    uint16_t icmp6_sum;
    uint16_t icmp6_id;
    uint16_t icmp6_seq;
};


void
icmp6_input(const uint8_t *data, size_t len, ip6_addr_t src, ip6_addr_t dst, struct ip6_iface *iface)
{
    char addr1[IPV6_ADDR_STR_MAX_LEN];
    char addr2[IPV6_ADDR_STR_MAX_LEN];

    debugf("%s => %s, len=%zu", ip6_addr_ntop(src, addr1, sizeof(addr1)), ip6_addr_ntop(dst, addr2, sizeof(addr2)), len);
    debugdump(data, len);
};

int
icmp6_init(void)
{
    //if (ip6_protocol_register("ICMPv6", IP_PROTOCOL_ICMPV6, icmp_input) == -1) {
    if (ip6_protocol_register(IP_PROTOCOL_ICMPV6, icmp6_input) == -1) {
        errorf("ip6_protocol_register() failure");
        return -1;
    }
    return 0;
}