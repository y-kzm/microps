#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sys/time.h>

#include "platform.h"

#include "util.h"
#include "net.h"
#include "ether.h"
#include "nd6.h"
#include "ip6.h"
#include "icmp6.h"

struct nd6_ns_hdr {
	uint8_t	type;
	uint8_t	code;
	uint16_t sum;
    ip6_addr_t target;
    uint8_t data[];
};

void
nd6_ns_input(const uint8_t *data, size_t len, ip6_addr_t src, ip6_addr_t dst, struct ip6_iface *iface)
{
    struct nd6_ns_hdr *hdr = (struct nd6_ns_hdr *)data;
    uint32_t flags = 0;
    char addr1[IPV6_ADDR_STR_LEN];
    char addr2[IPV6_ADDR_STR_LEN];
    char addr3[IPV6_ADDR_STR_LEN];

    if (!IPV6_ADDR_COMP(&hdr->target, &iface->addr, IPV6_ADDR_LEN)
        && !IPV6_ADDR_COMP(&dst, &IPV6_SOLICITED_NODE_ADDR_PREFIX, IPV6_SOLICITED_NODE_ADDR_PREFIX_LEN)) {
        errorf("nd6_ns_input() invalid target");
        return;
    }
    flags |= ND6_NA_FLAG_SOLICITED;

    debugf("%s => %s, iface=%s, type=%s(%u), len=%zu",
        ip6_addr_ntop(src, addr1, sizeof(addr1)),
        ip6_addr_ntop(dst, addr2, sizeof(addr2)),
        ip6_addr_ntop(iface->addr, addr3, sizeof(addr3)),
        icmp6_type_ntoa(hdr->type), hdr->type, len);
}