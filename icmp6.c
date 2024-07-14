#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "util.h"
#include "ip6.h"
#include "icmp6.h"

#define ICMP6_BUFSIZ IPV6_PAYLOAD_SIZE_MAX

static void
icmp6_input(const uint8_t *data, size_t len, ip6_addr_t src, ip6_addr_t dst, struct ip6_iface *iface)
{
    char addr1[IPV6_ADDR_STR_LEN];
    char addr2[IPV6_ADDR_STR_LEN];
    char addr3[IPV6_ADDR_STR_LEN];

    debugf("%s => %s, len=%zu, iface=%s",
        ip6_addr_ntop(src, addr1, sizeof(addr1)),
        ip6_addr_ntop(dst, addr2, sizeof(addr2)), len,
        ip6_addr_ntop(iface->addr, addr3, sizeof(addr3)));
    debugdump(data, len);
}

int
icmp6_init(void)
{
    if (ip6_protocol_register("ICMPV6", IPV6_PROTOCOL_ICMPV6, icmp6_input) == -1) {
        errorf("ip6_protocol_register() failure");
        return -1;
    }
    return 0;
}