#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "platform.h"

#include "util.h"
#include "net.h"
#include "ether.h"
#include "ip6.h"
#include "nd6.h"

static void
slaac_generate_linklocaladdr(const uint8_t *hwaddr, ip6_addr_t *ip6addr)
{
    uint8_t eui64[ETHER_EUI64_ID_LEN];

    ether_addr_eui64(hwaddr, eui64);
    ip6_generate_linklocaladdr(eui64, ip6addr);
}

struct ip6_iface *
slaac_iface_process(struct net_device *dev)
{
    struct ip6_iface *iface;
    ip6_addr_t ip6addr;
    char addr[IPV6_ADDR_STR_LEN];

    slaac_generate_linklocaladdr(dev->addr, &ip6addr);
    iface = ip6_iface_alloc(ip6_addr_ntop(ip6addr, addr, sizeof(addr)), 64, 0); // TODO: Avoid hard-coding
    if (ip6_iface_register(dev, iface) == -1) {
        errorf("ip6_iface_register() failure");
        return NULL;
    }

    if (ip6_route_set_multicast(iface) != 0) {
        errorf("ip6_route_set_multicast() failure");
        return NULL;
    }

    nd6_rs_output(iface);

    return iface;
}