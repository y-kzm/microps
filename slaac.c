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

static void
slaac_generate_globaladdr(const uint8_t *hwaddr, const ip6_addr_t prefix, const uint8_t prefixlen, ip6_addr_t *ip6addr)
{
    uint8_t eui64[ETHER_EUI64_ID_LEN];

    ether_addr_eui64(hwaddr, eui64);
    ip6_generate_globaladdr(eui64, prefix, prefixlen, ip6addr);
}

void
slaac_ra_input(const uint8_t *data, size_t len, ip6_addr_t src, ip6_addr_t dst, struct ip6_iface *iface)
{
    struct nd_router_adv *ra;
    struct nd_opt_lladdr *opt_lladdr;
    struct nd_opt_prefixinfo *opt_pi;

    struct ip6_iface *slaac_iface;
    ip6_addr_t ip6addr;
    char addr[IPV6_ADDR_STR_LEN];

    ra = (struct nd_router_adv *)data;
    opt_lladdr = nd6_options((uint8_t *)(ra + 1), len - sizeof(*ra), ND_OPT_SOURCE_LINKADDR);
    opt_pi = nd6_options((uint8_t *)(ra + 1), len - sizeof(*ra), ND_OPT_PREFIX_INFORMATION);

    slaac_generate_globaladdr(iface->iface.dev->addr, opt_pi->prefix, opt_pi->prefixlen, &ip6addr);
    slaac_iface = ip6_iface_alloc(ip6_addr_ntop(ip6addr, addr, sizeof(addr)), opt_pi->prefixlen, 1); // TODO: Avoid hard-coding
    if (ip6_iface_register(iface->iface.dev, slaac_iface) == -1) {
        errorf("ip6_iface_register() failure");
        return;
    }

    if (ip6_route_set_multicast(slaac_iface) != 0) {
        errorf("ip6_route_set_multicast() failure");
        return;
    }

    iface->slaac = 0;
}

static struct ip6_iface *
slaac_rs_output(struct net_device *dev)
{
    struct ip6_iface *iface;
    ip6_addr_t ip6addr;
    char addr[IPV6_ADDR_STR_LEN];

    slaac_generate_linklocaladdr(dev->addr, &ip6addr);
    iface = ip6_iface_alloc(ip6_addr_ntop(ip6addr, addr, sizeof(addr)), 64, 1); // TODO: Avoid hard-coding
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

struct ip6_iface *
slaac_process_start(struct net_device *dev)
{
    return slaac_rs_output(dev);
}

