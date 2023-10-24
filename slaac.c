#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "platform.h"

#include "util.h"
#include "net.h"
#include "ether.h"
#include "ip6.h"
#include "nd6.h"

/*
 * Utils
 */

static void
slaac_addr_create_globaladdr(const uint8_t *hwaddr, const ip6_addr_t prefix, const uint8_t prefixlen, ip6_addr_t *ip6addr)
{
    uint8_t eui64[ETHER_EUI64_ID_LEN];

    ether_addr_create_eui64(hwaddr, eui64);
    ip6_addr_create_global(eui64, prefix, prefixlen, ip6addr);
}

/*
 * SLAAC: input/output
 */

void
slaac_ra_input(const uint8_t *data, size_t len, ip6_addr_t src, ip6_addr_t dst, struct ip6_iface *iface)
{
    struct nd_router_adv *ra;
    struct nd_opt_prefixinfo *opt_pi;

    struct ip6_iface *slaac_iface;
    ip6_addr_t ip6addr;
    char addr[IPV6_ADDR_STR_LEN];

    ra = (struct nd_router_adv *)data;
    opt_pi = nd6_options((uint8_t *)(ra + 1), len - sizeof(*ra), ND_OPT_PREFIX_INFORMATION);

    slaac_addr_create_globaladdr(iface->iface.dev->addr, opt_pi->prefix, opt_pi->prefixlen, &ip6addr);
    slaac_iface = ip6_iface_alloc(ip6_addr_ntop(ip6addr, addr, sizeof(addr)), opt_pi->prefixlen, 0);
    if (ip6_iface_register(iface->iface.dev, slaac_iface) == -1) {
        errorf("ip6_iface_register() failure");
        return;
    }

    // TODO: DAD & Set Default Route

    if (ip6_route_set_multicast(slaac_iface) != 0) {
        errorf("ip6_route_set_multicast() failure");
        return;
    }
    if (ip6_route_set_default_gateway(slaac_iface, ip6_addr_ntop(src, addr, sizeof(addr))) == -1) {
        errorf("ip6_route_set_default_gateway() failure");
        return;
    }

    /* done */
    iface->slaac.running = 0;
}

static int
slaac_rs_output(struct ip6_iface *iface) {
    return nd6_rs_output(iface);
}

/*
 * Misc
 */ 

int
slaac_run(struct ip6_iface *iface)
{
    infof("start SLAAC");
    return slaac_rs_output(iface);
}

