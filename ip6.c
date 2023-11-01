#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "platform.h"

#include "util.h"
#include "net.h"
#include "ether.h"
#include "ip.h"
#include "ip6.h"
#include "icmp6.h"
#include "nd6.h"
#include "slaac.h"

struct ip6_protocol {
    struct ip6_protocol *next;
    char name[16];
    uint8_t type;
    void (*handler)(const uint8_t *data, size_t len, ip6_addr_t src, ip6_addr_t dst, struct ip6_iface *iface);    
};

struct ip6_route {
    struct ip6_route *next;
    ip6_addr_t network;
    ip6_addr_t netmask;
    ip6_addr_t nexthop;
    struct ip6_iface *iface;
};

static struct ip6_iface *ifaces;
static struct ip6_protocol *protocols; 
static struct ip6_route *routes;

static uint8_t
ip6_addr_netmask_to_prefixlen(ip6_addr_t netmask);
static int
ip6_forward(const uint8_t *data, size_t len, struct net_device *dev);

// Unspecified IPv6 address
const ip6_addr_t IPV6_UNSPECIFIED_ADDR = 
    IPV6_ADDR(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00);
// Loopback IPv6 address
const ip6_addr_t IPV6_LOOPBACK_ADDR = 
    IPV6_ADDR(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01);
// Link-local All-Nodes IPv6 address
const ip6_addr_t IPV6_LINK_LOCAL_ALL_NODES_ADDR = 
    IPV6_ADDR(0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01);
// Link-local All-Routers IPv6 address
const ip6_addr_t IPV6_LINK_LOCAL_ALL_ROUTERS_ADDR = 
    IPV6_ADDR(0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02);
// Link-local IPv6 address prefix
const ip6_addr_t IPV6_LINK_LOCAL_ADDR_PREFIX = 
    IPV6_ADDR(0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00);
// Solicited-node IPv6 address prefix
const ip6_addr_t IPV6_SOLICITED_NODE_ADDR_PREFIX =
    IPV6_ADDR(0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xff, 0x00, 0x00, 0x00);
// Multicast IPv6 address prefix
const ip6_addr_t IPV6_MULTICAST_ADDR_PREFIX =
    IPV6_ADDR(0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00);

/*
 * Utils
 */

/* reference: https://github.com/freebsd/freebsd-src/blob/main/sys/libkern/inet_pton.c */
int
ip6_addr_pton(const char *p, ip6_addr_t *n)
{
#define INT16_SIZE 2
	static const char xdigits_l[] = "0123456789abcdef";
	u_char tmp[IPV6_ADDR_LEN], *tp, *endp, *colonp;
	const char *xdigits;
	int ch, seen_xdigits;
	u_int val;

	memset((tp = tmp), '\0', IPV6_ADDR_LEN);
	endp = tp + IPV6_ADDR_LEN;
	colonp = NULL;

	if (*p == ':') {
		if (*++p != ':') {
			return 0;
        }
    }
	seen_xdigits = 0;
	val = 0;

	while ((ch = *p++) != '\0') {
		const char *pch;

		if ((pch = strchr((xdigits = xdigits_l), ch)) == NULL) {
            ;
        }
            
		if (pch != NULL) {
			val <<= 4;
			val |= (pch - xdigits);
			if (++seen_xdigits > 4) {
				return 0;
            }
			continue;
		}
		if (ch == ':') {
			if (!seen_xdigits) {
				if (colonp) {
					return 0;
                }
				colonp = tp;
				continue;
			} else if (*p == '\0') {
				return 0;
			}
			if (tp + INT16_SIZE > endp) {
				return 0;
            }
			*tp++ = (u_char) (val >> 8) & 0xff;
			*tp++ = (u_char) val & 0xff;
			seen_xdigits = 0;
			val = 0;
			continue;
		}
	}
	if (seen_xdigits) {
		if (tp + INT16_SIZE > endp) {
			return 0;
        }
		*tp++ = (u_char) (val >> 8) & 0xff;
		*tp++ = (u_char) val & 0xff;
	}
	if (colonp != NULL) {
		const int n = tp - colonp;
		int i;

		if (tp == endp)
			return (0);
		for (i = 1; i <= n; i++) {
			endp[- i] = colonp[n - i];
			colonp[n - i] = 0;
		}
		tp = endp;
	}
	if (tp != endp)
		return (0);
	memcpy(n->addr8, tmp, IPV6_ADDR_LEN);

	return 0;
}

/* reference: https://github.com/Oryx-Embedded/CycloneTCP/blob/master/ipv6/ipv6.c#L2364 */
char *
ip6_addr_ntop(const ip6_addr_t n, char *p, size_t size)
{
    uint16_t *u16;
    int i, j;
    char *tmp;
    int zstart = 0, zend = 0;
    u16 = (uint16_t *)&n.addr16;

    for (i = 0; i < IPV6_ADDR_LEN16; i++) {
        for(j = i; j < IPV6_ADDR_LEN16 && !u16[j]; j++) {
            // 
        }
        if ((j - i) > 1 && (j - i) > (zend - zstart)) {
            zstart = i;
            zend = j;
        }
    }
    for (tmp = p, i = 0; i < IPV6_ADDR_LEN16; i++) {
        if (i >= zstart && i < zend) {
            *(tmp++) = ':';
            i = zend - 1;
        } else {
            if (i > 0) {
                *(tmp++) = ':';
            }
            tmp += sprintf(tmp, "%x", ntoh16(u16[i]));
        }
    }
    if (zend == 8) {
        *(tmp++) = ':';
    }
    *tmp = '\0';
    return p;
}

/*
 * Dumnp
 */

void
ip6_dump(const uint8_t *data, size_t len)
{
    struct ip6_hdr *hdr;
    uint8_t v, tc;
    uint32_t flow;
    char addr[IPV6_ADDR_STR_LEN];

    flockfile(stderr);
    hdr = (struct ip6_hdr *)data;
    v = (hdr->ip6_vfc & 0xf0) >> 4;
    fprintf(stderr, "        ver: %u\n", v);
    tc = (hdr->ip6_vfc >> 4 & 0xf0);
    fprintf(stderr, "         tc: 0x%02x\n", tc);
    flow = (ntoh32(hdr->ip6_flow) & 0x000fffff);
    fprintf(stderr, "       flow: 0x%04x\n", flow);
    fprintf(stderr, "       plen: %u byte\n", ntoh16(hdr->ip6_plen));
    fprintf(stderr, "       next: %u\n", hdr->ip6_nxt);
    fprintf(stderr, "       hlim: %u\n", hdr->ip6_hlim);
    fprintf(stderr, "        src: %s\n", ip6_addr_ntop(hdr->ip6_src, addr, sizeof(addr)));
    fprintf(stderr, "        dst: %s\n", ip6_addr_ntop(hdr->ip6_dst, addr, sizeof(addr)));
#ifdef HEXDUMP
    hexdump(stderr, data, len);
#endif
    funlockfile(stderr);
}

void
ip6_fib_dump()
{
    struct ip6_route *route;
    char addr1[IPV6_ADDR_STR_LEN];
    char addr2[IPV6_ADDR_STR_LEN];
    char network[IPV6_ADDR_STR_LEN+4]; /* Add "/128" */
    char interface[IPV6_ADDR_STR_LEN+IFNAMSIZ+1];
    
    flockfile(stderr);
    fprintf(stderr, "network                        nexthop                        interface\n");
    fprintf(stderr, "=============================================================================================\n");
    for (route = routes; route; route = route->next) {
        sprintf(network, "%s/%d", ip6_addr_ntop(route->network, addr1, sizeof(addr1)), ip6_addr_netmask_to_prefixlen(route->netmask));
        sprintf(interface, "%s%%%s", ip6_addr_ntop(route->iface->ip6_addr.addr, addr1, sizeof(addr1)), route->iface->iface.dev->name);
        fprintf(stderr, "%-30s %-30s %-30s\n", 
                network, ip6_addr_ntop(route->nexthop, addr2, sizeof(addr2)), 
                interface);
    }
    funlockfile(stderr);
}

/*
 * Address-related
 */

/* Brief: generate multicast addr from mac addr by UEI-64 */
static void
ip6_addr_mcastaddr_to_hwaddr(const ip6_addr_t ip6mcaddr, uint8_t *hwaddr)
{
    char addr[IPV6_ADDR_STR_LEN];

    if (!IPV6_ADDR_IS_MULTICAST(&ip6mcaddr)) {
        errorf("%s is not multicast address", ip6_addr_ntop(ip6mcaddr, addr, sizeof(addr)));
        return;
    }
    hwaddr[0] = 0x33;
    hwaddr[1] = 0x33;

    hwaddr[2] = ip6mcaddr.addr8[12];
    hwaddr[3] = ip6mcaddr.addr8[13];
    hwaddr[4] = ip6mcaddr.addr8[14];
    hwaddr[5] = ip6mcaddr.addr8[15];
}

void 
ip6_addr_create_solicit_mcastaddr(const ip6_addr_t ip6addr, ip6_addr_t *solicited_node_mcaddr)
{
    char addr[IPV6_ADDR_STR_LEN];

    if (IPV6_ADDR_IS_MULTICAST(&ip6addr)) {
        errorf("%s is not unicast address", ip6_addr_ntop(ip6addr, addr, sizeof(addr)));
        return;
    }
    IPV6_ADDR_COPY(solicited_node_mcaddr, &IPV6_SOLICITED_NODE_ADDR_PREFIX, IPV6_SOLICITED_NODE_ADDR_PREFIX_LEN / __CHAR_BIT__);

    solicited_node_mcaddr->addr8[13] = ip6addr.addr8[13];
    solicited_node_mcaddr->addr8[14] = ip6addr.addr8[14];
    solicited_node_mcaddr->addr8[15] = ip6addr.addr8[15];
}

/* Brief: eui-64 addr to global addr */
void
ip6_addr_create_global(const uint8_t *eui64, const ip6_addr_t prefix, const uint8_t prefixlen, ip6_addr_t *ip6addr)
{
    ip6addr->addr16[0] = prefix.addr16[0];
    ip6addr->addr16[1] = prefix.addr16[1];
    ip6addr->addr16[2] = prefix.addr16[2];
    ip6addr->addr16[3] = prefix.addr16[3];

    ip6addr->addr16[4] = eui64[0];
    ip6addr->addr16[5] = eui64[1];
    ip6addr->addr16[6] = eui64[2];
    ip6addr->addr16[7] = eui64[3];
}

/* Brief: hwaddr to eui-64 addr to link local addr */
static void
ip6_addr_create_linklocal(const uint8_t *hwaddr, ip6_addr_t *ip6addr)
{
    uint8_t eui64[ETHER_EUI64_ID_LEN];

    ether_addr_create_eui64(hwaddr, eui64);

    ip6addr->addr16[0] = hton16(0xfe80);
    ip6addr->addr16[1] = hton16(0x0000);
    ip6addr->addr16[2] = hton16(0x0000);
    ip6addr->addr16[3] = hton16(0x0000);

    ip6addr->addr16[4] = eui64[0];
    ip6addr->addr16[5] = eui64[1];
    ip6addr->addr16[6] = eui64[2];
    ip6addr->addr16[7] = eui64[3];
}

/* Brief: prefix length to netmask */
static ip6_addr_t *
ip6_addr_prefixlen_to_netmask(const uint8_t prefixlen, ip6_addr_t *netmask)
{
    int i;

    memset(netmask, 0, sizeof(IPV6_ADDR_LEN));
    for (i = 0; i < prefixlen / __CHAR_BIT__; i++) {
        netmask->addr8[i] = 0xff;
    }

    return netmask;
}

/* Brief: netmask to prefix length */
static uint8_t
ip6_addr_netmask_to_prefixlen(ip6_addr_t netmask) {
    uint8_t prefixlen = 0;
    int i = 0;

    while ((netmask.addr8[i] & 0xff) == 0xff) {
        prefixlen += __CHAR_BIT__;
        if (i++ >= 16) break;
    }

    return prefixlen;
}

static uint32_t 
ip6_addr_get_scope(const ip6_addr_t *ip6addr)
{
    if (IPV6_ADDR_IS_MULTICAST(ip6addr)) {
        return IPV6_ADDR_MC_SCOPE(ip6addr);
    } else if (IPV6_ADDR_IS_LOOPBACK(ip6addr)) {
        return IPV6_ADDR_SCOPE_INTFACELOCAL;
    } else if (IPV6_ADDR_IS_LINKLOCAL(ip6addr)) {
        return IPV6_ADDR_SCOPE_LINKLOCAL;
    } else if (IPV6_ADDR_IS_SITELOCAL(ip6addr)) {
        return IPV6_ADDR_SCOPE_SITELOCAL;
    } else {
        return IPV6_ADDR_SCOPE_GLOBAL;
    }
}

/*
 * Rules
 */

struct ip6_iface *
ip6_rule_addr_select(const ip6_addr_t dst)
{
    struct ip6_iface *res, *entry;
    uint32_t scope = ip6_addr_get_scope(&dst);

    // Rule1: Prefer same address
    res = ip6_iface_select(dst);
    if (res != NULL)
        return res;

    // Rule2: Prefer appropriate scope
    // MEMO: 宛先アドレスのスコープより大きいスコープを持つ（到達可能性がある）アドレスの中でもっともスコープが小さいものを選択する
    for (entry = ifaces; entry; entry = entry->next) {
        if (ip6_addr_get_scope(&dst) <= entry->ip6_addr.scope) {
            if (entry->ip6_addr.scope <= scope)
                res = entry;
            scope = entry->ip6_addr.scope;
        }
    }
    return res;
}

/*
 * Routing
 */

static struct ip6_route *
ip6_route_lookup(ip6_addr_t dst)
{
    struct ip6_route *route, *candidate = NULL;
    ip6_addr_t masked;
#ifdef FIBDUMP
    ip6_fib_dump();
#endif

    for (route = routes; route; route = route->next) {
        IPV6_ADDR_MASK(&dst, &route->netmask, &masked);
        if (IPV6_ADDR_EQUAL(&masked, &route->network)) {
            /* Longest Matching */
            if (!candidate || ip6_addr_netmask_to_prefixlen(candidate->netmask) < ip6_addr_netmask_to_prefixlen(route->netmask)) {
                candidate = route;
            }
        }
    }

    return candidate;
}

/* NOTE: must not be call after net_run() */
//static struct ip6_route *
static int
ip6_route_add(ip6_addr_t network, ip6_addr_t netmask, ip6_addr_t nexthop, struct ip6_iface *iface)
{
    struct ip6_route *route, *res;
    char addr1[IPV6_ADDR_STR_LEN];
    char addr3[IPV6_ADDR_STR_LEN];
    char addr4[IPV6_ADDR_STR_LEN];

    res = ip6_route_lookup(network); 
    if (res != NULL) {
        if (IPV6_ADDR_EQUAL(&res->network, &network) && IPV6_ADDR_EQUAL(&res->netmask, &netmask)) {
            debugf("Route already exists: %s", ip6_addr_ntop(network, addr1, sizeof(addr1)));
            return 1;
        }
    }

    route = memory_alloc(sizeof(*route));
    if (!route) {
        errorf("memory_alloc() failure");
        return -1;
    }
    
    route->network = network;
    IPV6_ADDR_COPY(&route->netmask, &netmask, IPV6_ADDR_LEN);
    IPV6_ADDR_COPY(&route->nexthop, &nexthop, IPV6_ADDR_LEN);
    route->iface = iface;
    route->next = routes;
    routes = route;
    infof("network=%s/%d, nexthop=%s, iface=%s, dev=%s",
        ip6_addr_ntop(route->network, addr1, sizeof(addr1)),
        ip6_addr_netmask_to_prefixlen(route->netmask),
        ip6_addr_ntop(route->nexthop, addr3, sizeof(addr3)),
        ip6_addr_ntop(route->iface->ip6_addr.addr, addr4, sizeof(addr4)),
        NET_IFACE(iface)->dev->name
    );
    return 0;
    //return route;
}

/* NOTE: must not be call after net_run() */
int
ip6_route_set_default_gateway(struct ip6_iface *iface, const char *gateway)
{
    ip6_addr_t gw, mask;

    if (ip6_addr_pton(gateway, &gw) == -1) {
        errorf("ip6_addr_pton() failure, addr=%s", gateway);
        return -1;
    }

    ip6_addr_prefixlen_to_netmask(0, &mask);
    IPV6_ADDR_MASK(&IPV6_UNSPECIFIED_ADDR, &mask, &mask); 
    if (ip6_route_add(IPV6_UNSPECIFIED_ADDR, mask, gw, iface) < 0) {
        errorf("ip6_route_add() failure");
        return -1;
    }
    return 0;
}

int
ip6_route_set_multicast(struct ip6_iface *iface)
{
    ip6_addr_t mask;

    ip6_addr_prefixlen_to_netmask(IPV6_MULTICAST_ADDR_PREFIX_LEN, &mask);
    IPV6_ADDR_MASK(&IPV6_MULTICAST_ADDR_PREFIX, &mask, &mask); 
    if (ip6_route_add(IPV6_MULTICAST_ADDR_PREFIX, mask, IPV6_UNSPECIFIED_ADDR, iface) < 0) {
        errorf("ip6_route_add() failure");
        return -1;
    }

    return 0;
}

int
ip6_route_set_linklocal(struct ip6_iface *iface)
{
    ip6_addr_t mask;

    ip6_addr_prefixlen_to_netmask(64, &mask);
    IPV6_ADDR_MASK(&IPV6_LINK_LOCAL_ADDR_PREFIX, &mask, &mask); 
    if (ip6_route_add(IPV6_LINK_LOCAL_ADDR_PREFIX, mask, IPV6_UNSPECIFIED_ADDR, iface) < 0) {
        errorf("ip6_route_add() failure");
        return -1;
    }

    return 0;
}

struct ip6_iface *
ip6_route_get_iface(ip6_addr_t dst)
{
    struct ip6_route *route;

    route = ip6_route_lookup(dst);
    if (!route) {
        return NULL;
    }
    return route->iface;
}

/*
 * iface
 */

struct ip6_iface *
ip6_iface_alloc(const char *addr, const uint8_t prefixlen, int slaac_flgs)
{
    struct ip6_iface *iface;

    iface = memory_alloc(sizeof(*iface));
    if (!iface) {
        errorf("memory_alloc() failure");
        return NULL;   
    }
    NET_IFACE(iface)->family = NET_IFACE_FAMILY_IPV6;
    if (ip6_addr_pton(addr, &iface->ip6_addr.addr)) {
        errorf("ip6_addr_pton() failure, addr=%s", addr);
        memory_free(iface);
        return NULL;
    }
    iface->ip6_addr.prefixlen = prefixlen;
    ip6_addr_prefixlen_to_netmask(prefixlen, &iface->ip6_addr.netmask);
    iface->ip6_addr.scope = ip6_addr_get_scope(&iface->ip6_addr.addr);
    iface->slaac.state = slaac_flgs;

    return iface;
}

int
ip6_iface_register(struct net_device *dev, struct ip6_iface *iface)
{
    ip6_addr_t prefix;
    char addr[IPV6_ADDR_STR_LEN];

    if (net_device_add_iface(dev, NET_IFACE(iface)) == -1) {
        errorf("net_device_add_iface() failure");
        return -1;
    }
    IPV6_ADDR_MASK(&iface->ip6_addr.addr, &iface->ip6_addr.netmask, &prefix); 
    if (ip6_route_add(prefix, iface->ip6_addr.netmask, IPV6_UNSPECIFIED_ADDR, iface) < 0) {
        errorf("ip6_route_add() failure");
        return -1;
    }
    iface->next = ifaces;
    ifaces = iface;
    infof("registered: dev=%s, unicast=%s, prefixlen=%d, scope=%u",
        dev->name,
        ip6_addr_ntop(iface->ip6_addr.addr, addr, sizeof(addr)),
        iface->ip6_addr.prefixlen,
        iface->ip6_addr.scope);
    return 0;
}

struct ip6_iface *
ip6_iface_select(ip6_addr_t addr)
{
    struct ip6_iface *entry;

    for (entry = ifaces; entry; entry = entry->next) {
        if (IPV6_ADDR_EQUAL(&entry->ip6_addr.addr, &addr)) {
            break;
        }
    }
    return entry;
}

struct ip6_iface *
ip6_iface_select_linklocal()
{
    struct ip6_iface *entry;

    for (entry = ifaces; entry; entry = entry->next) {
        if (IPV6_ADDR_IS_LINKLOCAL(&entry->ip6_addr.addr)) {
            break;
        }
    }
    return entry;
}

/*
 * IPv6: input/output
 */

static void
ip6_hbh_input()
{
    warnf("Hop-by-Hop option is not supported: ignored");
}

static void
ip6_route_input(const uint8_t *data, size_t len, ip6_addr_t src, ip6_addr_t dst, struct ip6_iface *iface)
{
    warnf("Routing option is not supported: ignored");
}

static void
ip6_frag_input(const uint8_t *data, size_t len, ip6_addr_t src, ip6_addr_t dst, struct ip6_iface *iface)
{
    warnf("Fragment option is not supported; ignored");
}

static void
ip6_dest_input(const uint8_t *data, size_t len, ip6_addr_t src, ip6_addr_t dst, struct ip6_iface *iface)
{
    warnf("Destination option is not supported: ignored");
}

static void
ip6_input(const uint8_t *data, size_t len, struct net_device *dev)
{
    struct ip6_hdr *hdr;
    uint8_t v;
    struct ip6_iface *iface;
    struct net_iface *entry;
    struct ip6_protocol *proto;
    char addr1[IPV6_ADDR_STR_LEN];
    char addr2[IPV6_ADDR_STR_LEN];

    if (len < IPV6_HDR_SIZE) {
        errorf("too short");
        return;
    }
    
    hdr = (struct ip6_hdr *)data;
    v = (hdr->ip6_vfc & 0xf0) >> 4; 
    if (v != IP_VERSION_IPV6) {
        errorf("ip version error: v=%u", v);
        return;
    }

    /* check against address spoofing/corruption */
    if (IPV6_ADDR_IS_MULTICAST(&hdr->ip6_src) || 
        IPV6_ADDR_IS_UNSPECIFIED(&hdr->ip6_dst)) {
            errorf("bad addr");
            return;
    }
    if (IPV6_ADDR_IS_MULTICAST(&hdr->ip6_dst) && 
        (IPV6_ADDR_MC_SCOPE(&hdr->ip6_dst) == IPV6_ADDR_SCOPE_INTFACELOCAL)) {
            errorf("bad addr");
            return;
    }
    if (IPV6_ADDR_IS_MULTICAST(&hdr->ip6_dst) &&
        (IPV6_ADDR_MC_SCOPE(&hdr->ip6_dst) == 0)) {
            /* RFC4291 2.7 */
            errorf("bad addr");
            return;
    }

    /* unicast check */
    /* find an interface which has IPv6 address that matches the destination address  */
    int our_flg = 0; /* determine if the packet is addressed to our */
    ip6_addr_t mcaaddr;
    for (entry = dev->ifaces; entry; entry = entry->next) {
        if (entry->family == NET_IFACE_FAMILY_IPV6) {
            iface = (struct ip6_iface *)entry;
            if (IPV6_ADDR_EQUAL(&iface->ip6_addr.addr, &hdr->ip6_dst)) {
                /* recognize as the packet addressed to our */
                our_flg = 1;
                break;
            }
            if (IPV6_ADDR_IS_MULTICAST(&hdr->ip6_dst)) {
                ip6_addr_create_solicit_mcastaddr(iface->ip6_addr.addr, &mcaaddr);
                if (IPV6_ADDR_EQUAL(&mcaaddr, &hdr->ip6_dst)) {
                    break;
                }
            }
        }
    }

    debugf("%s => %s, dev=%s, len=%u" ,ip6_addr_ntop(hdr->ip6_src, addr1, sizeof(addr1)), 
    ip6_addr_ntop(hdr->ip6_dst, addr2, sizeof(addr2)), dev->name, ntoh16(hdr->ip6_plen));
#ifdef HDRDUMP
    ip6_dump(data, len);
#endif

    if (!our_flg && !IPV6_ADDR_IS_MULTICAST(&hdr->ip6_dst)) {
        /* iface is not registered to the device */
        /* for other host */
        ip6_forward(data, len, dev);
        return;
    }

    for (proto = protocols; proto; proto = proto->next) {
        if (proto->type == hdr->ip6_nxt) {
            proto->handler((uint8_t *)hdr + IPV6_HDR_SIZE, ntoh16(hdr->ip6_plen), hdr->ip6_src, hdr->ip6_dst, iface);
            return;
        }
    }
}

static int
ip6_output_device(struct ip6_iface *iface, const uint8_t *data, size_t len, ip6_addr_t dst)
{
    uint8_t hwaddr[NET_DEVICE_ADDR_LEN] = {};
    int ret;

    if (NET_IFACE(iface)->dev->flags & NET_DEVICE_FLAG_NEED_RESOLVE) {
        if (IPV6_ADDR_IS_MULTICAST(&dst)) {
            ip6_addr_mcastaddr_to_hwaddr(dst, hwaddr);
        } else {
            ret = nd6_resolve(iface, dst, hwaddr);
            // TODO: 解決できなかったときにdataをキューで保持
            if (ret != 1) {
                return ret;
            }
        }
    }

    return net_device_output(NET_IFACE(iface)->dev, NET_PROTOCOL_TYPE_IPV6, data, len, hwaddr);    
}

static ssize_t
ip6_output_core(struct ip6_iface *iface, uint8_t next, const uint8_t *data, size_t len, ip6_addr_t src, ip6_addr_t dst, ip6_addr_t nexthop)
{
    uint8_t buf[IPV6_TOTAL_SIZE_MAX];
    struct ip6_hdr *hdr;
    uint16_t plen;
    char addr1[IPV6_ADDR_STR_LEN];

    hdr = (struct ip6_hdr *)buf;
    hdr->ip6_flow = 0x0000;     // TODO: FlowLabelの生成: ポート番号はどうやって参照する？ 上位層がICMPの場合はどうする？
    hdr->ip6_vfc = (IP_VERSION_IPV6 << 4);
    plen = len;
    hdr->ip6_plen = hton16(plen);
    hdr->ip6_nxt = next;
    hdr->ip6_hlim = 0xff;
    IPV6_ADDR_COPY(&hdr->ip6_src, &src, IPV6_ADDR_LEN);
    IPV6_ADDR_COPY(&hdr->ip6_dst, &dst, IPV6_ADDR_LEN);
    memcpy(hdr + 1, data, len);  
    debugf("dev=%s, iface=%s, len=%u +hdr_len=%u",
        NET_IFACE(iface)->dev->name, ip6_addr_ntop(iface->ip6_addr.addr, addr1, sizeof(addr1)), len, sizeof(*hdr));
#ifdef HDRDUMP
    ip6_dump(buf, sizeof(*hdr));
#endif

    return ip6_output_device(iface, buf, len + sizeof(*hdr), nexthop);
}

ssize_t
ip6_output(uint8_t next, const uint8_t *data, size_t len, ip6_addr_t src, ip6_addr_t dst)
{
    struct ip6_route *route;
    struct ip6_iface *iface;
    char addr[IPV6_ADDR_STR_LEN];
    ip6_addr_t nexthop;

    if (IPV6_ADDR_EQUAL(&src, &IPV6_UNSPECIFIED_ADDR)) {
        errorf("invalid source address");
        return -1;
    } else {
        iface = ip6_iface_select(src);
        if (!iface) {
            errorf("iface not found, src=%s", ip6_addr_ntop(src, addr, sizeof(addr)));
            return -1;
        }
    }
    route = ip6_route_lookup(dst);
    if (!route) {
        errorf("no route to host, addr=%s", ip6_addr_ntop(dst, addr, sizeof(addr)));
        return -1;
    }

    //warnf("[!!!!! DEBUG !!!!!] iface address       = %s", ip6_addr_ntop(iface->ip6_addr.addr, addr, sizeof(addr)));  
    //warnf("[!!!!! DEBUG !!!!!] source address      = %s", ip6_addr_ntop(src, addr, sizeof(addr)));  
    //warnf("[!!!!! DEBUG !!!!!] destination address = %s", ip6_addr_ntop(dst, addr, sizeof(addr))); 
    if (!IPV6_ADDR_EQUAL(&src, &iface->ip6_addr.addr)) {
        errorf("unable to output with specified source address, addr=%s", ip6_addr_ntop(src, addr, sizeof(addr)));
        return -1;
    }
    nexthop = (!IPV6_ADDR_EQUAL(&route->nexthop, &IPV6_UNSPECIFIED_ADDR) && !IPV6_ADDR_IS_MULTICAST(&dst)) ? route->nexthop : dst;
    if (NET_IFACE(iface)->dev->mtu < IPV6_HDR_SIZE + len) {
        errorf("too long, dev=%s, mtu=%u < %zu",
            NET_IFACE(iface)->dev->name, NET_IFACE(iface)->dev->mtu, IPV6_HDR_SIZE + len);
        return -1;
    }  
    if (ip6_output_core(iface, next, data, len, iface->ip6_addr.addr, dst, nexthop) == -1) {
        errorf("ip6_output_core() failure");
        return -1;
    }
    
    return len;
}

/*
 * Forward
 */

static int
ip6_forward(const uint8_t *data, size_t len, struct net_device *dev)
{
    struct ip6_route *route;
    struct ip6_hdr *hdr;
    ip6_addr_t nexthop;
    char addr1[IPV6_ADDR_STR_LEN];
    char addr2[IPV6_ADDR_STR_LEN];

    hdr = (struct ip6_hdr *)data;
    
    /* check hlim */
    if (!(hdr->ip6_hlim - 1)) {
        errorf("drop, hop limit: %u", hdr->ip6_hlim);
        // send icmpv6
        return -1;
    }

    /* No router to host */
    route = ip6_route_lookup(hdr->ip6_dst);
    if (!route) {
        errorf("drop, no route: %s", ip6_addr_ntop(hdr->ip6_dst, addr1, sizeof(addr1)));
        // send icmpv6
        return -1;
    }

    /* packet too big */
    if (dev->mtu < IPV6_HDR_SIZE + len) {
        errorf("too long, dev=%s, mtu=%u < %zu", dev->name, dev->mtu, IPV6_HDR_SIZE + len);
        // send icmpv6
        return -1;
    }  

    /* hlim -1 */
    hdr->ip6_hlim--;

    debugf("forward, from=%s%%%s, to=%s%%%s", 
            ip6_addr_ntop(hdr->ip6_src, addr1, sizeof(addr1)), dev->name,
            ip6_addr_ntop(hdr->ip6_dst, addr2, sizeof(addr2)), route->iface->iface.dev->name);

    nexthop = (!IPV6_ADDR_EQUAL(&route->nexthop, &IPV6_UNSPECIFIED_ADDR) && !IPV6_ADDR_IS_MULTICAST(&hdr->ip6_dst)) ? route->nexthop : hdr->ip6_dst;
    if (ip6_output_device(route->iface, data, len, nexthop) == -1) {
        errorf("ip6_output_device() failure");
        // send icmpv6
        return -1;
    }

    return 0;
}

/*
 * Misc
 */

int
ip6_protocol_register(const char *name, uint8_t type, void (*handler)(const uint8_t *data, size_t len, ip6_addr_t src, ip6_addr_t dst, struct ip6_iface *iface))
{
    struct ip6_protocol *entry;

    for (entry = protocols; entry; entry = entry->next) {
        if (entry->type == type) {
            errorf("already exists, type=%s(0x%02x), exist=%s(0x%02x)", name, type, entry->name, entry->type);
            return -1;
        }
    }
    entry = memory_alloc(sizeof(*entry));
    if (!entry) {
        errorf("memory_alloc() failure");
        return -1;
    }
    strncpy(entry->name, name, sizeof(entry->name)-1);
    entry->type = type;
    entry->handler = handler;
    entry->next = protocols;
    protocols = entry;
    infof("registered, type=%s(0x%02x)", entry->name, entry->type);
    return 0;    
}

/* IPv6 Link-Local Address iface: Initial Register*/
struct ip6_iface *
ip6_device_init(struct net_device *dev)
{
    struct ip6_iface *iface;
    ip6_addr_t ip6addr;
    char addr[IPV6_ADDR_STR_LEN];

    ip6_addr_create_linklocal(dev->addr, &ip6addr);
    iface = ip6_iface_alloc(ip6_addr_ntop(ip6addr, addr, sizeof(addr)), IPV6_LINK_LOCAL_ADDR_PREFIX_LEN, SLAAC_ENABLE);
    if (ip6_iface_register(dev, iface) == -1) {
        errorf("ip6_iface_register() failure");
        return NULL;
    }
    if (ip6_route_set_multicast(iface) != 0) {
        errorf("ip6_route_set_multicast() failure");
        return NULL;
    }
    
    infof("created, link-local address=%s, dev=%s", ip6_addr_ntop(iface->ip6_addr.addr, addr, sizeof(addr)), dev->name);
    return iface;
}

int
ip6_init(void)
{
    if (net_protocol_register("IPV6", NET_PROTOCOL_TYPE_IPV6, ip6_input) == -1) {
        errorf("net_protocol_register() failure");
        return -1;
    }

    /* Extension headers */
    if (ip6_protocol_register("HOPOPT", PROTOCOL_HOPOPT, ip6_hbh_input) == -1) {
        errorf("ip6_protocol_register() failure");
        return -1;
    }
    if (ip6_protocol_register("ROUING", PROTOCOL_ROUTING, ip6_route_input) == -1) {
        errorf("ip6_protocol_register() failure");
        return -1;
    }
    if (ip6_protocol_register("FRAGMENT", PROTOCOL_FRAGMENT, ip6_frag_input) == -1) {
        errorf("ip6_protocol_register() failure");
        return -1;
    }
    if (ip6_protocol_register("DSTOPT", PROTOCOL_DSTOPT, ip6_dest_input) == -1) {
        errorf("ip6_protocol_register() failure");
        return -1;
    }

    return 0;  
}