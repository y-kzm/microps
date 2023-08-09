#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "platform.h"

#include "util.h"
#include "net.h"
#include "ether.h"
#include "ip6.h"
#include "icmp6.h"
#include "nd6.h"

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

// Unspecified IPv6 address
const ip6_addr_t IPV6_UNSPECIFIED_ADDR = 
    IPV6_ADDR(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00);
// Loopback IPv6 address
// Link-local All-Nodes IPv6 address
// Link-local All-Routers IPv6 address
// Link-local IPv6 address prefix
// Solicited-node IPv6 address prefix
const ip6_addr_t IPV6_SOLICITED_NODE_ADDR_PREFIX =
    IPV6_ADDR(0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xff, 0x00, 0x00, 0x00);

/*
 * REF: https://github.com/freebsd/freebsd-src/blob/main/sys/libkern/inet_pton.c
 */
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

/*
 * REF: https://github.com/Oryx-Embedded/CycloneTCP/blob/master/ipv6/ipv6.c#L2364
 */
char *
ip6_addr_ntop(const ip6_addr_t n, char *p, size_t size)
{
    uint16_t *u16;
    int i, j;
    char *tmp;
    int zstart = 0;
    int zend = 0;
    u16 = (uint16_t *)&n.addr16;

    /* Find the longest run of zeros for "::" short-handing */
    for (i = 0; i < IPV6_ADDR_LEN16; i++) {
        for(j = i; j < IPV6_ADDR_LEN16 && !u16[j]; j++) {
            // 
        }
        if ((j - i) > 1 && (j - i) > (zend - zstart)) {
            zstart = i;
            zend = j;
        }
    }
    /* Format IPv6 address */
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

// TODO: macro
ip6_addr_t *
ip6_addr_mask(const ip6_addr_t *addr1, const ip6_addr_t *addr2, ip6_addr_t *masked)
{
    masked->addr32[0] = (addr1)->addr32[0] & (addr2)->addr32[0]; 
    masked->addr32[1] = (addr1)->addr32[1] & (addr2)->addr32[1]; 
    masked->addr32[2] = (addr1)->addr32[2] & (addr2)->addr32[2]; 
    masked->addr32[3] = (addr1)->addr32[3] & (addr2)->addr32[3]; 

    return masked;
}

void 
ip6_get_solicit_node_mcaddr(const ip6_addr_t ip6addr, ip6_addr_t *solicit_node_mcaddr)
{
    char addr[IPV6_ADDR_STR_LEN];

    if (IPV6_ADDR_IS_MULTICAST(&ip6addr)) {
        errorf("%s is not unicast address", ip6_addr_ntop(ip6addr, addr, sizeof(addr)));
        return;
    }
    memcpy(solicit_node_mcaddr, &IPV6_SOLICITED_NODE_ADDR_PREFIX, IPV6_SOLICITED_NODE_ADDR_PREFIX_LEN / 8);
    solicit_node_mcaddr->addr8[13] = ip6addr.addr8[13];
    solicit_node_mcaddr->addr8[14] = ip6addr.addr8[14];
    solicit_node_mcaddr->addr8[15] = ip6addr.addr8[15];
}

void
ip6_multicast_to_mac(const ip6_addr_t ip6mcaddr, uint8_t *hwaddr)
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

/* NOTE: must not be call after net_run() */
static struct ip6_route *
ip6_route_add(ip6_addr_t network, ip6_addr_t netmask, ip6_addr_t nexthop, struct ip6_iface *iface)
{
    struct ip6_route *route;
    char addr1[IPV6_ADDR_STR_LEN];
    char addr2[IPV6_ADDR_STR_LEN];
    char addr3[IPV6_ADDR_STR_LEN];
    char addr4[IPV6_ADDR_STR_LEN];

    route = memory_alloc(sizeof(*route));
    if (!route) {
        errorf("memory_alloc() failure");
        return NULL;
    }
    route->network = network;
    route->netmask = netmask;
    route->nexthop = nexthop;
    route->iface = iface;
    route->next = routes;
    routes = route;
    infof("network=%s, netmask=%s, nexthop=%s, iface=%s dev=%s",
        ip6_addr_ntop(route->network, addr1, sizeof(addr1)),
        ip6_addr_ntop(route->netmask, addr2, sizeof(addr2)),
        ip6_addr_ntop(route->nexthop, addr3, sizeof(addr3)),
        ip6_addr_ntop(route->iface->ip6_addr.addr, addr4, sizeof(addr4)),
        NET_IFACE(iface)->dev->name
    );
    return route;
}

// TODO: 効率化（トライ木構造）
static struct ip6_route *
ip6_route_lookup(ip6_addr_t dst)
{
    struct ip6_route *route, *candidate = NULL;
    ip6_addr_t masked;

    for (route = routes; route; route = route->next) {
        ip6_addr_mask(&dst, &route->netmask, &masked);   // TODO: refactoring
        if (IPV6_ADDR_EQUAL(&masked, &route->network)) {
            // TODO: longest matching
            /*
            if (!candidate || ntoh32(candidate->netmask) < ntoh32(route->netmask)) {
                candidate = route;
            }
            */
            candidate = route;
        }
    }
    return candidate;
}

/* NOTE: must not be call after net_run() */
int
ip6_route_set_default_gateway(struct ip6_iface *iface, const char *gateway)
{
    ip6_addr_t gw;

    if (ip6_addr_pton(gateway, &gw) == -1) {
        errorf("ip6_addr_pton() failure, addr=%s", gateway);
        return -1;
    }
    if (!ip6_route_add(IPV6_UNSPECIFIED_ADDR, IPV6_UNSPECIFIED_ADDR, gw, iface)) {
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

// TODO: multicast用ifaceの確保
struct ip6_iface *
ip6_iface_alloc(const char *ip6addr, const char *prefix)
{
    struct ip6_iface *iface;

    iface = memory_alloc(sizeof(*iface));
    if (!iface) {
        errorf("memory_alloc() failure");
        return NULL;   
    }
    NET_IFACE(iface)->family = NET_IFACE_FAMILY_IPV6;
    if (ip6_addr_pton(ip6addr, &iface->ip6_addr.addr)) {
        errorf("ip6_addr_pton() failure, addr=%s", ip6addr);
        memory_free(iface);
        return NULL;
    }
    if (ip6_addr_pton(prefix, &iface->ip6_addr.prefix) == -1) {
        errorf("ip6_addr_pton() failure, addr=%s", prefix);
        memory_free(iface);
        return NULL;
    }
    return iface;
}

int
ip6_iface_register(struct net_device *dev, struct ip6_iface *iface)
{
    ip6_addr_t masked;
    char addr1[IPV6_ADDR_STR_LEN];
    char addr2[IPV6_ADDR_STR_LEN];

    if (net_device_add_iface(dev, NET_IFACE(iface)) == -1) {
        errorf("net_device_add_iface() failure");
        return -1;
    }
    ip6_addr_mask(&iface->ip6_addr.addr, &iface->ip6_addr.prefix, &masked);    // TODO: refactoring
    if (!ip6_route_add(masked, iface->ip6_addr.prefix, IPV6_UNSPECIFIED_ADDR, iface)) {
        errorf("ip_route_add() failure");
        return -1;
    }
    iface->next = ifaces;
    ifaces = iface;
    infof("registered: dev=%s, unicast=%s, prefix=%s",
        dev->name,
        ip6_addr_ntop(iface->ip6_addr.addr, addr1, sizeof(addr1)),
        ip6_addr_ntop(iface->ip6_addr.prefix, addr2, sizeof(addr2)));
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

static void
ip6_input_hbh()
{
    debugf("*********** called ip6_input_hbh() ***********");
}

static void
ip6_input(const uint8_t *data, size_t len, struct net_device *dev)
{
    struct ip6_hdr *hdr;
    uint8_t v;
    struct ip6_iface *iface;
    struct net_iface *entry;
    struct ip6_protocol *proto;
    char addr[IPV6_ADDR_STR_LEN];

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
    for (entry = dev->ifaces; entry; entry = entry->next) {
        if (entry->family == NET_IFACE_FAMILY_IPV6) {
            iface = (struct ip6_iface *)entry;
            if (IPV6_ADDR_EQUAL(&iface->ip6_addr.addr, &hdr->ip6_dst)) {
                break;
            }
        }
    }
    if (!iface) {
        /* iface is not registered to the device */
        // goto forwarding?
        return;
    }    

    debugf("dev=%s, iface=%s, next=%u, len=%u, frame=%u",
        dev->name, ip6_addr_ntop(iface->ip6_addr.addr, addr, sizeof(addr)), hdr->ip6_nxt, ntoh16(hdr->ip6_plen) + IPV6_HDR_SIZE, ntoh16(hdr->ip6_plen) + IPV6_HDR_SIZE + ETHER_HDR_SIZE);
    ip6_dump(data, len);
    
    if (hdr->ip6_nxt == IPV6_NEXT_HOP_BY_HOP) {
        ip6_input_hbh();
        return;
    } else {   
        for (proto = protocols; proto; proto = proto->next) {
            if (proto->type == hdr->ip6_nxt) {
                proto->handler((uint8_t *)hdr + IPV6_HDR_SIZE, ntoh16(hdr->ip6_plen), hdr->ip6_src, hdr->ip6_dst, iface);
                return;
            }
        }
    }
}

static void
route6_input(const uint8_t *data, size_t len, ip6_addr_t src, ip6_addr_t dst, struct ip6_iface *iface)
{
    debugf("*********** called route6_input() ***********");
}

static void
frag6_input(const uint8_t *data, size_t len, ip6_addr_t src, ip6_addr_t dst, struct ip6_iface *iface)
{
    debugf("*********** called frag6_input() ***********");
}

static void
dest6_input(const uint8_t *data, size_t len, ip6_addr_t src, ip6_addr_t dst, struct ip6_iface *iface)
{
    debugf("*********** called dest6_input() ***********");
}

static int
ip6_output_device(struct ip6_iface *iface, const uint8_t *data, size_t len, ip6_addr_t dst)
{
    uint8_t hwaddr[NET_DEVICE_ADDR_LEN] = {};
    int ret;

    if (NET_IFACE(iface)->dev->flags & NET_DEVICE_FLAG_NEED_RESOLVE) {
        if (IPV6_ADDR_IS_MULTICAST(&dst)) {
            ip6_multicast_to_mac(dst, hwaddr);
        } else {
            ret = nd6_resolve(iface, dst, hwaddr);
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
    char addr[IPV6_ADDR_STR_LEN];

    hdr = (struct ip6_hdr *)buf;
    hdr->ip6_flow = 0x0000;
    hdr->ip6_vfc = (IP_VERSION_IPV6 << 4);
    plen = len;
    hdr->ip6_plen = hton16(plen);
    hdr->ip6_nxt = next;
    hdr->ip6_hlim = 0xff;
    hdr->ip6_src = src; 
    hdr->ip6_dst = dst;
    memcpy(hdr+1, data, len);  
    debugf("dev=%s, iface=%s, len=%u +hdr_len=%u",
        NET_IFACE(iface)->dev->name, ip6_addr_ntop(iface->ip6_addr.addr, addr, sizeof(addr)), len, sizeof*hdr);
    ip6_dump(buf, sizeof(*hdr));

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
        errorf("ip routing does not implement");
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
    iface = route->iface;
    if (!IPV6_ADDR_EQUAL(&src, &IPV6_UNSPECIFIED_ADDR) && !IPV6_ADDR_EQUAL(&src, &iface->ip6_addr.addr)) {
        errorf("unable to output with specified source address, addr=%s", ip6_addr_ntop(src, addr, sizeof(addr)));
        return -1;
    }
    nexthop = !IPV6_ADDR_EQUAL(&route->nexthop, &IPV6_UNSPECIFIED_ADDR) && !IPV6_ADDR_IS_MULTICAST(&dst) ? route->nexthop : dst;
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

int
ip6_init(void)
{
    if (net_protocol_register("IPV6", NET_PROTOCOL_TYPE_IPV6, ip6_input) == -1) {
        errorf("net_protocol_register() failure");
        return -1;
    }

    if (ip6_protocol_register("ICMPV6", IPV6_NEXT_ICMPV6, icmp6_input) == -1) {
        errorf("ip6_protocol_register() failure");
        return -1;
    }
    if (ip6_protocol_register("ROUING", IPV6_NEXT_ROUTING, route6_input) == -1) {
        errorf("ip6_protocol_register() failure");
        return -1;
    }
    if (ip6_protocol_register("FRAGMENT", IPV6_NEXT_FRAGMENT, frag6_input) == -1) {
        errorf("ip6_protocol_register() failure");
        return -1;
    }
    if (ip6_protocol_register("DESTOPT", IPV6_NEXT_DEST_OPT, dest6_input) == -1) {
        errorf("ip6_protocol_register() failure");
        return -1;
    }

    return 0;  
}