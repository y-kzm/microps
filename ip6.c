#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "platform.h"

#include "util.h"
#include "net.h"
#include "ether.h"
#include "ip6.h"

struct ip6_protocol {
    struct ip6_protocol *next;
    char name[16];
    uint8_t type;
    void (*handler)(const uint8_t *data, size_t len, ip6_addr_t src, ip6_addr_t dst, struct ip6_iface *iface);
};

struct ip6_hdr {
    uint32_t vtf;  /* ver(4) tc(8) flowlabel(20) */
    uint16_t plen; /* payload length */
    uint8_t  next; /* next header */
    uint8_t  hlim; /* hop limit */
    ip6_addr_t src;
    ip6_addr_t dst;
};

const ip6_addr_t IPV6_UNSPECIFIED_ADDR =
    IPV6_ADDR(0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000);
const ip6_addr_t IPV6_LOOPBACK_ADDR =
    IPV6_ADDR(0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0001);
const ip6_addr_t IPV6_LINK_LOCAL_ALL_NODES_ADDR =
    IPV6_ADDR(0xff02, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0001);
const ip6_addr_t IPV6_LINK_LOCAL_ALL_ROUTERS_ADDR =
    IPV6_ADDR(0xff02, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0002);
const ip6_addr_t IPV6_LINK_LOCAL_ADDR_PREFIX =
    IPV6_ADDR(0xfe80, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000);
const ip6_addr_t IPV6_SOLICITED_NODE_ADDR_PREFIX =
    IPV6_ADDR(0xff02, 0x0000, 0x0000, 0x0000, 0x0000, 0x0001, 0xff00, 0x0000);
const ip6_addr_t IPV6_MULTICAST_ADDR_PREFIX =
    IPV6_ADDR(0xff00, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000);

/* NOTE: if you want to add/delete the entries after net_run(), you need to protect these lists with a mutex. */
static struct ip6_iface *ifaces;
static struct ip6_protocol *protocols;

int
ip6_addr_pton(const char *p, ip6_addr_t *n)
{
    unsigned char tmp[IPV6_ADDR_LEN];
    unsigned char *top, *end, *colon;
    const char *pend;
    int ch;
    size_t xdigits_seen = 0;
    unsigned int val = 0;

    top = memset(tmp, '\0', IPV6_ADDR_LEN);
    end = top + IPV6_ADDR_LEN;
    colon = NULL;

    if (*p == ':' && *++p != ':') {
        return 0;
    }

    pend = p + strlen(p);
    while (p < pend) {
        ch = *p++;
        int digit = hex_digit_value(ch);
        if (digit >= 0) {
            if (xdigits_seen == 4)
                return 0;
            val <<= 4;
            val |= digit;
            if (val > 0xffff)
                return 0;
            ++xdigits_seen;
            continue;
        }
        if (ch == ':') {
            if (xdigits_seen == 0) {
                if (colon)
                    return 0;
                colon = top;
                continue;
            } else if (p == pend)
                    return 0;
            if (top + sizeof(int32_t)/sizeof(uint16_t) > end)
                return 0;
            *top++ = (unsigned char) (val >> 8) & 0xff;
            *top++ = (unsigned char) val & 0xff;
            xdigits_seen = 0;
            val = 0;
            continue;
        }
        return 0;
    }
    if (xdigits_seen > 0) {
        if (top + sizeof(int32_t)/sizeof(uint16_t) > end)
            return 0;
        *top++ = (unsigned char) (val >> 8) & 0xff;
        *top++ = (unsigned char) val & 0xff;
    }
    if (colon != NULL) {
        if (top == end)
            return 0;
        size_t s = top - colon;
        memmove (end - s, colon, s);
        memset (colon, 0, end - s - colon);
        top = end;
    }
    if (top != end)
        return 0;
    memcpy (n, tmp, IPV6_ADDR_LEN);
    return 1;
}

char *
ip6_addr_ntop(const ip6_addr_t n, char *p, size_t size)
{
    uint16_t *addr = (uint16_t *)&n.addr16;;
    int i, j, zero_start = 0, zero_end = 0;
    char *tmp;

    for (i = 0; i < IPV6_ADDR_LEN16; i++) {
        for(j = i; j < IPV6_ADDR_LEN16 && !addr[j]; j++) {
            // nop
        }
        if ((j - i) > 1 && (j - i) > (zero_end - zero_start)) {
            zero_start = i;
            zero_end = j;
        }
    }
    for (tmp = p, i = 0; i < IPV6_ADDR_LEN16; i++) {
        if (i >= zero_start && i < zero_end) {
            *tmp++ = ':';
            i = zero_end - 1;
        } else {
            if (i > 0) {
                *tmp++ = ':';
            }
            tmp += sprintf(tmp, "%x", ntoh16(addr[i]));
        }
    }
    if (zero_end == IPV6_ADDR_LEN16) {
        *tmp++ = ':';
    }
    *tmp = '\0';
    return p;
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
    v = (ntoh32(hdr->vtf) & 0xf0000000) >> 28;
    fprintf(stderr, "        ver: %u\n", v);
    tc = (ntoh32(hdr->vtf) & 0x0ff00000) >> 24;
    fprintf(stderr, "         tc: 0x%02x\n", tc);
    flow = (ntoh32(hdr->vtf) & 0x000fffff);
    fprintf(stderr, "       flow: 0x%04x\n", flow);
    fprintf(stderr, "       plen: %u byte\n", ntoh16(hdr->plen));
    fprintf(stderr, "       next: %u\n", hdr->next);
    fprintf(stderr, "       hlim: %u\n", hdr->hlim);
    fprintf(stderr, "        src: %s\n", ip6_addr_ntop(hdr->src, addr, sizeof(addr)));
    fprintf(stderr, "        dst: %s\n", ip6_addr_ntop(hdr->dst, addr, sizeof(addr)));
#ifdef HEXDUMP
    hexdump(stderr, data, len);
#endif
    funlockfile(stderr);
}

struct ip6_iface *
ip6_iface_alloc(const char *addr, const uint8_t prefixlen)
{
    struct ip6_iface *iface;

    iface = memory_alloc(sizeof(*iface));
    if (!iface) {
        errorf("memory_alloc() failure");
        return NULL;
    }
    NET_IFACE(iface)->family = NET_IFACE_FAMILY_IPV6;
    if (ip6_addr_pton(addr, &iface->addr) == -1) {
        errorf("ip6_addr_pton() failure, addr=%s", addr);
        memory_free(iface);
        return NULL;
    }
    iface->prefixlen = prefixlen;
    iface->scope = ip6_get_addr_scope(&iface->addr);
    return iface;
}

int
ip6_iface_register(struct net_device *dev, struct ip6_iface *iface)
{
    char addr[IPV6_ADDR_STR_LEN];

    if (net_device_add_iface(dev, NET_IFACE(iface)) == -1) {
        errorf("net_device_add_iface() failure");
        return -1;
    }
    iface->next = ifaces;
    ifaces = iface;
    infof("registered: dev=%s, address=%s/%u",
        dev->name, ip6_addr_ntop(iface->addr, addr, sizeof(addr)), iface->prefixlen);
    return 0;
}

struct ip6_iface *
ip6_iface_select(ip6_addr_t addr)
{
    struct ip6_iface *entry;

    for (entry = ifaces; entry; entry = entry->next) {
        if (IPV6_ADDR_COMP(&entry->addr, &addr, IPV6_ADDR_LEN)) {
            break;
        }
    }
    return entry;
}

static void
ip6_input(const uint8_t *data, size_t len, struct net_device *dev)
{
    struct ip6_hdr *hdr;
    uint8_t v;
    struct ip6_iface *iface;
    struct ip6_protocol *proto;
    char addr[IPV6_ADDR_STR_LEN];

    if (len < IPV6_HDR_SIZE) {
        errorf("too short");
        return;
    }
    hdr = (struct ip6_hdr *)data;
    v = (ntoh32(hdr->vtf) & 0xf0000000) >> 28;
    if (v != IP_VERSION_IPV6) {
        errorf("ip version error: v=%u", v);
        return;
    }
    iface = (struct ip6_iface *)net_device_get_iface(dev, NET_IFACE_FAMILY_IPV6);
    if (!iface) {
        /* iface is not registered to the device */
        return;
    } else {
        /* find an iface which has IPv6 address that matches the destination address  */
        struct ip6_iface *entry;
        for (entry = ifaces; entry; entry = entry->next) {
            if (IPV6_ADDR_COMP(&entry->addr, &hdr->dst, IPV6_ADDR_LEN)) {
                iface = entry;
                break;
            }
        }
    }
    if (IPV6_ADDR_COMP(&hdr->dst, &IPV6_UNSPECIFIED_ADDR, IPV6_ADDR_LEN)) {
        /* for all hosts */
        return;
    }
    debugf("dev=%s(%s), protocol=%s(0x%02x), len=%u",
        dev->name, ip6_addr_ntop(iface->addr, addr, sizeof(addr)), ip6_protocol_name(hdr->next), hdr->next, ntoh16(hdr->plen) + IPV6_HDR_SIZE);
    ip6_dump(data, len);
    for (proto = protocols; proto; proto = proto->next) {
        if (proto->type == hdr->next) {
            proto->handler((uint8_t *)hdr + IPV6_HDR_SIZE, ntoh16(hdr->plen), hdr->src, hdr->dst, iface);
            return;
        }
    }
}

static int
ip6_output_device(struct ip6_iface *iface, const uint8_t *data, size_t len, ip6_addr_t dst)
{
    uint8_t hwaddr[NET_DEVICE_ADDR_LEN] = {};

    /* NDP is not implemented */
    if (NET_IFACE(iface)->dev->flags & NET_DEVICE_FLAG_NEED_ARP) {
        if (ip6_get_mcaddr_scope(&dst) == IPV6_ADDR_SCOPE_LINKLOCAL) {
            //  Find multicast mac addr from dst addr (solicited node addr)
        } else {
            // if (!nd6_resolve(iface, dst, hwaddr)) {
            //     return -1;
            // }
        }
    }
    /* Hard coding for debug */
    ether_addr_pton("ce:44:e3:98:83:e4", hwaddr);

    return net_device_output(NET_IFACE(iface)->dev, NET_PROTOCOL_TYPE_IPV6, data, len, hwaddr);
}

static ssize_t
ip6_output_core(struct ip6_iface *iface, uint8_t next, const uint8_t *data, size_t len, ip6_addr_t src, ip6_addr_t dst)
{
    uint8_t buf[IPV6_TOTAL_SIZE_MAX];
    struct ip6_hdr *hdr;
    uint16_t plen;
    char addr[IPV6_ADDR_STR_LEN];

    hdr = (struct ip6_hdr *)buf;
    hdr->vtf = hton32((IP_VERSION_IPV6 << 28));
    plen = len;
    hdr->plen = hton16(plen);
    hdr->next = next;
    hdr->hlim = 0xff;
    IPV6_ADDR_COPY(&hdr->src, &src, IPV6_ADDR_LEN);
    IPV6_ADDR_COPY(&hdr->dst, &dst, IPV6_ADDR_LEN);
    memcpy(hdr + 1, data, len);
    debugf("dev=%s, iface=%s, next=%s(0x%02x), len=%u",
        NET_IFACE(iface)->dev->name, ip6_addr_ntop(iface->addr, addr, sizeof(addr)), ip6_protocol_name(next), next, len + IPV6_HDR_SIZE);
    ip6_dump(buf, len + IPV6_HDR_SIZE);

    return ip6_output_device(iface, buf, len + IPV6_HDR_SIZE, dst);
}

ssize_t
ip6_output(uint8_t next, const uint8_t *data, size_t len, ip6_addr_t src, ip6_addr_t dst)
{
    struct ip6_iface *iface;
    char addr[IPV6_ADDR_STR_LEN];

    iface = ip6_iface_select(src);
    if (!iface) {
        errorf("iface not found, src=%s", ip6_addr_ntop(src, addr, sizeof(addr)));
        return -1;
    }

    if (NET_IFACE(iface)->dev->mtu < IPV6_HDR_SIZE + len) {
        errorf("too long, dev=%s, mtu=%u len=%zu",
            NET_IFACE(iface)->dev->name, NET_IFACE(iface)->dev->mtu, IPV6_HDR_SIZE + len);
        return -1;
    }
    if (ip6_output_core(iface, next, data, len, iface->addr, dst) == -1) {
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

char *
ip6_protocol_name(uint8_t type)
{
    struct ip6_protocol *entry;

    for (entry = protocols; entry; entry = entry->next) {
        if (entry->type == type) {
            return entry->name;
        }
    }
    return "UNKNOWN";
}

#define IPV6_ADDR_IS_MULTICAST(addr)   IPV6_ADDR_COMP(addr, &IPV6_MULTICAST_ADDR_PREFIX, 1)
#define IPV6_ADDR_IS_UNSPECIFIED(addr) IPV6_ADDR_COMP(addr, &IPV6_UNSPECIFIED_ADDR, IPV6_ADDR_LEN)
#define IPV6_ADDR_IS_LOOPBACK(addr)    IPV6_ADDR_COMP(addr, &IPV6_LOOPBACK_ADDR, IPV6_ADDR_LEN)
#define IPV6_ADDR_IS_LINKLOCAL(addr)   IPV6_ADDR_COMP(addr, &IPV6_LINK_LOCAL_ADDR_PREFIX, 8)
#define IPV6_ADDR_MC_SCOPE(addr)       ((addr)->addr8[1] & 0x0f)

uint32_t 
ip6_get_addr_scope(const ip6_addr_t *addr)
{
    if (IPV6_ADDR_IS_LOOPBACK(addr)) {
        return IPV6_ADDR_SCOPE_INTFACELOCAL;
    } else if (IPV6_ADDR_IS_LINKLOCAL(addr)) {
        return IPV6_ADDR_SCOPE_LINKLOCAL;
    } else {
        return IPV6_ADDR_SCOPE_GLOBAL;
    }
}

uint32_t 
ip6_get_mcaddr_scope(const ip6_addr_t *addr)
{
    if (!IPV6_ADDR_IS_MULTICAST(addr)) {
        return -1;
    }
    return IPV6_ADDR_MC_SCOPE(addr);
}

int
ip6_init(void)
{
    if (net_protocol_register("IPV6", NET_PROTOCOL_TYPE_IPV6, ip6_input) == -1) {
        errorf("net_protocol_register() failure");
        return -1;
    }

    return 0;
}