#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "platform.h"

#include "util.h"
#include "net.h"
#include "ip6.h"

struct ip6_protocol {
    struct ip6_protocol *next;
    uint8_t type;
    void (*handler)(const uint8_t *data, size_t len, ip6_addr_t src, ip6_addr_t dst, struct ip6_iface *iface);    
};

struct ip6_hdr {
    union {
		uint32_t ip6_un1_flow;	/* ver(4) tc(12) flow-ID(20) */
		uint8_t ip6_un2_vfc;	/* ver(4) tc(12) */
	} ip6_ctlun;
    uint16_t ip6_plen;	        /* payload length */
	uint8_t  ip6_nxt;	        /* next header */
	uint8_t  ip6_hlim;	        /* hop limit */
    ip6_addr_t ip6_src;
    ip6_addr_t ip6_dst;
#define ip6_vfc		ip6_ctlun.ip6_un2_vfc
#define ip6_flow	ip6_ctlun.ip6_un1_flow
};

const ip6_addr_t IPV6_ADDR_ANY = 
    IPV6_ADDR(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00);
//extern const ip_addr_t IPV6_ADDR_BROADCAST;

static struct ip6_iface *ifaces;
static struct ip6_protocol *protocols;

// TODO: 
int
ip6_addr_pton(const char *p, ip6_addr_t *n)
{
#define NS_IN6ADDRSZ	16
#define NS_INT16SZ	    2
	static const char xdigits_l[] = "0123456789abcdef",
			          xdigits_u[] = "0123456789ABCDEF";
	u_char tmp[NS_IN6ADDRSZ], *tp, *endp, *colonp;
	const char *xdigits;
	int ch, seen_xdigits;
	u_int val;

	memset((tp = tmp), '\0', NS_IN6ADDRSZ);
	endp = tp + NS_IN6ADDRSZ;
	colonp = NULL;
	/* Leading :: requires some special handling. */
	if (*p == ':')
		if (*++p != ':')
			return (0);
	seen_xdigits = 0;
	val = 0;

	while ((ch = *p++) != '\0') {
		const char *pch;

		if ((pch = strchr((xdigits = xdigits_l), ch)) == NULL)
			pch = strchr((xdigits = xdigits_u), ch);
		if (pch != NULL) {
			val <<= 4;
			val |= (pch - xdigits);
			if (++seen_xdigits > 4)
				return (0);
			continue;
		}
		if (ch == ':') {
			if (!seen_xdigits) {
				if (colonp)
					return (0);
				colonp = tp;
				continue;
			} else if (*p == '\0') {
				return (0);
			}
			if (tp + NS_INT16SZ > endp)
				return (0);
			*tp++ = (u_char) (val >> 8) & 0xff;
			*tp++ = (u_char) val & 0xff;
			seen_xdigits = 0;
			val = 0;
			continue;
		}
	}
	if (seen_xdigits) {
		if (tp + NS_INT16SZ > endp)
			return (0);
		*tp++ = (u_char) (val >> 8) & 0xff;
		*tp++ = (u_char) val & 0xff;
	}
	if (colonp != NULL) {
		/*
		 * Since some memmove()'s erroneously fail to handle
		 * overlapping regions, we'll do the shift by hand.
		 */
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
	memcpy(n->addr8, tmp, NS_IN6ADDRSZ);

	return 0;
}

// TODO: 
char *
ip6_addr_ntop(const ip6_addr_t n, char *p, size_t size)
{
    uint16_t *u16;
    int i, j;
    char *tmp;
    int zstart = 0;
    int zend = 0;

    u16 = (uint16_t *)&n.addr16;

    // Find the longest run of zeros for "::" short-handing
    for (i = 0; i < IPV6_ADDR16_LEN; i++) {
        for(j = i; j < IPV6_ADDR16_LEN && !u16[j]; j++) {
            // 
        }
        if ((j - i) > 1 && (j - i) > (zend - zstart)) {
            zstart = i;
            zend = j;
        }
    }

    // Format IPv6 address
    for (tmp = p, i = 0; i < IPV6_ADDR16_LEN; i++) {
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

void
ip6_dump(const uint8_t *data, size_t len)
{
    struct ip6_hdr *hdr;
    uint8_t v, tc;
    uint32_t flow;
    char addr[IPV6_ADDR_STR_MAX_LEN];

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

struct ip6_iface *
ip6_iface_alloc(const char *unicast, const char *prefix)
{
    struct ip6_iface *iface;

    iface = memory_alloc(sizeof(*iface));
    if (!iface) {
        errorf("memory_alloc() failure");
        return NULL;   
    }
    NET_IFACE(iface)->family = NET_IFACE_FAMILY_IPV6;
    if (ip6_addr_pton(unicast, &iface->unicast)) {
        errorf("ip6_addr_pton() failure, addr=%s", unicast);
        memory_free(iface);
        return NULL;
    }
    if (ip6_addr_pton(prefix, &iface->prefix) == -1) {
        errorf("ip6_addr_pton() failure, addr=%s", prefix);
        memory_free(iface);
        return NULL;
    }
    return iface;
}

int
ip6_iface_register(struct net_device *dev, struct ip6_iface *iface)
{
    char addr1[IPV6_ADDR_STR_MAX_LEN];
    char addr2[IPV6_ADDR_STR_MAX_LEN];

    if (net_device_add_iface(dev, NET_IFACE(iface)) == -1) {
        errorf("net_device_add_iface() failure");
        return -1;
    }
    iface->next = ifaces;
    ifaces = iface;
    infof("registered: dev=%s, unicast=%s, netmask=%s",
        dev->name,
        ip6_addr_ntop(iface->unicast, addr1, sizeof(addr1)),
        ip6_addr_ntop(iface->prefix, addr2, sizeof(addr2)));
    return 0;
}

struct ip6_iface *
ip6_iface_select(ip6_addr_t addr)
{
    struct ip6_iface *entry;

    for (entry = ifaces; entry; entry = entry->next) {
        if (memcmp(&entry->unicast, &addr, IPV6_ADDR_LEN) == 0) {
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
    char addr[IPV6_ADDR_STR_MAX_LEN];
    struct ip6_protocol *proto;
    
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
    if (ntoh16(hdr->ip6_plen) > (len - IPV6_HDR_SIZE)) {
        errorf("too short payload length");
        return;        
    }

    iface = (struct ip6_iface *)net_device_get_iface(dev, NET_IFACE_FAMILY_IPV6);
    if (!iface) {
        /* iface is not registered to the device */
        return;
    }

    // TODO: 要確認
    if (memcmp(&hdr->ip6_dst, &iface->unicast, IPV6_ADDR_LEN) != 0) {
        // TODO: マルチキャスの確認
        return;
    }

    debugf("dev=%s, iface=%s, next=0x%02x, len=%u",
        dev->name, ip6_addr_ntop(iface->unicast, addr, sizeof(addr)), hdr->ip6_nxt, ntoh16(hdr->ip6_plen) + IPV6_HDR_SIZE);
    ip6_dump(data, len);
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

    /*
    if (NET_IFACE(iface)->dev->flags & NET_DEVICE_FLAG_NEED_ARP) {
        if (dst == iface->broadcast || dst == IP_ADDR_BROADCAST) {
            memcpy(hwaddr, NET_IFACE(iface)->dev->broadcast, NET_IFACE(iface)->dev->alen);
        } else {
            errorf("arp does not implement");
            return -1;
        }
    }
    */

    return net_device_output(NET_IFACE(iface)->dev, NET_PROTOCOL_TYPE_IPV6, data, len, hwaddr);    
}

static ssize_t
ip6_output_core(struct ip6_iface *iface, uint8_t next, const uint8_t *data, size_t len, ip6_addr_t src, ip6_addr_t dst)
{
    // TODO: 拡張ヘッダ処理
    uint8_t buf[IPV6_HDR_SIZE];
    struct ip6_hdr *hdr;
    uint16_t plen;
    char addr[IPV6_ADDR_STR_MAX_LEN];

    hdr = (struct ip6_hdr *)buf;
    hdr->ip6_flow = 0x0000;
    hdr->ip6_vfc = (IP_VERSION_IPV6 << 4);
    plen = len - IPV6_HDR_SIZE;
    hdr->ip6_plen = hton16(plen);
    hdr->ip6_nxt = next;
    hdr->ip6_hlim = 0xff;
    memcpy(hdr->ip6_src.addr8, src.addr8, IPV6_ADDR_LEN);
    memcpy(hdr->ip6_dst.addr8, dst.addr8, IPV6_ADDR_LEN);

    debugf("dev=%s, iface=%s",
        NET_IFACE(iface)->dev->name, ip6_addr_ntop(iface->unicast, addr, sizeof(addr)));
    ip6_dump(buf, len);

    return ip6_output_device(iface, buf, plen + IPV6_HDR_SIZE, dst);
}

ssize_t
ip6_output(uint8_t next, const uint8_t *data, size_t len, ip6_addr_t src, ip6_addr_t dst)
{
    struct ip6_iface *iface;
    char addr[IPV6_ADDR_STR_MAX_LEN];
    
    if (memcmp(&src, &IPV6_ADDR_ANY, IPV6_ADDR_LEN) == 0) {
        errorf("ip routing does not implement");
        return -1;
    } else {
        iface = ip6_iface_select(src);
        if (!iface) {
            errorf("iface not found, src=%s", ip6_addr_ntop(src, addr, sizeof(addr)));
            return -1;
        }
        // TODO: prefixチェック，マルチキャスト対応
        // if ()
    }
    if (NET_IFACE(iface)->dev->mtu < IPV6_HDR_SIZE + len) {
        errorf("too long, dev=%s, mtu=%u < %zu",
            NET_IFACE(iface)->dev->name, NET_IFACE(iface)->dev->mtu, IPV6_HDR_SIZE + len);
        return -1;
    }
    if (ip6_output_core(iface, next, data, len, iface->unicast, dst) == -1) {
        errorf("ip6_output_core() failure");
        return -1;
    }

    return len;
}

int
ip6_protocol_register(uint8_t type, void (*handler)(const uint8_t *data, size_t len, ip6_addr_t src, ip6_addr_t dst, struct ip6_iface *iface))
{
    struct ip6_protocol *entry;

    for (entry = protocols; entry; entry = entry->next) {
        if (entry->type == type) {
            errorf("already exists, type=0x%02x", entry->type);
            return -1;
        }
    }
    entry = memory_alloc(sizeof(*entry));
    if (!entry) {
        errorf("memory_alloc() failure");
        return -1;
    }
    entry->type = type;
    entry->handler = handler;
    entry->next = protocols;
    protocols = entry;
    infof("registered, type=0x%02x", entry->type);
    return 0;    
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