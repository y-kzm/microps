#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "platform.h"

#include "util.h"
#include "net.h"
#include "arp.h"
#include "ip6.h"

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
    IPV6_ADDR(0xff02, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x01ff, 0x0000);
const ip6_addr_t IPV6_MULTICAST_ADDR_PREFIX =
    IPV6_ADDR(0xff00, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000);

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

static void
ip6_input(const uint8_t *data, size_t len, struct net_device *dev)
{
    struct ip6_hdr *hdr;
    uint8_t v;

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

    debugf("dev=%s, protocol=%s(0x%02x), len=%u",
        dev->name, ip6_protocol_name(hdr->next), hdr->next, ntoh16(hdr->plen) + IPV6_HDR_SIZE);
    ip6_dump(data, len);
}

char *
ip6_protocol_name(uint8_t type)
{
    return "NOT IMPELEMENTED";
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