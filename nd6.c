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

struct pseudo6_hdr {
    ip6_addr_t src;
    ip6_addr_t dst;
    uint32_t len;
    uint8_t zero[3];
    uint8_t next;
};

struct nd6_ns_hdr {
	uint8_t	type;
	uint8_t	code;
	uint16_t sum;
    uint32_t reserved;
    ip6_addr_t target;
    uint8_t data[]; // options
};

struct nd6_na_hdr {
	uint8_t	type;
	uint8_t	code;
	uint16_t sum;
    uint32_t flag;
    ip6_addr_t target;
    uint8_t data[]; // options
};

struct nd6_option_tlv {
	u_int8_t type;
	u_int8_t len;
    uint8_t data[]; // options
};

struct nd6_option_lladdr {
    uint8_t hwaddr[ETHER_ADDR_LEN];
};

void *
nd6_options(const uint8_t *data, size_t len, uint8_t type)
{
    struct nd6_option_tlv *opt;
    size_t i = 0;

    while (i <= len) {
        opt = (struct nd6_option_tlv *)(data + i);
        if (opt->len == 0 || (i + (opt->len * 8)) > len) {
            errorf("invalid option length");
            break;
        }
        i += opt->len * 8;
        if (opt->type == type) {
            return opt + 1;
        }
    }
    return NULL;
}

void
nd6_ns_input(const uint8_t *data, size_t len, ip6_addr_t src, ip6_addr_t dst, struct ip6_iface *iface)
{
    struct nd6_ns_hdr *hdr = (struct nd6_ns_hdr *)data;
    struct nd6_option_lladdr *lladdr;
    char hwaddr[ETHER_ADDR_STR_LEN];

    /* options */
    lladdr = nd6_options((uint8_t *)(hdr + 1), len - sizeof(*hdr), ND6_OPT_SOURCE_LINKADDR);
    if (lladdr != NULL) {
        debugf("source link layer address=%s", ether_addr_ntop(lladdr->hwaddr, hwaddr, sizeof(hwaddr)));
    }

    if (!IPV6_ADDR_COMP(&hdr->target, &iface->addr, IPV6_ADDR_LEN)
        && !IPV6_ADDR_COMP(&dst, &IPV6_SOLICITED_NODE_ADDR_PREFIX, IPV6_SOLICITED_NODE_ADDR_PREFIX_LEN)) {
        errorf("nd6_ns_input() invalid target");
        return;
    }

    nd6_na_output(hdr->target, iface, src);
}

int
nd6_na_output(const ip6_addr_t target, struct ip6_iface *iface, ip6_addr_t dst)
{
    uint8_t buf[ICMP6_BUFSIZ];
    struct nd6_na_hdr *hdr;
    struct pseudo6_hdr pseudo;
    struct nd6_option_tlv *opt;
    struct nd6_option_lladdr *lladdr;
    size_t len;
    uint16_t psum = 0;
    char addr1[IPV6_ADDR_STR_LEN];
    char addr2[IPV6_ADDR_STR_LEN];

    hdr = (struct nd6_na_hdr *)buf;
    hdr->type = ICMPV6_TYPE_NEIGHBOR_ADV;
    hdr->code = 0;
    hdr->sum = 0;
    hdr->flag = hton32(ND6_NA_FLAG_SOLICITED); // Unsocketed NA is not supported
    IPV6_ADDR_COPY(&hdr->target, &target, IPV6_ADDR_LEN);
    len = sizeof(*hdr);

    /*  options */
    opt = (struct nd6_option_tlv *)(hdr->data);
    opt->type = ND6_OPT_TARGET_LINKADDR;
    opt->len = 1;
    lladdr = (struct nd6_option_lladdr *)(opt->data);
    memcpy(lladdr->hwaddr, NET_IFACE(iface)->dev->addr, ETHER_ADDR_LEN);
    len += sizeof(*opt) + sizeof(*lladdr);

    memset(&pseudo, 0, sizeof(pseudo));
    IPV6_ADDR_COPY(&pseudo.src, &iface->addr, IPV6_ADDR_LEN);
    IPV6_ADDR_COPY(&pseudo.dst, &dst, IPV6_ADDR_LEN);
    pseudo.len = hton16(len);
    pseudo.zero[0] = pseudo.zero[1] = pseudo.zero[2] = 0;
    pseudo.next = IPV6_PROTOCOL_ICMPV6;
    psum =  ~cksum16((uint16_t *)&pseudo, sizeof(pseudo), 0);
    hdr->sum = cksum16((uint16_t *)hdr, len, psum);

    debugf("%s => %s, type=%s(%u), len=%zu",
        ip6_addr_ntop(iface->addr, addr1, sizeof(addr1)),
        ip6_addr_ntop(dst, addr2, sizeof(addr2)),
        icmp6_type_ntoa(hdr->type), hdr->type, len);
    return ip6_output(IPV6_PROTOCOL_ICMPV6, buf, len, iface->addr, dst);
}