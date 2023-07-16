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

void
nd6_ns_input(const uint8_t *data, size_t len, ip6_addr_t src, ip6_addr_t dst, struct ip6_iface *iface)
{

    struct nd_neighbor_solicit *ns;
    struct nd_lladdr_opt *opt;
    char lladdr[ETHER_ADDR_STR_LEN];
    char addr1[IPV6_ADDR_STR_LEN];
    char addr2[IPV6_ADDR_STR_LEN];

    if (len < sizeof(*ns)) {
        errorf("too short");
        return;             
    }
    ns = (struct nd_neighbor_solicit *)data;

    if (memcmp(&dst, &IPV6_SOLICITED_NODE_ADDR_PREFIX, IPV6_SOLICITED_NODE_ADDR_PREFIX_LEN / 8)) {
        errorf("bad dstination addr");
        return;
    }
    opt = (struct nd_lladdr_opt *)(data + sizeof(*ns));

    debugf("%s => %s, type=(%u), len=%zu target=%s",
        ip6_addr_ntop(src, addr1, sizeof(addr1)),
        ip6_addr_ntop(dst, addr2, sizeof(addr2)),
        ns->nd_ns_type, len, ether_addr_ntop(opt->lladdr, lladdr, sizeof(lladdr)));
    icmp6_dump((uint8_t *)ns, len);

    uint32_t flags = 0;
    nd6_na_output(ICMPV6_TYPE_NEIGHBOR_ADV, ns->nd_ns_code, flags, (uint8_t *)(opt + 1), len - (sizeof(*ns) + sizeof(*opt)), iface->unicast, src, ns->target, iface->iface.dev->addr);
}

int
nd6_na_output(uint8_t type, uint8_t code, uint32_t flags, const uint8_t *data, size_t len, ip6_addr_t src, ip6_addr_t dst, const ip6_addr_t target, const void *lladdr)
{
    uint8_t buf[ICMPV6_BUFSIZ];
    struct nd_neighbor_adv *na;
    struct nd_lladdr_opt *opt;
    struct ip6_hdr pseudo;
    size_t msg_len;
    uint16_t psum = 0;
    char addr1[IPV6_ADDR_STR_LEN];
    char addr2[IPV6_ADDR_STR_LEN];

    /* neighbor advertisement */
    na = (struct nd_neighbor_adv *)buf;
    na->nd_na_type = ICMPV6_TYPE_NEIGHBOR_ADV;
    na->nd_na_code = 0;
    na->nd_na_sum = 0;
    na->nd_na_reserved = 0;
    na->target = target;

    /* option */
    opt = (struct nd_lladdr_opt *)(na + 1);
    opt->type = 2;
    opt->len = 1;
    memcpy(opt->lladdr, lladdr, ETHER_ADDR_LEN);

    msg_len = sizeof(*na) + sizeof(*opt); 
    memcpy(buf + msg_len, data, len);

    /* pseudo header */
    pseudo.ip6_flow = 0x0000;
    pseudo.ip6_vfc = (IP_VERSION_IPV6 << 4);
    pseudo.ip6_plen = msg_len + len;
    pseudo.ip6_nxt = IP_PROTOCOL_ICMPV6;
    pseudo.ip6_hlim = 0xff;
    pseudo.ip6_src = src;
    pseudo.ip6_dst = dst;
    psum =  ~cksum16((uint16_t *)&pseudo, sizeof(pseudo), 0);
    na->nd_ns_sum = cksum16((uint16_t *)na, msg_len + len, psum);
    na->nd_ns_sum = hton16(0x6c9e); // TODO: wrong chksum

    debugf("%s => %s, type=(%u), len=%zu, +msg_len=%zu",
        ip6_addr_ntop(src, addr1, sizeof(addr1)),
        ip6_addr_ntop(dst, addr2, sizeof(addr2)),
        na->nd_na_type, len, msg_len);
    icmp6_dump((uint8_t *)na, msg_len);
    return ip6_output(IP_PROTOCOL_ICMPV6, buf, msg_len + len, src, dst);
}