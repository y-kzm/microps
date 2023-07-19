#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "util.h"
#include "ip6.h"
#include "icmp6.h"
#include "nd6.h"

void 
icmp6_dump(const uint8_t *data, size_t len)
{
    struct icmp6_hdr *hdr;
    struct icmp6_echo *echo;
    struct nd_neighbor_solicit *ns;
    struct nd_neighbor_adv *na;
    struct nd_lladdr_opt *opt;
    char addr[IPV6_ADDR_STR_LEN];
    char lladdr[ETHER_ADDR_STR_LEN];

    flockfile(stderr);
    hdr = (struct icmp6_hdr *)data;
    fprintf(stderr, "       type: %u\n", hdr->icmp6_type);
    fprintf(stderr, "       code: %u\n", hdr->icmp6_code);
    fprintf(stderr, "        sum: 0x%04x\n", ntoh16(hdr->icmp6_sum));
    switch (hdr->icmp6_type) {
    case ICMPV6_TYPE_DEST_UNREACH:
        break;
    case ICMPV6_TYPE_TOO_BIG:
        break;
    case ICMPV6_TYPE_TIME_EXCEEDED:
        break;
    case ICMPV6_TYPE_PARAM_PROBLEM:
        break;
    case ICMPV6_TYPE_ECHOREPLY:
        break;
    case ICMPV6_TYPE_ECHO:
        echo = (struct icmp6_echo *)hdr;
        fprintf(stderr, "         id: %u\n", ntoh16(echo->icmp6_id));
        break;
    case ICMPV6_TYPE_ROUTER_SOL:
        break;
    case ICMPV6_TYPE_ROUTER_ADV:
        break;
    case ICMPV6_TYPE_NEIGHBOR_SOL:
        ns = (struct nd_neighbor_solicit *)hdr;
        fprintf(stderr, "   reserved: 0x%04x\n", ntoh16(ns->nd_ns_reserved));
        fprintf(stderr, "     target: %s\n", ip6_addr_ntop(ns->target, addr, sizeof(addr)));
        opt = (struct nd_lladdr_opt *)(data + sizeof(*ns));
        fprintf(stderr, "       type: %u\n", opt->type);
        fprintf(stderr, "        len: %u\n", opt->len);
        fprintf(stderr, "     lladdr: %s\n", ether_addr_ntop(opt->lladdr, lladdr, sizeof(lladdr)));
        break;
    case ICMPV6_TYPE_NEIGHBOR_ADV:
        na = (struct nd_neighbor_adv *)hdr;
        fprintf(stderr, "   reserved: 0x%04x\n", ntoh16(na->nd_na_reserved));
        fprintf(stderr, "     target: %s\n", ip6_addr_ntop(na->target, addr, sizeof(addr)));
        opt = (struct nd_lladdr_opt *)(data + sizeof(*na));
        fprintf(stderr, "       type: %u\n", opt->type);
        fprintf(stderr, "        len: %u\n", opt->len);
        fprintf(stderr, "     lladdr: %s\n", ether_addr_ntop(opt->lladdr, lladdr, sizeof(lladdr)));
        break;
    case ICMPV6_TYPE_REDIRECT:
        break;
    default:
        break;
    }
#ifdef HEXDUMP
    hexdump(stderr, data, len);
#endif
    funlockfile(stderr);
}

void
icmp6_input(const uint8_t *data, size_t len, ip6_addr_t src, ip6_addr_t dst, struct ip6_iface *iface)
{
    struct icmp6_hdr *hdr;
    char addr1[IPV6_ADDR_STR_LEN];
    char addr2[IPV6_ADDR_STR_LEN];
    char addr3[IPV6_ADDR_STR_LEN];

    if (len < sizeof(*hdr)) {
        errorf("too short");
        return;        
    }
    hdr = (struct icmp6_hdr *)data;
    // TODO: include ipv6 header
    /*
    if (cksum16((uint16_t *)data, len, 0) != 0) {
        errorf("checksum error, sum=0x%04x, verify=0x%04x", ntoh16(hdr->icmp6_sum), ntoh16(cksum16((uint16_t *)data, len, -hdr->icmp6_sum)));
        return;
    }
    */

    debugf("%s => %s, type=(%u), len=%zu, iface=%s",
        ip6_addr_ntop(src, addr1, sizeof(addr1)),
        ip6_addr_ntop(dst, addr2, sizeof(addr2)),
        hdr->icmp6_type, len,
        ip6_addr_ntop(iface->unicast, addr3, sizeof(addr3)));
    //icmp6_dump(data, len);
    switch (hdr->icmp6_type) {
    case ICMPV6_TYPE_DEST_UNREACH:
        break;
    case ICMPV6_TYPE_TOO_BIG:
        break;
    case ICMPV6_TYPE_TIME_EXCEEDED:
        break;
    case ICMPV6_TYPE_PARAM_PROBLEM:
        break;
    case ICMPV6_TYPE_ECHOREPLY:
        break;
    case ICMPV6_TYPE_ECHO:
        icmp6_dump(data, len);
        if (memcmp(&dst, &iface->unicast, IPV6_ADDR_LEN) != 0) {
            //
        }
        icmp6_output(ICMPV6_TYPE_ECHOREPLY, hdr->icmp6_code, hdr->icmp6_flag_reserved, (uint8_t *)(hdr + 1), len - sizeof(*hdr), dst, src);
        break;
    case ICMPV6_TYPE_ROUTER_SOL:
        break;
    case ICMPV6_TYPE_ROUTER_ADV:
        break;
    case ICMPV6_TYPE_NEIGHBOR_SOL:
        if (hdr->icmp6_code != 0) {
            errorf("bad code");
            return;   
        }
        if (len < sizeof(struct nd_neighbor_solicit)) {
            errorf("too short");
            return;
        }
        nd6_ns_input(data, len, src, dst, iface);
        break;
    case ICMPV6_TYPE_NEIGHBOR_ADV:
        break;
    case ICMPV6_TYPE_REDIRECT:
        break;
    default:
        /* ignore */
        debugf("not supported type: %u", hdr->icmp6_type);
        break;
    }
}

int 
icmp6_output(uint8_t type, uint8_t code, uint32_t flags, const uint8_t*data, size_t len, ip6_addr_t src, ip6_addr_t dst)
{
    uint8_t buf[ICMPV6_BUFSIZ];
    struct icmp6_hdr *hdr;
    size_t msg_len;
    char addr1[IPV6_ADDR_STR_LEN];
    char addr2[IPV6_ADDR_STR_LEN];  
    struct ip6_pseudo_hdr pseudo;
    uint16_t psum = 0;

    hdr = (struct icmp6_hdr *)buf;
    hdr->icmp6_type = type;
    hdr->icmp6_code = code;
    hdr->icmp6_sum = 0;
    hdr->icmp6_flag_reserved = flags;
    memcpy(hdr + 1, data, len);
    msg_len = sizeof(*hdr) + len;
  
   /* pseudo header */
    pseudo.src = src;
    pseudo.dst = dst;
    pseudo.len = hton16(msg_len);
    pseudo.zero[0] = pseudo.zero[1] = pseudo.zero[2] = 0;
    pseudo.nxt = IP_PROTOCOL_ICMPV6;
    psum =  ~cksum16((uint16_t *)&pseudo, sizeof(pseudo), 0);
    hdr->icmp6_sum = cksum16((uint16_t *)buf, msg_len, psum);

    debugf("%s => %s, type=(%u), len=%zu",
        ip6_addr_ntop(src, addr1, sizeof(addr1)),
        ip6_addr_ntop(dst, addr2, sizeof(addr2)),
        hdr->icmp6_type, msg_len);
    icmp6_dump((uint8_t *)hdr, msg_len);
    return ip6_output(IP_PROTOCOL_ICMPV6, (uint8_t *)hdr, msg_len, src, dst);
}


int
icmp6_init(void)
{
    if (ip6_protocol_register("ICMPV6", IP_PROTOCOL_ICMPV6, icmp6_input) == -1) {
        errorf("ip6_protocol_register() failure");
        return -1;
    }
    return 0;
}