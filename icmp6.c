#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "util.h"
#include "ip6.h"
#include "icmp6.h"
#include "nd6.h"

/*
 * Dump
 */

static char *
icmp6_type_ntoa(uint8_t type) {
    switch (type) {
    case ICMPV6_TYPE_DEST_UNREACH:
        return "DestinationUnreachable";
    case ICMPV6_TYPE_TOO_BIG:
        return "Too Big"; 
    case ICMPV6_TYPE_TIME_EXCEEDED:
        return "Time Exceeded";
    case ICMPV6_TYPE_PARAM_PROBLEM:
        return "Parameter Problem";
    case ICMPV6_TYPE_ECHO_REQUEST:
        return "Echo Request";
    case ICMPV6_TYPE_ECHO_REPLY:
        return "Echo Reply";
    case ICMPV6_TYPE_ROUTER_SOL:
        return "Router Solicitation";
    case ICMPV6_TYPE_ROUTER_ADV:
        return "Router Advertisement";
    case ICMPV6_TYPE_NEIGHBOR_SOL:
        return "Neighbor Solicitation";
    case ICMPV6_TYPE_NEIGHBOR_ADV:
        return "Neighbor Advertisement";
    case ICMPV6_TYPE_REDIRECT:
        return "Redirect";
    }
    return "Unknown";
}

/*
static char *
icmp6_ra_flg_ntoa(uint8_t flg)
{
#define ND6_RA_FLAG_ISSET(x, y) ((x & 0x3f) & (y) ? 1 : 0)
#define ND6_RA_FLAG_MGMT 0x01
#define ND6_RA_FLAG_OTHER 0x02
#define ND6_RA_FLAG_HOME 0x04

    static char str[9];

    snprintf(str, sizeof(str), "--%c%c%c%c%c%c",
        TCP_FLG_ISSET(flg, TCP_FLG_URG) ? 'U' : '-',
        TCP_FLG_ISSET(flg, TCP_FLG_ACK) ? 'A' : '-',
        TCP_FLG_ISSET(flg, TCP_FLG_PSH) ? 'P' : '-',
        TCP_FLG_ISSET(flg, TCP_FLG_RST) ? 'R' : '-',
        TCP_FLG_ISSET(flg, TCP_FLG_SYN) ? 'S' : '-',
        TCP_FLG_ISSET(flg, TCP_FLG_FIN) ? 'F' : '-');
    return str;
}
*/

void 
icmp6_dump(const uint8_t *data, size_t len)
{
    struct icmp6_hdr *hdr;
    struct icmp6_echo *echo;
    struct nd_neighbor_solicit *ns;
    struct nd_neighbor_adv *na;
    struct nd_router_adv *ra;
    char addr[IPV6_ADDR_STR_LEN];

    flockfile(stderr);
    hdr = (struct icmp6_hdr *)data;
    fprintf(stderr, "       type: %s (%u)\n", icmp6_type_ntoa(hdr->icmp6_type), hdr->icmp6_type);
    fprintf(stderr, "       code: %u\n", hdr->icmp6_code);
    fprintf(stderr, "        sum: 0x%04x\n", ntoh16(hdr->icmp6_sum));
    switch (hdr->icmp6_type) {
    case ICMPV6_TYPE_DEST_UNREACH:
    case ICMPV6_TYPE_TOO_BIG:
    case ICMPV6_TYPE_TIME_EXCEEDED:
    case ICMPV6_TYPE_PARAM_PROBLEM:
    case ICMPV6_TYPE_ECHO_REQUEST:
        echo = (struct icmp6_echo *)hdr;
        fprintf(stderr, "         id: %u\n", ntoh16(echo->icmp6_id));
        fprintf(stderr, "        seq: %u\n", ntoh16(echo->icmp6_seq));
        break;
    case ICMPV6_TYPE_ECHO_REPLY:
        echo = (struct icmp6_echo *)hdr;
        fprintf(stderr, "         id: %u\n", ntoh16(echo->icmp6_id));
        fprintf(stderr, "        seq: %u\n", ntoh16(echo->icmp6_seq));
        break;
    case ICMPV6_TYPE_ROUTER_SOL:
        break;
    case ICMPV6_TYPE_ROUTER_ADV:
        ra = (struct nd_router_adv *)data;
        fprintf(stderr, " cur hlimit: %u\n", ra->cur_hlim);
        fprintf(stderr, "      flags: m=%u, o=%u, h=%u, prf=%u, p=%u, reserved=%u\n", ra->m, ra->o, ra->h, ra->prf, ra->p, ra->reserved);
        //fprintf(stderr, "      flags: 0x%02x (%s)\n", , icmp6_ra_flg_ntoa(hdr->flg));
        fprintf(stderr, "   lifetime: %u\n", ntoh16(ra->lifetime));
        fprintf(stderr, "  reachable: %u\n", ntoh32(ra->reachable_time));
        fprintf(stderr, "  retrasmit: %u\n", ntoh32(ra->retransmit_time));
        nd6_options_dump((uint8_t *)(ra + 1), len - sizeof(*ra));
        break;
    case ICMPV6_TYPE_NEIGHBOR_SOL:
        ns = (struct nd_neighbor_solicit *)hdr;
        fprintf(stderr, "   reserved: 0x%04x\n", ntoh16(ns->nd_ns_reserved));
        fprintf(stderr, "     target: %s\n", ip6_addr_ntop(ns->target, addr, sizeof(addr)));
        nd6_options_dump((uint8_t *)(ns + 1), len - sizeof(*ns));
        break;
    case ICMPV6_TYPE_NEIGHBOR_ADV:
        na = (struct nd_neighbor_adv *)hdr;
        fprintf(stderr, "   reserved: 0x%04x\n", ntoh16(na->nd_na_reserved));
        fprintf(stderr, "     target: %s\n", ip6_addr_ntop(na->target, addr, sizeof(addr)));
        nd6_options_dump((uint8_t *)(na + 1), len - sizeof(*na));
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

/*
 * ICMPv6 input/output
 */

void
icmp6_input(const uint8_t *data, size_t len, ip6_addr_t src, ip6_addr_t dst, struct ip6_iface *iface)
{
    struct icmp6_hdr *hdr;
    struct ip6_pseudo_hdr pseudo;
    uint16_t psum = 0;
    char addr1[IPV6_ADDR_STR_LEN];
    char addr2[IPV6_ADDR_STR_LEN];
    char addr3[IPV6_ADDR_STR_LEN];

    if (len < sizeof(*hdr)) {
        errorf("too short");
        return;        
    }

    if (IPV6_ADDR_IS_MULTICAST(&dst)) {
        // TODO: 
    }

    hdr = (struct icmp6_hdr *)data;

    /* verify checksum value */
    pseudo.src = src;
    pseudo.dst = dst;
    pseudo.len = hton16(len);
    pseudo.zero[0] = pseudo.zero[1] = pseudo.zero[2] = 0;
    pseudo.nxt = IPV6_NEXT_ICMPV6;
    psum = ~cksum16((uint16_t *)&pseudo, sizeof(pseudo), 0);
    if (cksum16((uint16_t *)hdr, len, psum) != 0) {
        errorf("checksum error: sum=0x%04x, verify=0x%04x", ntoh16(hdr->icmp6_sum), ntoh16(cksum16((uint16_t *)hdr, len, -hdr->icmp6_sum + psum)));
        return;
    }

    debugf("%s => %s, type=(%u), len=%zu, iface=%s",
        ip6_addr_ntop(src, addr1, sizeof(addr1)),
        ip6_addr_ntop(dst, addr2, sizeof(addr2)),
        hdr->icmp6_type, len,
        ip6_addr_ntop(iface->ip6_addr.addr, addr3, sizeof(addr3)));
#ifdef HDRDUMP
    icmp6_dump(data, len);
#endif
        
    switch (hdr->icmp6_type) {
    case ICMPV6_TYPE_DEST_UNREACH:
    case ICMPV6_TYPE_TOO_BIG:
    case ICMPV6_TYPE_TIME_EXCEEDED:
    case ICMPV6_TYPE_PARAM_PROBLEM:
    case ICMPV6_TYPE_ECHO_REQUEST:
        if (hdr->icmp6_code != 0) {
            errorf("bad icmpv6 code");
            break;
        }
        if (!IPV6_ADDR_EQUAL(&dst, &iface->ip6_addr.addr)) {
            dst = iface->ip6_addr.addr;
        }
        icmp6_output(ICMPV6_TYPE_ECHO_REPLY, hdr->icmp6_code, hdr->icmp6_flag_reserved, (uint8_t *)(hdr + 1), len - sizeof(*hdr), dst, src);
        break;    
    case ICMPV6_TYPE_ECHO_REPLY:
        if (hdr->icmp6_code != 0) {
            errorf("bad icmpv6 code");
            break;
        }
        break;
    case ICMPV6_TYPE_ROUTER_SOL:
    case ICMPV6_TYPE_ROUTER_ADV:
        if (hdr->icmp6_code != 0) {
            errorf("bad icmpv6 code");
            return;   
        }
        if (len < sizeof(struct nd_router_adv)) {
            errorf("too short");
            return;
        }
        nd6_ra_input(data, len, src, dst, iface);
        break;
    case ICMPV6_TYPE_NEIGHBOR_SOL:
        if (hdr->icmp6_code != 0) {
            errorf("bad icmpv6 code");
            return;   
        }
        if (len < sizeof(struct nd_neighbor_solicit)) {
            errorf("too short");
            return;
        }
        nd6_ns_input(data, len, src, dst, iface);
        break;
    case ICMPV6_TYPE_NEIGHBOR_ADV:
        if (hdr->icmp6_code != 0) {
            errorf("bad icmpv6 code");
            return;   
        }
        if (len < sizeof(struct nd_neighbor_adv)) {
            errorf("too short");
            return;
        }
        nd6_na_input(data, len, src, dst, iface);
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
icmp6_output(uint8_t type, uint8_t code, uint32_t flags, const uint8_t *data, size_t len, ip6_addr_t src, ip6_addr_t dst)
{
    uint8_t buf[ICMPV6_BUFSIZ];
    struct icmp6_hdr *hdr;
    char addr1[IPV6_ADDR_STR_LEN];
    char addr2[IPV6_ADDR_STR_LEN];  
    struct ip6_pseudo_hdr pseudo;
    size_t total;
    uint16_t psum = 0;

    /* select source address */
    struct ip6_iface *res;

    res = ip6_rule_addr_select(dst);
    if (res != NULL) {
        debugf("selected source address=%s, scope=%u", ip6_addr_ntop(res->ip6_addr.addr, addr1, sizeof(addr1)), res->ip6_addr.scope);
        IPV6_ADDR_COPY(&src, &res->ip6_addr.addr, IPV6_ADDR_LEN);
    } else {
        warnf("no appropriate source address");
        return -1;
    }

    /* icmp6 header */
    hdr = (struct icmp6_hdr *)buf;
    hdr->icmp6_type = type;
    hdr->icmp6_code = code;
    hdr->icmp6_sum = 0;
    hdr->icmp6_flag_reserved = flags;

    total = sizeof(*hdr) + len;
    memcpy(buf + sizeof(*hdr), data, len);

    /* calculate checksum value */
    pseudo.src = src;
    pseudo.dst = dst;
    pseudo.len = hton32(total);
    pseudo.zero[0] = pseudo.zero[1] = pseudo.zero[2] = 0;
    pseudo.nxt = IPV6_NEXT_ICMPV6;
    psum =  ~cksum16((uint16_t *)&pseudo, sizeof(pseudo), 0);
    hdr->icmp6_sum = cksum16((uint16_t *)buf, total, psum);

    debugf("%s => %s, type=(%u), len=%zu +hdr_len=%zu, total=%zu",
        ip6_addr_ntop(src, addr1, sizeof(addr1)),
        ip6_addr_ntop(dst, addr2, sizeof(addr2)),
        hdr->icmp6_type, len, sizeof(*hdr), total);
#ifdef HDRDUMP
    icmp6_dump((uint8_t *)hdr, total);
#endif
    return ip6_output(IPV6_NEXT_ICMPV6, buf, total, src, dst);
}

int
icmp6_init(void)
{
    if (ip6_protocol_register("ICMPV6", IPV6_NEXT_ICMPV6, icmp6_input) == -1) {
        errorf("ip6_protocol_register() failure");
        return -1;
    }
    return 0;
}