#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "util.h"
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

struct icmp6_hdr {
	uint8_t	type;
	uint8_t	code;
	uint16_t sum;
    uint8_t data[];
};

struct icmp6_echo {
    uint8_t type;
    uint8_t code;
    uint16_t sum;
    uint16_t id;
    uint16_t seq;
    uint8_t data[];
};

char *
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

void 
icmp6_dump(const uint8_t *data, size_t len)
{
    struct icmp6_hdr *hdr;
    struct icmp6_echo *echo;

    flockfile(stderr);
    hdr = (struct icmp6_hdr *)data;
    fprintf(stderr, "       type: %s (%u)\n", icmp6_type_ntoa(hdr->type), hdr->type);
    fprintf(stderr, "       code: %u\n", hdr->code);
    fprintf(stderr, "        sum: 0x%04x\n", ntoh16(hdr->sum));
    switch (hdr->type) {
    case ICMPV6_TYPE_DEST_UNREACH:
    case ICMPV6_TYPE_TOO_BIG:
    case ICMPV6_TYPE_TIME_EXCEEDED:
    case ICMPV6_TYPE_PARAM_PROBLEM:
        break;
    case ICMPV6_TYPE_ECHO_REQUEST:
    case ICMPV6_TYPE_ECHO_REPLY:
        echo = (struct icmp6_echo *)hdr;
        fprintf(stderr, "         id: %u\n", ntoh16(echo->id));
        fprintf(stderr, "        seq: %u\n", ntoh16(echo->seq));
        break;
    case ICMPV6_TYPE_ROUTER_SOL:
    case ICMPV6_TYPE_ROUTER_ADV:
    case ICMPV6_TYPE_NEIGHBOR_SOL:
    case ICMPV6_TYPE_NEIGHBOR_ADV:
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

static void
icmp6_input(const uint8_t *data, size_t len, ip6_addr_t src, ip6_addr_t dst, struct ip6_iface *iface)
{
    struct pseudo6_hdr pseudo;
    uint16_t psum = 0;
    struct icmp6_hdr *hdr;
    char addr1[IPV6_ADDR_STR_LEN];
    char addr2[IPV6_ADDR_STR_LEN];
    char addr3[IPV6_ADDR_STR_LEN];

    if (len < sizeof(*hdr)) {
        errorf("too short");
        return;
    }
    hdr = (struct icmp6_hdr *)data;
    IPV6_ADDR_COPY(&pseudo.src, &src, sizeof(pseudo.src));
    IPV6_ADDR_COPY(&pseudo.dst, &dst, sizeof(pseudo.dst));
    pseudo.len = hton32(len);
    pseudo.zero[0] = pseudo.zero[1] = pseudo.zero[2] = 0;
    pseudo.next = IPV6_PROTOCOL_ICMPV6;
    psum = ~cksum16((uint16_t *)&pseudo, sizeof(pseudo), 0);
    if (cksum16((uint16_t *)data, len, psum) != 0) {
        errorf("checksum error, sum=0x%04x, verify=0x%04x", ntoh16(hdr->sum), ntoh16(cksum16((uint16_t *)data, len, -hdr->sum + psum)));
        return;
    }
    debugf("%s => %s, type=%s(%u), len=%zu, iface=%s",
        ip6_addr_ntop(src, addr1, sizeof(addr1)),
        ip6_addr_ntop(dst, addr2, sizeof(addr2)), 
        icmp6_type_ntoa(hdr->type), hdr->type, len,
        ip6_addr_ntop(iface->addr, addr3, sizeof(addr3)));
    icmp6_dump(data, len);
    switch (hdr->type) {
    case ICMPV6_TYPE_ECHO_REQUEST:
        icmp6_output(ICMPV6_TYPE_ECHO_REPLY, 0, hdr->data, len - sizeof(*hdr), dst, src);
        break;
    case ICMPV6_TYPE_ROUTER_SOL:
    case ICMPV6_TYPE_ROUTER_ADV:
    case ICMPV6_TYPE_NEIGHBOR_SOL:
        nd6_ns_input(data, len, src, dst, iface);
        break;
    case ICMPV6_TYPE_NEIGHBOR_ADV:
    case ICMPV6_TYPE_REDIRECT:
        break;
    default:
        /* ignore */
        break;
    }
}

int
icmp6_output(uint8_t type, uint8_t code, const uint8_t *data, size_t len, ip6_addr_t src, ip6_addr_t dst)
{
    struct pseudo6_hdr pseudo;
    uint16_t psum = 0;
    uint8_t buf[ICMP6_BUFSIZ];
    struct icmp6_hdr *hdr;
    size_t msg_len;
    char addr1[IPV6_ADDR_STR_LEN];
    char addr2[IPV6_ADDR_STR_LEN];

    if (len > ICMP6_BUFSIZ - sizeof(*hdr)) {
        errorf("too long, len=%zu", len);
        return -1;
    }
    hdr = (struct icmp6_hdr *)buf;
    hdr->type = type;
    hdr->code = code;
    hdr->sum = 0;
    memcpy(hdr->data, data, len);
    IPV6_ADDR_COPY(&pseudo.src, &src, sizeof(pseudo.src));
    IPV6_ADDR_COPY(&pseudo.dst, &dst, sizeof(pseudo.dst));
    pseudo.len = hton32(len + sizeof(*hdr));
    pseudo.zero[0] = pseudo.zero[1] = pseudo.zero[2] = 0;
    pseudo.next = IPV6_PROTOCOL_ICMPV6;
    psum = ~cksum16((uint16_t *)&pseudo, sizeof(pseudo), 0);
    hdr->sum = cksum16((uint16_t *)hdr, len + sizeof(*hdr), psum);
    msg_len = len + sizeof(*hdr);
    debugf("%s => %s, type=%s(%u), len=%zu",
        ip6_addr_ntop(src, addr1, sizeof(addr1)),
        ip6_addr_ntop(dst, addr2, sizeof(addr2)),
        icmp6_type_ntoa(type), type, msg_len);
    icmp6_dump(buf, msg_len);
    return ip6_output(IPV6_PROTOCOL_ICMPV6, buf, msg_len, src, dst);
}

int
icmp6_init(void)
{
    if (ip6_protocol_register("ICMPV6", IPV6_PROTOCOL_ICMPV6, icmp6_input) == -1) {
        errorf("ip6_protocol_register() failure");
        return -1;
    }
    return 0;
}