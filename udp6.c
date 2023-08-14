#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <errno.h>

#include "platform.h"

#include "util.h"
#include "net.h"
#include "ip6.h"
#include "udp.h"

#ifdef COMMENT_OUT
struct udp6_pcb {
    int state;
    struct ip6_endpoint local;
    struct queue_head queue; /* receive queue */
    struct sched_ctx ctx;
};

/* NOTE: the data follows immediately after the structure */
struct udp6_queue_entry {
    struct ip6_endpoint foreign;
    uint16_t len;
};

static mutex_t mutex = MUTEX_INITIALIZER;
static struct udp6_pcb pcbs[UDP_PCB_SIZE];

#endif

/*
 * UDP Protocol Control Block (PCB)
 *
 * NOTE: UDP PCB functions must be called after mutex locked
 */

static void
udp6_input(const uint8_t *data, size_t len, ip6_addr_t src, ip6_addr_t dst, struct ip6_iface *iface)
{
    struct ip6_pseudo_hdr pseudo;
    uint16_t psum = 0;
    struct udp_hdr *hdr;
    char addr1[IPV6_ADDR_STR_LEN];
    char addr2[IPV6_ADDR_STR_LEN];
    // struct udp6_pcb *pcb;
    //struct udp6_queue_entry *entry;

    if (len < sizeof(*hdr)) {
        errorf("too short");
        return;
    }
    hdr = (struct udp_hdr *)data;
    if (len != ntoh16(hdr->len)) {
        errorf("length error: len=%zu, hdr->len=%u", len, ntoh16(hdr->len));
        return;
    }
    pseudo.src = src;
    pseudo.dst = dst;
    pseudo.len = hton16(len);
    pseudo.zero[0] = pseudo.zero[1] = pseudo.zero[2] = 0;
    pseudo.nxt = IPV6_NEXT_UDP;
    psum = ~cksum16((uint16_t *)&pseudo, sizeof(pseudo), 0);
    if (cksum16((uint16_t *)hdr, len, psum) != 0) {
        errorf("checksum error: sum=0x%04x, verify=0x%04x", ntoh16(hdr->sum), ntoh16(cksum16((uint16_t *)hdr, len, -hdr->sum + psum)));
        return;
    }
    debugf("[%s]%d => [%s]%d, len=%zu (payload=%zu)",
        ip6_addr_ntop(src, addr1, sizeof(addr1)), ntoh16(hdr->src),
        ip6_addr_ntop(dst, addr2, sizeof(addr2)), ntoh16(hdr->dst),
        len, len - sizeof(*hdr));
    udp_dump(data, len);
}

ssize_t
udp6_output(struct ip6_endpoint *src, struct ip6_endpoint *dst, const  uint8_t *data, size_t len)
{
    uint8_t buf[IPV6_PAYLOAD_SIZE_MAX];
    struct udp_hdr *hdr;
    struct ip6_pseudo_hdr pseudo;
    uint16_t total, psum = 0;
    char ep1[IPV6_ENDPOINT_STR_LEN];
    char ep2[IPV6_ENDPOINT_STR_LEN];

    if (len > IPV6_PAYLOAD_SIZE_MAX - sizeof(*hdr)) {
        errorf("too long");
        return -1;
    }
    hdr = (struct udp_hdr *)buf;

    hdr->src = src->port;
    hdr->dst = dst->port;
    total = sizeof(*hdr) + len;
    hdr->len = hton16(total);
    hdr->sum = 0;
    memcpy(hdr + 1, data, len);
    pseudo.src = src->addr;
    pseudo.dst = dst->addr;
    pseudo.len = hton16(total);
    pseudo.zero[0] = pseudo.zero[1] = pseudo.zero[2] = 0;
    pseudo.nxt = IPV6_NEXT_UDP;
    psum =  ~cksum16((uint16_t *)&pseudo, sizeof(pseudo), 0);
    hdr->sum = cksum16((uint16_t *)buf, total, psum);
    debugf("%s => %s, len=%zu (payload=%zu)",
        ip6_endpoint_ntop(src, ep1, sizeof(ep1)), ip6_endpoint_ntop(dst, ep2, sizeof(ep2)), total, len);
    udp_dump((uint8_t *)hdr, total);
    if (ip6_output(IPV6_NEXT_UDP, (uint8_t *)hdr, total, src->addr, dst->addr) == -1) {
        errorf("ip6_output() failure");
        return -1;
    }
    return len;
}

int
udp6_init(void)
{
    if (ip6_protocol_register("UDP", IPV6_NEXT_UDP, udp6_input) == -1) {
        errorf("ip6_protocol_register() failure");
        return -1;
    }
    //net_event_subscribe(event_handler, NULL);
    return 0;
}