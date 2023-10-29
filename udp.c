#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <errno.h>

#include "platform.h"

#include "util.h"
#include "net.h"
#include "ip.h"
#include "ip6.h"
#include "udp.h"

#include "sock.h"

struct udp_pcb {
    int state;
    struct ip_endpoint local;
    struct queue_head queue; /* receive queue */
    struct sched_ctx ctx;
};

/* NOTE: the data follows immediately after the structure */
struct udp_queue_entry {
    struct ip_endpoint foreign;
    uint16_t len;
};

static mutex_t mutex = MUTEX_INITIALIZER;
static struct udp_pcb pcbs[UDP_PCB_SIZE];

void
udp_dump(const uint8_t *data, size_t len)
{
    struct udp_hdr *hdr;

    flockfile(stderr);
    hdr = (struct udp_hdr *)data;
    fprintf(stderr, "        src: %u\n", ntoh16(hdr->src));
    fprintf(stderr, "        dst: %u\n", ntoh16(hdr->dst));
    fprintf(stderr, "        len: %u\n", ntoh16(hdr->len));
    fprintf(stderr, "        sum: 0x%04x\n", ntoh16(hdr->sum));
#ifdef HEXDUMP
    hexdump(stderr, data, len);
#endif
    funlockfile(stderr);
}

/*
 * UDP Protocol Control Block (PCB)
 *
 * NOTE: UDP PCB functions must be called after mutex locked
 */

static struct udp_pcb *
udp_pcb_alloc()
{
    struct udp_pcb *pcb;

    for (pcb = pcbs; pcb < tailof(pcbs); pcb++) {
        if (pcb->state == UDP_PCB_STATE_FREE) {
            pcb->state = UDP_PCB_STATE_OPEN;
            sched_ctx_init(&pcb->ctx);
            return pcb;
        }
    }
    return NULL;
}

static void
udp_pcb_release(struct udp_pcb *pcb)
{
    struct queue_entry *entry;

    pcb->state = UDP_PCB_STATE_CLOSING;
    if (sched_ctx_destroy(&pcb->ctx) == -1) {
        sched_wakeup(&pcb->ctx);
        return;
    }
    pcb->state = UDP_PCB_STATE_FREE;
    pcb->local.addr.s_addr4 = IP_ADDR_ANY;
    pcb->local.addr.s_addr6 = IPV6_UNSPECIFIED_ADDR;
    pcb->local.port = 0;
    while ((entry = queue_pop(&pcb->queue)) != NULL) {
        memory_free(entry);
    }
}

static struct udp_pcb *
udp_pcb_select(ip_addr_storage addr, uint16_t port)
{
    struct udp_pcb *pcb;

    for (pcb = pcbs; pcb < tailof(pcbs); pcb++) {
        switch (addr.family) {
        case AF_INET:    
            if (pcb->state == UDP_PCB_STATE_OPEN) {
                if ((pcb->local.addr.s_addr4 == IP_ADDR_ANY || pcb->local.addr.s_addr4 == addr.s_addr4) 
                    && pcb->local.port == port
                    && pcb->local.addr.family == AF_INET) {
                        return pcb;
                }
            }
            break;
        case AF_INET6: 
            if (pcb->state == UDP_PCB_STATE_OPEN) {
                if ((IPV6_ADDR_EQUAL(&pcb->local.addr.s_addr6, &IPV6_UNSPECIFIED_ADDR) || IPV6_ADDR_EQUAL(&pcb->local.addr.s_addr6, &addr.s_addr6)) 
                    && pcb->local.port == port
                    && pcb->local.addr.family == AF_INET6) {
                        return pcb;
                }
            }
            break;
        default:
            break;
        }
    }
    return NULL;
}

static struct udp_pcb *
udp_pcb_get(int id)
{
    struct udp_pcb *pcb;

    if (id < 0 || id >= (int)countof(pcbs)) {
        /* out of range */
        return NULL;
    }
    pcb = &pcbs[id];
    if (pcb->state != UDP_PCB_STATE_OPEN) {
        return NULL;
    }
    return pcb;
}

static int
udp_pcb_id(struct udp_pcb *pcb)
{
    return indexof(pcbs, pcb);
}

static void
udp_input(const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst, struct ip_iface *iface)
{
    struct ip_pseudo_hdr pseudo;
    uint16_t psum = 0;
    struct udp_hdr *hdr;
    char addr1[IP_ADDR_STR_LEN];
    char addr2[IP_ADDR_STR_LEN];
    struct udp_pcb *pcb;
    struct udp_queue_entry *entry;
    ip_addr_storage udp4_src, udp4_dst;

    if (len < sizeof(*hdr)) {
        errorf("too short");
        return;
    }
    hdr = (struct udp_hdr *)data;
    if (len != ntoh16(hdr->len)) { /* just to make sure */
        errorf("length error: len=%zu, hdr->len=%u", len, ntoh16(hdr->len));
        return;
    }
    udp4_src.family = AF_INET;
    udp4_src.s_addr4 = src;
    udp4_dst.family = AF_INET;
    udp4_dst.s_addr4 = dst;
    /* verify checksum value */
    pseudo.src = udp4_src.s_addr4;
    pseudo.dst = udp4_dst.s_addr4;
    pseudo.zero = 0;
    pseudo.protocol = PROTOCOL_UDP;
    pseudo.len = hton16(len);
    psum = ~cksum16((uint16_t *)&pseudo, sizeof(pseudo), 0);
    if (cksum16((uint16_t *)hdr, len, psum) != 0) {
        errorf("checksum error: sum=0x%04x, verify=0x%04x", ntoh16(hdr->sum), ntoh16(cksum16((uint16_t *)hdr, len, -hdr->sum + psum)));
        return;
    }
    debugf("%s:%d => %s:%d, len=%zu (payload=%zu)",
        ip_addr_ntop(udp4_src.s_addr4, addr1, sizeof(addr1)), ntoh16(hdr->src),
        ip_addr_ntop(udp4_dst.s_addr4, addr2, sizeof(addr2)), ntoh16(hdr->dst),
        len, len - sizeof(*hdr));
#ifdef HDRDUMP
    udp_dump(data, len);
#endif
    mutex_lock(&mutex);
    pcb = udp_pcb_select(udp4_dst, hdr->dst);
    if (!pcb) {
        /* port is not in use */
        mutex_unlock(&mutex);
        debugf("port is not in use");
        return;
    }
    entry = memory_alloc(sizeof(*entry) + (len - sizeof(*hdr)));
    if (!entry) {
        mutex_unlock(&mutex);
        errorf("memory_alloc() failure");
        return;
    }
    entry->foreign.addr = udp4_src;
    entry->foreign.port = hdr->src;
    entry->len = len - sizeof(*hdr);
    memcpy(entry + 1, hdr + 1, entry->len);
    if (!queue_push(&pcb->queue, entry)) {
        mutex_unlock(&mutex);
        errorf("queue_push() failure");
        return;
    }
    sched_wakeup(&pcb->ctx);
    mutex_unlock(&mutex);
}

static void
udp6_input(const uint8_t *data, size_t len, ip6_addr_t src, ip6_addr_t dst, struct ip6_iface *iface)
{
    struct ip6_pseudo_hdr pseudo;
    uint16_t psum = 0;
    struct udp_hdr *hdr;
    char addr1[IPV6_ADDR_STR_LEN];
    char addr2[IPV6_ADDR_STR_LEN];
    struct udp_pcb *pcb;
    struct udp_queue_entry *entry;
    ip_addr_storage udp6_src, udp6_dst;

    if (len < sizeof(*hdr)) {
        errorf("too short");
        return;
    }
    hdr = (struct udp_hdr *)data;
    if (len != ntoh16(hdr->len)) {
        errorf("length error: len=%zu, hdr->len=%u", len, ntoh16(hdr->len));
        return;
    }
    udp6_src.s_addr6 = src;
    udp6_src.family = AF_INET6;
    udp6_dst.s_addr6 = dst;
    udp6_dst.family = AF_INET6;
    /* verify checksum value */
    pseudo.src = udp6_src.s_addr6;
    pseudo.dst = udp6_dst.s_addr6;
    pseudo.len = hton16(len);
    pseudo.zero[0] = pseudo.zero[1] = pseudo.zero[2] = 0;
    pseudo.nxt = PROTOCOL_UDP;
    psum = ~cksum16((uint16_t *)&pseudo, sizeof(pseudo), 0);
    if (cksum16((uint16_t *)hdr, len, psum) != 0) {
        errorf("checksum error: sum=0x%04x, verify=0x%04x", ntoh16(hdr->sum), ntoh16(cksum16((uint16_t *)hdr, len, -hdr->sum + psum)));
        return;
    }
    debugf("[%s]:%d => [%s]:%d, len=%zu (payload=%zu)",
        ip6_addr_ntop(udp6_src.s_addr6, addr1, sizeof(addr1)), ntoh16(hdr->src),
        ip6_addr_ntop(udp6_dst.s_addr6, addr2, sizeof(addr2)), ntoh16(hdr->dst),
        len, len - sizeof(*hdr));
#ifdef HDRDUMP
    udp_dump(data, len);
#endif
    mutex_lock(&mutex);
    pcb = udp_pcb_select(udp6_dst, hdr->dst);
    if (!pcb) {
        /* port is not in use */
        mutex_unlock(&mutex);
        return;
    }
    entry = memory_alloc(sizeof(*entry) + (len - sizeof(*hdr)));
    if (!entry) {
        mutex_unlock(&mutex);
        errorf("memory_alloc() failure");
        return;
    }
    entry->foreign.addr = udp6_src;
    entry->foreign.port = hdr->src;
    entry->len = len - sizeof(*hdr);
    memcpy(entry + 1, hdr + 1, entry->len);
    if (!queue_push(&pcb->queue, entry)) {
        mutex_unlock(&mutex);
        errorf("queue_push() failure");
        return;
    }
    sched_wakeup(&pcb->ctx);
    mutex_unlock(&mutex);
}

ssize_t
udp_output(struct ip_endpoint *src, struct ip_endpoint *dst, const  uint8_t *data, size_t len)
{
    uint8_t buf[IP_PAYLOAD_SIZE_MAX];
    struct udp_hdr *hdr;
    struct ip_pseudo_hdr pseudo;
    uint16_t total, psum = 0;
    char ep1[IP_ENDPOINT_STR_LEN];
    char ep2[IP_ENDPOINT_STR_LEN];

    if (len > IP_PAYLOAD_SIZE_MAX - sizeof(*hdr)) {
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
    pseudo.src = src->addr.s_addr4;
    pseudo.dst = dst->addr.s_addr4;
    pseudo.zero = 0;
    pseudo.protocol = PROTOCOL_UDP;
    pseudo.len = hton16(total);
    psum = ~cksum16((uint16_t *)&pseudo, sizeof(pseudo), 0);
    hdr->sum = cksum16((uint16_t *)hdr, total, psum);
    debugf("%s => %s, len=%zu (payload=%zu)",
        ip_endpoint_ntop(src, ep1, sizeof(ep1)), ip_endpoint_ntop(dst, ep2, sizeof(ep2)), total, len);
#ifdef HDRDUMP
    udp_dump((uint8_t *)hdr, total);
#endif
    if (ip_output(PROTOCOL_UDP, (uint8_t *)hdr, total, src->addr.s_addr4, dst->addr.s_addr4) == -1) {
        errorf("ip_output() failure");
        return -1;
    }
    return len;
}

ssize_t
udp6_output(struct ip_endpoint *src, struct ip_endpoint *dst, const  uint8_t *data, size_t len)
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

    /* calculate checksum value */
    memset(&pseudo, 0, sizeof(struct ip6_pseudo_hdr));
    IPV6_ADDR_COPY(&pseudo.src, &src->addr.s_addr6, IPV6_ADDR_LEN);
    IPV6_ADDR_COPY(&pseudo.dst, &dst->addr.s_addr6, IPV6_ADDR_LEN);
    pseudo.len = hton16(total);
    pseudo.zero[0] = pseudo.zero[1] = pseudo.zero[2] = 0;
    pseudo.nxt = PROTOCOL_UDP;
    psum =  ~cksum16((uint16_t *)&pseudo, sizeof(pseudo), 0);
    hdr->sum = cksum16((uint16_t *)buf, total, psum);
    debugf("%s => %s, len=%zu (payload=%zu)",
        ip_endpoint_ntop(src, ep1, sizeof(ep1)), ip_endpoint_ntop(dst, ep2, sizeof(ep2)), total, len);
#ifdef HDRDUMP
    udp_dump((uint8_t *)hdr, total);
#endif
    if (ip6_output(PROTOCOL_UDP, (uint8_t *)hdr, total, src->addr.s_addr6, dst->addr.s_addr6) == -1) {
        errorf("ip6_output() failure");
        return -1;
    }
    return len;
}

static void
event_handler(void *arg)
{
    struct udp_pcb *pcb;

    mutex_lock(&mutex);
    for (pcb = pcbs; pcb < tailof(pcbs); pcb++) {
        if (pcb->state == UDP_PCB_STATE_OPEN) {
            sched_interrupt(&pcb->ctx);
        }
    }
    mutex_unlock(&mutex);
}

int
udp_init(void)
{
    if (ip_protocol_register("UDP", PROTOCOL_UDP, udp_input) == -1) {
        errorf("ip_protocol_register() failure");
        return -1;
    }
    if (ip6_protocol_register("UDP", PROTOCOL_UDP, udp6_input) == -1) {
        errorf("ip6_protocol_register() failure");
        return -1;
    }
    net_event_subscribe(event_handler, NULL);
    return 0;
}

/*
 * UDP User Commands
 */

int
udp_open(void)
{
    struct udp_pcb *pcb;
    int id;

    mutex_lock(&mutex);
    pcb = udp_pcb_alloc();
    if (!pcb) {
        errorf("udp_pcb_alloc() failure");
        mutex_unlock(&mutex);
        return -1;
    }
    id = udp_pcb_id(pcb);
    mutex_unlock(&mutex);
    return id;
}

int
udp_close(int id)
{
    struct udp_pcb *pcb;

    mutex_lock(&mutex);
    pcb = udp_pcb_get(id);
    if (!pcb) {
        errorf("pcb not found, id=%d", id);
        mutex_unlock(&mutex);
        return -1;
    }
    udp_pcb_release(pcb);
    mutex_unlock(&mutex);
    return 0;
}

int
udp_bind(int id, struct ip_endpoint *local)
{
    struct udp_pcb *pcb, *exist;
    char ep1[IP_ENDPOINT_STR_LEN];
    char ep2[IP_ENDPOINT_STR_LEN];

    mutex_lock(&mutex);
    pcb = udp_pcb_get(id);
    if (!pcb) {
        errorf("pcb not found, id=%d", id);
        mutex_unlock(&mutex);
        return -1;
    }
    exist = udp_pcb_select(local->addr, local->port);
    if (exist) {
        errorf("already in use, id=%d, want=%s, exist=%s",
            id, ip_endpoint_ntop(local, ep1, sizeof(ep1)), ip_endpoint_ntop(&exist->local, ep2, sizeof(ep2)));
        mutex_unlock(&mutex);
        return -1;
    }
    pcb->local = *local;
    debugf("bound, id=%d, local=%s", id, ip_endpoint_ntop(&pcb->local, ep1, sizeof(ep1)));
    mutex_unlock(&mutex);
    return 0;
}

ssize_t
udp_sendto(int id, uint8_t *data, size_t len, struct ip_endpoint *foreign)
{
    struct udp_pcb *pcb;
    struct ip_endpoint local;
    struct ip_iface *iface;
    struct ip6_iface *iface6;
    char addr1[IP_ADDR_STR_LEN], addr2[IPV6_ADDR_STR_LEN];
    uint32_t p;

    mutex_lock(&mutex);
    pcb = udp_pcb_get(id);
    if (!pcb) {
        errorf("pcb not found, id=%d", id);
        mutex_unlock(&mutex);
        return -1;
    }
    local.addr = pcb->local.addr;
    switch (foreign->addr.family) {
    case AF_INET:
        if (local.addr.s_addr4 == IP_ADDR_ANY) {
            iface = ip_route_get_iface(foreign->addr.s_addr4);
            if (!iface) {
                errorf("iface not found that can reach foreign address, addr=%s",
                    ip_addr_ntop(foreign->addr.s_addr4, addr1, sizeof(addr1)));
                mutex_unlock(&mutex);
                return -1;
            }
            local.addr.s_addr4 = iface->unicast;
            debugf("select local address, addr=%s", ip_addr_ntop(local.addr.s_addr4, addr1, sizeof(addr1)));
        }
        if (!pcb->local.port) {
            for (p = UDP_SOURCE_PORT_MIN; p <= UDP_SOURCE_PORT_MAX; p++) {
                if (!udp_pcb_select(local.addr, hton16(p))) {
                    pcb->local.port = hton16(p);
                    debugf("dinamic assign local port, port=%d", p);
                    break;
                }
            }
            if (!pcb->local.port) {
                warnf("failed to dinamic assign local port, addr=%s", ip_addr_ntop(local.addr.s_addr4, addr1, sizeof(addr1)));
                mutex_unlock(&mutex);
                return -1;
            }
        }
        local.port = pcb->local.port;
        local.addr.family = AF_INET;
        mutex_unlock(&mutex);
        return udp_output(&local, foreign, data, len);
    case AF_INET6:
        if (IPV6_ADDR_EQUAL(&local.addr.s_addr6, &IPV6_UNSPECIFIED_ADDR)) {
            // TODO: ソースアドレス選択
            iface6 = ip6_route_get_iface(foreign->addr.s_addr6);
            if (!iface6) {
                errorf("iface not found that can reach foreign address, addr=%s",
                    ip6_addr_ntop(foreign->addr.s_addr6, addr2, sizeof(addr2)));
                mutex_unlock(&mutex);
                return -1;
            }
            local.addr.s_addr6 = iface6->ip6_addr.addr;
            debugf("select local address, addr=%s", ip6_addr_ntop(local.addr.s_addr6, addr2, sizeof(addr2)));
        }
        if (!pcb->local.port) {
            for (p = UDP_SOURCE_PORT_MIN; p <= UDP_SOURCE_PORT_MAX; p++) {
                if (!udp_pcb_select(local.addr, hton16(p))) {
                    pcb->local.port = hton16(p);
                    debugf("dinamic assign local port, port=%d", p);
                    break;
                }
            }
            if (!pcb->local.port) {
                warnf("failed to dinamic assign local port, addr=%s", ip6_addr_ntop(local.addr.s_addr6, addr2, sizeof(addr2)));
                mutex_unlock(&mutex);
                return -1;
            }
        }
        local.port = pcb->local.port;
        local.addr.family = AF_INET6;
        mutex_unlock(&mutex);
        return udp6_output(&local, foreign, data, len);
    default:
        errorf("not supported address family: %ld", local.addr.family);
        return -1;
    }
}

ssize_t
udp_recvfrom(int id, uint8_t *buf, size_t size, struct ip_endpoint *foreign)
{
    struct udp_pcb *pcb;
    struct udp_queue_entry *entry;
    ssize_t len;

    mutex_lock(&mutex);
    pcb = udp_pcb_get(id);
    if (!pcb) {
        errorf("pcb not found, id=%d", id);
        mutex_unlock(&mutex);
        return -1;
    }
    while (!(entry = queue_pop(&pcb->queue))) {
        if (sched_sleep(&pcb->ctx, &mutex, NULL) == -1) {
            debugf("interrupted");
            mutex_unlock(&mutex);
            errno = EINTR;
            return -1;
        }
        if (pcb->state == UDP_PCB_STATE_CLOSING) {
            debugf("closed");
            udp_pcb_release(pcb);
            mutex_unlock(&mutex);
            return -1;
        }
    }
    mutex_unlock(&mutex);
    if (foreign) {
        *foreign = entry->foreign;
    }
    len = MIN(size, entry->len); /* truncate */
    memcpy(buf, entry + 1, len);
    memory_free(entry);
    return len;
}
