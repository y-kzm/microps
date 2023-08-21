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

struct udp6_pcb {
    int state;
    struct ip6_endpoint local;
    struct queue_head queue; /* receive queue */
    int wc; /* wait count */
    //struct sched_ctx ctx;
};

/* NOTE: the data follows immediately after the structure */
struct udp6_queue_entry {
    struct ip6_endpoint foreign;
    uint16_t len;
    uint8_t data[];
};

static mutex_t mutex = MUTEX_INITIALIZER;
static struct udp6_pcb pcbs[UDP_PCB_SIZE];

/*
 * UDP Protocol Control Block (PCB)
 *
 * NOTE: UDP PCB functions must be called after mutex locked
 */

static struct udp6_pcb *
udp6_pcb_alloc(void)
{
    struct udp6_pcb *pcb;

    for (pcb = pcbs; pcb < tailof(pcbs); pcb++) {
        if (pcb->state == UDP_PCB_STATE_FREE) {
            pcb->state = UDP_PCB_STATE_OPEN;
            //sched_ctx_init(&pcb->ctx);
            return pcb;
        }
    }
    return NULL;
}

static void
udp6_pcb_release(struct udp6_pcb *pcb)
{
    struct queue_entry *entry;

    pcb->state = UDP_PCB_STATE_CLOSING;
    //if (sched_ctx_destroy(&pcb->ctx) == -1) {
    //    sched_wakeup(&pcb->ctx);
    //    return;
    //}
    if (pcb->wc) {
        pcb->state = UDP_PCB_STATE_CLOSING;
        return;
    }
    pcb->state = UDP_PCB_STATE_FREE;
    pcb->local.addr = IPV6_UNSPECIFIED_ADDR;
    pcb->local.port = 0;
    while ((entry = queue_pop(&pcb->queue)) != NULL) {
        memory_free(entry);
    }
}

static struct udp6_pcb *
udp6_pcb_select(ip6_addr_t addr, uint16_t port)
{
    struct udp6_pcb *pcb;

    for (pcb = pcbs; pcb < tailof(pcbs); pcb++) {
        if (pcb->state == UDP_PCB_STATE_OPEN) {
            if ((IPV6_ADDR_EQUAL(&pcb->local.addr, &IPV6_UNSPECIFIED_ADDR) || 
                IPV6_ADDR_EQUAL(&pcb->local.addr, &addr)) && pcb->local.port == port) {
                    return pcb;
            }
        }
    }
    return NULL;
}

static struct udp6_pcb *
udp6_pcb_get(int id)
{
    struct udp6_pcb *pcb;

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
udp6_pcb_id(struct udp6_pcb *pcb)
{
    return indexof(pcbs, pcb);
}

static void
udp6_input(const uint8_t *data, size_t len, ip6_addr_t src, ip6_addr_t dst, struct ip6_iface *iface)
{
    struct ip6_pseudo_hdr pseudo;
    uint16_t psum = 0;
    struct udp_hdr *hdr;
    char addr1[IPV6_ADDR_STR_LEN];
    char addr2[IPV6_ADDR_STR_LEN];
    struct udp6_pcb *pcb;
    struct udp6_queue_entry *entry;

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
    mutex_lock(&mutex);
    pcb = udp6_pcb_select(dst, hdr->dst);
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
    entry->foreign.addr = src;
    entry->foreign.port = hdr->src;
    entry->len = len - sizeof(*hdr);
    memcpy(entry->data, hdr + 1, entry->len);  // "entry + 1" > "entry->data"
    if (!queue_push(&pcb->queue, entry)) {
        mutex_unlock(&mutex);
        errorf("queue_push() failure");
        return;
    }
    //sched_wakeup(&pcb->ctx);
    mutex_unlock(&mutex);
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

/*
 * UDP User Commands
 */

int
udp6_open(void)
{
    struct udp6_pcb *pcb;
    int id;

    mutex_lock(&mutex);
    pcb = udp6_pcb_alloc();
    if (!pcb) {
        errorf("udp_pcb_alloc() failure");
        mutex_unlock(&mutex);
        return -1;
    }
    id = udp6_pcb_id(pcb);
    mutex_unlock(&mutex);
    return id;
}

int
udp6_close(int id)
{
    struct udp6_pcb *pcb;

    mutex_lock(&mutex);
    pcb = udp6_pcb_get(id);
    if (!pcb) {
        errorf("pcb not found, id=%d", id);
        mutex_unlock(&mutex);
        return -1;
    }
    udp6_pcb_release(pcb);
    mutex_unlock(&mutex);
    return 0;
}

int
udp6_bind(int id, struct ip6_endpoint *local)
{
    struct udp6_pcb *pcb, *exist;
    char ep1[IP_ENDPOINT_STR_LEN];
    char ep2[IP_ENDPOINT_STR_LEN];

    mutex_lock(&mutex);
    pcb = udp6_pcb_get(id);
    if (!pcb) {
        errorf("pcb not found, id=%d", id);
        mutex_unlock(&mutex);
        return -1;
    }
    exist = udp6_pcb_select(local->addr, local->port);
    if (exist) {
        errorf("already in use, id=%d, want=%s, exist=%s",
            id, ip6_endpoint_ntop(local, ep1, sizeof(ep1)), ip6_endpoint_ntop(&exist->local, ep2, sizeof(ep2)));
        mutex_unlock(&mutex);
        return -1;
    }
    pcb->local = *local;
    debugf("bound, id=%d, local=%s", id, ip6_endpoint_ntop(&pcb->local, ep1, sizeof(ep1)));
    mutex_unlock(&mutex);
    return 0;
}

ssize_t
udp6_sendto(int id, uint8_t *data, size_t len, struct ip6_endpoint *foreign)
{
    struct udp6_pcb *pcb;
    struct ip6_endpoint local;
    struct ip6_iface *iface;
    char addr[IPV6_ADDR_STR_LEN];
    uint32_t p;

    mutex_lock(&mutex);
    pcb = udp6_pcb_get(id);
    if (!pcb) {
        errorf("pcb not found, id=%d", id);
        mutex_unlock(&mutex);
        return -1;
    }
    local.addr = pcb->local.addr;
    if (IPV6_ADDR_EQUAL(&local.addr, &IPV6_UNSPECIFIED_ADDR)) {
        iface = ip6_route_get_iface(foreign->addr);
        if (!iface) {
            errorf("iface not found that can reach foreign address, addr=%s",
                ip6_addr_ntop(foreign->addr, addr, sizeof(addr)));
            mutex_unlock(&mutex);
            return -1;
        }
        local.addr = iface->ip6_addr.addr;
        debugf("select local address, addr=%s", ip6_addr_ntop(local.addr, addr, sizeof(addr)));
    }
    if (!pcb->local.port) {
        for (p = UDP_SOURCE_PORT_MIN; p <= UDP_SOURCE_PORT_MAX; p++) {
            if (!udp6_pcb_select(local.addr, hton16(p))) {
                pcb->local.port = hton16(p);
                debugf("dinamic assign local port, port=%d", p);
                break;
            }
        }
        if (!pcb->local.port) {
            debugf("failed to dinamic assign local port, addr=%s", ip6_addr_ntop(local.addr, addr, sizeof(addr)));
            mutex_unlock(&mutex);
            return -1;
        }
    }
    local.port = pcb->local.port;
    mutex_unlock(&mutex);
    return udp6_output(&local, foreign, data, len);
}

ssize_t
udp6_recvfrom(int id, uint8_t *buf, size_t size, struct ip6_endpoint *foreign)
{
    struct udp6_pcb *pcb;
    struct udp6_queue_entry *entry;
    ssize_t len;

    mutex_lock(&mutex);
    pcb = udp6_pcb_get(id);
    if (!pcb) {
        errorf("pcb not found, id=%d", id);
        mutex_unlock(&mutex);
        return -1;
    }
    while (1) {
        entry = queue_pop(&pcb->queue);
        if (entry) {
            break;
        }
        pcb->wc++;
        mutex_unlock(&mutex);
        sleep(1);
        mutex_lock(&mutex);
        pcb->wc--;
        if (pcb->state == UDP_PCB_STATE_CLOSING) {
            debugf("closed");
            udp6_pcb_release(pcb);
            mutex_unlock(&mutex);
            return -1;
        }
    }
    mutex_unlock(&mutex);
    if (foreign) {
        *foreign = entry->foreign;
    }
    len = MIN(size, entry->len); /* truncate */
    memcpy(buf, entry->data, len);
    memory_free(entry);
    return len;

}