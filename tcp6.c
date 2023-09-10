#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/time.h>

#include "platform.h"

#include "util.h"
#include "net.h"
#include "ip6.h"
#include "tcp.h"

struct tcp6_pcb {
    int state;
    //int mode; /* user command mode */
    struct ip6_endpoint local;
    struct ip6_endpoint foreign;
    struct {
        uint32_t nxt;
        uint32_t una;
        uint16_t wnd;
        uint16_t up;
        uint32_t wl1;
        uint32_t wl2;
    } snd;
    uint32_t iss;
    struct {
        uint32_t nxt;
        uint16_t wnd;
        uint16_t up;
    } rcv;
    uint32_t irs;
    uint16_t mtu;
    uint16_t mss;
    uint8_t buf[65535]; /* receive buffer */
    struct sched_ctx ctx;
    struct queue_head queue; /* retransmit queue */
    struct timeval tw_timer;
    //struct tcp_pcb *parent;
    //struct queue_head backlog;
};

static mutex_t mutex = MUTEX_INITIALIZER;
static struct tcp6_pcb pcbs[TCP_PCB_SIZE];

static ssize_t
tcp6_output_segment(uint32_t seq, uint32_t ack, uint8_t flg, uint16_t wnd, uint8_t *data, size_t len, struct ip6_endpoint *local, struct ip6_endpoint *foreign);;

/*
 * TCP Protocol Control Block (PCB)
 *
 * NOTE: TCP PCB functions must be called after mutex locked
 */

static struct tcp6_pcb *
tcp6_pcb_alloc(void)
{
    struct tcp6_pcb *pcb;

    for (pcb = pcbs; pcb < tailof(pcbs); pcb++) {
        if (pcb->state == TCP_PCB_STATE_FREE) {
            pcb->state = TCP_PCB_STATE_CLOSED;
            sched_ctx_init(&pcb->ctx);
            return pcb;
        }
    }
    return NULL;
}

static void
tcp6_pcb_release(struct tcp6_pcb *pcb)
{
    char ep1[IPV6_ENDPOINT_STR_LEN];
    char ep2[IPV6_ENDPOINT_STR_LEN];

    if (sched_ctx_destroy(&pcb->ctx) == -1) {
        sched_wakeup(&pcb->ctx);
        return;
    }
    debugf("released, local=%s, foreign=%s",
        ip6_endpoint_ntop(&pcb->local, ep1, sizeof(ep1)), ip6_endpoint_ntop(&pcb->foreign, ep2, sizeof(ep2)));
    memset(pcb, 0, sizeof(*pcb));
}

static struct tcp6_pcb *
tcp6_pcb_select(struct ip6_endpoint *local, struct ip6_endpoint *foreign)
{
    struct tcp6_pcb *pcb, *listen_pcb = NULL;

    for (pcb = pcbs; pcb < tailof(pcbs); pcb++) {
        if ((IPV6_ADDR_EQUAL(&pcb->local.addr, &IPV6_UNSPECIFIED_ADDR) || IPV6_ADDR_EQUAL(&pcb->local.addr, &local->addr)) 
            && pcb->local.port == local->port) {
            if (!foreign) {
                return pcb;
            }
            if (IPV6_ADDR_EQUAL(&pcb->foreign.addr, &foreign->addr) && pcb->foreign.port == foreign->port) {
                return pcb;
            }
            if (pcb->state == TCP_PCB_STATE_LISTEN) {
                if (IPV6_ADDR_EQUAL(&pcb->foreign.addr, &IPV6_UNSPECIFIED_ADDR) && pcb->foreign.port == 0) {
                    /* LISTENed with wildcard foreign address/port */
                    listen_pcb = pcb;
                }
            }
        }
    }
    return listen_pcb;
}

static struct tcp6_pcb *
tcp6_pcb_get(int id)
{
    struct tcp6_pcb *pcb;

    if (id < 0 || id >= (int)countof(pcbs)) {
        /* out of range */
        return NULL;
    }
    pcb = &pcbs[id];
    if (pcb->state == TCP_PCB_STATE_FREE) {
        return NULL;
    }
    return pcb;
}

static int
tcp6_pcb_id(struct tcp6_pcb *pcb)
{
    return indexof(pcbs, pcb);
}

/*
 * TCP Retransmit
 *
 * NOTE: TCP Retransmit functions must be called after mutex locked
 */

static int
tcp6_retransmit_queue_add(struct tcp6_pcb *pcb, uint32_t seq, uint8_t flg, uint8_t *data, size_t len)
{
    struct tcp_queue_entry *entry;

    entry = memory_alloc(sizeof(*entry) + len);
    if (!entry) {
        errorf("memory_alloc() failure");
        return -1;
    }
    entry->rto = TCP_DEFAULT_RTO;
    entry->seq = seq;
    entry->flg = flg;
    entry->len = len;
    memcpy(entry + 1, data, entry->len);
    gettimeofday(&entry->first, NULL);
    entry->last = entry->first;
    if (!queue_push(&pcb->queue, entry)) {
        errorf("queue_push() failure");
        memory_free(entry);
        return -1;
    }
    return 0;
}

static void
tcp6_retransmit_queue_cleanup(struct tcp6_pcb *pcb)
{
    struct tcp_queue_entry *entry;

    while ((entry = queue_peek(&pcb->queue))) {
        if (entry->seq >= pcb->snd.una) {
            break;
        }
        entry = queue_pop(&pcb->queue);
        debugf("remove, seq=%u, flags=%s, len=%u", entry->seq, tcp_flg_ntoa(entry->flg), entry->len);
        memory_free(entry);
    }
    return;
}

static void
tcp6_retransmit_queue_emit(void *arg, void *data)
{
    struct tcp6_pcb *pcb;
    struct tcp_queue_entry *entry;
    struct timeval now, diff, timeout;

    pcb = (struct tcp6_pcb *)arg;
    entry = (struct tcp_queue_entry *)data;
    gettimeofday(&now, NULL);
    timersub(&now, &entry->first, &diff);
    if (diff.tv_sec >= TCP_RETRANSMIT_DEADLINE) {
        pcb->state = TCP_PCB_STATE_CLOSED;
        sched_wakeup(&pcb->ctx);
        return;
    }
    timeout = entry->last;
    timeval_add_usec(&timeout, entry->rto);
    if (timercmp(&now, &timeout, >)) {
        tcp6_output_segment(entry->seq, pcb->rcv.nxt, entry->flg, pcb->rcv.wnd, (uint8_t *)(entry+1), entry->len, &pcb->local, &pcb->foreign);
        entry->last = now;
        entry->rto *= 2;
    }
}

/*
 * TCP6 input/output
 */

static ssize_t
tcp6_output_segment(uint32_t seq, uint32_t ack, uint8_t flg, uint16_t wnd, uint8_t *data, size_t len, struct ip6_endpoint *local, struct ip6_endpoint *foreign)
{
    uint8_t buf[IPV6_PAYLOAD_SIZE_MAX] = {};
    struct tcp_hdr *hdr;
    struct ip6_pseudo_hdr pseudo;
    uint16_t psum;
    uint16_t total;
    char ep1[IPV6_ENDPOINT_STR_LEN];
    char ep2[IPV6_ENDPOINT_STR_LEN];

    hdr = (struct tcp_hdr *)buf;
    hdr->src = local->port;
    hdr->dst = foreign->port;
    hdr->seq = hton32(seq);
    hdr->ack = hton32(ack);
    hdr->off = (sizeof(*hdr) >> 2) << 4;
    hdr->flg = flg;
    hdr->wnd = hton16(wnd);
    hdr->sum = 0;
    hdr->up = 0;
    memcpy(hdr + 1, data, len);
    pseudo.src = local->addr;
    pseudo.dst = foreign->addr;
    pseudo.zero[0] = pseudo.zero[1] = pseudo.zero[2] = 0;
    pseudo.nxt = IPV6_NEXT_TCP;
    total = sizeof(*hdr) + len;
    pseudo.len = hton16(total);
    /* calculate checksum value */
    psum = ~cksum16((uint16_t *)&pseudo, sizeof(pseudo), 0);
    hdr->sum = cksum16((uint16_t *)hdr, total, psum);

    debugf("%s => %s, len=%zu (payload=%zu)",
        ip6_endpoint_ntop(local, ep1, sizeof(ep1)), ip6_endpoint_ntop(foreign, ep2, sizeof(ep2)), total, len);
    tcp_dump((uint8_t *)hdr, total);
    if (ip6_output(IPV6_NEXT_TCP, (uint8_t *)hdr, total, local->addr, foreign->addr) == -1) {
        return -1;
    }
    return len;
}

static ssize_t
tcp6_output(struct tcp6_pcb *pcb, uint8_t flg, uint8_t *data, size_t len)
{
    uint32_t seq;

    seq = pcb->snd.nxt;
    if (TCP_FLG_ISSET(flg, TCP_FLG_SYN)) {
        seq = pcb->iss;
    }
    if (TCP_FLG_ISSET(flg, TCP_FLG_SYN | TCP_FLG_FIN) || len) {
        tcp6_retransmit_queue_add(pcb, seq, flg, data, len);
    }
    return tcp6_output_segment(seq, pcb->rcv.nxt, flg, pcb->rcv.wnd, data, len, &pcb->local, &pcb->foreign);
}

/* rfc793 - section 3.9 [Event Processing > SEGMENT ARRIVES] */
static void
tcp6_segment_arrives(struct tcp_segment_info *seg, uint8_t flags, uint8_t *data, size_t len, struct ip6_endpoint *local, struct ip6_endpoint *foreign)
{
    struct tcp6_pcb *pcb, *new_pcb;
    int acceptable = 0;

    pcb = tcp6_pcb_select(local, foreign);
    if (!pcb || pcb->state == TCP_PCB_STATE_CLOSED) {
        if (TCP_FLG_ISSET(flags, TCP_FLG_RST)) {
            return;
        }
        if (!TCP_FLG_ISSET(flags, TCP_FLG_ACK)) {
            tcp6_output_segment(0, seg->seq + seg->len, TCP_FLG_RST | TCP_FLG_ACK, 0, NULL, 0, local, foreign);
        } else {
            tcp6_output_segment(seg->ack, 0, TCP_FLG_RST, 0, NULL, 0, local, foreign);
        }
        return;
    }
    switch(pcb->state) {
    case TCP_PCB_STATE_LISTEN:
        /*
         * first check for an RST
         */
        if (TCP_FLG_ISSET(flags, TCP_FLG_RST)) {
            return;
        }
        /*
         * second check for an ACK
         */
        if (TCP_FLG_ISSET(flags, TCP_FLG_ACK)) {
            tcp6_output_segment(seg->ack, 0, TCP_FLG_RST, 0, NULL, 0, local, foreign);
            return;
        }
        /*
         * third check for an SYN
         */
        if (TCP_FLG_ISSET(flags, TCP_FLG_SYN)) {
            /* ignore: security/compartment check */
            /* ignore: precedence check */
            /*
            if (pcb->mode == TCP_PCB_MODE_SOCKET) {
                new_pcb = tcp_pcb_alloc();
                if (!new_pcb) {
                    errorf("tcp_pcb_alloc() failure");
                    return;
                }
                new_pcb->mode = TCP_PCB_MODE_SOCKET;
                new_pcb->parent = pcb;
                pcb = new_pcb;
            }
            */
            pcb->local = *local;
            pcb->foreign = *foreign;
            pcb->rcv.wnd = sizeof(pcb->buf);
            pcb->rcv.nxt = seg->seq + 1;
            pcb->irs = seg->seq;
            pcb->iss = random();
            tcp6_output(pcb, TCP_FLG_SYN | TCP_FLG_ACK, NULL, 0);
            pcb->snd.nxt = pcb->iss + 1;
            pcb->snd.una = pcb->iss;
            pcb->state = TCP_PCB_STATE_SYN_RECEIVED;
            /* ignore: Note that any other incoming control or data (combined with SYN) will be processed
                        in the SYN-RECEIVED state, but processing of SYN and ACK  should not be repeated */
            return;
        }
        /*
         * fourth other text or control
         */
        /* drop segment */
        return;
    case TCP_PCB_STATE_SYN_SENT:
        /*
         * first check the ACK bit
         */
        if (TCP_FLG_ISSET(flags, TCP_FLG_ACK)) {
            if (seg->ack <= pcb->iss || seg->ack > pcb->snd.nxt) {
                tcp6_output_segment(seg->ack, 0, TCP_FLG_RST, 0, NULL, 0, local, foreign);
                return;
            }
            if (pcb->snd.una <= seg->ack && seg->ack <= pcb->snd.nxt) {
                acceptable = 1;
            }
        }
        /*
         * second check the RST bit
         */
        if (TCP_FLG_ISSET(flags, TCP_FLG_RST)) {
            if (acceptable) {
                errorf("connection reset");
                pcb->state = TCP_PCB_STATE_CLOSED;
                tcp6_pcb_release(pcb);
            }
            /* drop segment */
            return;
        }
        /*
         * ignore: third check security and precedence
         */
        /*
         * fourth check the SYN bit
         */
        if (TCP_FLG_ISSET(flags, TCP_FLG_SYN)) {
            pcb->rcv.nxt = seg->seq + 1;
            pcb->irs = seg->seq;
            if (acceptable) {
                pcb->snd.una = seg->ack;
                tcp6_retransmit_queue_cleanup(pcb);
            }
            if (pcb->snd.una > pcb->iss) {
                pcb->state = TCP_PCB_STATE_ESTABLISHED;
                tcp6_output(pcb, TCP_FLG_ACK, NULL, 0);
                /* NOTE: not specified in the RFC793, but send window initialization required */
                pcb->snd.wnd = seg->wnd;
                pcb->snd.wl1 = seg->seq;
                pcb->snd.wl2 = seg->ack;
                sched_wakeup(&pcb->ctx);
                /* ignore: continue processing at the sixth step below where the URG bit is checked */
                return;
            } else {
                pcb->state = TCP_PCB_STATE_SYN_RECEIVED;
                tcp6_output(pcb, TCP_FLG_SYN | TCP_FLG_ACK, NULL, 0);
                /* ignore: If there are other controls or text in the segment, queue them for processing after the ESTABLISHED state has been reached */
                return;
            }
        }
        /*
         * fifth, if neither of the SYN or RST bits is set then drop the segment and return
         */
        /* drop segment */
        return;
    }
    /*
     * Otherwise
     */
    /*
     * first check sequence number
     */
    switch (pcb->state) {
    case TCP_PCB_STATE_SYN_RECEIVED:
    case TCP_PCB_STATE_ESTABLISHED:
    case TCP_PCB_STATE_FIN_WAIT1:
    case TCP_PCB_STATE_FIN_WAIT2:
    case TCP_PCB_STATE_CLOSE_WAIT:
    case TCP_PCB_STATE_CLOSING:
    case TCP_PCB_STATE_LAST_ACK:
    case TCP_PCB_STATE_TIME_WAIT:
        if (!seg->len) {
            if (!pcb->rcv.wnd) {
                if (seg->seq == pcb->rcv.nxt) {
                    acceptable = 1;
                }
            } else {
                if (pcb->rcv.nxt <= seg->seq && seg->seq < pcb->rcv.nxt + pcb->rcv.wnd) {
                    acceptable = 1;
                }
            }
        } else {
            if (!pcb->rcv.wnd) {
                /* not acceptable */
            } else {
                if ((pcb->rcv.nxt <= seg->seq && seg->seq < pcb->rcv.nxt + pcb->rcv.wnd) ||
                    (pcb->rcv.nxt <= seg->seq + seg->len - 1 && seg->seq + seg->len - 1 < pcb->rcv.nxt + pcb->rcv.wnd)) {
                    acceptable = 1;
                }
            }
        }
        if (!acceptable) {
            if (!TCP_FLG_ISSET(flags, TCP_FLG_RST)) {
                tcp6_output(pcb, TCP_FLG_ACK, NULL, 0);
            }
            return;
        }
        /*
         * In the following it is assumed that the segment is the idealized
         * segment that begins at RCV.NXT and does not exceed the window.
         * One could tailor actual segments to fit this assumption by
         * trimming off any portions that lie outside the window (including
         * SYN and FIN), and only processing further if the segment then
         * begins at RCV.NXT.  Segments with higher begining sequence
         * numbers may be held for later processing.
         */
    }
}

static void
tcp6_input(const uint8_t *data, size_t len, ip6_addr_t src, ip6_addr_t dst, struct ip6_iface *iface)
{
    struct tcp_hdr *hdr;
    struct ip6_pseudo_hdr pseudo;
    uint16_t psum, hlen;
    char addr1[IPV6_ADDR_STR_LEN];
    char addr2[IPV6_ADDR_STR_LEN];
    struct ip6_endpoint local, foreign;
    struct tcp_segment_info seg;

    if (len < sizeof(*hdr)) {
        errorf("too short");
        return;
    }
    hdr = (struct tcp_hdr *)data;

    /* verify checksum value */
    pseudo.src = src;
    pseudo.dst = dst;
    pseudo.len = hton16(len);
    pseudo.zero[0] = pseudo.zero[1] = pseudo.zero[2] = 0;
    pseudo.nxt = IPV6_NEXT_TCP;
    psum = ~cksum16((uint16_t *)&pseudo, sizeof(pseudo), 0);
    if (cksum16((uint16_t *)hdr, len, psum) != 0) {
        errorf("checksum error: sum=0x%04x, verify=0x%04x", ntoh16(hdr->sum), ntoh16(cksum16((uint16_t *)hdr, len, -hdr->sum + psum)));
        return;
    }
    if (IPV6_ADDR_IS_MULTICAST(&src) || IPV6_ADDR_IS_MULTICAST(&dst)) {
        errorf("only supports unicast, src=%s, dst=%s",
            ip6_addr_ntop(src, addr1, sizeof(addr1)), ip6_addr_ntop(dst, addr2, sizeof(addr2)));
        return;
    }
    debugf("[%s]%d => [%s]%d, len=%zu (payload=%zu)",
        ip6_addr_ntop(src, addr1, sizeof(addr1)), ntoh16(hdr->src),
        ip6_addr_ntop(dst, addr2, sizeof(addr2)), ntoh16(hdr->dst),
        len, len - sizeof(*hdr));
    tcp_dump(data, len);

    local.addr = dst;
    local.port = hdr->dst;
    foreign.addr = src;
    foreign.port = hdr->src;
    hlen = (hdr->off >> 4) << 2;
    seg.seq = ntoh32(hdr->seq);
    seg.ack = ntoh32(hdr->ack);
    seg.len = len - hlen;
    if (TCP_FLG_ISSET(hdr->flg, TCP_FLG_SYN)) {
        seg.len++; /* SYN flag consumes one sequence number */
    }
    if (TCP_FLG_ISSET(hdr->flg, TCP_FLG_FIN)) {
        seg.len++; /* FIN flag consumes one sequence number */
    }
    seg.wnd = ntoh16(hdr->wnd);
    seg.up = ntoh16(hdr->up);
    mutex_lock(&mutex);
    tcp6_segment_arrives(&seg, hdr->flg, (uint8_t *)hdr + hlen, len - hlen, &local, &foreign);
    mutex_unlock(&mutex);
    
    return;
}

static void
tcp6_timer(void)
{
    struct tcp6_pcb *pcb;
    struct timeval now;
    char ep1[IPV6_ENDPOINT_STR_LEN];
    char ep2[IPV6_ENDPOINT_STR_LEN];

    mutex_lock(&mutex);
    gettimeofday(&now, NULL);
    for (pcb = pcbs; pcb < tailof(pcbs); pcb++) {
        if (pcb->state == TCP_PCB_STATE_FREE) {
            continue;
        }
        if (pcb->state == TCP_PCB_STATE_TIME_WAIT) {
            if (timercmp(&now, &pcb->tw_timer, >) != 0) {
                debugf("timewait has elapsed, local=%s, foreign=%s",
                    ip6_endpoint_ntop(&pcb->local, ep1, sizeof(ep1)), ip6_endpoint_ntop(&pcb->foreign, ep2, sizeof(ep2)));
                tcp6_pcb_release(pcb);
                continue;
            }
        }
        queue_foreach(&pcb->queue, tcp6_retransmit_queue_emit, pcb);
    }
    mutex_unlock(&mutex);
}

//static void
//event_handler(void *arg)

int 
tcp6_init(void)
{
    struct timeval interval = {0,100000};

    if (ip6_protocol_register("TCP6", IPV6_NEXT_TCP, tcp6_input) == -1) {
        errorf("ip6_protocol_register() failure");
        return -1;
    }
    if (net_timer_register("TCP6 Timer", interval, tcp6_timer) == -1) {
        errorf("net_timer_register() failure");
        return -1;
    }
    //net_event_subscribe(event_handler, NULL);
    
    return 0;
}

/*
 * TCP User Command (RFC793)
 */

int
tcp6_open_rfc793(struct ip6_endpoint *local, struct ip6_endpoint *foreign, int active)
{
    struct tcp6_pcb *pcb;
    char ep1[IPV6_ENDPOINT_STR_LEN];
    char ep2[IPV6_ENDPOINT_STR_LEN];
    int state, id;

    mutex_lock(&mutex);
    pcb = tcp6_pcb_alloc();
    if (!pcb) {
        errorf("tcp6_pcb_alloc() failure");
        mutex_unlock(&mutex);
        return -1;
    }
    if (active) {
        debugf("active open: local=%s, foreign=%s, connecting...",
            ip6_endpoint_ntop(local, ep1, sizeof(ep1)), ip6_endpoint_ntop(foreign, ep2, sizeof(ep2)));
        pcb->local = *local;
        pcb->foreign = *foreign;
        pcb->rcv.wnd = sizeof(pcb->buf);
        pcb->iss = random();
        if (tcp6_output(pcb, TCP_FLG_SYN, NULL, 0) == -1) {
            errorf("tcp_output() failure");
            pcb->state = TCP_PCB_STATE_CLOSED;
            tcp6_pcb_release(pcb);
            mutex_unlock(&mutex);
            return -1;
        }
        pcb->snd.una = pcb->iss;
        pcb->snd.nxt = pcb->iss + 1;
        pcb->state = TCP_PCB_STATE_SYN_SENT;
    } else {
        debugf("passive open: local=%s, waiting for connection...", ip6_endpoint_ntop(local, ep1, sizeof(ep1)));
        pcb->local = *local;
        if (foreign) {
            pcb->foreign = *foreign;
        }
        pcb->state = TCP_PCB_STATE_LISTEN;
    }
AGAIN:
    state = pcb->state;
    /* waiting for state changed */
    while (pcb->state == state) {
        if (sched_sleep(&pcb->ctx, &mutex, NULL) == -1) {
            debugf("interrupted");
            pcb->state = TCP_PCB_STATE_CLOSED;
            tcp6_pcb_release(pcb);
            mutex_unlock(&mutex);
            errno = EINTR;
            return -1;
        }
    }
    if (pcb->state != TCP_PCB_STATE_ESTABLISHED) {
        if (pcb->state == TCP_PCB_STATE_SYN_RECEIVED) {
            goto AGAIN;
        }
        errorf("open error: %d", pcb->state);
        pcb->state = TCP_PCB_STATE_CLOSED;
        tcp6_pcb_release(pcb);
        mutex_unlock(&mutex);
        return -1;
    }
    id = tcp6_pcb_id(pcb);
    debugf("connection established: local=%s, foreign=%s",
        ip6_endpoint_ntop(&pcb->local, ep1, sizeof(ep1)), ip6_endpoint_ntop(&pcb->foreign, ep2, sizeof(ep2)));
    mutex_unlock(&mutex);
    return id;
}

/*
 * TCP User Command (Socket)
 */



/*
 * TCP User Command (Common)
 */

ssize_t
tcp6_send(int id, uint8_t *data, size_t len)
{
    struct tcp6_pcb *pcb;
    ssize_t sent = 0;
    struct ip6_iface *iface;
    size_t mss, cap, slen;

    mutex_lock(&mutex);
    pcb = tcp6_pcb_get(id);
    if (!pcb) {
        errorf("pcb not found");
        mutex_unlock(&mutex);
        return -1;
    }

RETRY:
    switch (pcb->state) {
    case TCP_PCB_STATE_ESTABLISHED:
        iface = ip6_route_get_iface(pcb->local.addr);
        if (!iface) {
            errorf("iface not found");
            mutex_unlock(&mutex);
            return -1;
        }
        mss = NET_IFACE(iface)->dev->mtu - (IPV6_HDR_SIZE + sizeof(struct tcp_hdr));
        while (sent < (ssize_t)len) {
            cap = pcb->snd.wnd - (pcb->snd.nxt - pcb->snd.una);
            if (!cap) {
                if (sched_sleep(&pcb->ctx, &mutex, NULL) == -1) {
                    debugf("interrupted");
                    if (!sent) {
                        mutex_unlock(&mutex);
                        errno = EINTR;
                        return -1;
                    }
                    break;
                }
                goto RETRY;
            }
            slen = MIN(MIN(mss, len - sent), cap);
            if (tcp6_output(pcb, TCP_FLG_ACK | TCP_FLG_PSH, data + sent, slen) == -1) {
                errorf("tcp6_output() failure");
                pcb->state = TCP_PCB_STATE_CLOSED;
                tcp6_pcb_release(pcb);
                mutex_unlock(&mutex);
                return -1;
            }
            pcb->snd.nxt += slen;
            sent += slen;
        }
        break;
    default:
        errorf("unknown state '%u'", pcb->state);
        mutex_unlock(&mutex);
        return -1;
    }
    mutex_unlock(&mutex);
    return sent;
}

ssize_t
tcp6_receive(int id, uint8_t *buf, size_t size)
{
    struct tcp6_pcb *pcb;
    size_t remain, len;

    mutex_lock(&mutex);
    pcb = tcp6_pcb_get(id);
    if (!pcb) {
        errorf("pcb not found");
        mutex_unlock(&mutex);
        return -1;
    }

RETRY:
    switch (pcb->state) {
    case TCP_PCB_STATE_ESTABLISHED:
        remain = sizeof(pcb->buf) - pcb->rcv.wnd;
        if (!remain) {
            if (sched_sleep(&pcb->ctx, &mutex, NULL) == -1) {
                debugf("interrupted");
                mutex_unlock(&mutex);
                errno = EINTR;
                return -1;
            }
            goto RETRY;
        }
        break;
    default:
        errorf("unknown state '%u'", pcb->state);
        mutex_unlock(&mutex);
        return -1;
    }
    len = MIN(size, remain);
    memcpy(buf, pcb->buf, len);
    memmove(pcb->buf, pcb->buf + len, remain - len);
    pcb->rcv.wnd += len;
    mutex_unlock(&mutex);
    return len;
}

int
tcp6_close(int id)
{
    struct tcp6_pcb *pcb;

    mutex_lock(&mutex);
    pcb = tcp6_pcb_get(id);
    if (!pcb) {
        errorf("pcb not found");
        mutex_unlock(&mutex);
        return -1;
    }
    tcp6_output(pcb, TCP_FLG_RST, NULL, 0);
    tcp6_pcb_release(pcb);
    mutex_unlock(&mutex);
    return 0;
}