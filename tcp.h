#ifndef TCP_H
#define TCP_H

#include <stdint.h>
#include <sys/types.h>

#include "ip.h"
#include "ip6.h"

#define TCP_STATE_CLOSED       1
#define TCP_STATE_LISTEN       2
#define TCP_STATE_SYN_SENT     3
#define TCP_STATE_SYN_RECEIVED 4
#define TCP_STATE_ESTABLISHED  5
#define TCP_STATE_FIN_WAIT1    6
#define TCP_STATE_FIN_WAIT2    7
#define TCP_STATE_CLOSING      8
#define TCP_STATE_TIME_WAIT    9
#define TCP_STATE_CLOSE_WAIT  10
#define TCP_STATE_LAST_ACK    11

/* transition from tcp.c */
#define TCP_PCB_SIZE 16

#define TCP_FLG_FIN 0x01
#define TCP_FLG_SYN 0x02
#define TCP_FLG_RST 0x04
#define TCP_FLG_PSH 0x08
#define TCP_FLG_ACK 0x10
#define TCP_FLG_URG 0x20

#define TCP_FLG_IS(x, y) ((x & 0x3f) == (y))
#define TCP_FLG_ISSET(x, y) ((x & 0x3f) & (y) ? 1 : 0)

#define TCP_PCB_MODE_RFC793 1
#define TCP_PCB_MODE_SOCKET 2

#define TCP_PCB_STATE_FREE         0
#define TCP_PCB_STATE_CLOSED       1
#define TCP_PCB_STATE_LISTEN       2
#define TCP_PCB_STATE_SYN_SENT     3
#define TCP_PCB_STATE_SYN_RECEIVED 4
#define TCP_PCB_STATE_ESTABLISHED  5
#define TCP_PCB_STATE_FIN_WAIT1    6
#define TCP_PCB_STATE_FIN_WAIT2    7
#define TCP_PCB_STATE_CLOSING      8
#define TCP_PCB_STATE_TIME_WAIT    9
#define TCP_PCB_STATE_CLOSE_WAIT  10
#define TCP_PCB_STATE_LAST_ACK    11

#define TCP_DEFAULT_RTO 200000 /* micro seconds */
#define TCP_RETRANSMIT_DEADLINE 12 /* seconds */
#define TCP_TIMEWAIT_SEC 30 /* substitute for 2MSL */

#define TCP_SOURCE_PORT_MIN 49152
#define TCP_SOURCE_PORT_MAX 65535

struct tcp_segment_info {
    uint32_t seq;
    uint32_t ack;
    uint16_t len;
    uint16_t wnd;
    uint16_t up;
};

struct tcp_hdr {
    uint16_t src;
    uint16_t dst;
    uint32_t seq;
    uint32_t ack;
    uint8_t off;
    uint8_t flg;
    uint16_t wnd;
    uint16_t sum;
    uint16_t up;
};

struct tcp_queue_entry {
    struct timeval first;
    struct timeval last;
    unsigned int rto; /* micro seconds */
    uint32_t seq;
    uint8_t flg;
    size_t len;
};

/* tcp.c */
extern void
tcp_dump(const uint8_t *data, size_t len);
extern char *
tcp_flg_ntoa(uint8_t flg);

extern int
tcp_init(void);

extern int
tcp_open_rfc793(struct ip_endpoint *local, struct ip_endpoint *foreign, int active);
extern int
tcp_state(int id);
extern int
tcp_close(int id);
extern ssize_t
tcp_send(int id, uint8_t *data, size_t len);
extern ssize_t
tcp_receive(int id, uint8_t *buf, size_t size);

extern int
tcp_open(void);
extern int
tcp_bind(int id, struct ip_endpoint *local);
extern int
tcp_connect(int id, struct ip_endpoint *foreign);
extern int
tcp_listen(int id, int backlog);
extern int
tcp_accept(int id, struct ip_endpoint *foreign);

/* tcp6.c */
extern int 
tcp6_init(void);

extern int
tcp6_open_rfc793(struct ip6_endpoint *local, struct ip6_endpoint *foreign, int active);

extern int
tcp6_close(int id);
extern ssize_t
tcp6_send(int id, uint8_t *data, size_t len);
extern ssize_t
tcp6_receive(int id, uint8_t *buf, size_t size);

#endif
