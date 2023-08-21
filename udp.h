#ifndef UDP_H
#define UDP_H

#include <stddef.h>
#include <stdint.h>

#include "platform.h"

#include "ip.h"
#include "ip6.h"

#define UDP_PCB_SIZE 16

#define UDP_PCB_STATE_FREE    0
#define UDP_PCB_STATE_OPEN    1
#define UDP_PCB_STATE_CLOSING 2

/* see https://tools.ietf.org/html/rfc6335 */
#define UDP_SOURCE_PORT_MIN 49152
#define UDP_SOURCE_PORT_MAX 65535

struct udp_hdr {
    uint16_t src;
    uint16_t dst;
    uint16_t len;
    uint16_t sum;
};

/* udp.c */
extern void
udp_dump(const uint8_t *data, size_t len);

extern ssize_t
udp_output(struct ip_endpoint *src, struct ip_endpoint *dst, const uint8_t *buf, size_t len);

extern int
udp_init(void);

extern int
udp_open(void);
extern int
udp_bind(int index, struct ip_endpoint *local);
extern ssize_t
udp_sendto(int id, uint8_t *buf, size_t len, struct ip_endpoint *foreign);
extern ssize_t
udp_recvfrom(int id, uint8_t *buf, size_t size, struct ip_endpoint *foreign);
extern int
udp_close(int id);

/* udp6.c */
extern ssize_t
udp6_output(struct ip6_endpoint *src, struct ip6_endpoint *dst, const  uint8_t *data, size_t len);

extern int
udp6_init(void);

extern int
udp6_open(void);
extern int
udp6_bind(int id, struct ip6_endpoint *local);
extern int
udp6_close(int id);
extern ssize_t
udp6_sendto(int id, uint8_t *data, size_t len, struct ip6_endpoint *foreign);
extern ssize_t
udp6_recvfrom(int id, uint8_t *buf, size_t size, struct ip6_endpoint *foreign);

#endif
