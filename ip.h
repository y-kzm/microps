#ifndef IP_H
#define IP_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "net.h"
#include "ip6.h"

#define IP_VERSION_IPV4 4

#define IP_HDR_SIZE_MIN 20
#define IP_HDR_SIZE_MAX 60

#define IP_TOTAL_SIZE_MAX UINT16_MAX /* maximum value of uint16 */
#define IP_PAYLOAD_SIZE_MAX (IP_TOTAL_SIZE_MAX - IP_HDR_SIZE_MIN)

#define IP_ADDR_LEN 4
#define IP_ADDR_STR_LEN 16 /* "ddd.ddd.ddd.ddd\0" */

#define IP_ENDPOINT_STR_LEN (IP_ADDR_STR_LEN + 6) /* xxx.xxx.xxx.xxx:yyyyy\n */

/* see https://www.iana.org/assignments/protocol-numbers/protocol-numbers.txt */
#define PROTOCOL_HOPOPT   0x00
#define PROTOCOL_ICMP     0x01
#define PROTOCOL_TCP      0x06
#define PROTOCOL_UDP      0x11
#define PROTOCOL_IPV6     0x29 
#define PROTOCOL_ROUTING  0x2b 
#define PROTOCOL_FRAGMENT 0x2c 
#define PROTOCOL_ICMPV6   0x3a 
#define PROTOCOL_NONE     0x3b
#define PROTOCOL_DSTOPT   0x3c

typedef uint32_t ip_addr_t;

typedef struct {
    unsigned short family;
    union {
        ip_addr_t __u_addr4;
        ip6_addr_t __u_addr6;
    } __ip_un;
#define s_addr4 __ip_un.__u_addr4
#define s_addr6 __ip_un.__u_addr6
} ip_addr_storage;

struct ip_endpoint {
    ip_addr_storage addr;
    uint16_t port;
};

struct ip_iface {
    struct net_iface iface;
    struct ip_iface *next;
    ip_addr_t unicast;
    ip_addr_t netmask;
    ip_addr_t broadcast;
};

struct ip_pseudo_hdr {
    uint32_t src;
    uint32_t dst;
    uint8_t zero;
    uint8_t protocol;
    uint16_t len;
};

extern const ip_addr_t IP_ADDR_ANY;
extern const ip_addr_t IP_ADDR_BROADCAST;

extern int
ip_addr_pton(const char *p, ip_addr_t *n);
extern char *
ip_addr_ntop(const ip_addr_t n, char *p, size_t size);
extern int
ip_endpoint_pton(unsigned short family, const char *p, struct ip_endpoint *n);
extern char *
ip_endpoint_ntop(const struct ip_endpoint *n, char *p, size_t size);

extern int
ip_route_set_default_gateway(struct ip_iface *iface, const char *gateway);
extern struct ip_iface *
ip_route_get_iface(ip_addr_t dst);

extern struct ip_iface *
ip_iface_alloc(const char *addr, const char *netmask);
extern int
ip_iface_register(struct net_device *dev, struct ip_iface *iface);
extern struct ip_iface *
ip_iface_select(ip_addr_t addr);

extern ssize_t
ip_output(uint8_t protocol, const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst);

extern int
ip_protocol_register(const char *name, uint8_t type, void (*handler)(const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst, struct ip_iface *iface));
extern char *
ip_protocol_name(uint8_t type);

extern int
ip_init(void);

#endif
