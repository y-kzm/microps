#ifndef ND6_H
#define ND6_H

#include <stdint.h>

#include "net.h"
#include "ip6.h"

#define ND6_RESOLVE_ERROR      -1
#define ND6_RESOLVE_INCOMPLETE  0
#define ND6_RESOLVE_FOUND       1

#define ND6_NA_FLG_ISSET(x, y) ((x & 0xe0000000) & (y) ? 1 : 0)
#define ND6_NA_FLAG_ROUTER      0x80000000
#define ND6_NA_FLAG_SOLICITED	0x40000000
#define ND6_NA_FLAG_OVERRIDE	0x20000000

#define ND6_NA_FLG_ISSET(x, y) ((x & 0xe0000000) & (y) ? 1 : 0)
#define ND6_NA_FLAG_ROUTER      0x80000000
#define ND6_NA_FLAG_SOLICITED	0x40000000
#define ND6_NA_FLAG_OVERRIDE	0x20000000

/* ndp options */
#define ND6_OPT_SOURCE_LINKADDR	    1
#define ND6_OPT_TARGET_LINKADDR	    2
#define ND6_OPT_PREFIX_INFORMATION  3
#define ND6_OPT_REDIRECTED_HEADER   4
#define ND6_OPT_MTU                 5

extern void
nd6_ns_input(const uint8_t *data, size_t len, ip6_addr_t src, ip6_addr_t dst, struct ip6_iface *iface);
extern int
nd6_na_output(const ip6_addr_t target, struct ip6_iface *iface, ip6_addr_t dst);

extern int
nd6_resolve(ip6_addr_t addr, uint8_t *hwaddr, struct ip6_iface *iface);

extern int 
nd6_init(void);

#endif