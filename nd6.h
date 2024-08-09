#ifndef ND6_H
#define ND6_H

#include <stdint.h>

#include "net.h"
#include "ip6.h"

#define ND6_NA_FLG_ISSET(x, y) ((x & 0xe0000000) & (y) ? 1 : 0)
#define ND6_NA_FLAG_ROUTER		0x80000000
#define ND6_NA_FLAG_SOLICITED	0x40000000
#define ND6_NA_FLAG_OVERRIDE	0x20000000

void
nd6_ns_input(const uint8_t *data, size_t len, ip6_addr_t src, ip6_addr_t dst, struct ip6_iface *iface);

#endif