#ifndef ICMP6_H
#define ICMP6_H

#include <stddef.h>
#include <stdint.h>

#include "ip6.h"

void
icmp6_input(const uint8_t *data, size_t len, ip6_addr_t src, ip6_addr_t dst, struct ip6_iface *iface);

int
icmp6_init(void);

#endif