#ifndef SLAAC_H
#define SLAAC_H

#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "net.h"

extern void
slaac_ra_input(const uint8_t *data, size_t len, ip6_addr_t src, ip6_addr_t dst, struct ip6_iface *iface);
extern struct ip6_iface *
slaac_process_start(struct net_device *dev);

#endif