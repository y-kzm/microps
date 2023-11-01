#ifndef SLAAC_H
#define SLAAC_H

#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "net.h"

#define SLAAC_DISABLE   0
#define SLAAC_ENABLE    1
#define SLAAC_DONE      2

extern int
slaac_ra_input(const uint8_t *data, size_t len, ip6_addr_t src, ip6_addr_t dst, struct ip6_iface *iface);
extern int
slaac_run(struct ip6_iface *iface);

#endif