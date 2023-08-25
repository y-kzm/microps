#ifndef SLAAC_H
#define SLAAC_H

#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "net.h"

extern struct ip6_iface *
slaac_iface_alloc(struct net_device *dev);

#endif