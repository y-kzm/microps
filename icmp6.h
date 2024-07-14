#ifndef ICMP6_H
#define ICMP6_H

#include <stddef.h>
#include <stdint.h>

#include "ip6.h"

#define ICMPV6_HDR_SIZE 8

extern int
icmp6_init(void);

#endif