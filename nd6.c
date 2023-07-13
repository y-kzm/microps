#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "platform.h"

#include "util.h"
#include "net.h"
#include "ether.h"
#include "ip6.h"
#include "icmp6.h"
#include "nd6.h"

static void
nd6_ns_dump(const uint8_t *data, size_t len)
{
    struct nd_neighbor_solicit *msg;
    struct nd_lladdr_opt *opt;
    char lladdr[ETHER_ADDR_STR_LEN];

    // TODO: merge ndp dump
    flockfile(stderr);
    msg = (struct nd_neighbor_solicit *)data;
    opt = (struct nd_lladddr_opt *)msg->options;
    fprintf(stderr, "        type: %u\n", opt->type);
    fprintf(stderr, "         len: %u\n", opt->len);
    fprintf(stderr, "      lladdr: %s\n", ether_addr_ntop(opt->lladdr, lladdr, sizeof(lladdr)));

#ifdef HEXDUMP
    hexdump(stderr, data, len);
#endif
    funlockfile(stderr);
}

void
nd6_ns_input(const uint8_t *data, size_t len, ip6_addr_t src, ip6_addr_t dst, struct ip6_iface *iface)
{

    struct nd_neighbor_solicit *msg;
    struct nd_lladdr_opt *opt;

    if (len < sizeof(*msg)) {
        errorf("too short");
        return;             
    }
    msg = (struct nd_neighbor_solicit *)data;

    if (memcmp(&dst, &IPV6_SOLICITED_NODE_ADDR_PREFIX, IPV6_SOLICITED_NODE_ADDR_PREFIX_LEN / 8)) {
        errorf("bad dstination addr");
        return;
    }
    opt = (struct nd_lladddr_opt *)msg->options;

    debugf("called nd6_ns_input() by %s", iface->iface.dev->name);
    nd6_ns_dump(data, len);

    //nd6_na_output();
}

/*
int
nd6_na_output()
*/