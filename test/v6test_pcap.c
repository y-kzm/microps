#include <stdio.h>
#include <stdint.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>

#include "util.h"
#include "net.h"
#include "ip6.h"
#include "icmp6.h"

#include "driver/null.h"
#include "driver/loopback.h"
#include "driver/ether_pcap.h"

#include "test.h"

static volatile sig_atomic_t terminate;

static void
on_signal(int s)
{
    (void)s;
    terminate = 1;
}

int
main(int argc, char *argv[])
{
    int opt, noop = 0;
    struct net_device *dev;
    struct ip6_iface *iface;
    ip6_addr_t src = IPV6_UNSPECIFIED_ADDR, dst;
    uint16_t id, seq = 0;
    //size_t offset = IPV6_HDR_SIZE + ICMPV6_HDR_SIZE;

    /*
     * Parse command line parameters
     */
    while ((opt = getopt(argc, argv, "n")) != -1) {
        switch (opt) {
        case 'n':
            noop = 1;
            break;
        default:
            fprintf(stderr, "Usage: %s [-n] [src] dst\n", argv[0]);
            return -1;
        }
    }
    switch (argc - optind) {
    case 2:
        if (ip6_addr_pton(argv[optind], &src) == -1) {
            errorf("ip6_addr_pton() failure, addr=%s", argv[optind]);
            return -1;
        }
        optind++;
        /* fall through */
    case 1:
        if (ip6_addr_pton(argv[optind], &dst) == -1) {
            errorf("ip6_addr_pton() failure, addr=%s", argv[optind]);
            return -1;
        }
        optind++;
        break;
    case 0:
        if (noop) {
            break;
        }
        /* fall through */
    default:
        fprintf(stderr, "Usage: %s [-n] [src] dst\n", argv[0]);
        return -1;
    }
    /*
     * Setup protocol stack
     */
    signal(SIGINT, on_signal);
    if (net_init() == -1) {
        errorf("net_init() failure");
        return -1;
    }
    dev = null_init();
    if (!dev) {
        errorf("null_init() failure");
        return -1;
    }
    dev = loopback_init();
    if (!dev) {
        errorf("loopback_init() failure");
        return -1;
    }
    iface = ip6_iface_alloc(LOOPBACK_IPV6_ADDR, LOOPBACK_IPV6_NETMASK);
    if (!iface) {
        errorf("ip6_iface_alloc() failure");
        return -1;
    }
    if (ip6_iface_register(dev, iface) == -1) {
        errorf("ip6_iface_register() failure");
        return -1;
    }
    dev = ether_pcap_init(ETHER_PCAP_NAME, ETHER_PCAP_HW_ADDR);
    if (!dev) {
        errorf("ether_pcap_init() failure");
        return -1;
    }
    iface = ip6_iface_alloc(ETHER_PCAP_IPV6_ADDR, ETHER_PCAP_IPV6_NETMASK);
    if (!iface) {
        errorf("ip6_iface_alloc() failure");
        return -1;
    }
    if (ip6_iface_register(dev, iface) == -1) {
        errorf("ip6_iface_register() failure");
        return -1;
    }
    if (ip6_route_set_default_gateway(iface, IPV6_DEFAULT_GATEWAY) == -1) {
        errorf("ip6_route_set_default_gateway() failure");
        return -1;
    }
    if (net_run() == -1) {
        errorf("net_run() failure");
        return -1;
    }
    /*
     * Test Code
     */
    id = getpid() % UINT16_MAX;
    while (!terminate) {
        if (!noop) {
            debugf("########## Send Echo Request !!! ##########");
            if (icmp6_output(ICMPV6_TYPE_ECHO_REQUEST, 0, hton32(id << 16 | ++seq), echo_data, sizeof(echo_data), src, dst) == -1) {
                errorf("icmpv6_output() failure");
                break;
            }
        }
        sleep(1);
    }
    /*
     * Cleanup protocol stack
     */
    net_shutdown();
    return 0;
}
