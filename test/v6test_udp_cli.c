#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <signal.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>

#include "util.h"
#include "net.h"
#include "ip6.h"
#include "icmp6.h"
#include "udp.h"

#include "driver/loopback.h"
#include "driver/ether_tap.h"

#include "test.h"

static volatile sig_atomic_t terminate;

static void
on_signal(int s)
{
    (void)s;
    terminate = 1;
    close(0); /* close STDIN */
}

static int
setup(void)
{
    struct net_device *dev;
    struct ip6_iface *iface;

    signal(SIGINT, on_signal);
    if (net_init() == -1) {
        errorf("net_init() failure");
        return -1;
    }
    dev = loopback_init();
    if (!dev) {
        errorf("loopback_init() failure");
        return -1;
    }
    iface = ip6_iface_alloc(LOOPBACK_IPV6_ADDR, LOOPBACK_IPV6_PREFIXLEN, 0);
    if (!iface) {
        errorf("ip6_iface_alloc() failure");
        return -1;
    }
    if (ip6_iface_register(dev, iface) == -1) {
        errorf("ip6_iface_register() failure");
        return -1;
    }
    dev = ether_tap_init(ETHER_TAP_NAME, ETHER_TAP_HW_ADDR);
    if (!dev) {
        errorf("ether_tap_init() failure");
        return -1;
    }
    iface = ip6_iface_alloc(ETHER_TAP_IPV6_ADDR, ETHER_TAP_IPV6_PREFIXLEN, 0);
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
    return 0;
}

static void
cleanup(void)
{
    net_shutdown();
}

int
main(int argc, char *argv[])
{
    int soc;
    struct ip6_endpoint foreign;
    uint8_t buf[1024];

    if (setup() == -1) {
        errorf("setup() failure");
        return -1;
    }
    soc = udp6_open();
    if (soc == -1) {
        errorf("udp6_open() failure");
        return -1;
    }
    ip6_endpoint_pton("[2001:db8::1]10007",  &foreign);
    while (!terminate) {
        if (!fgets((char *)buf, sizeof(buf), stdin)) {
            break;
        }
        if (udp6_sendto(soc, buf, strlen((char *)buf), &foreign) == -1) {
            errorf("udp6_sendto() failure");
            break;
        }
    }
    udp6_close(soc);
    cleanup();
    return 0;
}
