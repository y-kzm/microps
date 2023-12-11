#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>

#include "util.h"
#include "net.h"
#include "ip.h"
#include "ip6.h"
#include "slaac.h"

#include "driver/loopback.h"
#include "driver/ether_pcap.h"

#include "app/config.h"

static volatile sig_atomic_t terminate;

static void
on_signal(int s)
{
    (void)s;
    terminate = 1;
    net_interrupt();
    close(0);
}

static int
setup(void)
{
    struct net_device *dev;
    struct ip6_iface *iface;
    int i = 0;

    signal(SIGINT, on_signal);
    if (net_init() == -1) {
        errorf("net_init() failure");
        return -1;
    }

    /* loopback device */
    dev = loopback_init();
    if (!dev) {
        errorf("loopback_init() failure");
        return -1;
    }
    iface = ip6_iface_alloc(LOOPBACK_IPV6_ADDR, LOOPBACK_IPV6_PREFIXLEN, SLAAC_DISABLE);
    if (!iface) {
        errorf("ip6_iface_alloc() failure");
        return -1;
    }
    if (ip6_iface_register(dev, iface) == -1) {
        errorf("ip6_iface_register() failure");
        return -1;
    }

    /* devices */
    while (i < ETHER_DEVICES_NUM) {
        dev = ether_pcap_init(ETHER_DEVICES_NAME[i], ETHER_DEVICES_HW_ADDR[i]);
        if (!dev) {
            errorf("ether_pcap_init() failure");
            return -1;
        }
        iface = ip6_iface_alloc(ETHER_DEVICES_IPV6_ADDR[i], ETHER_DEVICES_IPV6_PREFIXLEN[i], SLAAC_DISABLE);
        if (!iface) {
            errorf("ip6_iface_alloc() failure");
            return -1;
        }
        if (ip6_iface_register(dev, iface) == -1) {
            errorf("ip6_iface_register() failure");
            return -1;
        }
        i++;
    }
    if (ip6_route_set_default_gateway(iface, IPV6_DEFAULT_GATEWAY) == -1) {
        errorf("ip6_route_set_default_gateway() failure");
        return -1;
    }

    /* runnig */
    if (net_run() == -1) {
        errorf("net_run() failure");
        return -1;
    }
    return 0;
}

int
main(int argc, char *argv[])
{
    /*
     * Setup protocol stack
     */
    if (setup() == -1) {
        errorf("setup() failure");
        return -1;
    }
    while (!terminate) {
        sleep(1);
    }
    /*
     * Cleanup protocol stack
     */
    net_shutdown();
    return 0;
}
