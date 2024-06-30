#include <stdio.h>
#include <stdint.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>

#include "util.h"
#include "net.h"
#include "ip6.h"

#include "driver/null.h"
#include "driver/loopback.h"
#include "driver/ether_tap.h"

#include "test6.h"

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
    struct net_device *dev;
    struct ip6_iface *iface;

    /*
     * Setup protocol stack
     */
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

    iface = ip6_iface_alloc(LOOPBACK_IPV6_ADDR, LOOPBACK_IPV6_PREFIX_LEN);
    if (!iface) {
        errorf("ip6_iface_alloc() failure");
        return -1;
    }
    if (ip6_iface_register(dev, iface) == -1) {
        errorf("ip6_iface_register() failure");
        return -1;
    }
    if (net_run() == -1) {
        errorf("net_run() failure");
        return -1;
    }
    /*
     * Test Code
     */
    while (!terminate) {
        if (net_device_output(dev, NET_PROTOCOL_TYPE_IPV6, test_data, sizeof(test_data), NULL) == -1) {
            errorf("net_device_output() failure");
            break;
        }
        sleep(1);
    }
    /*
     * Cleanup protocol stack
     */
    net_shutdown();
    return 0;
}