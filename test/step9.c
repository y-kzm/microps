#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <signal.h>
#include <sys/types.h>
#include <unistd.h>

#include "util.h"
#include "net.h"
#include "ip.h"
#include "icmp.h"
#include "ip6.h"
#include "icmp6.h"

#include "driver/loopback.h"

#include "test.h"

static volatile sig_atomic_t terminate;

static void
on_signal(int s)
{
    (void)s;
    terminate = 1;
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
    iface = ip6_iface_alloc(LOOPBACK_IPV6_ADDR, LOOPBACK_IPV6_NETMASK);
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
    ip6_addr_t src, dst;
    uint16_t id, seq = 0;
    size_t offset = IPV6_HDR_SIZE + ICMPV6_HDR_SIZE;

    if (setup() == -1) {
        errorf("setup() failure");
        return -1;
    }
    ip6_addr_pton(LOOPBACK_IPV6_ADDR, &src);
    ip6_addr_pton(LOOPBACK_IPV6_ADDR, &dst);
    id = getpid() % UINT16_MAX;
    while (!terminate) {
        if (icmp6_output(ICMPV6_TYPE_ECHO, 0, hton32(id << 16 | ++seq), test_data + offset, sizeof(test_data) - offset, src, dst) == -1) {
            errorf("icmp6_output() failure");
            break;
        }
        sleep(1);
    }
    cleanup();
    return 0;
}