#include <stdio.h>
#include <stdint.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <string.h>

#include "util.h"
#include "net.h"
#include "ip6.h"
#include "icmp6.h"
#include "slaac.h"
#include "udp.h"

#include "driver/null.h"
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

int
main(int argc, char *argv[])
{
    int opt, noop = 0;
    struct net_device *dev;
    struct ip6_iface *iface;
    ip6_addr_t src = IPV6_UNSPECIFIED_ADDR, dst;

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

    /* ==================================================================== */
    /* ==================================================================== */
    /* 
     * Setup protocol stack
     */
    // init proto stack
    signal(SIGINT, on_signal);
    if (net_init() == -1) {
        errorf("net_init() failure");
        return -1;
    }
    // init devices
    dev = ether_tap_init(ETHER_TAP_NAME, ETHER_TAP_HW_ADDR);
    if (!dev) {
        errorf("ether_tap_init() failure");
        return -1;
    }
    // start proto stack
    if (net_run() == -1) {
        errorf("net_run() failure");
        return -1;
    }

    // start SLAAC: alloc autoconf-iface, register autoconf-iface
    iface = slaac_run(dev);
    if (!iface) {
        errorf("slaac_init() failure");
        return -1;
    } 
    sleep(3); /* waito for address autoconfiguration */
    /* ==================================================================== */
    /* ==================================================================== */

    /*
     * Test Code: ping
     */
    uint16_t id, seq = 0;
    id = getpid() % UINT16_MAX;
    while (!terminate) {
        if (!noop) {
            debugf("<--------------------------- Send echo request --------------------------->");
            if (icmp6_output(ICMPV6_TYPE_ECHO_REQUEST, 0, hton32(id << 16 | ++seq), echo_data, sizeof(echo_data), src, dst) == -1) {
                errorf("icmpv6_output() failure");
                break;
            }
            debugf("<---------------------------  Eend of loop...  --------------------------->");
        }
        sleep(1);
    }

#ifdef COMMENTOUT
    int soc;
    struct ip6_endpoint foreign;
    uint8_t buf[1024];

    soc = udp6_open();
    if (soc == -1) {
        errorf("udp6_open() failure");
        return -1;
    }
    ip6_endpoint_pton("[2001:db8::1]10007",  &foreign);
    while (!terminate) {
        debugf("<--------------------------- Send udp message --------------------------->");
        if (!fgets((char *)buf, sizeof(buf), stdin)) {
            break;
        }
        if (udp6_sendto(soc, buf, strlen((char *)buf), &foreign) == -1) {
            errorf("udp6_sendto() failure");
            break;
        }
        debugf("<---------------------------  Eend of loop...  --------------------------->");
    }
    udp6_close(soc);
#endif

    /*
     * Cleanup protocol stack
     */
    net_shutdown();
    return 0;
}
