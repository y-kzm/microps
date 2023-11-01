#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <errno.h>

#include "util.h"
#include "net.h"
#include "ip.h"
#include "ip6.h"
#include "slaac.h"
#include "tcp.h"
#include "sock.h"

#include "driver/loopback.h"
#include "driver/ether_tap.h"

/* listen device */
#define ETHER_DEVICE_NAME             "tap0" /* device name */
#define ETHER_DEVICE_HW_ADDR          "00:00:5e:00:53:02" /* MAC address */
#define ETHER_DEVICE_IPV6_ADDR        "2001:db8::2" /* listen address */
#define ETHER_DEVICE_IPV6_PREFIXLEN   64 /* prefix length */
#define IPV6_DEFAULT_GATEWAY          "2001:db8::1" /* gateway address */

static volatile sig_atomic_t terminate;

static void
on_signal(int s)
{
    (void)s;
    terminate = 1;
    net_interrupt();
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

    /* listen device */
    dev = ether_tap_init(ETHER_DEVICE_NAME, ETHER_DEVICE_HW_ADDR);
    if (!dev) {
        errorf("ether_pcap_init() failure");
        return -1;
    }
    iface = ip6_iface_alloc(ETHER_DEVICE_IPV6_ADDR, ETHER_DEVICE_IPV6_PREFIXLEN, SLAAC_DISABLE);
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

    /* running */
    if (net_run() == -1) {
        errorf("net_run() failure");
        return -1;
    }
    return 0;
}

int
main(int argc, char *argv[])
{
    int soc, acc;
    long int port;
    struct sockaddr_in6 local = { .sin6_family=AF_INET6 }, foreign;
    int foreignlen;
    char addr[SOCKADDR_IN6_STR_LEN];
    uint8_t buf[1024];
    char response[1024];
    ssize_t ret;

    /*
     * Parse command line parameters
     */
    switch (argc) {
    case 3:
        if (ip6_addr_pton(argv[argc-2], &local.sin6_addr) == -1) {
            errorf("ip6_addr_pton() failure, addr=%s", optarg);
            return -1;
        }
        /* fall through */
    case 2:
        port = strtol(argv[argc-1], NULL, 10);
        if (port < 0 || port > UINT16_MAX) {
            errorf("invalid port, port=%s", optarg);
            return -1;
        }
        local.sin6_port = hton16(port);
        break;
    default:
        fprintf(stderr, "Usage: %s [addr] port\n", argv[0]);
        return -1;
    }
    /*
     * Setup protocol stack
     */
    if (setup() == -1) {
        errorf("setup() failure");
        return -1;
    }
    /*
     *  Application Code
     */
    soc = sock_open(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (soc == -1) {
        errorf("sock_open() failure");
        return -1;
    }
    if (sock_bind(soc, (struct sockaddr *)&local, sizeof(local)) == -1) {
        errorf("sock_bind() failure");
        return -1;
    }
    if (sock_listen(soc, 1) == -1) {
        errorf("sock_listen() failure");
        return -1;
    }
    foreignlen = sizeof(foreignlen);
    acc = sock_accept(soc, (struct sockaddr *)&foreign, &foreignlen);
    if (acc == -1) {
        errorf("sock_accept() failure");
        return -1;
    }
    infof("connection accepted, foreign=%s", sockaddr_ntop((struct sockaddr *)&foreign, addr, sizeof(addr)));
    while (!terminate) {
        ret = sock_recv(acc, buf, sizeof(buf));
        if (ret == -1) {
            if (errno == EINTR) {
                continue;
            }
            errorf("sock_recv() failure");
            break;
        }
        if (ret == 0) {
            debugf("connection closed");
            break;
        }
        infof("%zu bytes received", ret);
        hexdump(stderr, buf, ret);
        sprintf(response, "HTTP/1.1 200 OK\r\n\r\n<html><head><title>hello</title></head><body>Hello %s</body></html>", 
                sockaddr_ntop((struct sockaddr *)&foreign, addr, sizeof(addr)));
        if (sock_send(acc, response, ret) == -1) {
            errorf("sock_send() failure");
            break;
        }
    }
    sock_close(acc);
    sock_close(soc);
    /*
     * Cleanup protocol stack
     */
    net_shutdown();
    return 0;
}
