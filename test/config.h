#ifndef TEST_H
#define TEST_H

/* loopback */
#define LOOPBACK_IP_ADDR            "127.0.0.1"
#define LOOPBACK_NETMASK            "255.0.0.0"
#define LOOPBACK_IPV6_ADDR          "::1"
#define LOOPBACK_IPV6_PREFIXLEN     128

/* device1 */
#define ETHER_DEVICE1_NAME             "router-host1"
#define ETHER_DEVICE1_HW_ADDR          "00:00:5e:00:53:01"
#define ETHER_DEVICE1_IPV6_ADDR        "2001:db8:1::1"
#define ETHER_DEVICE1_IPV6_PREFIXLEN   64
/* device2 */
#define ETHER_DEVICE2_NAME             "router-host2"
#define ETHER_DEVICE2_HW_ADDR          "00:00:5e:00:53:02"
#define ETHER_DEVICE2_IPV6_ADDR        "2001:db8:2::1"
#define ETHER_DEVICE2_IPV6_PREFIXLEN   64

#endif
