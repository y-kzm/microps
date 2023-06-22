#ifndef TEST_H
#define TEST_H

#include <stdint.h>

#define LOOPBACK_IP_ADDR "127.0.0.1"
#define LOOPBACK_NETMASK "255.0.0.0"

#define LOOPBACK_IPV6_ADDR "::1"
//#define LOOPBACK_IPV6_ADDR "fd00:123::1"
#define LOOPBACK_IPv6_NETMASK "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"

#define ETHER_TAP_NAME    "tap0"
#define ETHER_TAP_HW_ADDR "00:00:5e:00:53:01"
#define ETHER_TAP_IP_ADDR "192.0.2.2"
#define ETHER_TAP_NETMASK "255.255.255.0"

#define DEFAULT_GATEWAY "192.0.2.1"

/*
const uint8_t test_data[] = {
    0x45, 0x00, 0x00, 0x30,
    0x00, 0x80, 0x00, 0x00,
    0xff, 0x01, 0xbd, 0x4a,
    0x7f, 0x00, 0x00, 0x01,
    0x7f, 0x00, 0x00, 0x01,
    0x08, 0x00, 0x35, 0x64,
    0x00, 0x80, 0x00, 0x01,
    0x31, 0x32, 0x33, 0x34,
    0x35, 0x36, 0x37, 0x38,
    0x39, 0x30, 0x21, 0x40,
    0x23, 0x24, 0x25, 0x5e,
    0x26, 0x2a, 0x28, 0x29
};
*/

/*
const uint8_t test_data[] = {
    0x60, 0x00, 0x00, 0x00, 
    0x00, 0x20, 0x3a, 0xff, 
    0xfd, 0x00, 0x01, 0x23, 
    0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x02, 
    0xff, 0x02, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x01, 
    0xff, 0x00, 0x00, 0x01,
    0x87, 0x00, 0xa2, 0xe4, 
    0x00, 0x00, 0x00, 0x00, 
    0xfd, 0x00, 0x01, 0x23, 
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x01, 
    0x01, 0x01, 0x90, 0x96, 
    0xf3, 0x4a, 0x56, 0x8d
}; 
*/


const uint8_t test_data[] = {
    0x60, 0x09, 0x02, 0x00, 
    0x00, 0x10, 0x3a, 0x40, 
    0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x01, 
    0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x01,
    0x80, 0x00, 0x9f, 0xac, 
    0xf5, 0xe7, 0x00, 0x00, 
    0x64, 0x94, 0x75, 0x4c, 
    0x00, 0x04, 0x10, 0x3a
};



#endif
