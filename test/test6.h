#ifndef TEST6_H
#define TEST6_H

#include <stdint.h>

#define ETHER_TAP_NAME "tap0"
/* Scope of EUI-48 Documentation Values. see https://tools.ietf.org/html/rfc7042 */
#define ETHER_TAP_HW_ADDR "00:00:5e:00:53:01"
/* Scope of Documentation Address Blocks (TEST-NET-1). see https://tools.ietf.org/html/rfc5731 */
#define LOOPBACK_IPV6_ADDR "::1"
#define LOOPBACK_IPV6_PREFIX_LEN 128
#define ETHER_TAP_IPV6_ADDR "2001:db8::2"
#define ETHER_TAP_IPV6_PREFIX_LEN 64


const uint8_t test_data[] = {
    0x60, 0x0d, 0x03, 0x00,
    0x00, 0x10, 0x3a, 0x40,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x01,
    0x80, 0x00, 0x8c, 0x47,
    0x11, 0x11, 0x00, 0x01,
    0x12, 0x34, 0x56, 0x78,
    0x9a, 0xbc, 0xde, 0xf0,
};

#endif
