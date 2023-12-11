#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "util.h"
#include "net.h"
#include "ether.h"

struct ether_hdr {
    uint8_t dst[ETHER_ADDR_LEN];
    uint8_t src[ETHER_ADDR_LEN];
    uint16_t type;
};

const uint8_t ETHER_ADDR_ANY[ETHER_ADDR_LEN] = {"\x00\x00\x00\x00\x00\x00"};
const uint8_t ETHER_ADDR_BROADCAST[ETHER_ADDR_LEN] = {"\xff\xff\xff\xff\xff\xff"};

int
ether_addr_pton(const char *p, uint8_t *n)
{
    int index;
    char *ep;
    long val;

    if (!p || !n) {
        return -1;
    }
    for (index = 0; index < ETHER_ADDR_LEN; index++) {
        val = strtol(p, &ep, 16);
        if (ep == p || val < 0 || val > 0xff || (index < ETHER_ADDR_LEN - 1 && *ep != ':')) {
            break;
        }
        n[index] = (uint8_t)val;
        p = ep + 1;
    }
    if (index != ETHER_ADDR_LEN || *ep != '\0') {
        return -1;
    }
    return  0;
}

static const char *
ether_type_ntoa(uint16_t type)
{
    switch (ntoh16(type)) {
    case ETHER_TYPE_IP:
        return "IP";
    case ETHER_TYPE_ARP:
        return "ARP";
    case ETHER_TYPE_IPV6:
        return "IPv6";
    }
    return "UNKNOWN";
}

char *
ether_addr_ntop(const uint8_t *n, char *p, size_t size)
{
    if (!n || !p) {
        return NULL;
    }
    snprintf(p, size, "%02x:%02x:%02x:%02x:%02x:%02x", n[0], n[1], n[2], n[3], n[4], n[5]);
    return p;
}

/* Brief: ipv6 addr to mac addr */
static int
ether_addr_create_mcastaddr(const uint8_t *hwaddr)
{
    if (hwaddr[0] == 0x33 && hwaddr[1] == 0x33) {
        return 0;
    }
    return -1;
}

void
ether_addr_create_eui64(const uint8_t *hwaddr, uint8_t *eui64)
{
    eui64[0] = hwaddr[0];
    eui64[1] = hwaddr[1];
    eui64[2] = hwaddr[2];

    eui64[3] = 0xff;
    eui64[4] = 0xff;

    eui64[5] = hwaddr[3];
    eui64[6] = hwaddr[4];
    eui64[7] = hwaddr[5];

    /* invert the 7th bit */
    eui64[0] ^= 0x02;
}

#ifdef ENABLE_HDRDUMP
static void
ether_dump(const uint8_t *frame, size_t flen)
{
    struct ether_hdr *hdr;
    char addr[ETHER_ADDR_STR_LEN];

    hdr = (struct ether_hdr *)frame;
    flockfile(stderr);
    fprintf(stderr, "        src: %s\n", ether_addr_ntop(hdr->src, addr, sizeof(addr)));
    fprintf(stderr, "        dst: %s\n", ether_addr_ntop(hdr->dst, addr, sizeof(addr)));
    fprintf(stderr, "       type: 0x%04x (%s)\n", ntoh16(hdr->type), ether_type_ntoa(hdr->type));
#ifdef ENABLE_HEXDUMP
    hexdump(stderr, frame, flen);
#endif
    funlockfile(stderr);
}
#endif

int
ether_transmit_helper(struct net_device *dev, uint16_t type, const uint8_t *data, size_t len, const void *dst, ssize_t (*callback)(struct net_device *dev, const uint8_t *data, size_t len))
{
    uint8_t frame[ETHER_FRAME_SIZE_MAX] = {};
    struct ether_hdr *hdr;
    size_t flen, pad = 0;
    char addr1[ETHER_ADDR_STR_LEN];
    char addr2[ETHER_ADDR_STR_LEN];

    hdr = (struct ether_hdr *)frame;
    memcpy(hdr->dst, dst, ETHER_ADDR_LEN);
    memcpy(hdr->src, dev->addr, ETHER_ADDR_LEN);
    hdr->type = hton16(type);
    memcpy(hdr + 1, data, len);
    if (len < ETHER_PAYLOAD_SIZE_MIN) {
        pad = ETHER_PAYLOAD_SIZE_MIN - len;
    }
    flen = sizeof(*hdr) + len + pad;
    debugf("%s => %s, dev=%s, type=%s(0x%04x), len=%zu",
        ether_addr_ntop(hdr->src, addr1, sizeof(addr1)), 
        ether_addr_ntop(hdr->dst, addr2, sizeof(addr2)), dev->name, 
        ether_type_ntoa(hdr->type), type, flen);
#ifdef ENABLE_HDRDUMP
    ether_dump(frame, flen);
#endif
    return callback(dev, frame, flen) == (ssize_t)flen ? 0 : -1;
}

int
ether_poll_helper(struct net_device *dev, ssize_t (*callback)(struct net_device *dev, uint8_t *buf, size_t size))
{
    uint8_t frame[ETHER_FRAME_SIZE_MAX];
    ssize_t flen;
    struct ether_hdr *hdr;
    uint16_t type;
    char addr1[ETHER_ADDR_STR_LEN];
    char addr2[ETHER_ADDR_STR_LEN];

    flen = callback(dev, frame, sizeof(frame));
    if (flen < (ssize_t)sizeof(*hdr)) {
        errorf("input data is too short");
        return -1;
    }
    hdr = (struct ether_hdr *)frame;
    if (memcmp(dev->addr, hdr->dst, ETHER_ADDR_LEN) != 0) {
        if (memcmp(ETHER_ADDR_BROADCAST, hdr->dst, ETHER_ADDR_LEN) != 0) {
            if (ether_addr_create_mcastaddr(hdr->dst) != 0) {
                /* for other host */
                debugf("for other host %s", ether_addr_ntop(hdr->dst, addr1, sizeof(addr1)));
                return -1;
            }
        }
    }
    type = ntoh16(hdr->type);
    debugf("%s => %s, dev=%s, type=%s(0x%04x), len=%zu", 
            ether_addr_ntop(hdr->src, addr1, sizeof(addr1)), 
            ether_addr_ntop(hdr->dst, addr2, sizeof(addr2)), dev->name, 
            ether_type_ntoa(hdr->type), type, flen);
#ifdef ENABLE_HDRDUMP
    ether_dump(frame, flen);
#endif
    return net_input_handler(type, (uint8_t *)(hdr + 1), flen - sizeof(*hdr), dev);
}

void
ether_setup_helper(struct net_device *dev)
{
    dev->type = NET_DEVICE_TYPE_ETHERNET;
    dev->mtu = ETHER_PAYLOAD_SIZE_MAX;
    dev->flags = (NET_DEVICE_FLAG_BROADCAST | NET_DEVICE_FLAG_NEED_RESOLVE);
    dev->hlen = ETHER_HDR_SIZE;
    dev->alen = ETHER_ADDR_LEN;
    memcpy(dev->broadcast, ETHER_ADDR_BROADCAST, ETHER_ADDR_LEN);
}