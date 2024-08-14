#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sys/time.h>

#include "platform.h"

#include "util.h"
#include "net.h"
#include "ether.h"
#include "nd6.h"
#include "ip6.h"
#include "icmp6.h"

#define ND6_CACHE_SIZE    64
#define ND6_CACHE_TIMEOUT 30 /* seconds */

#define ND6_STATE_NONE        0
#define ND6_STATE_INCOMPLETE  1
#define ND6_STATE_REACHABLE   2
#define ND6_STATE_STALE       3
#define ND6_STATE_DELAY       4
#define ND6_STATE_PROBE       5
#define ND6_STATE_PERMANENT   6

struct nd6_cache_ops {
    int (*solicit)(struct ip6_iface *iface, const ip6_addr_t target);
};

struct nd6_cache {
    struct net_device *dev;
    uint8_t state; 
    ip6_addr_t addr;
    uint8_t hwaddr[ETHER_ADDR_LEN];
    bool router;
    struct timeval timestamp;
    time_t timeout;
    struct nd6_cache_ops *ops;
};

static mutex_t mutex = MUTEX_INITIALIZER;
static struct nd6_cache caches[ND6_CACHE_SIZE];

struct pseudo6_hdr {
    ip6_addr_t src;
    ip6_addr_t dst;
    uint32_t len;
    uint8_t zero[3];
    uint8_t next;
};

struct nd6_ns_hdr {
	uint8_t	type;
	uint8_t	code;
	uint16_t sum;
    uint32_t reserved;
    ip6_addr_t target;
    uint8_t data[]; // options
};

struct nd6_na_hdr {
	uint8_t	type;
	uint8_t	code;
	uint16_t sum;
    uint32_t flag;
    ip6_addr_t target;
    uint8_t data[]; // options
};

struct nd6_option_tlv {
	u_int8_t type;
	u_int8_t len;
    uint8_t data[]; // options
};

struct nd6_option_lladdr {
    uint8_t hwaddr[ETHER_ADDR_LEN];
};

// static char *
// nd6_state_ntoa(uint8_t state) {
//     switch (state) {
//     case ND6_STATE_NONE:
//         return "NONE";
//     case ND6_STATE_INCOMPLETE:
//         return "INCOMPLETE";
//     case ND6_STATE_REACHABLE:
//         return "REACHABLE";
//     case ND6_STATE_STALE:
//         return "STALE";
//     case ND6_STATE_DELAY:
//         return "DELAY";
//     case ND6_STATE_PROBE:
//         return "PROBE";
//     case ND6_STATE_PERMANENT:
//         return "PERMANENT";
//     }
//     return "UNKNOWN";
// }

static struct nd6_cache *
nd6_cache_alloc() 
{
    struct nd6_cache *entry, *oldest = NULL;

    for (entry = caches; entry < tailof(caches); entry++) {
        if (entry->state == ND6_STATE_NONE) {
            return entry;
        }
        if (!oldest || timercmp(&oldest->timestamp, &entry->timestamp, >)) {
            oldest = entry;
        }
    }
    return oldest;
}

static struct nd6_cache *
nd6_cache_select(ip6_addr_t addr)
{
    struct nd6_cache *entry;

    for (entry = caches; entry < tailof(caches); entry++) {
        if (entry->state != ND6_STATE_NONE && IPV6_ADDR_COMP(&entry->addr, &addr, IPV6_ADDR_LEN)) {
            return entry;
        }
    }
    return NULL;
}

static struct nd6_cache *
nd6_cache_update(ip6_addr_t addr, uint8_t *hwaad)
{
    struct nd6_cache *cache;
    char addr1[IPV6_ADDR_STR_LEN];
    char addr2[ETHER_ADDR_STR_LEN];

    cache = nd6_cache_select(addr);
    if (!cache) {
        /* not found */
        return NULL;
    }
    cache->state = ND6_STATE_REACHABLE;
    memcpy(cache->hwaddr, hwaad, ETHER_ADDR_LEN);
    gettimeofday(&cache->timestamp, NULL);
    debugf("UPDATE: addr=%s, hwaddr=%s", 
        ip6_addr_ntop(addr, addr1, sizeof(addr1)), ether_addr_ntop(hwaad, addr2, sizeof(addr2)));
    return cache; 
}

static struct nd6_cache *
nd6_cache_insert(ip6_addr_t addr, const uint8_t *hwaddr, struct net_iface *iface)
{
    struct nd6_cache *cache;
    char addr1[IPV6_ADDR_STR_LEN];
    char addr2[ETHER_ADDR_STR_LEN];

    cache = nd6_cache_alloc();
    if (!cache) {
        errorf("nd6_cache_alloc() failure");
        return NULL;
    }
    cache->state = ND6_STATE_STALE;
    IPV6_ADDR_COPY(&cache->addr, &addr, IPV6_ADDR_LEN);
    memcpy(cache->hwaddr, hwaddr, ETHER_ADDR_LEN);
    gettimeofday(&cache->timestamp, NULL);
    cache->dev = iface->dev;
    debugf("INSERT: addr=%s, hwaddr=%s, dev=%s", 
        ip6_addr_ntop(addr, addr1, sizeof(addr1)), 
        ether_addr_ntop(hwaddr, addr2, sizeof(addr2)),
        cache->dev->name);
    return cache;    
}

static void
nd6_cache_delete(struct nd6_cache *cache)
{
    char addr1[IPV6_ADDR_STR_LEN];
    char addr2[ETHER_ADDR_STR_LEN];

    debugf("DELETE: ip6addr=%s, lladdr=%s", 
        ip6_addr_ntop(cache->addr, addr1, sizeof(addr1)), ether_addr_ntop(cache->hwaddr, addr2, sizeof(addr2)));
    cache->state =  ND6_STATE_NONE;
    memset(cache->addr.addr8, 0, IPV6_ADDR_LEN);
    memset(cache->hwaddr, 0, ETHER_ADDR_LEN);
    timerclear(&cache->timestamp);
}

void *
nd6_options(const uint8_t *data, size_t len, uint8_t type)
{
    struct nd6_option_tlv *opt;
    size_t i = 0;

    while (i <= len) {
        opt = (struct nd6_option_tlv *)(data + i);
        if (opt->len == 0 || (i + (opt->len * 8)) > len) {
            errorf("invalid option length");
            break;
        }
        i += opt->len * 8;
        if (opt->type == type) {
            return opt + 1;
        }
    }
    return NULL;
}

void
nd6_ns_input(const uint8_t *data, size_t len, ip6_addr_t src, ip6_addr_t dst, struct ip6_iface *iface)
{
    struct nd6_ns_hdr *hdr = (struct nd6_ns_hdr *)data;
    struct nd6_option_lladdr *lladdr;
    char hwaddr[ETHER_ADDR_STR_LEN];

    /* options */
    lladdr = nd6_options((uint8_t *)(hdr + 1), len - sizeof(*hdr), ND6_OPT_SOURCE_LINKADDR);
    if (lladdr != NULL) {
        int merge = 0;
        debugf("source link layer address=%s", ether_addr_ntop(lladdr->hwaddr, hwaddr, sizeof(hwaddr)));
        mutex_lock(&mutex);
        if (nd6_cache_update(src, lladdr->hwaddr)) {
            /* update */
            merge = 1;
        }
        mutex_unlock(&mutex);
        if (!merge) {
            mutex_lock(&mutex);
            nd6_cache_insert(src, lladdr->hwaddr, NET_IFACE(iface));
            mutex_unlock(&mutex);
        }
    }

    if (!IPV6_ADDR_COMP(&hdr->target, &iface->addr, IPV6_ADDR_LEN)
        && !IPV6_ADDR_COMP(&dst, &IPV6_SOLICITED_NODE_ADDR_PREFIX, IPV6_SOLICITED_NODE_ADDR_PREFIX_LEN)) {
        errorf("nd6_ns_input() invalid target");
        return;
    }

    nd6_na_output(hdr->target, iface, src);
}

static int
nd6_ns_output(struct ip6_iface *iface, const ip6_addr_t target)
{
    uint8_t buf[ICMP6_BUFSIZ];
    struct nd6_ns_hdr *hdr;
    struct nd6_option_tlv *opt;
    struct nd6_option_lladdr *lladdr;
    struct pseudo6_hdr pseudo;
    size_t len;
    uint16_t psum = 0;
    char addr1[IPV6_ADDR_STR_LEN];
    char addr2[IPV6_ADDR_STR_LEN];

    hdr = (struct nd6_ns_hdr *)buf;
    hdr->type = ICMPV6_TYPE_NEIGHBOR_SOL;
    hdr->code = 0;
    hdr->sum = 0;
    hdr->reserved = 0;
    IPV6_ADDR_COPY(&hdr->target, &target, IPV6_ADDR_LEN);
    len = sizeof(*hdr);

    /* options */
    opt = (struct nd6_option_tlv *)(hdr->data);
    opt->type = ND6_OPT_TARGET_LINKADDR;
    opt->len = 1;
    lladdr = (struct nd6_option_lladdr *)(opt->data);
    memcpy(lladdr->hwaddr, NET_IFACE(iface)->dev->addr, ETHER_ADDR_LEN);
    len += sizeof(*opt) + sizeof(*lladdr);

    memset(&pseudo, 0, sizeof(pseudo));
    IPV6_ADDR_COPY(&pseudo.src, &iface->addr, IPV6_ADDR_LEN);
    IPV6_ADDR_COPY(&pseudo.dst, &IPV6_SOLICITED_NODE_ADDR_PREFIX, IPV6_SOLICITED_NODE_ADDR_PREFIX_LEN / 8);
    pseudo.dst.addr8[13] = target.addr8[13];
    pseudo.dst.addr8[14] = target.addr8[14];
    pseudo.dst.addr8[15] = target.addr8[15];
    pseudo.len = hton16(len);
    pseudo.zero[0] = pseudo.zero[1] = pseudo.zero[2] = 0;
    pseudo.next = IPV6_PROTOCOL_ICMPV6;
    psum =  ~cksum16((uint16_t *)&pseudo, sizeof(pseudo), 0);
    hdr->sum = cksum16((uint16_t *)hdr, len, psum);

    debugf("%s => %s, type=%s(%u), len=%zu",
        ip6_addr_ntop(iface->addr, addr1, sizeof(addr1)),
        ip6_addr_ntop(pseudo.dst, addr2, sizeof(addr2)),
        icmp6_type_ntoa(hdr->type), hdr->type, len);
    return ip6_output(IPV6_PROTOCOL_ICMPV6, buf, len, iface->addr, pseudo.dst);
}

int
nd6_na_output(const ip6_addr_t target, struct ip6_iface *iface, ip6_addr_t dst)
{
    uint8_t buf[ICMP6_BUFSIZ];
    struct nd6_na_hdr *hdr;
    struct pseudo6_hdr pseudo;
    struct nd6_option_tlv *opt;
    struct nd6_option_lladdr *lladdr;
    size_t len;
    uint16_t psum = 0;
    char addr1[IPV6_ADDR_STR_LEN];
    char addr2[IPV6_ADDR_STR_LEN];

    hdr = (struct nd6_na_hdr *)buf;
    hdr->type = ICMPV6_TYPE_NEIGHBOR_ADV;
    hdr->code = 0;
    hdr->sum = 0;
    hdr->flag = hton32(ND6_NA_FLAG_SOLICITED); // Unsocketed NA is not supported
    IPV6_ADDR_COPY(&hdr->target, &target, IPV6_ADDR_LEN);
    len = sizeof(*hdr);

    /*  options */
    opt = (struct nd6_option_tlv *)(hdr->data);
    opt->type = ND6_OPT_TARGET_LINKADDR;
    opt->len = 1;
    lladdr = (struct nd6_option_lladdr *)(opt->data);
    memcpy(lladdr->hwaddr, NET_IFACE(iface)->dev->addr, ETHER_ADDR_LEN);
    len += sizeof(*opt) + sizeof(*lladdr);

    memset(&pseudo, 0, sizeof(pseudo));
    IPV6_ADDR_COPY(&pseudo.src, &iface->addr, IPV6_ADDR_LEN);
    IPV6_ADDR_COPY(&pseudo.dst, &dst, IPV6_ADDR_LEN);
    pseudo.len = hton16(len);
    pseudo.zero[0] = pseudo.zero[1] = pseudo.zero[2] = 0;
    pseudo.next = IPV6_PROTOCOL_ICMPV6;
    psum =  ~cksum16((uint16_t *)&pseudo, sizeof(pseudo), 0);
    hdr->sum = cksum16((uint16_t *)hdr, len, psum);

    debugf("%s => %s, type=%s(%u), len=%zu",
        ip6_addr_ntop(iface->addr, addr1, sizeof(addr1)),
        ip6_addr_ntop(dst, addr2, sizeof(addr2)),
        icmp6_type_ntoa(hdr->type), hdr->type, len);
    return ip6_output(IPV6_PROTOCOL_ICMPV6, buf, len, iface->addr, dst);
}

int
nd6_resolve(ip6_addr_t addr, uint8_t *hwaddr, struct ip6_iface *iface)
{
    struct nd6_cache *cache;
    char addr1[IPV6_ADDR_STR_LEN];
    char addr2[ETHER_ADDR_STR_LEN];

    if (NET_IFACE(iface)->dev->type != NET_DEVICE_TYPE_ETHERNET) {
        debugf("unsupported hardware address type");
        return ND6_RESOLVE_ERROR;
    }
    if (NET_IFACE(iface)->family != NET_IFACE_FAMILY_IPV6) {
        debugf("unsupported protocol address type");
        return ND6_RESOLVE_ERROR;
    }
    
    mutex_lock(&mutex);
    cache = nd6_cache_select(addr);
    if (!cache) {
        cache = nd6_cache_alloc();
        if (!cache) {
            mutex_unlock(&mutex);
            errorf("nd6_cache_alloc() failure");
            return ND6_RESOLVE_ERROR;
        }
        cache->state = ND6_STATE_INCOMPLETE;
        IPV6_ADDR_COPY(&cache->addr, &addr, IPV6_ADDR_LEN);
        cache->ops->solicit = nd6_ns_output;
        gettimeofday(&cache->timestamp, NULL);
        cache->ops->solicit(iface, addr);
        mutex_unlock(&mutex);
        debugf("cache not found, addr=%s", ip6_addr_ntop(addr, addr1, sizeof(addr1)));
        return ND6_RESOLVE_INCOMPLETE;
    }
    if (cache->state == ND6_STATE_INCOMPLETE) {
        nd6_ns_output(iface, addr);
        mutex_unlock(&mutex);
        return ND6_RESOLVE_INCOMPLETE;
    }
    memcpy(hwaddr, cache->hwaddr, ETHER_ADDR_LEN);
    mutex_unlock(&mutex);
    debugf("resolved, addr=%s, hwaddr=%s",
        ip6_addr_ntop(addr, addr1, sizeof(addr1)), ether_addr_ntop(hwaddr, addr2, sizeof(addr2)));
    return ND6_RESOLVE_FOUND;    
}

static void 
nd6_timer(void) 
{
    struct nd6_cache *entry;
    struct timeval now, diff;

    mutex_lock(&mutex);
    gettimeofday(&now, NULL);
    for (entry = caches; entry < tailof(caches); entry++) {
        if (entry->state != ND6_STATE_NONE) {
            timersub(&now, &entry->timestamp, &diff);
            if (diff.tv_sec > ND6_CACHE_TIMEOUT) {
                nd6_cache_delete(entry);
            }
        }
    }
    mutex_unlock(&mutex);
}

int 
nd6_init(void)
{
    struct timeval interval = {1, 0};

    if (net_timer_register("ND6 Timer", interval, nd6_timer) == -1) {
        errorf("net_timer_register() failure");
        return -1;
    }
    return 0;
}