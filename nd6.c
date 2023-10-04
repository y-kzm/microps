#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#include "platform.h"

#include "util.h"
#include "net.h"
#include "ether.h"
#include "ip.h"
#include "ip6.h"
#include "icmp6.h"
#include "nd6.h"
#include "slaac.h"

#define ND6_CACHE_SIZE    32
#define ND6_CACHE_TIMEOUT 30 /* seconds */

#define ND6_STATE_NONE        0
#define ND6_STATE_INCOMPLETE  1
#define ND6_STATE_REACHABLE   2
#define ND6_STATE_STALE       3
#define ND6_STATE_DELAY       4
#define ND6_STATE_PROBE       5
#define ND6_STATE_PERMANENT   6

struct nd6_cache {
    uint8_t state; 
    ip6_addr_t ip6addr;
    uint8_t lladdr[ETHER_ADDR_LEN];
    int isrouter; /* typedef int bool */
    struct timeval timestamp;
    struct net_device *dev;
    time_t timeout;
};

static mutex_t mutex = MUTEX_INITIALIZER;
static struct nd6_cache caches[ND6_CACHE_SIZE];

/*
 * Dump
 */

static char *
nd6_state_ntoa(uint8_t state) {
    switch (state) {
    case ND6_STATE_NONE:
        return "NONE";
    case ND6_STATE_INCOMPLETE:
        return "INCOMPLETE";
    case ND6_STATE_REACHABLE:
        return "REACHABLE";
    case ND6_STATE_STALE:
        return "STALE";
    case ND6_STATE_DELAY:
        return "DELAY";
    case ND6_STATE_PROBE:
        return "PROBE";
    case ND6_STATE_PERMANENT:
        return "PERMANENT";
    }
    return "UNKNOWN";
}

static void
nd6_cache_dump(FILE *fp)
{
    struct nd6_cache *entry = caches;
    char addr1[IPV6_ADDR_STR_LEN];
    char addr2[ETHER_ADDR_STR_LEN];

    flockfile(fp);
    fprintf(fp, "+---------------------------------------------------------------------------+\n");
    for (entry = caches; entry < tailof(caches); entry++) {
        if (entry->state != ND6_STATE_NONE){
            fprintf(fp, " %s lladdr %s state %s ", 
                ip6_addr_ntop(entry->ip6addr, addr1, sizeof(addr1)), 
                ether_addr_ntop(entry->lladdr, addr2, sizeof(addr2)), 
                nd6_state_ntoa(entry->state));
            if (entry->isrouter) {
                fprintf(fp, "router");
            }
            fprintf(fp, "\n");
        }
    }
    fprintf(fp, "+---------------------------------------------------------------------------+\n");
    funlockfile(fp);
}

static char *
nd6_pi_flg_ntoa(uint8_t flg)
{
    static char str[9];

    snprintf(str, sizeof(str), "%c%c%c*****",
        ND6_RA_PI_FLG_ISSET(flg, ND6_RA_PI_FLG_LINK)  ? 'L'  : '-',
        ND6_RA_PI_FLG_ISSET(flg, ND6_RA_PI_FLG_AUTO)  ? 'A'  : '-',
        ND6_RA_PI_FLG_ISSET(flg, ND6_RA_PI_FLG_RTR)   ? 'R'  : '-');
    return str;
}

void
nd6_options_dump(const uint8_t *options, size_t len)
{
    struct nd_opt_hdr *opt;
    size_t i = 0;
    struct nd_opt_lladdr *opt_lladdr;
    struct nd_opt_prefixinfo *opt_pi;
    char lladdr[ETHER_ADDR_STR_LEN];
    char addr[IPV6_ADDR_STR_LEN];

    flockfile(stderr);
    while (i <= len) {
        opt = (struct nd_opt_hdr *)(options + i);
        if (opt->len == 0) 
            break;
        if ((i + (opt->len * 8)) > len) 
            break;
        i += (opt->len * 8);
        fprintf(stderr, "       type: %u\n", opt->type);
        fprintf(stderr, "        len: %u (%u byte)\n", opt->len, opt->len * 8);
        switch (opt->type) {
        case ND_OPT_SOURCE_LINKADDR:
        case ND_OPT_TARGET_LINKADDR:
            opt_lladdr = (struct nd_opt_lladdr *)(opt + 1);
            fprintf(stderr, "     lladdr: %s\n", ether_addr_ntop(opt_lladdr->lladdr, lladdr, sizeof(lladdr)));
            break;
        case ND_OPT_PREFIX_INFORMATION:
            opt_pi = (struct nd_opt_prefixinfo *)(opt + 1);
            fprintf(stderr, "  prefixlen: %u\n", opt_pi->prefixlen);
            fprintf(stderr, "      flags: 0x%02x (%s)\n", opt_pi->flg, nd6_pi_flg_ntoa(opt_pi->flg));
            fprintf(stderr, " valid time: %u\n", ntoh32(opt_pi->valid_time)); 
            fprintf(stderr, "prefer time: %u\n", ntoh32(opt_pi->preferred_time)); 
            fprintf(stderr, "   reserved: %u\n", ntoh32(opt_pi->reserved2));
            fprintf(stderr, "     prefix: %s\n", ip6_addr_ntop(opt_pi->prefix, addr, sizeof(addr))); 
            break;
        case ND_OPT_REDIRECTED_HEADER:
        case ND_OPT_MTU:
        default:
            debugf("not supported");
            break;
        }
#ifdef HEXDUMP
        hexdump(stderr, options, len);
#endif
    }
    funlockfile(stderr);
}

/*
 * Neighbor Cache
 */

static int 
jenkins_hash(uint8_t *key)
{
    int i;
    uint32_t hash = 0;

    hash = 0;
    for (i = 0; i < IPV6_ADDR_LEN; i++){
        hash += key[i];
        hash += hash << 10;
        hash ^= hash >> 6;
    }
    hash += hash << 3;
    hash ^= hash >> 11;
    hash += hash << 15;
    return hash % ND6_CACHE_SIZE;
}

static struct nd6_cache *
nd6_cache_alloc(int index) 
{
    struct nd6_cache *entry, *oldest = NULL;
    int offset = index;

    entry = &caches[index];
    while (entry->state != ND6_STATE_NONE) {
        ++offset;
        if (offset > ND6_CACHE_SIZE || offset < 0) {
            errorf("nd6 cache table range exceeded: %d", offset);
        }
        if (!oldest || timercmp(&oldest->timestamp, &entry->timestamp, >)) {
            oldest = &caches[offset];
        } 
        if (offset == index) {
            debugf("insert entry into caches[%d], hashindex=%d", offset, index);
            return oldest;
        }
        offset %= ND6_CACHE_SIZE;
        entry = &caches[offset];
    }

    debugf("ALLOC: caches[%d], hashindex=%d", offset, index);
    return entry;
}

static struct nd6_cache *
nd6_cache_select(ip6_addr_t ip6addr)
{
    struct nd6_cache *entry;
    int hashindex, offset;

    hashindex = jenkins_hash(ip6addr.addr8);
    offset = hashindex;
    entry = &caches[hashindex];
    while (1) {
        ++offset;
        if (offset > ND6_CACHE_SIZE || offset < 0) {
            errorf("nd6 cache table range exceeded: %d", offset);
            break;
        }
        if (offset == hashindex) {
            break;
        }
        if (entry->state != ND6_STATE_NONE && memcmp(&entry->ip6addr, &ip6addr, IPV6_ADDR_LEN) == 0) {
            return entry;
        }
        offset %= ND6_CACHE_SIZE;
        entry = &caches[offset]; 
    }

    return NULL;
}

static struct nd6_cache *
nd6_cache_update(ip6_addr_t ip6addr, uint8_t *lladdr)
{
    struct nd6_cache *cache;
    char addr1[IPV6_ADDR_STR_LEN];
    char addr2[ETHER_ADDR_STR_LEN];

    cache = nd6_cache_select(ip6addr);
    if (!cache) {
        /* not found */
        return NULL;
    }
    cache->state = ND6_STATE_REACHABLE;
    memcpy(cache->lladdr, lladdr, ETHER_ADDR_LEN);
    gettimeofday(&cache->timestamp, NULL);
    debugf("UPDATE: ip6addr=%s, lladdr=%s", ip6_addr_ntop(ip6addr, addr1, sizeof(addr1)), ether_addr_ntop(lladdr, addr2, sizeof(addr2)));
    return cache; 
}

static struct nd6_cache *
nd6_cache_insert(ip6_addr_t ip6addr, const uint8_t *lladdr, struct net_iface *iface)
{
    struct nd6_cache *cache;
    char addr1[IPV6_ADDR_STR_LEN];
    char addr2[ETHER_ADDR_STR_LEN];
    int hashindex;

    hashindex = jenkins_hash(ip6addr.addr8);
    cache = nd6_cache_alloc(hashindex);
    if (!cache) {
        errorf("nd6_cache_alloc() failure");
        return NULL;
    }
    cache->state = ND6_STATE_STALE;
    cache->ip6addr = ip6addr;
    memcpy(cache->lladdr, lladdr, ETHER_ADDR_LEN);
    gettimeofday(&cache->timestamp, NULL);
    cache->dev = iface->dev;
    debugf("INSERT: ip6addr=%s, lladdr=%s, dev=%s", 
        ip6_addr_ntop(ip6addr, addr1, sizeof(addr1)), 
        ether_addr_ntop(lladdr, addr2, sizeof(addr2)),
        cache->dev->name);
    return cache;    
}

static void
nd6_cache_delete(struct nd6_cache *cache)
{
    char addr1[IPV6_ADDR_STR_LEN];
    char addr2[ETHER_ADDR_STR_LEN];

    debugf("DELETE: ip6addr=%s, lladdr=%s", ip6_addr_ntop(cache->ip6addr, addr1, sizeof(addr1)), ether_addr_ntop(cache->lladdr, addr2, sizeof(addr2)));
    cache->state =  ND6_STATE_NONE;
    memset(cache->ip6addr.addr8, 0, IPV6_ADDR_LEN);
    memset(cache->lladdr, 0, ETHER_ADDR_LEN);
    timerclear(&cache->timestamp);
}

int
nd6_resolve(struct ip6_iface *iface, ip6_addr_t ip6addr, uint8_t *lladdr)
{
    struct nd6_cache *cache;
    char addr1[IPV6_ADDR_STR_LEN];
    char addr2[ETHER_ADDR_STR_LEN];
    int hashindex;

    if (NET_IFACE(iface)->dev->type != NET_DEVICE_TYPE_ETHERNET) {
        debugf("unsupported hardware address type");
        return ND6_RESOLVE_ERROR;
    }
    if (NET_IFACE(iface)->family != NET_IFACE_FAMILY_IPV6) {
        debugf("unsupported protocol address type");
        return ND6_RESOLVE_ERROR;
    }
#ifdef NDCACHEDUMP
        nd6_cache_dump(stderr);
#endif
    
    mutex_lock(&mutex);
    cache = nd6_cache_select(ip6addr);
    if (!cache) {
        hashindex = jenkins_hash(ip6addr.addr8);
        cache = nd6_cache_alloc(hashindex);
        if (!cache) {
            mutex_unlock(&mutex);
            errorf("nd6_cache_alloc() failure");
            return ND6_RESOLVE_ERROR;
        }
        cache->state = ND6_STATE_INCOMPLETE;
        IPV6_ADDR_COPY(&cache->ip6addr, &ip6addr, IPV6_ADDR_LEN);
        gettimeofday(&cache->timestamp, NULL);
        // TODO: start retrans timer
        nd6_ns_output(iface, ip6addr);
        mutex_unlock(&mutex);
        debugf("cache not found, ip6addr=%s", ip6_addr_ntop(ip6addr, addr1, sizeof(addr1)));
        return ND6_RESOLVE_INCOMPLETE;        
    }
    if (cache->state == ND6_STATE_INCOMPLETE) {
        nd6_ns_output(iface, ip6addr);
        mutex_unlock(&mutex);
        return ND6_RESOLVE_INCOMPLETE;
    }
    memcpy(lladdr, cache->lladdr, ETHER_ADDR_LEN);
    mutex_unlock(&mutex);
    debugf("resolved, ip6addr=%s, lladdr=%s",
        ip6_addr_ntop(ip6addr, addr1, sizeof(addr1)), ether_addr_ntop(lladdr, addr2, sizeof(addr2)));
    return ND6_RESOLVE_FOUND;    
}

/*
 * Options
 */

void *
nd6_options(const uint8_t *options, size_t len, uint8_t type)
{
    struct nd_opt_hdr *opt;
    size_t i = 0;

    while (i <= len) {
        opt = (struct nd_opt_hdr *)(options + i);
        if (opt->len == 0) 
            break;
        if ((i + (opt->len * 8)) > len) 
            break;
        i += (opt->len * 8);
        if (opt->type == type) {
            return (opt + 1);
        }
    }
    debugf("could not find option: type=%u", type);
    return NULL;
}

/*
 * Neighbor Discovery Protocol: input/output
 */

/*
 * Router Solicitation
 */

int
nd6_rs_output(struct ip6_iface *iface)
{
    uint8_t buf[ICMPV6_BUFSIZ];
    struct nd_router_solicit *rs;
    struct ip6_pseudo_hdr pseudo;
    size_t msg_len;
    uint16_t psum = 0;
    char addr1[IPV6_ADDR_STR_LEN];
    char addr2[IPV6_ADDR_STR_LEN];

    /* router solicitation message */
    rs = (struct nd_router_solicit *)buf;
    rs->nd_ns_type = ICMPV6_TYPE_ROUTER_SOL;
    rs->nd_ns_code = 0;
    rs->nd_ns_sum = 0;
    rs->nd_ns_reserved = 0;
    msg_len = sizeof(*rs);

    /* calculate the checksum */
    pseudo.src = iface->ip6_addr.addr;
    IPV6_ADDR_COPY(&pseudo.dst, &IPV6_LINK_LOCAL_ALL_ROUTERS_ADDR, IPV6_ADDR_LEN);
    pseudo.len = hton16(msg_len);
    pseudo.zero[0] = pseudo.zero[1] = pseudo.zero[2] = 0;
    pseudo.nxt = PROTOCOL_ICMPV6;
    psum =  ~cksum16((uint16_t *)&pseudo, sizeof(pseudo), 0);
    rs->nd_ns_sum = cksum16((uint16_t *)buf, msg_len, psum);

    debugf("%s => %s, type=(%u), +msg_len=%zu",
        ip6_addr_ntop(iface->ip6_addr.addr, addr1, sizeof(addr1)),
        ip6_addr_ntop(pseudo.dst, addr2, sizeof(addr2)),
        rs->nd_ns_type, msg_len);
#ifdef HDRDUMP
    icmp6_dump((uint8_t *)rs, msg_len);
#endif
    return ip6_output(PROTOCOL_ICMPV6, buf, msg_len, iface->ip6_addr.addr, pseudo.dst); 
}

/*
 * Router Advertisement
 */

void
nd6_ra_input(const uint8_t *data, size_t len, ip6_addr_t src, ip6_addr_t dst, struct ip6_iface *iface)
{
    struct nd_router_adv *ra;
    struct nd_opt_lladdr *opt_lladdr;
    struct nd_opt_prefixinfo *opt_pi;
    char lladdr[ETHER_ADDR_STR_LEN];
    int merge = 0;
    char addr1[IPV6_ADDR_STR_LEN];
    char addr2[IPV6_ADDR_STR_LEN];

    if (len < sizeof(*ra)) {
        errorf("too short");
        return;             
    }

    /* router advertisement message */
    ra = (struct nd_router_adv *)data;
    if (ND6_RA_FLG_ISSET(ra->nd_ra_flg, ND6_RA_FLG_MGMT)) {
        debugf("use stateful DHCPv6 to configure addresses");
        iface->slaac.running = 0;
    }
    if (ND6_RA_FLG_ISSET(ra->nd_ra_flg, ND6_RA_FLG_OTHER)) {
        warnf("use stateful DHCPv6 to obtain non-address information");
        iface->slaac.rdns = 0;
    }

    /* possible options */
    /* source link-layer address */
    opt_lladdr = nd6_options((uint8_t *)(ra + 1), len - sizeof(*ra), ND_OPT_SOURCE_LINKADDR);
    if (opt_lladdr != NULL) {
        debugf("option: lladdr(src)=%s", ether_addr_ntop(opt_lladdr->lladdr, lladdr, sizeof(lladdr)));
        /* update neighbor cache */
        mutex_lock(&mutex);
        if (nd6_cache_update(src, opt_lladdr->lladdr)) {
            /* update */
            merge = 1;
        }
        mutex_unlock(&mutex);
        if (!merge) {
            mutex_lock(&mutex);
            nd6_cache_insert(src, opt_lladdr->lladdr, NET_IFACE(iface));
#ifdef NDCACHEDUMP
            nd6_cache_dump(stderr);
#endif
            mutex_unlock(&mutex);
        }
    }

    /* prefix information */
    opt_pi = nd6_options((uint8_t *)(ra + 1), len - sizeof(*ra), ND_OPT_PREFIX_INFORMATION);
    if (opt_pi != NULL) {
        if (!ND6_RA_PI_FLG_ISSET(opt_pi->flg, ND6_RA_PI_FLG_LINK)) {
            warnf("Advertised prefix is not On-link: This case is not yet supported");
            iface->slaac.running = 0;
        }
        if (!ND6_RA_PI_FLG_ISSET(opt_pi->flg, ND6_RA_PI_FLG_AUTO)) {
            warnf("Autonomous address-configuration is disabled");
            iface->slaac.running = 0;
        }
        // TODO: print prefix info
    }
    
    debugf("%s => %s, type=(%u), len=%zu",
        ip6_addr_ntop(src, addr1, sizeof(addr1)),
        ip6_addr_ntop(dst, addr2, sizeof(addr2)),
        ra->nd_ra_type, len);
    if (iface->slaac.running) {
        slaac_ra_input(data, len, src, dst, iface);
    }
}

/*
 * Neighbor Solicitation
 */

void
nd6_ns_input(const uint8_t *data, size_t len, ip6_addr_t src, ip6_addr_t dst, struct ip6_iface *iface)
{
    struct nd_neighbor_solicit *ns;
    struct nd_opt_hdr *opt;
    struct nd_opt_lladdr *opt_lladdr;
    int merge = 0;
    uint32_t flags = 0;
    char lladdr[ETHER_ADDR_STR_LEN];
    char addr1[IPV6_ADDR_STR_LEN];
    char addr2[IPV6_ADDR_STR_LEN];

    if (len < sizeof(*ns)) {
        errorf("too short");
        return;             
    }

    /* neighbor solicit message */
    ns = (struct nd_neighbor_solicit *)data;
    if (!IPV6_ADDR_EQUAL(&dst, &iface->ip6_addr.addr)) {
        if (IPV6_ADDR_IS_MULTICAST(&dst)) {
            if (memcmp(&dst, &IPV6_SOLICITED_NODE_ADDR_PREFIX, IPV6_SOLICITED_NODE_ADDR_PREFIX_LEN / 8) == 0) {
                flags |= ND6_NA_FLAG_SOLICITED;
            } 
        }else {
            errorf("bad dstination addr: %s", ip6_addr_ntop(dst, addr1, sizeof(addr1)));
            return;
        }
    }
    if (IPV6_ADDR_EQUAL(&iface->ip6_addr.addr, &src)) {
        errorf("duplicate ipv6 address: %s", ip6_addr_ntop(src, addr1, sizeof(addr1)));
        return;
    }
    if (IPV6_ADDR_IS_UNSPECIFIED(&src)) {
        // TODO: received dad
    }
    if (IPV6_ADDR_IS_MULTICAST(&ns->target)) {
        errorf("bad target addr: %s", ip6_addr_ntop(ns->target, addr1, sizeof(addr1)));
        return;
    }

    /* possible options */
    /* source link-layer address */
    opt = (struct nd_opt_hdr *)(data + sizeof(*ns));
    opt_lladdr = nd6_options((uint8_t *)(ns + 1), len - sizeof(*ns), ND_OPT_SOURCE_LINKADDR);
    if (opt_lladdr != NULL) {
        debugf("option: lladdr=%s", ether_addr_ntop(opt_lladdr->lladdr, lladdr, sizeof(lladdr)));
        /* update neighbor cache */
        mutex_lock(&mutex);
        if (nd6_cache_update(src, opt_lladdr->lladdr)) {
            /* update */
            merge = 1;
        }
        mutex_unlock(&mutex);
        if (!merge) {
            mutex_lock(&mutex);
            nd6_cache_insert(src, opt_lladdr->lladdr, NET_IFACE(iface));
#ifdef NDCACHEDUMP
            nd6_cache_dump(stderr);
#endif
            mutex_unlock(&mutex);
        }
    }

    debugf("%s => %s, type=(%u), len=%zu ",
        ip6_addr_ntop(src, addr1, sizeof(addr1)),
        ip6_addr_ntop(dst, addr2, sizeof(addr2)),
        ns->nd_ns_type, len);
    
    nd6_na_output(ICMPV6_TYPE_NEIGHBOR_ADV, ns->nd_ns_code, flags, (uint8_t *)(opt + 1), len - (sizeof(*ns) + sizeof(*opt)), iface->ip6_addr.addr, src, ns->target, NET_IFACE(iface)->dev->addr);
}

int
nd6_ns_output(struct ip6_iface *iface, const ip6_addr_t target)
{
    uint8_t buf[ICMPV6_BUFSIZ];
    struct nd_neighbor_solicit *ns;
    struct nd_opt_hdr *opt;
    struct nd_opt_lladdr *opt_lladdr;
    struct ip6_pseudo_hdr pseudo;
    size_t msg_len;
    uint16_t psum = 0;
    char addr1[IPV6_ADDR_STR_LEN];
    char addr2[IPV6_ADDR_STR_LEN];

    /* neighbor solicitation message */
    ns = (struct nd_neighbor_solicit *)buf;
    ns->nd_ns_type = ICMPV6_TYPE_NEIGHBOR_SOL;
    ns->nd_ns_code = 0;
    ns->nd_ns_sum = 0;
    ns->nd_ns_reserved = 0;
    ns->target = target;

    /* possible options */
    /* source link-layer address */
    opt = (struct nd_opt_hdr *)(ns + 1);
    opt->type = ND_OPT_SOURCE_LINKADDR;
    opt->len = 1;
    opt_lladdr = (struct nd_opt_lladdr *)(opt + 1);
    memcpy(opt_lladdr->lladdr, NET_IFACE(iface)->dev->addr, ETHER_ADDR_LEN);
    msg_len = sizeof(*ns) + sizeof(*opt) + sizeof(*opt_lladdr); 

    /* calculate the checksum */
    pseudo.src = iface->ip6_addr.addr;
    ip6_addr_create_solicit_mcastaddr(target, &pseudo.dst);
    pseudo.len = hton16(msg_len);
    pseudo.zero[0] = pseudo.zero[1] = pseudo.zero[2] = 0;
    pseudo.nxt = PROTOCOL_ICMPV6;
    psum =  ~cksum16((uint16_t *)&pseudo, sizeof(pseudo), 0);
    ns->nd_ns_sum = cksum16((uint16_t *)buf, msg_len, psum);

    debugf("%s => %s, type=(%u), +msg_len=%zu",
        ip6_addr_ntop(iface->ip6_addr.addr, addr1, sizeof(addr1)),
        ip6_addr_ntop(pseudo.dst, addr2, sizeof(addr2)),
        ns->nd_ns_type, msg_len);
#ifdef HDRDUMP
    icmp6_dump((uint8_t *)ns, msg_len);
#endif
    return ip6_output(PROTOCOL_ICMPV6, buf, msg_len, iface->ip6_addr.addr, pseudo.dst); 
}

/*
 * Neighbor Advertisement
 */

void
nd6_na_input(const uint8_t *data, size_t len, ip6_addr_t src, ip6_addr_t dst, struct ip6_iface *iface)
{
    struct nd_neighbor_adv *na;
    struct nd_opt_lladdr *opt_lladdr;
    char lladdr[ETHER_ADDR_STR_LEN];
    char addr1[IPV6_ADDR_STR_LEN];
    char addr2[IPV6_ADDR_STR_LEN];

    if (len < sizeof(*na)) {
        errorf("too short");
        return;             
    }

    /* neighbor avertisement message */
    na = (struct nd_neighbor_adv *)data;
    if (IPV6_ADDR_IS_MULTICAST(&na->target)) {
        errorf("bad target addr: %s", ip6_addr_ntop(na->target, addr1, sizeof(addr1)));
        return;
    }

    if (!IPV6_ADDR_EQUAL(&dst, &iface->ip6_addr.addr)) {
        if (!IPV6_ADDR_IS_MULTICAST(&dst)) {
            errorf("bad dstination addr");
            return;
        }
    }
    if (IPV6_ADDR_IS_MULTICAST(&na->target)) {
        errorf("bad target addr: %s", ip6_addr_ntop(na->target, addr1, sizeof(addr1)));
        return;
    }

    /* possible options */
    /* target link-layer address */
    opt_lladdr = nd6_options((uint8_t *)(na + 1), len - sizeof(*na), ND_OPT_TARGET_LINKADDR);
    if (opt_lladdr == NULL) {
        warnf("Link-layer Address opson is empty");
        return;
    }

    /* update neighbor cache */
    mutex_lock(&mutex);
    if (nd6_cache_update(src, opt_lladdr->lladdr)) {
#ifdef NDCACHEDUMP
        nd6_cache_dump(stderr);
#endif
    }
    mutex_unlock(&mutex);

    debugf("%s => %s, type=(%u), len=%zu target=%s",
        ip6_addr_ntop(src, addr1, sizeof(addr1)),
        ip6_addr_ntop(dst, addr2, sizeof(addr2)),
        na->nd_na_type, len, ether_addr_ntop(opt_lladdr->lladdr, lladdr, sizeof(lladdr)));
}

int
nd6_na_output(uint8_t type, uint8_t code, uint32_t flags, const uint8_t *data, size_t len, ip6_addr_t src, ip6_addr_t dst, const ip6_addr_t target, const void *lladdr)
{
    uint8_t buf[ICMPV6_BUFSIZ];
    struct nd_neighbor_adv *na;
    struct nd_opt_hdr *opt;
    struct nd_opt_lladdr *opt_lladdr;
    struct ip6_pseudo_hdr pseudo;
    size_t msg_len;
    uint16_t psum = 0;
    char addr1[IPV6_ADDR_STR_LEN];
    char addr2[IPV6_ADDR_STR_LEN];

    /* select source address */
    struct ip6_iface *res;

    res = ip6_rule_addr_select(dst);
    if (res != NULL) {
        debugf("selected source address=%s, scope=%u", ip6_addr_ntop(res->ip6_addr.addr, addr1, sizeof(addr1)), res->ip6_addr.scope);
        IPV6_ADDR_COPY(&src, &res->ip6_addr.addr, IPV6_ADDR_LEN);
        memcpy((uint8_t *)lladdr, NET_IFACE(res)->dev->addr, ETHER_ADDR_LEN);
    } else {
        warnf("no appropriate source address");
        return -1;
    }

    /* neighbor advertisement message */
    na = (struct nd_neighbor_adv *)buf;
    na->nd_na_type = ICMPV6_TYPE_NEIGHBOR_ADV;
    na->nd_na_code = 0;
    na->nd_na_sum = 0;
    na->nd_na_flg = hton32(flags);
    na->target = target;

    /* possible options */
    opt = (struct nd_opt_hdr *)(na + 1);
    opt->type = ND_OPT_TARGET_LINKADDR;
    opt->len = 1;
    opt_lladdr = (struct nd_opt_lladdr *)(opt + 1);
    memcpy(opt_lladdr->lladdr, lladdr, ETHER_ADDR_LEN);
    msg_len = sizeof(*na) + sizeof(*opt) + sizeof(*opt_lladdr); 
    memcpy(buf + msg_len, data, len);

    /* calculate the checksum */
    pseudo.src = src;
    pseudo.dst = dst;
    pseudo.len = hton16(msg_len);
    pseudo.zero[0] = pseudo.zero[1] = pseudo.zero[2] = 0;
    pseudo.nxt = PROTOCOL_ICMPV6;
    psum =  ~cksum16((uint16_t *)&pseudo, sizeof(pseudo), 0);
    na->nd_na_sum = cksum16((uint16_t *)buf, msg_len, psum);

    debugf("%s => %s, type=(%u), len=%zu, +msg_len=%zu",
        ip6_addr_ntop(src, addr1, sizeof(addr1)),
        ip6_addr_ntop(dst, addr2, sizeof(addr2)),
        na->nd_na_type, len, msg_len);
#ifdef HDRDUMP
    icmp6_dump((uint8_t *)na, msg_len);
#endif
    return ip6_output(PROTOCOL_ICMPV6, buf, msg_len, src, dst);
}

/*
 * Misc
 */

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