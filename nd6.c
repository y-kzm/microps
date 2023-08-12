#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#include "platform.h"

#include "util.h"
#include "net.h"
#include "ether.h"
#include "ip6.h"
#include "icmp6.h"
#include "nd6.h"

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
    // dad timeout
};

static mutex_t mutex = MUTEX_INITIALIZER;
static struct nd6_cache caches[ND6_CACHE_SIZE];

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

/*
 * Neighbor Cache
 *
 * NOTE: Neighbor Cache functions must be called after mutex locked
 */
#ifdef CACHEDUMP
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
nd6_cache_show(FILE *fp)
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
#endif

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

    debugf("insert entry into caches[%d], hashindex=%d", offset, index);
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
    cache->state = ND6_STATE_REACHABLE;
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
        memcpy(&cache->ip6addr, &ip6addr, IPV6_ADDR_LEN);
        gettimeofday(&cache->timestamp, NULL);
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

void
nd6_ns_input(const uint8_t *data, size_t len, ip6_addr_t src, ip6_addr_t dst, struct ip6_iface *iface)
{
    struct nd_neighbor_solicit *ns;
    struct nd_opt *opt;
    int merge = 0;
    char lladdr[ETHER_ADDR_STR_LEN];
    char addr1[IPV6_ADDR_STR_LEN];
    char addr2[IPV6_ADDR_STR_LEN];

    if (len < sizeof(*ns)) {
        errorf("too short");
        return;             
    }
    ns = (struct nd_neighbor_solicit *)data;

    if (!IPV6_ADDR_EQUAL(&dst, &iface->ip6_addr.addr)) {
        if (memcmp(&dst, &IPV6_SOLICITED_NODE_ADDR_PREFIX, IPV6_SOLICITED_NODE_ADDR_PREFIX_LEN / 8) != 0) {
            errorf("bad dstination addr");
            return;
        }
    }

    if (IPV6_ADDR_IS_UNSPECIFIED(&src)) {
        /* solicited node multicast address */
    }

    if (IPV6_ADDR_IS_MULTICAST(&ns->target)) {
        errorf("bad target addr");
        return;
    }
    opt = (struct nd_opt *)(data + sizeof(*ns));
    // TODO: opt_len check

    if (IPV6_ADDR_IS_MULTICAST(&dst)) {
        /**
         * 1. 受信インターフェイスの有効なユニキャスト/エニーキャストアドレス
         * 2. DADが実行されている「暫定」アドレス
         */
    }

    if (IPV6_ADDR_EQUAL(&iface->ip6_addr.addr, &src)) {
        errorf("duplicate ipv6 address");
        return;
    }

    debugf("%s => %s, type=(%u), len=%zu target=%s",
        ip6_addr_ntop(src, addr1, sizeof(addr1)),
        ip6_addr_ntop(dst, addr2, sizeof(addr2)),
        ns->nd_ns_type, len, ether_addr_ntop(opt->nd_opt_lladdr, lladdr, sizeof(lladdr)));
    icmp6_dump((uint8_t *)ns, len);

    mutex_lock(&mutex);
    if (nd6_cache_update(src, opt->nd_opt_lladdr)) {
        /* update */
        merge = 1;
    }
    mutex_unlock(&mutex);
    if (!merge) {
        mutex_lock(&mutex);
        nd6_cache_insert(src, opt->nd_opt_lladdr, NET_IFACE(iface));
#ifdef CACHEDUMP
        nd6_cache_show(stderr);
#endif
        mutex_unlock(&mutex);
    }

    if (ns->hdr.icmp6_type == ICMPV6_TYPE_NEIGHBOR_SOL) {
        uint32_t flags = 0;
        nd6_na_output(ICMPV6_TYPE_NEIGHBOR_ADV, ns->nd_ns_code, flags, (uint8_t *)(opt + 1), len - (sizeof(*ns) + sizeof(*opt)), iface->ip6_addr.addr, src, ns->target, NET_IFACE(iface)->dev->addr);
    }
}

int
nd6_ns_output(struct ip6_iface *iface, const ip6_addr_t target)
{
    uint8_t buf[ICMPV6_BUFSIZ];
    struct nd_neighbor_solicit *ns;
    struct nd_lladdr_opt *opt;
    struct ip6_pseudo_hdr pseudo;
    size_t msg_len;
    uint16_t psum = 0;
    char addr1[IPV6_ADDR_STR_LEN];
    char addr2[IPV6_ADDR_STR_LEN];

    /* neighbor solicit */
    ns = (struct nd_neighbor_solicit *)buf;
    ns->nd_ns_type = ICMPV6_TYPE_NEIGHBOR_SOL;
    ns->nd_ns_code = 0;
    ns->nd_ns_sum = 0;
    ns->nd_ns_reserved = 0;
    ns->target = target;

    /* option */
    opt = (struct nd_lladdr_opt *)(ns + 1);
    opt->type = ND_OPT_SOURCE_LINKADDR;
    opt->len = 1;
    memcpy(opt->lladdr, NET_IFACE(iface)->dev->addr, ETHER_ADDR_LEN);
    msg_len = sizeof(*ns) + sizeof(*opt); 

    /* pseudo header */
    pseudo.src = iface->ip6_addr.addr;
    ip6_get_solicit_node_mcaddr(target, &pseudo.dst);
    pseudo.len = hton16(msg_len);
    pseudo.zero[0] = pseudo.zero[1] = pseudo.zero[2] = 0;
    pseudo.nxt = IPV6_NEXT_ICMPV6;
    psum =  ~cksum16((uint16_t *)&pseudo, sizeof(pseudo), 0);
    ns->nd_ns_sum = cksum16((uint16_t *)buf, msg_len, psum);

    debugf("%s => %s, type=(%u), +msg_len=%zu",
        ip6_addr_ntop(iface->ip6_addr.addr, addr1, sizeof(addr1)),
        ip6_addr_ntop(pseudo.dst, addr2, sizeof(addr2)),
        ns->nd_ns_type, msg_len);
    icmp6_dump((uint8_t *)ns, msg_len);
    return ip6_output(IPV6_NEXT_ICMPV6, buf, msg_len, iface->ip6_addr.addr, pseudo.dst); 
}

void
nd6_na_input(const uint8_t *data, size_t len, ip6_addr_t src, ip6_addr_t dst, struct ip6_iface *iface)
{
    struct nd_neighbor_adv *na;
    struct nd_opt *opt;
    char lladdr[ETHER_ADDR_STR_LEN];
    char addr1[IPV6_ADDR_STR_LEN];
    char addr2[IPV6_ADDR_STR_LEN];

    if (len < sizeof(*na)) {
        errorf("too short");
        return;             
    }
    na = (struct nd_neighbor_adv *)data;
    opt = (struct nd_opt *)(data + sizeof(*na));

    if (IPV6_ADDR_IS_MULTICAST(&na->target)) {
        errorf("bad target addr");
        return;
    }

    if (!IPV6_ADDR_EQUAL(&dst, &iface->ip6_addr.addr)) {
        if (!IPV6_ADDR_IS_MULTICAST(&dst)) {
            errorf("bad dstination addr");
            return;
        }
        // if (is_solicited)
    }

    // DAD check: nd6_dad_input()

    debugf("%s => %s, type=(%u), len=%zu target=%s",
        ip6_addr_ntop(src, addr1, sizeof(addr1)),
        ip6_addr_ntop(dst, addr2, sizeof(addr2)),
        na->nd_ns_type, len, ether_addr_ntop(opt->nd_opt_lladdr, lladdr, sizeof(lladdr)));
    icmp6_dump((uint8_t *)na, len);

    mutex_lock(&mutex);
    if (nd6_cache_update(src, opt->nd_opt_lladdr)) {
#ifdef CACHEDUMP
        nd6_cache_show(stderr);
#endif
    }
    mutex_unlock(&mutex);
}

int
nd6_na_output(uint8_t type, uint8_t code, uint32_t flags, const uint8_t *data, size_t len, ip6_addr_t src, ip6_addr_t dst, const ip6_addr_t target, const void *lladdr)
{
    uint8_t buf[ICMPV6_BUFSIZ];
    struct nd_neighbor_adv *na;
    struct nd_lladdr_opt *opt;
    struct ip6_pseudo_hdr pseudo;
    size_t msg_len;
    uint16_t psum = 0;
    char addr1[IPV6_ADDR_STR_LEN];
    char addr2[IPV6_ADDR_STR_LEN];

    /* neighbor advertisement */
    na = (struct nd_neighbor_adv *)buf;
    na->nd_na_type = ICMPV6_TYPE_NEIGHBOR_ADV;
    na->nd_na_code = 0;
    na->nd_na_sum = 0;
    na->nd_na_reserved = 0;
    na->target = target;

    /* option */
    opt = (struct nd_lladdr_opt *)(na + 1);
    opt->type = ND_OPT_TARGET_LINKADDR;
    opt->len = 1;
    memcpy(opt->lladdr, lladdr, ETHER_ADDR_LEN);

    msg_len = sizeof(*na) + sizeof(*opt) + len; 
    memcpy(buf + msg_len, data, len);

    /* pseudo header */
    pseudo.src = src;
    pseudo.dst = dst;
    pseudo.len = hton16(msg_len);
    pseudo.zero[0] = pseudo.zero[1] = pseudo.zero[2] = 0;
    pseudo.nxt = IPV6_NEXT_ICMPV6;
    psum =  ~cksum16((uint16_t *)&pseudo, sizeof(pseudo), 0);
    na->nd_ns_sum = cksum16((uint16_t *)buf, msg_len, psum);

    debugf("%s => %s, type=(%u), len=%zu, +msg_len=%zu",
        ip6_addr_ntop(src, addr1, sizeof(addr1)),
        ip6_addr_ntop(dst, addr2, sizeof(addr2)),
        na->nd_na_type, len, msg_len);
    icmp6_dump((uint8_t *)na, msg_len);
    return ip6_output(IPV6_NEXT_ICMPV6, buf, msg_len, src, dst);
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