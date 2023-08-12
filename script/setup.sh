#!/bin/sh
if [ "`whoami`" != "root" ]; then
        echo "You need to be root to perform this script."
        exit 1;
fi

# 
# +-------+            <-- RA +--------+                   +-------+
# | Host1 | veth0 ----- veth0 | Router | veth1 ----- veth0 | Host2 |
# +-------+                :1 +--------+ :1             :2 +-------+
#
#         fd00:cafe:dead:1::/64        fd00:cafe:dead:2::/64
#

ip netns add Host1
ip netns add Router
ip netns add Host2

ip link add name Host1-veth0 type veth peer name Router-veth0
ip link add name Host2-veth0 type veth peer name Router-veth1

ip link set Host1-veth0 netns Host1
ip link set Router-veth0 netns Router
ip link set Router-veth1 netns Router
ip link set Host2-veth0 netns Host2

ip netns exec Host1 ip link set Host1-veth0 up
ip netns exec Router ip link set Router-veth0 up
ip netns exec Router ip link set Router-veth1 up
ip netns exec Host2 ip link set Host2-veth0 up

ip netns exec Router sysctl -w net.ipv6.conf.all.forwarding=1  

ip netns exec Router ip -6 addr add fd00:cafe:dead:1::1/64 dev Router-veth0
ip netns exec Router ip -6 addr add fd00:cafe:dead:2::1/64 dev Router-veth1
ip netns exec Host2 ip -6 addr add fd00:cafe:dead:2::2/64 dev Host2-veth0
ip netns exec Host2 ip -6 route add default via fd00:cafe:dead:2::1 dev Host2-veth0

#ip netns exec Router sudo radvd

#    $ sudo apt-get install radvd
#    $ cat /etc/radvd.conf 
#    interface Router-veth0{
#        AdvSendAdvert on;
#        AdvManagedFlag off; 
#        AdvOtherConfigFlag off;
#        prefix fd00:cafe:dead:1::/64{};
#    };
