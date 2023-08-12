ip tuntap add mode tap user $USER name tap0
ip addr add 192.0.2.1/24 dev tap0
ip -6 addr add 2001:db8::1/64 dev tap0
ip link set tap0 up
