#ifndef PARAM_H
#define PARAM_H

#include <stdint.h>




/* loopback */
const char LOOPBACK_IP_ADDR[]        = "127.0.0.1";
const char LOOPBACK_IP_NETMASK[]     = "255.0.0.0";
const char LOOPBACK_IPV6_ADDR[]      = "::1";
const int  LOOPBACK_IPV6_PREFIXLEN   = 128;

/* devices */
const int ETHER_DEVICES_NUM               = 1;
const char *ETHER_DEVICES_NAME[]          = {"tap0"};
const char *ETHER_DEVICES_HW_ADDR[]       = {"00:00:5e:00:53:01"};
const char *ETHER_DEVICES_IP_ADDR[]       = {"192.0.2.2"};
const char *ETHER_DEVICES_IP_NETMASK[]    = {"255.255.255.0"};
const char *ETHER_DEVICES_IPV6_ADDR[]     = {"2001:db8::2"};
const int  ETHER_DEVICES_IPV6_PREFIXLEN[] = {64};
/* use pcap device.. */
/* ---
const char *ETHER_DEVICES_NAME[]          = {"enp0s1"};
const char *ETHER_DEVICES_HW_ADDR[]       = {"00:00:5e:00:53:02"};
const char *ETHER_DEVICES_IPV6_ADDR[]     = {"fd09:471d:e8d3:1a0c::beef"};
const int  ETHER_DEVICES_IPV6_PREFIXLEN[] = {64};
*/
/* try router6.. */
/* ---
const int ETHER_DEVICES_NUM               = 2;
const char *ETHER_DEVICES_NAME[]          = {"router1-host1", "router1-router2"};
const char *ETHER_DEVICES_HW_ADDR[]       = {"00:00:5e:00:53:01", "00:00:5e:00:53:02"};
const char *ETHER_DEVICES_IPV6_ADDR[]     = {"2001:db8:1::1", "2001:db8:2::1"};
const int  ETHER_DEVICES_IPV6_PREFIXLEN[] = {64, 64};
*/


/* default route */
const char IP_DEFAULT_GATEWAY[]   = "192.0.2.1";
const char IPV6_DEFAULT_GATEWAY[] = "2001:db8::1";
//const char IPV6_DEFAULT_GATEWAY[] = "2001:db8:2::2";

#endif
