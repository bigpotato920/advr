#ifndef ROUTE_ENGINE_H
#define ROUTE_ENGINE_H

#include <sys/types.h>
#include <net/if.h>
#include <stdint.h>
#include <netinet/in.h>

typedef struct interface {
	char ifname[IFNAMSIZ];
	uint8_t ifnumber; 
	uint8_t active;  
	in_addr_t network;//network id
	in_addr_t mask;//netmask
	in_addr_t ip;//ip address
	in_addr_t broadcast;//broadcast address
	//socket file descriptors assosiated with current network interface
	int send_fd;
	int recv_fd;
	struct interface * next;

} interface;

typedef struct if_list {
	int length;
	interface *head;
} interface_list;

//RIP2 entry
#pragma pack(push, 1)
typedef struct rte {
	uint8_t family;
	uint8_t tag;
	in_addr_t ip;
	in_addr_t mask;
	in_addr_t nexthop;
	uint32_t metric;
} rte;

//RIP2 packet
typedef struct rip_packet {
	uint8_t command;
	uint8_t version;
	uint8_t pad1;
	uint8_t pad2;
	rte routes[0];
} rip_packet;

#pragma pack(pop)
//User space route entry
//The expire timer is initialized when a route is established, and any time
//an update message is received for the route.If 180 seconds elapse
//from the last time the route_entry has never update, the route is
//considered to have expired.The route change flag is set to indicate
//that this entry has been hanged.The holddown timer is set
//for 120 seconds.Until the holddown timer expires, the route entry
//is included in all updates sent by this router.When the holddown
//timer expires, the route is deleted from the routing table.
typedef struct route_entry {
	in_addr_t dst;
	in_addr_t genmask;
	in_addr_t gateway;
	uint32_t metric;
	uint32_t type;
	uint32_t flags;
	time_t expire_timer;
	time_t holddown_timer;
	//on which interface the route entry come from
	//which will help to implement split horizon
	interface *rif;
	struct route_entry *next;
} route_entry;


typedef struct route_entry_list {
	int length;
	route_entry *head;
} route_entry_list;
#endif