#ifndef ROUTE_ENGINE_H
#define ROUTE_ENGINE_H

#include <sys/types.h>
#include <net/if.h>
#include <stdint.h>
#include <netinet/in.h>
#include <pthread.h>

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

//RIP2 entry
#pragma pack(push, 1)
typedef struct rte {
	uint8_t family;
	uint8_t tag;
	in_addr_t dst;
	in_addr_t netmask;
	in_addr_t gateway;
	uint32_t metric;
} rte;

//RIP2 packet
typedef struct rip_packet {
	// uint8_t command;
	// uint8_t version;
	// uint8_t pad1;
	// uint8_t pad2;
	// uint8_t hop_count;
	// uint8_t rtt;
	// uint8_t payload;
	// uint8_t sat_sigal;
	uint32_t send_time;
	uint16_t rtt;
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
	in_addr_t netmask;
	in_addr_t gateway;
	uint32_t metric;
	uint32_t type;
	uint32_t flags;
	time_t expire_timer;
	time_t holddown_timer;
	//on which interface the route entry come from
	//which will help to implement split horizon
	interface *recvif;
	struct route_entry *next;
} route_entry;

typedef struct gateway_info {
	char ping_if[IFNAMSIZ];
	uint8_t ping_if_status;
	in_addr_t ping_gw_ip;
	in_addr_t ping_ip;
	in_addr_t netmask;
	in_addr_t default_gw_ip;
	uint16_t rtt;
	time_t expire_timer;
	pthread_mutex_t gw_info_lock;
} gateway_info;


typedef struct advp {
	time_t update_send_timer;
	interface *if_list_head;
	route_entry *re_list_head;
	gateway_info *gw_info;

} advp;

#endif