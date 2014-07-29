#ifndef ROUTE_ENGINE_H
#define ROUTE_ENGINE_H

#include <sys/types.h>
#include <net/if.h>
#include <stdint.h>
#include <netinet/in.h>
#include <pthread.h>
#include "hashmap.h"
#include "packet_sniffer.h"
#include "queue.h"

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
	//on which interface the route entry comes from
	//which will help to implement split horizon
	int ifnumber;
	time_t recv_time;
	struct route_entry *next;
} route_entry;

typedef struct tg_info {
	char ping_if[IFNAMSIZ];
	uint8_t ping_if_status;
	in_addr_t ping_ip;
	in_addr_t netmask;
	in_addr_t ping_gw_ip;
	in_addr_t default_gw_ip;
	int default_gw_ifnumber;
	uint16_t rtt;
	time_t expire_timer;
	uint8_t expire_count;
	pthread_mutex_t tg_info_lock;
} tg_info;

#define MAX_PCAP_ROULE_LENGTH 50

typedef struct sate_info_entry {
	char interface[IFNAMSIZ];
	char rule[MAX_PCAP_ROULE_LENGTH];

} sate_info_entry;

typedef struct sate_info {
	int pcap_if_count;
	int pipe_fds[2];
	queue *req_queue;
	int running;
	pthread_cond_t last_choice;
	pthread_mutex_t cond_mutex;
	sate_info_entry entries[0];
} sate_info;


typedef struct advp {
	time_t update_send_timer;
	interface *if_list_head;
	route_entry *re_list_head;
	route_entry *default_re;
	tg_info *tg_info;
	sate_info *sate_info;
	hashmap *neighbor_hp;

} advp;

int modify_default_re(int ifnumber, in_addr_t sender_ip);
#endif