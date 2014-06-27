#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netinet/ip.h> 
#include <stdlib.h>
#include <sys/epoll.h>
#include <assert.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include "log.h"
#include "route_engine.h"

#define UPDATE_INTERVAL 5
#define EXPIRE_INTERVAL 20
#define HODLDOWN_INTERVAL 10
#define RIP_RESPONSE 0
#define RIP_REQUEST 1
#define RIP_VERSION 2

#define RIP_BROADCAST_PORT 5555
#define MAX_IF_NUM 4

#define MAX_EPOLL_EVENTS 64
#define MAX_RTE_NUM 25

#define LOCAL_ROUTE_ENTRY 0
#define NON_LOCAL_ROUTE_ENTRY 1
#define VALID_ROUTE_ENTRY 0
#define INVALID_ROUTE_ENTRY 1
#define INFINITY 16
#define NOTUSED_TIMER -1

#define IP_STR_LEN 16
#define SECOND_TO_MILLSECOND(second) ((second) * 1000)
//a rip packet can contine 1 to 25(inclusize)rip route entry
#define MAX_RIP_PACKET_SIZE (sizeof(rip_packet) + MAX_RTE_NUM * sizeof(rte))
//return the rip_entry num contained in the rip packet
#define get_rte_num(packet_size)((packet_size - sizeof(rip_packet)) / sizeof(rte)) 
#define get_rip_packet_size(rte_num) (sizeof(rip_packet) + rte_num * sizeof(rte))

//utility function
int is_local_ip(in_addr_t ip);
int ip_to_str(in_addr_t ip, char *str);

//debugging function
void print_if(interface *cif);
void print_route_entry(route_entry *rte);
void print_rte(rte *r);
void print_rip_packet(rip_packet *packet, int rte_num) ;


int init_system();
int init_ifs(const char **active_ifs, int n);
int add_local_rtes();
int get_if_info(interface *cif);
void get_broadcast(interface * cif);
int set_if_fds(interface *cif);
int sendto_if(interface *cif, rip_packet *rp, int size);
void broadcast_update_msg();
void send_rip_packet(rip_packet *rp, int rte_num, interface *cif);
rip_packet *prepare_rip_packet(interface *cif, int *rte_num);
int process_upcoming_msg(int fd);
void maintain_route_list();
void parse_rip_packet(rip_packet *rp, int rte_num, in_addr_t sender_ip);
int is_better_rte(rte *r);
int re_list_insert(rte *r, in_addr_t sender_ip);
int re_list_delete(route_entry *re);
void start_route_service();

interface_list *if_list;
route_entry_list *re_list;

/**
 * Judge whether the ip is a local interface bounded ip
 * @param  ip ip address in network order
 * @return    1 on yes or 0 on no
 */
int is_local_ip(in_addr_t ip)
{
	interface *cif = if_list->head;
	while (cif) {
		if (ip == cif->ip)
			return 1;
		cif = cif->next;
	}
	return 0;
}

int ip_to_str(in_addr_t ip, char *str)
{
	struct in_addr addr;
	addr.s_addr = ip;
	if (inet_ntop(AF_INET, &addr, str, IP_STR_LEN))
		return 0;
	log_err("inet_ntop");
	return -1;
}

void print_if(interface *cif)
{
	char ip[IP_STR_LEN];
	char network[IP_STR_LEN];
	char mask[IP_STR_LEN];
	char broadcast[IP_STR_LEN];

	assert(ip_to_str(cif->ip, ip) == 0);
	assert(ip_to_str(cif->network, network) == 0);
	assert(ip_to_str(cif->mask, mask) == 0);
	assert(ip_to_str(cif->broadcast, broadcast) == 0);

	debug("ifname = %s, ifnumber = %d,  active = %d, send_fd = %d, recv_fd = %d, ip = %s, network = %s,"
		"mask = %s, broadcast = %s", cif->ifname, cif->ifnumber, cif->active, cif->send_fd,
		cif->recv_fd,ip, network,mask, broadcast);
}

void print_route_entry(route_entry *rte)
{
	char dst[IP_STR_LEN];
	char gateway[IP_STR_LEN];
	char genmask[IP_STR_LEN];

	assert(ip_to_str(rte->dst, dst) == 0);
	assert(ip_to_str(rte->gateway, gateway) == 0);
	assert(ip_to_str(rte->genmask, genmask) == 0);

	debug("dst:%s, gateway:%s, genmask:%s, metric:%d, flags:%d, type:%d, expire_timer:%ld, holddown_timer:%ld", 
		dst, gateway, genmask, rte->metric, rte->flags, rte->type, rte->expire_timer, rte->holddown_timer);
}

//print rip route entry
void print_rte(rte *r)
{
	char dst[IP_STR_LEN];
	char gateway[IP_STR_LEN];

	assert(ip_to_str(r->ip, dst) == 0);
	assert(ip_to_str(r->nexthop, gateway) == 0);

	debug("To:%s via:%s, metric is %d", dst, gateway, r->metric);
}

void print_rip_packet(rip_packet *packet, int rte_num) 
{
	rte *r = (rte*)((char*)packet + sizeof(rip_packet));
	int i;
	for (i = 0; i < rte_num; i++) {
		
		print_rte(r);
		r++;
	}
	

}
/**
 * init interface list and route entry list
 * @return 0 on success or -1 on failure
 */
int init_system()
{
	if_list = (interface_list*)malloc(sizeof(interface_list));
	if (if_list == NULL) {
		log_err("Failed to create interface list");
		return -1;
	}
	if_list->length = 0;
	if_list->head = NULL;

	re_list = (route_entry_list*)malloc(sizeof(route_entry_list));
	if (re_list == NULL) {
		log_err("Failed to create route entry list");
		return -1;
	}
	re_list->length = 0;
	re_list->head = NULL;

	return 0;
}

/**
 * insert all the valid active network interfaces to the interface list
 * @param if_list head of the interface list
 * @param active_ifs name of the active network interface
 * @return 0 on success or -1 on failure
 */
int init_ifs(const char **active_ifs, int n)
{
	int ifindex;
	char ifname[IFNAMSIZ];
	interface *cur_if = NULL;
    int i;



	for (ifindex = 1; if_indextoname(ifindex, ifname) != 0; ifindex++) {
		
		cur_if = (interface*)malloc(sizeof(interface));
		if (cur_if == NULL) {
			log_err("Failed to create interface:%s", ifname);
			return -1;
		}

		strcpy(cur_if->ifname, ifname);


		cur_if->ifnumber = ifindex;
		cur_if->active = 0;
		for (i = 0; i < n; i++) {
			debug("ifname = %s, active[%d] = %s", ifname, i, active_ifs[i]);
			if (strcmp(ifname, active_ifs[i]) == 0) {
				cur_if->active = 1;
				log_info("Found active network interface:%s", cur_if->ifname);
				break;
			}
		}

		if (get_if_info(cur_if) == -1) {
			free(cur_if);
			continue;
		}
		//insert the current interface to the head of the list
		if (if_list->head == NULL) {

			if_list->head = cur_if;
			cur_if->next = NULL;

		} else {
			cur_if->next = if_list->head;
			if_list->head = cur_if;
		}
		if_list->length++;
	}

	cur_if = if_list->head;
	while (cur_if != NULL) {
		print_if(cur_if);
		cur_if = cur_if->next;
	}
	assert(if_list != NULL);
	return 0;
}
/**
 * get infomation about current network interface
 * @param  cif name of the current network interface
 * @return     0 on success or -1 on failure
 */
int get_if_info(interface *cif)
{
	struct ifreq ifreq;
	int fd;
	struct sockaddr_in * address = (struct sockaddr_in *) &ifreq.ifr_addr;

	fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
	strncpy(ifreq.ifr_name, cif->ifname, sizeof(ifreq.ifr_name));

	/* Check if this interface has broadcasting enabled */
	log_info("Sending ioctls for interface: %s.", ifreq.ifr_name);
	if ((ioctl(fd, SIOCGIFFLAGS, &ifreq)) == -1) {
		log_err("Couldn't get interface flags.");
		return -1;
	} else {
		log_info("Flags received: %d.", ifreq.ifr_flags);
	}

	/* IFF_BROADCAST is in linux/if.h */
	if ((ifreq.ifr_flags & IFF_BROADCAST) == IFF_BROADCAST) {
		log_info("Broadcast is enabled on interface %s.",
		    cif->ifname);
	} else {
		log_info("Broadcast is NOT enabled on interface %s.",
		    cif->ifname);
		close(fd);
		return -1;
	}

	/* Only attempt to get the broadcast address if broadcast
	 * is enabled on this interface. */
	if ((ioctl(fd, SIOCGIFADDR, &ifreq)) == -1) {
		log_info("Couldn't get IP address.");
		return -1;
	} else {
		cif->ip = address->sin_addr.s_addr;
	}

	if ((ioctl(fd, SIOCGIFNETMASK, &ifreq)) == -1) {
		log_info("Couldn't get network mask.");
		return 0;
	} else {
		cif->mask = address->sin_addr.s_addr;
	}
	close(fd);

	cif->network = cif->ip & cif->mask;
	get_broadcast(cif);
	if (set_if_fds(cif) == -1)
		return -1;

	return 0;
}

/**
 * get broadcast infomation about specific network interface
 * @param cif current network interface
 */
void get_broadcast(interface *cif)
{
	uint32_t hostmask = 0;
	uint32_t allOnes = 4294967295U; // (2^32)-1, all bits flipped on

	hostmask = cif->mask ^ allOnes;
	cif->broadcast = cif->network | hostmask;

	return;
}

/**
 * set interface's socket file descriptors, for sending and receiving route update messages
 * @param  cif current network interface
 * @return     0 on success or -1 on failure
 */
int set_if_fds(interface *cif)
{
	int send_fd = -1;
	int recv_fd = -1;
	int on = 1;
	int ret;
	struct sockaddr_in local_server;

	//We only send/receive route updates on active network interface
	if (cif->active) {
		if ((send_fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
			log_err("Failed to create socket send fd for inerface:%s", cif->ifname);
			return -1;
		} 

		/* "socket" option means "layer 3" option */
		ret = setsockopt(send_fd, SOL_SOCKET, SO_BROADCAST, &on, sizeof(int));
		if (ret == -1) {
			log_err("Failed to set socket boradcast option for interface:%s", cif->ifname);
			close(send_fd);
			return -1;
		} 

		if ((recv_fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
			log_err("Failed to create socket recv fd for inerface:%s", cif->ifname);
			close(send_fd);
			return -1;
		}

		local_server.sin_family = AF_INET;
		local_server.sin_addr.s_addr = cif->broadcast;
		local_server.sin_port = htons(RIP_BROADCAST_PORT);
		ret = bind(recv_fd, (struct sockaddr *) &local_server, sizeof(local_server));
		if (ret == -1) {
			log_err("Failed to bind socket recv fd for interface:%s, with fd = %d",
	                cif->ifname, recv_fd);
			close(recv_fd);
			close(send_fd);
			return -1;
		} 
	}


	cif->send_fd = send_fd;
	cif->recv_fd = recv_fd;

	return 0;
}

/**
 * add local route entries to the route_entry list
 * set the type to LOCAL_ROUTE_ENTRY, so the entry won't be expired
 * set the expire_timer and holddown_timer to NOTUSED_TIMER
 * @return 0 on success or -1 on failure
 */
int add_local_rtes()
{
	interface *cur_if = if_list->head;
	route_entry *cur_rte = NULL;
	assert(cur_if != NULL);

	while (cur_if) {
		cur_rte = (route_entry*)malloc(sizeof(route_entry));
		if (cur_rte == NULL) {
			log_err("Failed to create route entry");
			continue;
		}
		cur_rte->dst = cur_if->network;
		cur_rte->genmask = cur_if->mask;
		cur_rte->gateway = 0;
		cur_rte->metric = 0;
		cur_rte->type = LOCAL_ROUTE_ENTRY;
		cur_rte->flags = VALID_ROUTE_ENTRY;
		cur_rte->expire_timer = NOTUSED_TIMER;
		cur_rte->holddown_timer = NOTUSED_TIMER;
		cur_rte->recvif = NULL;

		if (re_list->head == NULL) {
			cur_rte->next = NULL;
			re_list->head = cur_rte;
		} else {
			cur_rte->next = re_list->head;
			re_list->head = cur_rte;
		}
		cur_if = cur_if->next;
		re_list->length++;
	}

	cur_rte = re_list->head;
    //just for debugging
	while (cur_rte) {
		print_route_entry(cur_rte);
		cur_rte = cur_rte->next;
	}
	return 0;
}

/**
 * Judge whether the rte in the rip packet is suitable to insert into the 
 * route entry list and kernel route entry list.
 * Two standards:
 * 1. destination never appert in the route entry list
 * 2. if metric is less than the entry in the route entry list
 * @param  r rip route entry in the rip packet
 * @return   1 on better or 0 on worth
 */
int is_better_rte(rte *r)
{
	route_entry *re = re_list->head;
	int has_entry = 0;
	while (re) {
		if (r->ip == re->dst)
			has_entry = 1;
		if (has_entry && r->metric + 1< re->metric)
			return 1;   
		re = re->next;
	}
	if (has_entry)
		return 0;
	return 1;
}

/**
 * insert the better rte in the rip packet into the route entry lists
 * invoke after is_better_rte() to make sure it's a better path
 * @param  r the bettoer rte
 * @return   0 on success or -1 on failure
 */
int re_list_insert(rte *r, in_addr_t sender_ip)
{
	route_entry *re = re_list->head;
	while (re) {
		if (re->dst == r->ip) {
			re->metric = r->metric + 1;
			re->expire_timer = EXPIRE_INTERVAL;
			re->holddown_timer = HODLDOWN_INTERVAL;
			break;
		}
		re = re->next;
	}

	route_entry *new_re = (route_entry*)malloc(sizeof(route_entry));
	if (new_re == NULL) {
		log_err("Failed to create route entry");
		return -1;
	}
	new_re->dst = r->ip;
	new_re->gateway = sender_ip;
	new_re->genmask = r->mask;
	new_re->metric = r->metric + 1;
	new_re->flags = VALID_ROUTE_ENTRY;
	new_re->type = NON_LOCAL_ROUTE_ENTRY;
	new_re->expire_timer = EXPIRE_INTERVAL;
	new_re->holddown_timer = HODLDOWN_INTERVAL;
	
	new_re->next = re_list->head;
	re_list->head = new_re;
	re_list->length++;
	
	log_info("new route entry inserted");
	print_route_entry(new_re);

	return 0;
}

/**
 * delete the expired route entry from the route entry list
 * when expire_timer and holddown timer both expired
 * @param  re route entry to be deleted
 * @return    0 on success or -1 on failure
 */
int re_list_delete(route_entry *re)
{
	route_entry *cur_re = re_list->head;
	route_entry *prev_re = NULL;
	assert(re != NULL);
	while (cur_re) {
		if (cur_re == re) {
			if (prev_re == NULL) {
				re_list->head = cur_re->next;
			} else {
				prev_re->next = cur_re->next;
			}

			free(re);
			re_list->length--;
			break;
		}
		prev_re = cur_re;
		cur_re = cur_re->next;
	}

	return 0;
}

/**
 * count how many route entry should send through specific interface
 * @param  cif which interface to send to
 * @return     num of route entry
 */
int count_re4if(interface *cif)
{
	route_entry *re = re_list->head;
	int cnt = 0;
	while (re) {
		if (re->recvif != cif)
			cnt++;
		re = re->next;
	}

	return cnt;
}

/**
 *prepare a rip packet send to specific interface
 *@parama cif interface to send to
 *@param rte_num get the rip route entry number
 *@return rip packet construct for specific interface
 */
rip_packet *prepare_rip_packet(interface *cif, int *rte_num)
{
	
	route_entry *re = re_list->head;

	rte *cur_r = NULL;
    rip_packet *rp = NULL;

    *rte_num = count_re4if(cif);
    int rip_packet_size = sizeof(rip_packet) + (*rte_num) * sizeof(rte);
    rp = (rip_packet*)malloc(rip_packet_size);
    if (rp == NULL) {
        log_err("Failed to create rip packet");
        return NULL;
    }
    memset(rp, 0, rip_packet_size);
    rp->command = RIP_RESPONSE;
    rp->version = RIP_VERSION;
    rp->pad1 = 0;
    rp->pad2 = 0;
    //not forget to cast rp to char* or the pointer will 
    //forward sizeof(rip_packet) * sizeof(rip_packet)
    //not just sizeof(rip_packet)
	cur_r = (rte*)((char*)rp + sizeof(rip_packet));

	while (re) {

		cur_r->family = 0;
		cur_r->tag = 0;
		cur_r->ip = re->dst;

		cur_r->mask = re->genmask;
		cur_r->nexthop = re->gateway;
		cur_r->metric = re->metric;
		print_rte(cur_r);
		re = re->next;
		cur_r++;
	}

    return rp;
}

/**
 * walk through the rtes in the rip packet
 * judge whether each rte is worth to insert into the route entry list
 * @param rte_num rte count in the rip packet
 */
void parse_rip_packet(rip_packet *rp, int rte_num, in_addr_t sender_ip) 
{
	debug("enter parse_rip_packet");
	rte *r = (rte*)((char*)rp + sizeof(rip_packet));
	int i;
	for (i = 0; i < rte_num; i++) {
		if (is_better_rte(r)) {
			log_info("Receive a better rte");
			print_rte(r);
			re_list_insert(r, sender_ip);
		}
		r++;
	}
	debug("leave parse_rip_packet");
}
/**
 * send rip packet through specific interface
 * @param  cif  current network interface
 * @param  rp   rip packet
 * @param  size size of the whole rip packet
 * @return successfully written size of the rip packet or -1 on failure
 */
int sendto_if(interface *cif, rip_packet *rp, int size)
{
	log_info("send through interface :%s", cif->ifname);
	int nwrite;
	struct sockaddr_in remote_server;
	remote_server.sin_family = AF_INET;
	remote_server.sin_addr.s_addr = cif->broadcast;
	remote_server.sin_port = htons(RIP_BROADCAST_PORT);

	nwrite = sendto(cif->send_fd, rp, size, 0, (struct sockaddr*)&remote_server, sizeof(remote_server));

	return nwrite;
}

void send_rip_packet(rip_packet *rp, int rte_num, interface *cif) 
{
    int size = get_rip_packet_size(rte_num);
	int res;
    
	for (; cif != NULL; cif = cif->next) {
		if (cif->active) {
			res = sendto_if(cif, rp, size);
			if (res == -1) {
				log_err("Failed send rip packet through interface:%s", cif->ifname);
				continue;
			}
		}
	}
}

/**
 * broad cast route entry update message
 */
void broadcast_update_msg()
{
	rip_packet *rp = NULL;
	interface *cif = if_list->head;
    int rte_num = 0;

	for (; cif != NULL; cif = cif->next) {
		if (cif->active) {
			rp = prepare_rip_packet(cif, &rte_num);
			assert(rp != NULL);
			send_rip_packet(rp, rte_num, cif);
			free(rp);
		}
	}
}

/**
 * process update message receiving from specific interface
 * @param  fd socket descriptor bound to specific interface
 * @return    0 on success or -1 on failure
 */
int process_upcoming_msg(int fd)
{
    char buffer[MAX_RIP_PACKET_SIZE];
	struct sockaddr_in sender_addr;
	socklen_t sender_len;
	int nread;
	int rte_num;

	sender_len = sizeof(sender_addr);
    memset(&buffer, 0, MAX_RIP_PACKET_SIZE);

	nread = recvfrom(fd, &buffer, MAX_RIP_PACKET_SIZE, 0, (struct sockaddr *)&sender_addr, &sender_len);
	if (nread < 0) {
		log_err("Failed to read rip packet from fd:%d", fd);
		close(fd);
		return -1;
	}
	//ignore the broadcast packets send by itself
	if (!is_local_ip(sender_addr.sin_addr.s_addr)) {
		log_info("Receive rip update messages");
		rte_num = get_rte_num(nread);
		assert(rte_num > 0);
		log_info("Receive a route update message from fd:%d,which contain %d route entr%s", fd, rte_num, (rte_num == 1) ? "y\b": "ies");
		print_rip_packet((rip_packet*)&buffer, rte_num);
		parse_rip_packet((rip_packet*)&buffer, rte_num, sender_addr.sin_addr.s_addr);
	}

	return 0;
}

/**
 * maintain the route entry list
 * update specific timers in the route entry
 * check whether the route entry is expired
 * delete the expired route entry
 */
void maintain_route_list()
{
	route_entry *re = re_list->head;
	while (re) {
		//LOCAL ROUTE ENTRY will never expire
		if (re->type != LOCAL_ROUTE_ENTRY) {
			if (re->flags == VALID_ROUTE_ENTRY) {
				re->expire_timer -= UPDATE_INTERVAL;

				if (re->expire_timer <= 0) {
					re->flags = INVALID_ROUTE_ENTRY;
					re->metric = INFINITY;
				}
			} else {
				re->holddown_timer -= UPDATE_INTERVAL;
				if (re->holddown_timer <= 0) {
					log_info("Begin to delete route from route entry list");
					print_route_entry(re);
					re_list_delete(re);
				}
			}
			
		}
		re = re->next;
	}
}

/**
 * add various events to epoll
 * @param efd epool fd
 * @TODO add interface to the event.data.ptr,so we can get more information when socket is ready
 */
void epoll_add_events(int efd)
{
	interface *cur_if = if_list->head;
	assert(cur_if != NULL);
	struct epoll_event event;
	int res;

	while (cur_if) {
		if (cur_if->active) {
			log_info("Add interface:%s's recv_fd:%d to epoll", cur_if->ifname, cur_if->recv_fd);
			event.data.fd = cur_if->recv_fd;
			event.events = EPOLLIN | EPOLLET;
			res = epoll_ctl(efd, EPOLL_CTL_ADD, cur_if->recv_fd, &event);
			if (res == -1) {
				log_err("Failed to add event to epoll queue");
				return;
			}
		}
		cur_if = cur_if->next;
	}
}

void start_route_service()
{

	struct epoll_event *events;
	int efd;

	if ((efd = epoll_create(1)) == -1) {
		log_err("Failed to create epoll fd");
		return;
	}

	events = (struct epoll_event*)calloc(MAX_EPOLL_EVENTS, sizeof(struct epoll_event));
	if (events == NULL) {
		log_err("Failed to create events");
		return;
	}
	//add events we focus on
	epoll_add_events(efd);

	int timeout = SECOND_TO_MILLSECOND(UPDATE_INTERVAL);
	while (1) {
		int n, i;
		time_t init_time = time(NULL);

		n = epoll_wait(efd, events, MAX_EPOLL_EVENTS, timeout);
		if (n == 0) {
			timeout = SECOND_TO_MILLSECOND(UPDATE_INTERVAL);
			log_info("Timeout");
			//1. send route update message
			broadcast_update_msg();
			//2. update expire_timer and holddown_timer in route_entry, 
			//remove the expired route_entry to holddown list, delete 
			//holddown entry when its timer is to zero
			maintain_route_list();
		} else {
			//read route update message from specific sock fd
			for (i = 0; i < n; i++) {
				if ((events[i].events & EPOLLERR) ||
					(events[i].events & EPOLLHUP) ||
					(!events[i].events & EPOLLIN)) {
					log_err("An error has occured on fd:%d", events[i].data.fd);
					close(events[i].data.fd);
					continue;
				
				} else {
					process_upcoming_msg(events[i].data.fd);
				}	
			}
			timeout = SECOND_TO_MILLSECOND(UPDATE_INTERVAL-(time(NULL) - init_time));
		}

	}
}

int main(int argc, char const *argv[])
{

	assert(sizeof(rip_packet) == 4);
	assert(sizeof(rte) == 18);

	const char *active_ifs[MAX_IF_NUM];
	int res;
	int i;
	if (argc < 2) {
		printf("Usage:%s eth0\n", argv[0]);
		exit(EXIT_FAILURE);
	}
	for (i = 1; i < argc; i++) {
		active_ifs[i-1] = argv[i];
		debug("active interface:%s", active_ifs[i-1]);
	}

	res = init_system();
	if (res == -1) {
		log_err("Failed to initialize system variables");
		exit(EXIT_FAILURE);
	}
	res = init_ifs(active_ifs, 1);
	if (res == -1) {
		log_err("Failed to initialize all the interfaces");
		exit(EXIT_FAILURE);
	}
	res = add_local_rtes();
	if (res == -1) {
		log_err("Failed to add local route entries");
		exit(EXIT_FAILURE);
	}
	start_route_service();
	sleep(1000);
	return 0;
}
