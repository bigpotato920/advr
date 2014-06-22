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

#include "log.h"
#include "route_engine.h"

#define UPDATE_INTERVAL 30
#define EXPIRE_INTERVAL 180
#define HODLDOWN_INTERVAL 120
#define RIP_BROADCAST_PORT 555
#define MAX_IF_NUM 4

#define MAX_EPOLL_EVENTS 64
#define MAX_RTE_NUM 25

#define SECOND_TO_MILLSECOND(second) (second * 1000)
//a rip packet can contine 1 to 25(inclusize)rip route entry
#define MAX_RIP_PACKET_SIZE (sizeof(rip_packet) + MAX_RTE_NUM * sizeof(rte))
//return the rip_entry num contained in the rip packet
#define get_rte_num(packet) ((sizeof(packet) - sizeof(rip_packet)) / sizeof(rte))

int init_ifs();
int add_local_rtes(route_entry *rte_list);
int get_if_info(interface *cif);
void get_broadcast(interface * cif);
int set_if_fds(interface *cif);


char *ip_to_str(in_addr_t ip)
{
	struct in_addr addr;
	addr.s_addr = ip;

	return inet_ntoa(addr);
}

/**
 * insert all the valid active network interfaces to the interface list
 * @param if_head head of the interface list
 * @param active_ifs name of the active network interface
 * @return 0 on success or -1 on failure
 */
int init_ifs(interface *if_head, const char **active_ifs, int n)
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

		if (get_if_info(cur_if) == -1) {
			free(cur_if);
			continue;
		}
		cur_if->ifnumber = ifindex;
		cur_if->active = 0;
		for (i = 0; i < n; i++) {
			if (strcmp(ifname, active_ifs[i]) == 0) {
				cur_if->active = 1;
				log_info("Found active network interface:%s", cur_if->ifname);
				break;
			}
		}
		//insert the current interface to the head of the list
		if (if_head == NULL) {

			if_head = cur_if;
			cur_if->next = NULL;

		} else {
			cur_if->next = if_head;
			if_head = cur_if;
		}
	}

	cur_if = if_head;
	while (cur_if != NULL) {
		debug("ifname = %s, ifnumber = %d,  active = %d, send_fd = %d, recv_fd = %d, ip = %s, network = %s,"
			"mask = %s, broadcast = %s", cur_if->ifname, cur_if->ifnumber, cur_if->active,
			cur_if->send_fd, cur_if->recv_fd,ip_to_str(cur_if->ip), ip_to_str(cur_if->network),
			ip_to_str(cur_if->mask), ip_to_str(cur_if->broadcast));
		cur_if = cur_if->next;
	}

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
		return -1;
	}

	/* Only attempt to get the broadcast address if broadcast
	 * is enabled on this interface. */
	if ((ioctl(fd, SIOCGIFADDR, &ifreq)) == -1) {
		log_info("Couldn't get IP address.");
		return -1;
	} else {
		cif->ip = address->sin_addr.s_addr;
		log_info("IP address is: %s", ip_to_str(cif->ip));
	}

	if ((ioctl(fd, SIOCGIFNETMASK, &ifreq)) == -1) {
		log_info("Couldn't get network mask.");
		return 0;
	} else {
		cif->mask = address->sin_addr.s_addr;
		log_info("Netmask is %s.", ip_to_str(cif->mask));
	}

	cif->network = cif->ip & cif->mask;
	log_info("NetID is %s.", ip_to_str(cif->network));
	get_broadcast(cif);
	if (set_if_fds(cif) == -1) {
        close(fd);
		return -1;
    }
    close(fd);
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
	log_info("snmask = %u, hmask = %u", cif->mask, hostmask);
	cif->broadcast = cif->network | hostmask;

	log_info("Broadcast is %s.", ip_to_str(cif->broadcast));
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
	struct sockaddr_in server;
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
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = cif->broadcast;
	server.sin_port = htons(RIP_BROADCAST_PORT);
	ret = bind(recv_fd, (struct sockaddr *) &server, sizeof(server));
	if (ret == -1) {
		log_err("Failed to bind socket recv fd for interface:%s, with fd = %d",
                cif->ifname, recv_fd);
		close(send_fd);
		return -1;
	} 

	cif->send_fd = send_fd;
	cif->recv_fd = recv_fd;

	return 0;
}

int add_local_rtes(route_entry *rte_list)
{

}
int start_route_service(interface *if_list)
{
	interface *cur_if = if_list;
	route_entry *route_entry_list = NULL;
	route_entry *holddown_list = NULL;

	struct epoll_event event;
	struct epoll_event *events;
	int efd;
	int res;

	if ((efd = epoll_create(1)) == -1) {
		log_err("Failed to create epoll fd");
		return -1;
	}
	events = (struct epoll_event*)calloc(MAX_EPOLL_EVENTS, sizeof(event));
	if (events == NULL) {
		log_err("Failed to create events");
		return -1;
	}
	while (cur_if) {
		event.data.fd = cur_if->recv_fd;
		event.events = EPOLLIN | EPOLLET;
		res = epoll_ctl(efd, EPOLL_CTL_ADD, cur_if->recv_fd, &event);
		if (res == -1) {
			log_err("Failed to add event to epoll queue");
			return -1;
		}
		cur_if = cur_if->next;
	}

	while (1) {
		int n, i;
		n = epoll_wait(efd, events, MAX_EPOLL_EVENTS, SECOND_TO_MILLSECOND(UPDATE_INTERVAL) );
		if (n == 0) {
			log_info("Timeout");  
		}
		for (i = 0; i < n; i++) {
			if ((events[i].events & EPOLLERR) ||
				(events[i].events & EPOLLHUP) ||
				(!events[i].events & EPOLLIN)) {
				log_err("An error has occured on fd:%d", events[i].data.fd);
				close(events[i].data.fd);
				continue;
			//read route update message from specific sock fd
			} else {
				rip_packet packet;
				int fd = events[i].data.fd;
				int nread;
				int rte_num;

				nread = read(fd, &packet, MAX_RIP_PACKET_SIZE);
				if (nread < 0) {
					log_err("Failed to read rip packet from fd:%d", fd);
					close(fd);
					continue;
				}
				rte_num = get_rte_num(packet);
				assert(rte_num > 0);
				log_info("Receive a route update message from fd:%d,which contain %d route entry%c", fd, rte_num, (rte_num == 1) ? '\b': 's');

			}	
		}
	}
}

int main(int argc, char const *argv[])
{
	interface *if_list = NULL;

	const char *active_ifs[] = {"eth0", "vmnet1"};
	init_ifs(if_list, active_ifs, 3);
	start_route_service(if_list);
	return 0;
}
