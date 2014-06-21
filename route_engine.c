#include <string.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <stdlib.h>

#include "log.h"
#include "route_engine.h"

#define UPDATE_INTERVAL 30
#define EXPIRE_INTERVAL 180
#define HODLDOWN_INTERVAL 120

#define MAX_IF_NUM 4

int init_ifs();
int get_if_info(interface *cif);
void get_broadcast(interface * cif);


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
int init_ifs(interface *if_head, const char **active_ifs)
{
	int ifindex;
	char ifname[IFNAMSIZ];
	interface *cur_if = NULL;


	for (ifindex = 1; if_indextoname(ifindex, ifname) != 0; ifindex++) {
		cur_if = (interface*)malloc(sizeof(interface));
		if (cur_if == NULL) {
			log_err("Failed to create interface:%s", ifname);
			return -1;
		}
		strcpy(cur_if->ifname, ifname);
		cur_if->ifnumber = ifindex;
		cur_if->active = 0;
		cur_if->sock_fd = -1;
		if (get_if_info(cur_if) == -1) {
			free(cur_if);
			continue;
		}
		//insert the current interface to the head of the list
		if (if_head == NULL) {

			if_head = cur_if;
			cur_if->next = NULL;
		}
		else {
			cur_if->next = if_head;
			if_head = cur_if;
		}
		
	}

	cur_if = if_head;
	while (cur_if != NULL) {
		debug("ifname = %s, ifnumber = %d, active = %d, ip = %s, network = %s,"
			"mask = %s, broadcast = %s", cur_if->ifname, cur_if->ifnumber,
			cur_if->active, ip_to_str(cur_if->ip), ip_to_str(cur_if->network),
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
 * set interface's socket file descriptor
 * @param  cif current network interface
 * @return     0 on success or -1 on failure
 */
int set_if_fd(interface *cif)
{

	return 0;
}
int start_route_service(interface *if_list)
{
	route_entry *route_entry_list = NULL;
	route_entry *holddown_list = NULL;
}

int main(int argc, char const *argv[])
{
	interface *if_list = NULL;

	const char *active_ifs[MAX_IF_NUM + 1];
	init_ifs(if_list, active_ifs);
	start_route_service(if_list);
	return 0;
}