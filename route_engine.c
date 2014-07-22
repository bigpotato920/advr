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
#include <pthread.h>
#include <libconfig.h>
#include <sys/time.h>

#include "log.h"
#include "route_engine.h"
#include "kroute.h"
#include "detector.h"

#define ROUTE_UPDATE_INTERVAL 15
#define EXPIRE_INTERVAL 30
#define HODLDOWN_INTERVAL 15
#define GW_UPATE_INTERVAL 30
#define GW_EXPIRE_INTERVAL 60
#define LOCAL_GI_ENTRY 0
#define NONLOCAL_GI_ENTRY 1

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

#define IF_ONLINE 1
#define IF_OFFLINE 0

#define USUAL_UPDATE 0
#define URGENT_UPDATE 1
#define IP_STR_LEN 16
#define SECOND_TO_MILLSECOND(second) ((second) * 1000)

//a rip packet can contine 1 to 25(inclusize)rip route entry
#define MAX_RIP_PACKET_SIZE (sizeof(rip_packet) + MAX_RTE_NUM * sizeof(rte))
//return the rip_entry num contained in the rip packet
#define get_rte_num(packet_size)((packet_size - sizeof(rip_packet)) / sizeof(rte)) 
#define get_rip_packet_size(rte_num) (sizeof(rip_packet) + rte_num * sizeof(rte))


#define DAFAULT_GW "10.103.240.200"
//utility function
int is_local_ip(in_addr_t ip);
int ip_to_str(in_addr_t ip, char *str);

//debugging function
void print_if(interface *cif);
void print_route_entry(route_entry *rte);
void print_re_list();
void print_rte(rte *r);
void print_rip_packet(rip_packet *packet, int rte_num) ;


int init_system();
int init_ifs(config_setting_t *if_setting);
int init_gateway(config_setting_t *gw_setting);
int add_local_rtes();
int add_gw_re();
int add_default_re();
int set_if_info(interface *cif);
void get_broadcast(interface * cif);
int set_if_fds(interface *cif);
int sendto_if(interface *cif, rip_packet *rp, int size);
void broadcast_update_msg(int type);
void send_rip_packet(rip_packet *rp, int rte_num, interface *cif);
rip_packet *prepare_rip_packet(interface *cif, int type, int *rte_num);
int process_upcoming_msg(void *data);
void process_time_event();
void check_route_list();
void check_gw_info();
void check_if_status();
void process_rip_packet(rip_packet *rp, int rte_num, interface *recvif, in_addr_t sender_ip);
void process_gw_info(uint16_t rtt, int ifnumber, in_addr_t sender_ip);
void process_rte(rte *r, interface *recvif, in_addr_t sender_ip);
int re_list_add(route_entry *new_re);
int re_list_delete(route_entry *re);
int re_list_modify(route_entry *old_re, route_entry *new_re);
void copy_route_entry(route_entry *dst, route_entry *src);
void start_route_service();
int create_detection_thread();


advp *m_advp = NULL;
/**
 * Judge whether the ip is a local interface bounded ip
 * @param  ip ip address in network order
 * @return    1 on yes or 0 on no
 */
int is_local_ip(in_addr_t ip)
{
	interface *cif = m_advp->if_list_head;
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
	char netmask[IP_STR_LEN];
	char ifname[IFNAMSIZ];
	assert(ip_to_str(rte->dst, dst) == 0);
	assert(ip_to_str(rte->gateway, gateway) == 0);
	assert(ip_to_str(rte->netmask, netmask) == 0);
	

	if (rte->ifnumber != -1)
		if_indextoname(rte->ifnumber, ifname);
	else
		strcpy(ifname, "none");

	debug("dst:%s, gateway:%s, netmask:%s, metric:%d, flags:%d, type:%d, ifname:%s, expire_timer:%ld, holddown_timer:%ld", 
		dst, gateway, netmask, rte->metric, rte->flags, rte->type, ifname,
		rte->expire_timer - time(NULL), rte->holddown_timer - time(NULL));
}

void print_re_list()
{
	log_info("main routing table");
	route_entry *re = m_advp->re_list_head;
	while (re) {
		print_route_entry(re);
		re = re->next;
	}
}


//print rip route entry
void print_rte(rte *r)
{
	char dst[IP_STR_LEN];
	char gateway[IP_STR_LEN];

	assert(ip_to_str(r->dst, dst) == 0);
	assert(ip_to_str(r->gateway, gateway) == 0);

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
	//read configuration file
	int res;
	config_t cfg;
	config_setting_t *setting;

	config_init(&cfg);
	if (!config_read_file(&cfg, "mconfig.cfg"))
	{
		fprintf(stderr, "%s:%d - %s\n", config_error_file(&cfg),
		        config_error_line(&cfg), config_error_text(&cfg));
		config_destroy(&cfg);
		return(EXIT_FAILURE);
	}

	m_advp = (advp*)malloc(sizeof(advp));
	if (m_advp == NULL) {
		log_err("Failed to create advp structure");
		return -1;
	}
	m_advp->update_send_timer = time(NULL) + ROUTE_UPDATE_INTERVAL;
	m_advp->if_list_head = NULL;
	m_advp->re_list_head = NULL;

	setting = config_lookup(&cfg, "advp.interfaces");
	res = init_ifs(setting);
	if (res == -1) {
		log_err("Failed to initialize all the interfaces");
		exit(EXIT_FAILURE);
	}

	m_advp->gw_info = (gateway_info*)malloc(sizeof(gateway_info));
	setting = config_lookup(&cfg, "advp.gateway");
	res = init_gateway(setting);
	if (res == -1) {
		log_err("Failed to initialize gateway");
		exit(EXIT_FAILURE);
	}
	
	m_advp->neighbor_hp = hashmap_new(50);
	if (m_advp->neighbor_hp == NULL) {
		log_err("Failed to initialize neighbor hashmap");
		return -1;
	}

	return 0;
}

/**
 * insert all the valid active network interfaces to the interface list
 * @param if_list head of the interface list
 * @param active_ifs name of the active network interface
 * @return 0 on success or -1 on failure
 */
int init_ifs(config_setting_t *if_setting)
{

	interface *cur_if = NULL;

	if (if_setting) {
		int count = config_setting_length(if_setting);
		int i;
		printf("%-30s %-30s %-30s %-30s\n", "IF_NAME", "IP", "NETMASK", "ACTIVE");
		for (i = 0; i < count; i++) {
			config_setting_t *conf_if = config_setting_get_elem(if_setting, i);
			const char *if_name = NULL;
			const char *ip = NULL;
			const char *netmask = NULL;

			int active = 0;
			if (!(config_setting_lookup_string(conf_if, "if_name", &if_name)
				&& config_setting_lookup_string(conf_if, "ip", &ip)
				&& config_setting_lookup_string(conf_if, "netmask", &netmask)
				&& config_setting_lookup_int(conf_if, "active", &active)))
				continue;
			printf("%-30s %-30s %-30s %-30d\n", if_name, ip, netmask, active);

			cur_if = (interface*)malloc(sizeof(interface));
			if (cur_if == NULL) {
				log_err("Failed to create interface:%s", if_name);
				return -1;
			}

			strcpy(cur_if->ifname, if_name);
			cur_if->active = active;
			cur_if->ifnumber = if_nametoindex(if_name);
			cur_if->ip = inet_addr(ip);
			cur_if->mask = inet_addr(netmask);
			cur_if->network = cur_if->ip & cur_if->mask;

			get_broadcast(cur_if);

			set_if_info(cur_if);
			if (set_if_fds(cur_if) == -1)
				return -1;
			//insert the current interface to the head of the list
			if (m_advp->if_list_head == NULL) {

				m_advp->if_list_head = cur_if;
				cur_if->next = NULL;

			} else {
				cur_if->next = m_advp->if_list_head;
				m_advp->if_list_head = cur_if;
			}
		}
	}

	cur_if = m_advp->if_list_head;
	while (cur_if != NULL) {
		print_if(cur_if);
		cur_if = cur_if->next;
	}
	
	return 0;
}
/**
 * get infomation about current network interface
 * @param  cif name of the current network interface
 * @return     0 on success or -1 on failure
 */
 int set_if_info(interface *cif)
 {
 	struct ifreq ifr;
 	int fd;
 	struct sockaddr_in address;

 	fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
 	strncpy(ifr.ifr_name, cif->ifname, sizeof(ifr.ifr_name));

 	address.sin_family = AF_INET;
 	address.sin_addr.s_addr = cif->ip;
 	memcpy(&ifr.ifr_addr, &address, sizeof(struct sockaddr));
 	
 	if (ioctl(fd, SIOCSIFADDR, &ifr) < 0) {
 		log_err("Failed to set %s's ip address", cif->ifname);
 		return -1;
 	}

 	address.sin_addr.s_addr = cif->mask;
 	memcpy(&ifr.ifr_addr, &address, sizeof(struct sockaddr));

 	if (ioctl(fd, SIOCSIFNETMASK, &ifr) < 0) {
 		log_err("Failed to set %s's netmask", cif->ifname);
 		close(fd);
 		return -1;
 	}

 	if (!(ifr.ifr_flags & IFF_UP)) {
 		log_info("up interface :%s", cif->ifname);
 		ifr.ifr_flags |= IFF_UP;
 		if (ioctl(fd, SIOCSIFFLAGS, &ifr) < 0) {
 			log_err("Failed to up %s", cif->ifname);
 			close(fd);
 			return -1;
 		}
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

int init_gateway(config_setting_t *gw_setting)
{
	const char *if_name = NULL;
	const char *ping_gw_ip = NULL;
	const char *ping_ip = NULL;
	const char *netmask = NULL;
	int res;

	if (!(config_setting_lookup_string(gw_setting, "if_name", &if_name)
		&&config_setting_lookup_string(gw_setting, "ping_ip", &ping_ip)
		&&config_setting_lookup_string(gw_setting, "ping_gw_ip", &ping_gw_ip)
		&&config_setting_lookup_string(gw_setting, "netmask", &netmask))) {
		return -1;
	}
	strcpy(m_advp->gw_info->ping_if, if_name);
	m_advp->gw_info->ping_ip = inet_addr(ping_ip);
	m_advp->gw_info->netmask = inet_addr(netmask);
	m_advp->gw_info->ping_gw_ip = inet_addr(ping_gw_ip);
	m_advp->gw_info->default_gw_ip = inet_addr(ping_gw_ip);
	m_advp->gw_info->rtt = 5000;
	m_advp->gw_info->expire_timer = time(NULL) + GW_EXPIRE_INTERVAL;
	m_advp->gw_info->ping_if_status = IF_ONLINE;
	if (pthread_mutex_init(&m_advp->gw_info->gw_info_lock, NULL) != 0) {
		log_err("Failed to initialize gi list's lock");
		free(m_advp->gw_info);
		return -1;
	}	


	//add ping gateway route entry
	res = add_gw_re();
	res = add_default_re();
	printf("%-30s %-30s\n", ping_ip, ping_gw_ip);

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
	interface *cur_if = m_advp->if_list_head;
	route_entry *cur_rte = NULL;
	assert(cur_if != NULL);

	while (cur_if) {
		cur_rte = (route_entry*)malloc(sizeof(route_entry));
		if (cur_rte == NULL) {
			log_err("Failed to create route entry");
			continue;
		}
		cur_rte->dst =  cur_if->network;
		cur_rte->netmask = cur_if->mask;
		cur_rte->gateway = 0;
		cur_rte->metric = 0;
		cur_rte->type = LOCAL_ROUTE_ENTRY;
		cur_rte->flags = VALID_ROUTE_ENTRY;
		cur_rte->expire_timer = NOTUSED_TIMER;
		cur_rte->holddown_timer = NOTUSED_TIMER;
		cur_rte->ifnumber = -1;

		if (m_advp->re_list_head == NULL) {
			cur_rte->next = NULL;
			m_advp->re_list_head = cur_rte;
		} else {
			cur_rte->next = m_advp->re_list_head;
			m_advp->re_list_head = cur_rte;
		}
		cur_if = cur_if->next;
	}

	cur_rte = m_advp->re_list_head;
    //just for debugging
	while (cur_rte) {
		print_route_entry(cur_rte);
		cur_rte = cur_rte->next;
	}
	return 0;
}

/**
 * check whether specific interface is online
 * @param  name of the interface
 * @return     0 on down or 1 on up
 */
int is_if_online(char *if_name)
{
	struct ifreq ifr;
	int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, if_name);
	if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0) {
	    perror("SIOCGIFFLAGS");
	}
	close(sock);
	return (ifr.ifr_flags & IFF_UP);
}
/**
 * in order to send icmp packets through 3G router,we have to let
 * the 3G router to be the gateway to the ping address.
 * @return         0 on success or -1 on failure
 */
int add_gw_re()
{
	route_entry re;
	int res;

	gateway_info *gw_info = m_advp->gw_info;
	re.ifnumber = if_nametoindex(gw_info->ping_if);
	re.dst = m_advp->gw_info->ping_ip;
	re.gateway = m_advp->gw_info->ping_gw_ip;
	re.netmask = m_advp->gw_info->netmask;
	re.metric = 1;

	res = kernel_route(ROUTE_ADD, &re, NULL);
	if (res < 0) {
		log_err("Failed to add gateway route entry");
		return -1;
	}
	printf("add ping gateway route entry\n");
	return 0;
}

/**
 * add default route entry
 * @return 0 on success or -1 on failure
 */
int add_default_re()
{
	route_entry *re = (route_entry*)malloc(sizeof(route_entry));
	if (re == NULL) {
		log_err("Failed to create default route entry");
		return -1;
	}

	interface *cif = (interface*)malloc(sizeof(interface));
	if (cif == NULL) {
		log_err("Failed to create default route entry's interface");
		free(re);
		return -1;
	}

	int res;
	re->ifnumber  = if_nametoindex(m_advp->gw_info->ping_if);
	re->dst = 0;
	re->netmask = 0;
	re->gateway = m_advp->gw_info->ping_gw_ip;
	re->metric = 0;

	res = kernel_route(ROUTE_ADD, re, NULL);
	if (res < 0) {
		log_err("Failed to add gateway route entry");
		return -1;
	}
	m_advp->default_re = re;
	printf("add default route entry\n");

	return 0;
}

int modify_default_re(int ifnumber, in_addr_t sender_ip)
{
	route_entry *new_re = (route_entry*)malloc(sizeof(route_entry));
	if (new_re == NULL) {
		log_err("Failed to create default route entry");
		return -1;
	}

	int res;

	new_re->ifnumber = ifnumber;
	new_re->dst = 0;
	new_re->netmask = 0;
	new_re->gateway = m_advp->gw_info->default_gw_ip;
	new_re->metric = 0;

	assert(sender_ip == m_advp->gw_info->default_gw_ip);

	res = kernel_route(ROUTE_MOD, m_advp->default_re, new_re);

	free(m_advp->default_re);

	m_advp->default_re = new_re;

	return res;
}
/**
 * add new route entry into the route entry list
 * @param  r rip route entry in rip packet
 * @param  recvif on which interface receive the rip packet
 * @param  sender_ip neighbor's ip address
 * @return        0 on success or -1 on failure
 */
int re_list_add(route_entry *new_re)
{
	int res;

	new_re->next = m_advp->re_list_head;
	m_advp->re_list_head = new_re;
	
	res = kernel_route(ROUTE_ADD, new_re, NULL);
	log_info("new route entry inserted");
	print_route_entry(new_re);

	return res;
}
/**
 * delete the expired route entry
 * when expire_timer and holddown timer both expired
 * @param  re route entry to be deleted
 * @return    0 on success or -1 on failure
 */
int re_list_delete(route_entry *cur_re)
{

	assert(cur_re != NULL);
	int res;

	res = kernel_route(ROUTE_DEL, cur_re, NULL);
	if (cur_re->next == NULL) {
		free(cur_re);
		cur_re = NULL;

	} else {
		route_entry *next_re = cur_re->next;
		memcpy(cur_re, next_re, sizeof(route_entry));
		cur_re->next = next_re->next;
		free(next_re);
	}


	return res == 0 ? 0 : -1;
}

/**
 * modify route entry
 * @param  old_re old route entry
 * @param  new_re new route entry
 * @return        0 on success or -1 on failure
 */
int re_list_modify(route_entry *old_re, route_entry *new_re)
{
	int res;
	log_info("upate a route entry");
	log_info("From:");
	print_route_entry(old_re);
	log_info("To:");
	print_route_entry(new_re);
	
	res = kernel_route(ROUTE_MOD, old_re, new_re);
	copy_route_entry(old_re, new_re);

	return res;
}



/**
 * count how many route entry should send through specific interface
 * @param  cif which interface to send to
 * @return     num of route entry
 */
int count_re4if(interface *cif)
{
	route_entry *re = m_advp->re_list_head;
	int cnt = 0;
	while (re) {
		if (re->ifnumber != cif->ifnumber)
			cnt++;
		re = re->next;
	}

	return cnt;
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
	
	int nwrite;
	struct sockaddr_in remote_server;
	remote_server.sin_family = AF_INET;
	remote_server.sin_addr.s_addr = cif->broadcast;
	remote_server.sin_port = htons(RIP_BROADCAST_PORT);

	nwrite = sendto(cif->send_fd, rp, size, 0, (struct sockaddr*)&remote_server, sizeof(remote_server));

	return nwrite;
}

/**
 *prepare a rip packet send to specific interface
 *@parama cif interface to send to
 *@param rte_num get the rip route entry number
 *@return rip packet construct for specific interface
 */
rip_packet *prepare_rip_packet(interface *cif, int type, int *rte_num)
{
	
	route_entry *re = NULL;
	rte *cur_r = NULL;
    rip_packet *rp = NULL;


    if (type == USUAL_UPDATE) {
    	re = m_advp->re_list_head;
    	*rte_num = count_re4if(cif);
    } else {
    	return NULL;
    }
    debug("prepare rip packet rte_num = %d", *rte_num);
    int rip_packet_size = sizeof(rip_packet) + (*rte_num) * sizeof(rte);
    rp = (rip_packet*)malloc(rip_packet_size);
    if (rp == NULL) {
        log_err("Failed to create rip packet");
        return NULL;
    }
    memset(rp, 0, rip_packet_size);
    // rp->command = RIP_RESPONSE;
    // rp->version = RIP_VERSION;
    // rp->pad1 = 0;
    // rp->pad2 = 0;
    
    rp->send_time = time(NULL);
    //poison reverse
    if (cif->ifnumber == m_advp->gw_info->default_gw_ifnumber)
    	rp->rtt = 5000;
    else {
    	pthread_mutex_lock(&(m_advp->gw_info->gw_info_lock));
    	rp->rtt = m_advp->gw_info->rtt;
    	pthread_mutex_unlock(&(m_advp->gw_info->gw_info_lock));
    }
  
    //dont forget to cast rp to char* or the pointer will 
    //forward sizeof(rip_packet) * sizeof(rip_packet)
    //not just sizeof(rip_packet)
	cur_r = (rte*)((char*)rp + sizeof(rip_packet));

	while (re) {
		//don't include the route entry receive from interface cif
		if (re->ifnumber != cif->ifnumber) {
			cur_r->family = 0;
			cur_r->tag = 0;
			cur_r->dst = re->dst;

			cur_r->netmask = re->netmask;
			cur_r->gateway = re->gateway;
			cur_r->metric = re->metric;
			//print_rte(cur_r);
			cur_r++;
		}

		re = re->next;
		
	}

    return rp;
}

/**
 * send rip packet through specific network interface
 * @param rp      rip packet
 * @param rte_num rte num in the packet
 * @param cif     network interface name
 */
void send_rip_packet(rip_packet *rp, int rte_num, interface *cif) 
{
    int size = get_rip_packet_size(rte_num);
	int res;
    
    res = sendto_if(cif, rp, size);
    if (res == -1) {
    	log_err("Failed send rip packet through interface:%s", cif->ifname);
    }
    return;
}

/**
 * judge whether the gateway info is worth to insert into gateway info list
 * walk through the rtes in the rip packet
 * judge whether each rte is worth to insert into the route entry list
 * @param rte_num rte count in the rip packet
 */
void process_rip_packet(rip_packet *rp, int rte_num, interface* recvif, in_addr_t sender_ip) 
{
	debug("enter process_rip_packet");

	process_gw_info(rp->rtt, recvif->ifnumber, sender_ip);
	//check earch rip route entry
	rte *r = (rte*)((char*)rp + sizeof(rip_packet));
	int i;
	for (i = 0; i < rte_num; i++) {
		process_rte(r, recvif, sender_ip);
		r++;
	}
	debug("leave process_rip_packet");
}

//两个timeval相减
static void tv_sub(struct timeval *out, struct timeval *in)
{
    if ((out->tv_usec -= in->tv_usec) < 0) {   /* out -= in */
        --out->tv_sec;
        out->tv_usec += 1000000;
    }
    out->tv_sec -= in->tv_sec;
}

/**
 * compute the link quality
 * @param  sender_ip sennder ip of the rip update message
 * @return           link delay in milliseconds
 */
int compute_link_qty(in_addr_t sender_ip)
{
	struct timeval cur;
	struct timeval last;
	long interval;
	gettimeofday(&cur, NULL);
	if (hashmap_search(m_advp->neighbor_hp, sender_ip) == NULL) {
		hashmap_put(m_advp->neighbor_hp, sender_ip, &cur, sizeof(struct timeval));
		return 5000;
	}

	hashmap_get(m_advp->neighbor_hp, sender_ip, &last, sizeof(struct timeval));
	hashmap_put(m_advp->neighbor_hp, sender_ip, &cur, sizeof(struct timeval));
	tv_sub(&cur, &last);
	interval = cur.tv_sec * 1000 + cur.tv_usec / 1000;
	debug("interval = %ld", interval);
	/**
	 * The update interval maybe a little shorter than ROUTE_UPDATE_INTERVAL,
	 * but not too much
	 */
	if (interval - SECOND_TO_MILLSECOND(ROUTE_UPDATE_INTERVAL) < 0) {
		if (abs(interval- SECOND_TO_MILLSECOND(ROUTE_UPDATE_INTERVAL)) < 3)
			return (interval - SECOND_TO_MILLSECOND(ROUTE_UPDATE_INTERVAL) + 3);
		else {
			log_err("route update interval is a liitle bit short");
			return 0;
		}
		
	} 

	return interval - SECOND_TO_MILLSECOND(ROUTE_UPDATE_INTERVAL);
}

void process_gw_info(uint16_t rtt, int ifnumber, in_addr_t sender_ip)
{
	log_info("receive rtt = %d\n", rtt);

	int link_qty = compute_link_qty(sender_ip);
	log_info("link qty = %d", link_qty);
	pthread_mutex_lock(&(m_advp->gw_info->gw_info_lock));

	if (sender_ip == m_advp->gw_info->default_gw_ip) {
		m_advp->gw_info->rtt = rtt + 2 * link_qty;
		m_advp->gw_info->expire_timer = time(NULL) + GW_EXPIRE_INTERVAL;
	} else {
		//better gateway
		if (rtt + 2 * link_qty < m_advp->gw_info->rtt) {
			debug("a better gateway:rtt = %d\n", rtt + 2 * link_qty);
			m_advp->gw_info->rtt = rtt + 2 * link_qty;
			m_advp->gw_info->default_gw_ip = sender_ip;
			m_advp->gw_info->default_gw_ifnumber = ifnumber;
			m_advp->gw_info->expire_timer = time(NULL) + GW_EXPIRE_INTERVAL;
			
			modify_default_re(ifnumber, sender_ip);
		}
	}
	pthread_mutex_unlock(&(m_advp->gw_info->gw_info_lock));
}

route_entry *search4rte(rte *r)
{
	route_entry *re = m_advp->re_list_head;
	while (re) {
		if (re->dst == r->dst)
			return re;
		re = re->next;
	}

	return NULL;
}

int is_better_re(route_entry *new_re, route_entry *old_re)
{
	if (new_re->metric < old_re->metric)
		return 1;
	return 0;
}

int is_same_gateway(route_entry *new_re, route_entry *old_re)
{
	return new_re->gateway == old_re->gateway;
}

void copy_route_entry(route_entry *dst, route_entry *src)
{
	route_entry *old_next = dst->next;
	memcpy(dst, src, sizeof(route_entry));
	dst->next = old_next;
}

void process_rte(rte *r, interface *recvif, in_addr_t sender_ip)
{

	r->metric = (r->metric + 1 >= INFINITY ? INFINITY : r->metric + 1);
	in_addr_t gateway;

	gateway = sender_ip;

	route_entry *old_re = search4rte(r);
	route_entry new_re;
	route_entry *new_re_p = NULL;

	time_t now = time(NULL);
	new_re.dst = r->dst;
	new_re.gateway = gateway;
	new_re.netmask = r->netmask;
	new_re.metric = r->metric;

	if (r->metric != INFINITY) {
		new_re.flags = VALID_ROUTE_ENTRY;
		new_re.expire_timer = now + EXPIRE_INTERVAL;
		new_re.holddown_timer = now + EXPIRE_INTERVAL +  HODLDOWN_INTERVAL;
	}
	else{
		log_info("Receive an expired route entry");
		new_re.flags = INVALID_ROUTE_ENTRY;
		new_re.expire_timer = old_re->expire_timer;
		new_re.holddown_timer = old_re->holddown_timer;
	}
	new_re.type = NON_LOCAL_ROUTE_ENTRY;
	new_re.ifnumber = recvif->ifnumber;

	if (old_re) {

		if (old_re->type == LOCAL_ROUTE_ENTRY || old_re->flags == INVALID_ROUTE_ENTRY)
			return;
		if (is_better_re(&new_re, old_re) || (is_same_gateway(&new_re, old_re) && (new_re.metric != old_re->metric))){
			re_list_modify(old_re, &new_re);
			return;  
		} else  if (is_same_gateway(&new_re, old_re)) {
			old_re->expire_timer = now + EXPIRE_INTERVAL;
			old_re->holddown_timer = now + EXPIRE_INTERVAL + ROUTE_UPDATE_INTERVAL;
		}

		return;
	}

	if (new_re.flags == INVALID_ROUTE_ENTRY)
		return;
	//fresh rte
	debug("fresh rte");
	new_re_p = (route_entry*)malloc(sizeof(route_entry));
	if (new_re_p == NULL) {
		log_err("Failed to create new_re");
		return;
	}
	memcpy(new_re_p, &new_re, sizeof(route_entry));
	re_list_add(new_re_p);
}

/**
 * broadcast route entry update message
 */
void broadcast_update_msg(int type)
{
	rip_packet *rp = NULL;
	interface *cif = m_advp->if_list_head;
    int rte_num = 0;
    assert(type == USUAL_UPDATE || type == URGENT_UPDATE);
	for (; cif != NULL; cif = cif->next) {
		if (cif->active) {
			rp = prepare_rip_packet(cif, USUAL_UPDATE, &rte_num);
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
int process_upcoming_msg(void *data)
{
	interface *cif = (interface*)data;
    char buffer[MAX_RIP_PACKET_SIZE];
	struct sockaddr_in sender_addr;
	socklen_t sender_len;
	int nread;
	int rte_num;

	sender_len = sizeof(sender_addr);
    memset(&buffer, 0, MAX_RIP_PACKET_SIZE);

	nread = recvfrom(cif->recv_fd, &buffer, MAX_RIP_PACKET_SIZE, 0, (struct sockaddr *)&sender_addr, &sender_len);
	if (nread < 0) {
		log_err("Failed to read rip packet from fd:%d", cif->recv_fd);
		close(cif->recv_fd);
		return -1;
	}
	//ignore the broadcast packets send by itself
	if (!is_local_ip(sender_addr.sin_addr.s_addr)) {
		log_info("Receive rip update messages");
		rte_num = get_rte_num(nread);
		assert(rte_num > 0);
		debug("nread = %d", nread);
		log_info("Receive a route update message from interface:%s,which contain %d route entr%s", cif->ifname, rte_num, (rte_num == 1) ? "y\b": "ies");
		print_rip_packet((rip_packet*)&buffer, rte_num);
		process_rip_packet((rip_packet*)&buffer, rte_num, cif, sender_addr.sin_addr.s_addr);
	} else
		log_info("Ignore a packet send by itself!");

	return 0;
}

void process_time_event()
{

	/**
	 * loop through all the time event,judge whethe it should be triggered
	 */
	//1.check update timer
	time_t cur_time = time(NULL);
	if (m_advp->update_send_timer <= cur_time) {
		print_re_list();
		broadcast_update_msg(USUAL_UPDATE);
		m_advp->update_send_timer = cur_time + ROUTE_UPDATE_INTERVAL;
	}


	//2. check expire_timer and holddown_timer in route_entry, 
	//if expore_timer timeout change flag to INVALID_ROUTE_ENTRY, delete 
	//holddown entry when its holddown timer is below or equall to zero
	check_route_list();
	//3. traverse the route entry list and print each route entry
	//print_re_list();
	check_gw_info();

	//check whether the 3G router interface is down to up
	//if so add the ping gateway route entry
	check_if_status();
}

/**
 * check the route entry list
 * update specific timers in the route entry
 * check whether the route entry is expired
 * delete the expired route entry
 */
void check_route_list()
{
	route_entry *re = m_advp->re_list_head;
	while (re != NULL) {
		//LOCAL ROUTE ENTRY will never expire
		if (re->type != LOCAL_ROUTE_ENTRY) {
			//decrease the expire timer
			if (re->flags == VALID_ROUTE_ENTRY) {
				//set flag to INVALID_ROUTE_ENTRY, set matrix to INFINITY
				//modify the kernel routing table
				if (re->expire_timer <= time(NULL)) {

					route_entry new_re;
					memcpy(&new_re, re, sizeof(route_entry));
					new_re.flags = INVALID_ROUTE_ENTRY;
					new_re.metric = INFINITY;
					
					log_info("find an invalid route entry try to broadcast to all neighbors");
					re_list_modify(re, &new_re);
					
					//broadcast_update_msg(URGENT_UPDATE);
				}
			} else {
				//remove route entry from user space and kernel space routing table
				if (re->holddown_timer <= time(NULL)) {
					log_err("Begin to delete route from route entry list");
					print_route_entry(re);
					re_list_delete(re);
				}
			}
			
		}

		re = re->next;
	}
}

/**
 * check wheter the gateway information is invalid
 */
void check_gw_info()
{
	pthread_mutex_lock(&(m_advp->gw_info->gw_info_lock));
	if (m_advp->gw_info->expire_timer <= time(NULL)) {
		log_info("gateway expired");
		m_advp->gw_info->rtt = 5000;
		m_advp->gw_info->expire_timer = time(NULL) + GW_EXPIRE_INTERVAL;
	}
	char ip[IP_STR_LEN];
	ip_to_str(m_advp->gw_info->default_gw_ip, ip);
	log_info("Check gw info, rtt = %d, gw = %s", m_advp->gw_info->rtt, ip);
	pthread_mutex_unlock(&(m_advp->gw_info->gw_info_lock));
}

/**
 * check whether the 3G router interface is down to up
 * if so we should add the ping gateway route entry
 * @param if_name name of the interface
 */
void check_if_status()
{
	printf("check if status\n");
	char *if_name = m_advp->gw_info->ping_if;
	if (is_if_online(if_name)) {
		if (m_advp->gw_info->ping_if_status == IF_OFFLINE) {
			m_advp->gw_info->ping_if_status = IF_ONLINE;
			printf("%s is down to up\n", if_name);
			add_gw_re();
			add_default_re();
		}
	} else {
		m_advp->gw_info->ping_if_status = IF_OFFLINE;
		printf("%s is offline\n", if_name);
	}
}
/**
 * add various events to epoll
 * @param efd epool fd
 */
void epoll_add_events(int efd)
{
	interface *cur_if = m_advp->if_list_head;
	assert(cur_if != NULL);
	struct epoll_event event;
	int res;

	while (cur_if) {
		if (cur_if->active) {
			log_info("Add interface:%s's recv_fd:%d to epoll", cur_if->ifname, cur_if->recv_fd);
			//event.data.fd = cur_if->recv_fd;
			event.data.ptr = cur_if;
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

/**
 * search nearest time event
 * @return when the nearest time event should be triggered
 */
time_t search_nearest_timer()
{
	time_t shortest = m_advp->update_send_timer;
	route_entry *re = m_advp->re_list_head;


	debug("update timer = %ld", m_advp->update_send_timer);
	while (re && re->type == NON_LOCAL_ROUTE_ENTRY) {
		if (re->flags == VALID_ROUTE_ENTRY) {
			if (re->expire_timer < shortest)
				shortest = re->expire_timer;
		} else {
			if (re->holddown_timer < shortest)
				shortest = re->holddown_timer;
		}
		re = re->next;
	}
	
	if (m_advp->gw_info->expire_timer < shortest)
		shortest = m_advp->gw_info->expire_timer;

	return shortest;
}

int create_detection_thread()
{

	pthread_t detection_thread;
	int rv;
	rv = pthread_create(&detection_thread, NULL, 
		start_detection_service, (void*)m_advp->gw_info);
   	
   	if (rv != 0) {
   		
   		return -1;
   	}

   	return 0;
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

	while (1) {
		int n, i;

		time_t shortest = search_nearest_timer();
		time_t now = time(NULL);
		int timeout = abs(SECOND_TO_MILLSECOND(shortest - now));
		


		n = epoll_wait(efd, events, MAX_EPOLL_EVENTS, timeout);
		debug("n = %d", n);
		if (n > 0 ){
			//read route update message from specific sock fd
			for (i = 0; i < n; i++) {
				if ((events[i].events & EPOLLERR) ||
					(events[i].events & EPOLLHUP) ||
					(!events[i].events & EPOLLIN)) {
					log_err("An error has occured on fd:%d", events[i].data.fd);
					close(events[i].data.fd);
					continue;
				
				} else {
					process_upcoming_msg(events[i].data.ptr);
				}	
			}
		}
		process_time_event();
	}
}

int main(int argc, char const *argv[])
{

	assert(sizeof(rip_packet) == 6);
	assert(sizeof(rte) == 18);
	int res;

	res = init_system();
	if (res == -1) {
		log_err("Failed to initialize system variables");
		exit(EXIT_FAILURE);
	}

	res = add_local_rtes();
	if (res == -1) {
		log_err("Failed to add local route entries");
		exit(EXIT_FAILURE);
	}
	res = create_detection_thread();
	if (res == -1) {
		log_err("Failed to create detection thread");
		exit(EXIT_FAILURE);
	}
	start_route_service();
	sleep(1000);
	return 0;
}
