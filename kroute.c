/* kroute.c -- Add/remove routes to the kernel
 *
 * Most of the code here is adapted from Asanga Udugama's HOWTO for rtnetlink.
 * See his website: http://www.comnets.uni-bremen.de/~adu/
 *
 * The error checking code is mostly from libnetlink.c, part of the
 * iproute2 package.
 *
 * TODO: We "should" use the rtnetlink macros to add attributes, etc.,
 * but currently we do not.  In the future, it would be nice to use the
 * libnetlink library for all of this, which is a much cleaner interface.
 */

#include <stdio.h>
#include <sys/socket.h>
#include <asm/types.h>
#include <linux/rtnetlink.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <netinet/in.h>

#include "kroute.h"
#include "log.h"

/**
 * count network prefix length
 * for example "255.255.255.0" --> 24
 * @param  network network mask in network order
 * @return        	prefix length
 */
int count_prefix(in_addr_t network)
{
	int i = 0;
	int n = ntohl(network);

	while (n) {
		n = n << 1;
		i++;
	}

	return i;
}


/**
 * update kernel routing table with netlink
 * @param  command operation type
 * @param  re      route entry
 * @param  new_re  route enttry
 * @return         0 on success or nagtive on failure
 */
int kernel_route(int command, route_entry *re, route_entry *new_re)
{
	struct {
		struct nlmsghdr nl;
		struct rtmsg rt;
		char buf[8192];
	} req;
	char rbuf[8192];                  /* Reply buffer for errors */
	struct nlmsghdr * h;
	struct rtattr * attr;
	int fd;
	int len;
	struct sockaddr_nl laddr, paddr;  /* local, peer address */
	struct msghdr msg;
	struct iovec iov;
	int flags = 0;
	int type = 0;
	int ret;

	/* Make the message */
	bzero(&req, sizeof(req));
	len = sizeof(struct rtmsg);
	attr = (struct rtattr *) req.buf;

	switch (command) {
		case ROUTE_ADD:

			flags |= NLM_F_CREATE;
			type |= RTM_NEWROUTE;

			/* Add other route attributes if not local */
			req.rt.rtm_type = RTN_UNICAST;

			/* Exit interface */
			attr = (struct rtattr *) (((char *) attr) +
			        attr->rta_len);
			attr->rta_type = RTA_OIF;
			attr->rta_len = sizeof(struct rtattr) + 4;
			memcpy(((char *) attr) + sizeof(struct rtattr),
			       (int *) &(re->recvif->ifnumber), 1);
			len += attr->rta_len;
		
			/* Next hop */
			attr = (struct rtattr *) (((char *) attr) +
			        attr->rta_len);
			attr->rta_type = RTA_GATEWAY;
			attr->rta_len = sizeof(struct rtattr) + 4;
			memcpy(((char *) attr) + sizeof(struct rtattr),
			       (int *) &(re->gateway), 4);
			len += attr->rta_len;

			/* Metric */
			attr = (struct rtattr *) (((char *) attr) +
			        attr->rta_len);
			attr->rta_type = RTA_PRIORITY;
			attr->rta_len = sizeof(struct rtattr) + 4;
			memcpy(((char *) attr) + sizeof(struct rtattr),
			       (int *) &(re->metric), 1);
			len += attr->rta_len;
			
			break;
		case ROUTE_DEL:

			flags |= NLM_F_CREATE;
			type |= RTM_DELROUTE;
			break;
		case ROUTE_MOD:

			return kernel_route(ROUTE_DEL, re, NULL) + kernel_route(ROUTE_ADD, new_re, NULL);
	
		default:
			log_err("Unknown cmd passed to kernel_route: %d.", command);
			return -1;
			break;
	}

	if ((fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)) < 0) {
		log_err("Failed to create socket");
		return -1;
	}

	memset(&laddr, 0, sizeof(laddr));
	laddr.nl_family = AF_NETLINK;

	if (bind(fd, (struct sockaddr *) &laddr, sizeof(laddr)) < 0) {
		log_err("Cannot bind netlink socket.");
		close(fd);
		return 1;
	}

	/* Add the dst network attribute to all messages */
	attr = (struct rtattr *) (((char *) attr) + attr->rta_len);
	attr->rta_type = RTA_DST;
	attr->rta_len = sizeof(struct rtattr) + 4;
	memcpy(((char *) attr) + sizeof(struct rtattr), &re->dst,4);
	len += attr->rta_len;

	/* Set up netlink header */
	req.nl.nlmsg_len = NLMSG_LENGTH(len);
	req.nl.nlmsg_flags = NLM_F_REQUEST | flags;
	req.nl.nlmsg_type = type;

	/* Set up rtnetlink message */
	req.rt.rtm_family = AF_INET;
	req.rt.rtm_table = RT_TABLE_MAIN;
	req.rt.rtm_protocol = RTPROT_STATIC;
	req.rt.rtm_scope = RT_SCOPE_UNIVERSE;
	req.rt.rtm_dst_len = count_prefix(re->netmask);

	/* Set up the message header and peer address */
	memset(&msg, 0, sizeof(msg));
	msg.msg_name = (void *) &paddr;
	msg.msg_namelen = sizeof(paddr);
	iov.iov_base = (void *) &req.nl;
	iov.iov_len = req.nl.nlmsg_len;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	memset(&paddr, 0, sizeof(paddr));
	paddr.nl_family = AF_NETLINK;

	/* Send the message */
	if (sendmsg(fd, &msg, 0) <= 0) {
		log_err("Could not send route message to kernel.");
		close(fd);
		return -1;
	}

	/* Check for errors */
	errno = 0;
	if ((ret = recv(fd, &rbuf, sizeof(rbuf), MSG_DONTWAIT)) == -1) {
		/* EAGAIN is set if no message is waiting for us */
		if (errno == EAGAIN) {
			close(fd);
			return 0;
		} else {
			log_err("Could not receive response from kernel.");
			close(fd);
			return -1;
		}
	}

	h = (struct nlmsghdr *) rbuf;
	if (NLMSG_OK(h, ret) && h->nlmsg_type == NLMSG_ERROR) {
		struct nlmsgerr *err = (struct nlmsgerr *) NLMSG_DATA(h);
		log_err("Kernel responded: %s.", strerror(-err->error));
		close(fd);
		if (errno == 0)
			return 0;
		return -1;
	}
	close(fd);

	return 0;
}
