#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>

#include "../kroute.h"

int main(int argc, char const *argv[])
{
	route_entry cur_rte1, cur_rte2;
	interface cif;
	int res;

	cif.ifnumber = 2;
	cur_rte1.dst = inet_addr("192.168.201.0") ;
	cur_rte1.genmask = inet_addr("255.255.255.0");
	cur_rte1.gateway = inet_addr("10.103.240.202");
	cur_rte1.metric = 1;

	cur_rte1.recvif = &cif;

	cur_rte2.dst = inet_addr("192.168.201.0") ;
	cur_rte2.genmask = inet_addr("255.255.255.0");
	cur_rte2.gateway = inet_addr("10.103.240.202");
	cur_rte2.metric = 2;

	cur_rte2.recvif = &cif;

	//res = kernel_route(ROUTE_ADD, &cur_rte1, NULL);
	//res = kernel_route(ROUTE_MOD, &cur_rte1, &cur_rte2);
	res = kernel_route(ROUTE_DEL, &cur_rte2, NULL);
	printf("res = %d\n", res);
	return 0;
}