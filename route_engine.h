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
	struct interface * next;
	struct interface * prev;
} interface;