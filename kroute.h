#include <inttypes.h>
#include <netinet/in.h>

#include "route_engine.h"

#ifndef ADVRP_KERN_H
#define ADVRP_KERN_H

#define ROUTE_ADD 0
#define ROUTE_DEL 1
#define ROUTE_MOD 2

int kernel_route(int command, route_entry *re, route_entry *new_re);

#endif
