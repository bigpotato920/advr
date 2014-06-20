#include <stdio.h>
#include <string.h>

#include "../route_engine.h"

int main(int argc, const char *argv[])
{
    interface cif;
    strcpy(cif.ifname, "eth0");
    get_if_info(&cif);
    strcpy(cif.ifname, "eth1");
    get_if_info(&cif);
    return 0;
}
