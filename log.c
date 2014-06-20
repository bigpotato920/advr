#include "log.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>


int main(int argc, char const *argv[])
{
	debug("a = %d, b = %s", 1, "abc");
	log_err("can not send msg from %s to %s", "a", "b");
	printf("............................abc...........\n");
	log_info("can not send msg from %s to %s", "a", "b");
	printf("..............def.............................\n");
	debug("a = %d, b = %s", 1, "abc");
	return 0;
}