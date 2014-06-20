#ifndef __LOG__
#define __LOG__

#include <stdio.h>
#include <errno.h>
#include <string.h>

#define ESC_START       "\033["
#define ESC_END         "\033[0m"
#define COLOR_ERROR     "35;1m"
#define COLOR_INFO      "32;1m"
#define COLOR_DEBUG     "36;1m"

//get the absolute filename of a file
#define __FILENAME__ strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__

#ifdef NDEBUG
#define debug(M, ...)
#else
#define debug(M, ...) fprintf(stderr, ESC_START COLOR_DEBUG "DEBUG %s:%d: " M "\n" ESC_END, __FILENAME__, __LINE__, ##__VA_ARGS__)
#endif

#define clean_errno() (errno == 0 ? "None" : strerror(errno))

#define log_err(M, ...) fprintf(stderr, ESC_START COLOR_ERROR "[ERROR] (%s:%d: errno: %s) " M "\n" ESC_END, __FILENAME__, __LINE__, clean_errno(), ##__VA_ARGS__)
#define log_info(M, ...) fprintf(stderr, ESC_START COLOR_INFO "[INFO] (%s:%d) " M "\n" ESC_END, __FILENAME__, __LINE__, ##__VA_ARGS__)

#endif