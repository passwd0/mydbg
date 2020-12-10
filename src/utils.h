#ifndef H_UTILS
#define H_UTILS

#include <ctype.h>
#include <string.h>
#include <sys/stat.h>

int is_dec(char *src);
int is_hex(char *src);
int cfileexists(const char* filename);
#endif