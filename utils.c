#include "utils.h"

int is_dec(char *src){
	int found = 0;
	int l = strlen(src);
	for (int i=0; i<l; i++){
		if (!isdigit(src[i])){
			found = 1;
		}
	}
	return !found;
}

int is_hex(char *src){
	int l = strlen(src);
	if (l <= 2 || src[0] != '0' || src[1] != 'x')
		return 0;
	
	int found = 0;
	for (int i=2; i<l; i++){
		if (!isxdigit(src[i])){
			return 0;
		}
	}
	return 1;
}