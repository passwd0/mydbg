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
	int found = 0;
	int l = strlen(src);
	for (int i=0; i<l; i++){
		if (!isxdigit(src[i])){
			found = 1;
		}
	}
	return !found;
}