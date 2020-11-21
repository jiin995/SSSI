#include <stdio.h>

typedef void (*fptr)(void);

int main(){
 	fptr  ptrs[3] = { NULL};

	//printf("%ld",sizeof(ptrs[0]));
	
	char  buf[1024] = {0};
	int r;
	r = read(0, buf, sizeof(buf)-sizeof(char));
	buf[r] = '\0';
	int s = atoi(buf);
	printf("%ld",s);			
}
