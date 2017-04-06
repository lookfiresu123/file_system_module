#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

int main(){
	open("zhao1", O_RDWR|O_CREAT, 0666);
	//open("zhao2", O_RDWR|O_CREAT, 0666);
	return 0;
} 
