#include <stdio.h>
#include <stdlib.h> //为了使用exit()
int main(){
	int ch;
	FILE* fp;
	char fname[50]; //用于存放文件名
	printf("输入文件名：");
	scanf("%s",fname);
	fp=fopen(fname,"w+"); //只供读取
	if(fp==NULL){
		printf("错误！");
		exit(1); //中止程序
	}
//getc()用于在打开文件中获取一个字符 
	while((ch=getc(fp))!=EOF)
	putchar(ch);
	fclose(fp); //关闭文件 
	return 0;
} 
