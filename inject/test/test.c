/*
 * target.c
 *
 *  Created on: 2015年6月26日
 *      Author: Administrator
 */

#include<stdio.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/mman.h>


#include <sys/types.h>
#include <sys/wait.h>

#include <dlfcn.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <asm/ptrace.h>

int main(int argc,char **argv)
{

	void * addr = mmap(0,0x1000,PROT_READ | PROT_WRITE | PROT_EXEC,MAP_ANONYMOUS | MAP_PRIVATE,0,0);

	printf("mmap:%x\r\n",addr);

	static unsigned int i =0;
	while(1){
		sleep(1);
		printf("i am target program %d",i++);
		break;
	}
	return 0;
}
