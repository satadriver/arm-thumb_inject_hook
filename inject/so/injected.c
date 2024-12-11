/*
 * hello.c
 *
 *  Created on: 2015年6月26日
 *      Author: Administrator
 */



#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <elf.h>
#include <fcntl.h>
#include <syslog.h>
#include <string.h>

#define LOG_TAG "[liujinguang]"

//#define LOGD(fmt, args...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, fmt, ##args)

#define LOGD(fmt, args...) printf(fmt, ##args)

//#define LOGD(fmt, args...) syslog(LOG_DEBUG,fmt, ##args)

int InjectEntry(char * param){

    FILE *fp = freopen("/tmp/ljg.txt","ab+",stdout);

    LOGD("hello InjectEntry\r\n");
    LOGD("pid: %d,param:%s,file:%s,function:%s\n", getpid(),param,__FILE__,__FUNCTION__);

    openlog(LOG_TAG, LOG_CONS | LOG_PID, 0);
    syslog(LOG_DEBUG,"welcome to InjectEntry!\r\n");
    closelog();

    chdir("/tmp");
    char * args[] = {"/tmp/monolith", "--attach", NULL};
    execve(args[0], args, NULL);

    //char * str = "hello,how are you?\r\n";
    //fwrite(str,1,strlen(str),fp);  

    fclose (fp);
    
    return 0x12345678;
}
