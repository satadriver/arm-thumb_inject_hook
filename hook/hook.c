#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include "inlineHook.h"

int (*old_puts)(const char *) = NULL;

int new_puts(const char *string)
{
    return old_puts("inlineHook 32 success");
}

void test1_new(char * param){
    printf("test1_new\r\n");
    old_puts(param);
}

void test1(char * param){
    printf("test1\r\n");
}

int hook()
{
    if (registerInlineHook((uint32_t) test1, (uint32_t) test1_new, (uint32_t **) &old_puts) != 
    ELE7EN_OK) {
        printf("registerInlineHook error:%d\r\n",errno);
        return -1;
    }
    if (inlineHook((uint32_t) test1) != ELE7EN_OK) {
        printf("inlineHook error:%d\r\n",errno);
        return -1;
    }

    printf("hook ok\r\n");

    return 0;
}

int unHook()
{
    if (inlineUnHook((uint32_t) test1) != ELE7EN_OK) {
        printf("inlineUnHook error:%d\r\n",errno);
        return -1;
    }

    return 0;
}

int InjectEntry(char * param)
{
    FILE * fp = freopen("/tmp/ljg.txt","ab+",stdout);
    test1("test0");
    getchar();
    hook();
    test1("test1");
    getchar();
    unHook();
    test1("test2");
    fclose(fp);
    return 0x12345678;
}