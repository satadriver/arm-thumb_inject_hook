
#include <dirent.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <unistd.h>
#include <stdint.h>
//#include <EGL/egl.h>
//#include <GLES/gl.h>
#include <elf.h>
#include <fcntl.h>
#include <sys/mman.h>
//#include <fstream>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <errno.h>

#define LOG_TAG "HOOKGOT"

//#define LOGD(fmt, args...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, fmt, ##args)
#define LOGD(fmt, args...) printf( fmt, ##args)
//#define LIBSF_PATH  "/data/app-lib/com.example.encript-1/libtest.so"
#define LIBSF_PATH  "/usr/lib/libc.so.6"

typedef int (*ptr_old_strcmp)(const char* c1, const char* c2) ;

ptr_old_strcmp old_strcmp = 0;

int new_strcmp(const char* c1, const char* c2)
{
    LOGD("[+]new_strcmp called [+]\n");
    LOGD("[+] s1 = %s [+]\n", c1);
    LOGD("[+] s2 = %s [+]\n", c2);
    if (old_strcmp == 0)
        LOGD("[+] error:old_strcmp = -1 [+]\n");
    return 0;
}







ssize_t readline(int fd, char *buffer, size_t n)
{
    ssize_t numRead;
    size_t totRead;
    char *buf;
    char ch;

    if (n <= 0 || buffer == NULL) {
        errno = EINVAL;
        return -1;
    }

    buf = (char*)buffer;

    totRead = 0;
    for (;;) {
        numRead = read(fd, &ch, 1);
        if (-1 == numRead) {
            if (errno == EINTR) {
                continue;
            } else {
                return -1;
            }
        } else if (numRead == 0) {
            if (totRead == 0) {
                return 0;
            } else {
                break;
            }
        } else {
            if (totRead < n - 1) {
                totRead++;
                *buf++ = ch;
            }

            if (ch == '\n') {
                break;
            }
        }
    }

    *buf = '\0';

    return totRead;
}



extern void* get_module_base(pid_t pid, const char* module_name);





int Hook(void* new_func,char* so_path,void* old_func){

    // 获取目标pid进程中"/data/app-lib/com.xxxx/libxxxx.so"模块的加载地址
    void* base_addr = get_module_base(getpid(), so_path);
    LOGD("[+] libxxxx.so address = %p \n", base_addr);

    // 保存Hook目标函数的原始调用地址
    unsigned long old_fopen = (unsigned long) old_func;
    unsigned long new_fopen =  (unsigned long) new_func;
    
    int fd;
    // 用open打开内存模块文件"/data/app-lib/com.xxxx/libxxxx.so"
    fd = open(so_path, O_RDONLY);
    if(-1 == fd){
        LOGD("open file:%s error\r\n",so_path);
        return -1;
    }

     // elf32文件的文件头结构体Elf32_Ehdr
    Elf32_Ehdr ehdr;
    // 读取elf32格式的文件"/data/app-lib/com.xxxx/libxxxx.so"的文件头信息
    read(fd, &ehdr, sizeof(Elf32_Ehdr));

    // elf32文件中节区表信息结构的文件偏移
    unsigned long shdr_addr = ehdr.e_shoff;
    // elf32文件中节区表信息结构的数量
    int shnum = ehdr.e_shnum;
    // elf32文件中每个节区表信息结构中的单个信息结构的大小（描述每个节区的信息的结构体的大小）
    int shent_size = ehdr.e_shentsize;

    // elf32文件节区表中每个节区的名称存放的节区名称字符串表，在节区表中的序号index
    unsigned long stridx = ehdr.e_shstrndx;

    // elf32文件中节区表的每个单元信息结构体（描述每个节区的信息的结构体）
    Elf32_Shdr shdr;
    // elf32文件中定位到存放每个节区名称的字符串表的信息结构体位置.shstrtab
    lseek(fd, shdr_addr + stridx * shent_size, SEEK_SET);
    // 读取elf32文件中的描述每个节区的信息的结构体（这里是保存elf32文件的每个节区的名称字符串的）
    read(fd, &shdr, shent_size);

    // 为保存elf32文件的所有的节区的名称字符串申请内存空间
    char * string_table = (char *)malloc(shdr.sh_size);
    // 定位到具体存放elf32文件的所有的节区的名称字符串的文件偏移处
    lseek(fd, shdr.sh_offset, SEEK_SET);
    read(fd, string_table, shdr.sh_size);
    lseek(fd, shdr_addr, SEEK_SET);

    int i;
    uint32_t out_addr = 0;
    uint32_t out_size = 0;
    uint32_t got_item = 0;
    int32_t got_found = 0;

    // 循环遍历elf32文件的节区表（描述每个节区的信息的结构体）
    for(i = 0; i<shnum; i++){
        // 依次读取节区表中每个描述节区的信息的结构体
        read(fd, &shdr, shent_size);
        // 判断当前节区描述结构体描述的节区是否是SHT_PROGBITS类型
        //类型为SHT_PROGBITS的.got节区包含全局偏移表
        if(shdr.sh_type == SHT_PROGBITS){
            // 获取节区的名称字符串在保存所有节区的名称字符串段.shstrtab中的序号
            int name_idx = shdr.sh_name;

            // 判断节区的名称是否为".got.plt"或者".got"
            if(strcmp(&(string_table[name_idx]), ".got.plt") == 0
                || strcmp(&(string_table[name_idx]), ".got") == 0){
                // 获取节区".got"或者".got.plt"在内存中实际数据存放地址
                out_addr = (uint32_t)( (char*) base_addr + shdr.sh_addr);
                // 获取节区".got"或者".got.plt"的大小
                out_size = shdr.sh_size;

                int j = 0;
                // 遍历节区".got"或者".got.plt"获取保存的全局的函数调用地址
                for(j = 0; j<out_size; j += 4){
                    // 获取节区".got"或者".got.plt"中的单个函数的调用地址
                    got_item = *(uint32_t*)(out_addr + j);
                    // 判断节区".got"或者".got.plt"中函数调用地址是否是将要被Hook的目标函数地址
                    if(got_item == old_fopen){
                        LOGD("[+] Found fopen in got.\n");
                        got_found = 1;
                        // 获取当前内存分页的大小
                        uint32_t page_size = getpagesize();
                        // 获取内存分页的起始地址（需要内存对齐）
                        uint32_t entry_page_start = (out_addr + j) & (~(page_size - 1));
                        LOGD("[+] entry_page_start = %lx, page size = %lx\n", entry_page_start, page_size);
                        // 修改内存属性为可读可写可执行
                        if(mprotect((uint32_t*)entry_page_start, page_size, PROT_READ | PROT_WRITE | PROT_EXEC) == -1){
                            LOGD("mprotect false.\n");
                            return -1;
                        }
                        LOGD("[+] %s, old_fopen = %lx, new_fopen = %lx\n", "before hook function", got_item, new_fopen);

                        // Hook函数为我们自己定义的函数
                        got_item = new_fopen;
                        LOGD("[+] %s, old_fopen = %lx, new_fopen = %lx\n", "after hook function", got_item, new_fopen);
                        // 恢复内存属性为可读可执行
                        if(mprotect((uint32_t*)entry_page_start, page_size, PROT_READ | PROT_EXEC) == -1){
                            LOGD("mprotect false.\n");
                            return -1;
                        }
                        break;
                    // 此时，目标函数的调用地址已经被Hook了
                    }else if(got_item == new_fopen){
                        LOGD("[+] Already hooked.\n");
                        break;
                    }
                }
                // Hook目标函数成功，跳出循环
                if(got_found)
                    break;
            }
        }
    }
    free(string_table);
    close(fd);
}


int Hook_old(void* new_func,char* so_path,void* old_func)
{
    void* base_addr = NULL;

    Elf32_Shdr shdr;
    Elf32_Ehdr ehdr;
    unsigned long shdr_addr;
    int shnum;
    int shent_size;
    int i;
    unsigned long stridx;

    uint32_t out_addr = 0;
    uint32_t out_size = 0;
    uint32_t got_item = 0;
    int32_t got_found = 0;
    char * string_table = NULL;

    LOGD("[+]so path = %s [+]\n", so_path);
    if(so_path != NULL)
        base_addr = get_module_base(getpid(),so_path);
    LOGD("%s address = %p\n",so_path,base_addr);

    int fd = open(so_path, O_RDONLY);
    if (-1 == fd) {
        LOGD("[+] error: Open %s failed [+]\n",so_path);
        return -1;
    }

    read(fd, &ehdr, sizeof(Elf32_Ehdr));

    shdr_addr = ehdr.e_shoff;
    shnum = ehdr.e_shnum;
    shent_size = ehdr.e_shentsize;
    stridx = ehdr.e_shstrndx;

    lseek(fd, shdr_addr + stridx * shent_size, SEEK_SET);
    read(fd, &shdr, shent_size);

    string_table = (char *)malloc(shdr.sh_size);
    lseek(fd, shdr.sh_offset, SEEK_SET);
    read(fd, string_table, shdr.sh_size);
    lseek(fd, shdr_addr, SEEK_SET);

    for (i = 0; i < shnum; i++) {
        read(fd, &shdr, shent_size);
        if (shdr.sh_type == SHT_PROGBITS) {
            int name_idx = shdr.sh_name;
            if (strcmp(&(string_table[name_idx]), ".got.plt") == 0
                || strcmp(&(string_table[name_idx]), ".got") == 0) {
                out_addr = (uint32_t)base_addr + (uint32_t)shdr.sh_addr;
                out_size = shdr.sh_size;
                LOGD("[+] out_addr = %lx, out_size = %lx [+]\n", out_addr, out_size);

                for (i = 0; i < out_size; i += 4) {
//                  LOGD("loop\n");
                    got_item = *(uint32_t *)(out_addr + i);
                    if (got_item  == (uint32_t)old_func) {
                        LOGD("[+] Found target function in got[+]\n");
                        got_found = 1;

                        uint32_t page_size = getpagesize();
                        uint32_t entry_page_start = (out_addr + i) & (~(page_size - 1));
                        mprotect((uint32_t *)entry_page_start, page_size, PROT_READ | PROT_WRITE);
                        *(uint32_t *)(out_addr + i) = (uint32_t)new_func;

                        break;
                    } else if (got_item == (uint32_t)new_func) {
                        LOGD("[+] Already hooked [+]\n");
                        break;
                    }
                }
                if (got_found)
                    break;
            }
        }
    }

    free(string_table);
    close(fd);

}




int GotHookTest(char * param){

    FILE * fp = freopen("/tmp/ljg.txt","ab+",stdout);
    LOGD("Start hooking\n");

    void * handle = dlopen("/usr/lib/libc.so.6",RTLD_NOW| RTLD_GLOBAL );
    void * addr = dlsym(handle,"strcmp");

    Hook((void*)new_strcmp,(char*)LIBSF_PATH,(void*)strcmp);

    strcmp("test1","test2");

    LOGD("Hook success\n");
    fclose(fp);

    return 0;
}