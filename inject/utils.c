




#include "inject.h"


char * getProcessName(char * path){
	for(int i = strlen(path);i >=0 ;i-- ){
		if(path[i] == '/'){
			return path + i + 1;
		}	
	}
	return path;
}



int find_pid_of(const char *process_name)
{
    int id;
    pid_t pid = -1;
    DIR* dir;
    FILE *fp;
    char filename[256];
    char cmdline[1024];

    struct dirent * entry;

    if (process_name == NULL)
        return -1;

    dir = opendir("/proc");
    if (dir == NULL)
        return -1;

    
    while((entry = readdir(dir)) != NULL) {
        id = atoi(entry->d_name);
        //printf("%s\r\n",entry->d_name);
        if (id != 0) {

            sprintf(filename, "/proc/%d/cmdline", id);
            fp = fopen(filename, "r");
            if (fp) {
                fgets(cmdline, sizeof(cmdline), fp);
                fclose(fp);
				
                //printf("id: %d, %s\r\n", id,cmdline);

				char * fn = getProcessName(cmdline);

                if (strstr(fn, process_name) ) {
                    //printf("success\r\n");
                    pid = id;
                    break;
                }
            }
        }
    }

    closedir(dir);
    return pid;
}



void* get_module_base(pid_t pid, const char* module_name)
{
    FILE *fp;
    long addr = 0;
    char *pch;
    char filename[64];
    char line[1024];

    if (pid < 0) {
        snprintf(filename, sizeof(filename), "/proc/self/maps");
    } else {
        snprintf(filename, sizeof(filename), "/proc/%d/maps", pid);
    }

    fp = fopen(filename, "r");

    if (fp != NULL) {
        //768f8000-769f5000 r-xp 00000000 fd:00 2678       /usr/lib/libc.so.6
        //769f5000-76a04000 ---p 000fd000 fd:00 2678       /usr/lib/libc.so.6
        //76a04000-76a06000 r--p 000fc000 fd:00 2678       /usr/lib/libc.so.6
        //76a06000-76a08000 rw-p 000fe000 fd:00 2678       /usr/lib/libc.so.6
        //the attrubution of the first found line is "r-xp",meaning executable code memory section
        //the memory page aligned at 4kb

        //76df4000-76ef1000 r-xp 00000000 fd:00 2678       /usr/lib/libc.so.6
        //76ef1000-76f00000 ---p 000fd000 fd:00 2678       /usr/lib/libc.so.6
        //76f00000-76f02000 r--p 000fc000 fd:00 2678       /usr/lib/libc.so.6
        //76f02000-76f04000 rw-p 000fe000 fd:00 2678       /usr/lib/libc.so.6

        //76e22000-76f1f000 r-xp 00000000 fd:00 2678       /usr/lib/libc.so.6
        //76f1f000-76f2e000 ---p 000fd000 fd:00 2678       /usr/lib/libc.so.6
        //76f2e000-76f30000 r--p 000fc000 fd:00 2678       /usr/lib/libc.so.6
        //76f30000-76f32000 rw-p 000fe000 fd:00 2678       /usr/lib/libc.so.6

        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, module_name)) {
                pch = strtok( line, "-" );
                addr = strtoul( pch, NULL, 16 );

                if (addr == 0x8000){
                    //addr = 0;
                }
                break;
            }
        }

        fclose(fp) ;
    }

    return (void *)addr;
}



void* get_remote_addr(pid_t target_pid, const char* module_name, void* local_addr,char * funcname)
{
    void* local_handle, *remote_handle;

    local_handle = get_module_base(-1, module_name);
    remote_handle = get_module_base(target_pid, module_name);

    //localAddress - localBase = remoteAddress - remoteBase,
    //so remoteAddress = localAddress - localBase + remoteBase
    
    void * ret_addr = (void *)( (uint32_t)remote_handle + (uint32_t)local_addr - (uint32_t)local_handle );

    DEBUG_PRINT("[+] pid:%d %s moudle name:%s, local module address:%p,\
    remote module address:%p,fucntion name:%s, address:%p\r\n",
    target_pid, __FUNCTION__, module_name,local_handle, remote_handle, funcname,ret_addr);

#if defined(__i386__)
    if (!strcmp(module_name, libc_path)) {
        ret_addr += 2;
    }
#endif
    return ret_addr;
}



void myTest(char * soPath){

    void * h = dlopen(soPath,RTLD_NOW| RTLD_GLOBAL);
    if(h){

        void * addr = dlsym(h,"dlsym");
        if(addr ){

            printf("dlsym:%x\r\n",addr);
        }
        else{
            printf("dlsym:%x\r\n",0);
        }
    }
    else{
        printf("dlopen:%s\r\n",soPath);
    }

}


int IsNumber(char * str){
    int i = 0;
    int len = strlen(str);
    for( i = 0;i < len;i ++){
        if(str[i] >= '0' && str[i] <= '9'){

        }
        else{
            return 0;
        }
    }
    if(i >= len){
        return 1;
    }
    return 0;
}