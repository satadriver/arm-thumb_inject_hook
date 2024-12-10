
#include <unistd.h>

int find_pid_of(const char *process_name);

void* get_remote_addr(pid_t target_pid, const char* module_name, void* local_addr,char * funcname);

void* get_module_base(pid_t pid, const char* module_name);

char * getProcessName(char * path);

void myTest(char * soPath);