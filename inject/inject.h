

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



#if defined(__i386__)
#undef (__i386__)
#define pt_regs         user_regs_struct
#endif

#define ENABLE_DEBUG 1

#if ENABLE_DEBUG
#define  LOG_TAG "INJECT"
//#define  LOGD(fmt, args...)  __android_log_print(ANDROID_LOG_DEBUG,LOG_TAG, fmt, ##args)
#define  LOGD(fmt, args...)  printf( fmt, ##args)
#define DEBUG_PRINT(format,args...) LOGD(format, ##args)
#else
#define DEBUG_PRINT(format,args...)
#endif

#define CPSR_T_MASK     ( 1u << 5 )

#define THUMB2_CALL_COUNTER 4


int ptrace_readdata(pid_t pid,  uint8_t *src, uint8_t *buf, size_t size);

int ptrace_writedata(pid_t pid, uint8_t *dest, uint8_t *data, size_t size);

int ptrace_call(pid_t pid, uint32_t addr, long *params, uint32_t num_params, struct pt_regs* regs);

int ptrace_getregs(pid_t pid, struct pt_regs * regs);

int ptrace_setregs(pid_t pid, struct pt_regs * regs);

int ptrace_continue(pid_t pid);

int ptrace_attach(pid_t pid);

int ptrace_detach(pid_t pid);

long ptrace_retval(struct pt_regs * regs);

long ptrace_ip(struct pt_regs * regs);

long ptrace_cpsr(struct pt_regs * regs);

int ptrace_call_wrapper(pid_t target_pid, const char * func_name, void * func_addr, long * parameters, int param_num, struct pt_regs * regs);

int inject_remote_process(pid_t target_pid, const char *library_path, const char *function_name, const char *param, size_t param_size);

