
#include "inject.h"
#include "utils.h"

//const char *libc_path = "/system/lib/libc.so";
//const char *linker_path = "/system/bin/linker";

const char *libc_path = "/usr/lib/libc.so.6";
const char *linker_path = (const char *)"/usr/lib/libc.so.6";


#ifndef __arm__
#define __arm__
#endif

int g_tag = 0;

int ptrace_readdata(pid_t pid,  uint8_t *src, uint8_t *buf, size_t size)
{
    uint32_t i, j, remain;
    uint8_t *laddr;

    union u {
        long val;
        char chars[sizeof(long)];
    } d;

    j = size / 4;
    remain = size % 4;

    laddr = buf;

    for (i = 0; i < j; i ++) {
        d.val = ptrace(PTRACE_PEEKTEXT, pid, src, 0);
        memcpy(laddr, d.chars, 4);
        src += 4;
        laddr += 4;
    }

    if (remain > 0) {
        d.val = ptrace(PTRACE_PEEKTEXT, pid, src, 0);
        memcpy(laddr, d.chars, remain);
    }

    return 0;
}

int ptrace_writedata(pid_t pid, uint8_t *dest, uint8_t *data, size_t size)
{
    uint32_t i, j, remain;
    uint8_t *laddr;

    union u {
        long val;
        char chars[sizeof(long)];
    } d;

    j = size / 4;
    remain = size % 4;

    laddr = data;

    for (i = 0; i < j; i ++) {
        memcpy(d.chars, laddr, 4);
        ptrace(PTRACE_POKETEXT, pid, dest, d.val);

        dest  += 4;
        laddr += 4;
    }

    if (remain > 0) {
        d.val = ptrace(PTRACE_PEEKTEXT, pid, dest, 0);
        for (i = 0; i < remain; i ++) {
            d.chars[i] = *laddr ++;
        }

        ptrace(PTRACE_POKETEXT, pid, dest, d.val);
    }

    return 0;
}



#if defined(__arm__)
int ptrace_call(pid_t pid, uint32_t addr, long *params, uint32_t num_params, struct pt_regs* regs)
{    
    uint32_t i;
    for (i = 0; i < num_params && i < THUMB2_CALL_COUNTER; i ++) {
        regs->uregs[i] = params[i];
    }

    //
    // push remained params onto stack
    //
    if (i < num_params) {
        int cnt = (num_params - i) ;
        regs->ARM_sp -= cnt * sizeof(long) ;
        ptrace_writedata(pid, (unsigned char *)regs->ARM_sp, (uint8_t *)&params[i], cnt * sizeof(long));
    }

    regs->ARM_pc = addr;
    if (regs->ARM_pc & 1) {
        /* thumb */
        regs->ARM_pc &= (~1u);
        regs->ARM_cpsr |= CPSR_T_MASK;
    } else {
        /* arm */
        regs->ARM_cpsr &= ~CPSR_T_MASK;
    }

    //regs->ARM_cpsr &= ~CPSR_T_MASK;

    printf("ptrace_call pid:%u,code:%x,cpsr:%x\r\n",pid,regs->ARM_pc,regs->ARM_cpsr );

    regs->ARM_lr = 0;

    if (ptrace_setregs(pid, regs) == -1 || ptrace_continue(pid) == -1) {
        printf("error\n");
        return -1;
    }

    if(g_tag){
        return 0;
    }

//程序中的0xb7f就表示子进程进入了暂停状态，且发送的错误信号为11(SIGSEGV)，
//它表示试图访问未分配给自己的内存, 或试图往没有写权限的内存地址写数据。
//由于我们在前面设置了regs->ARM_lr = 0，它就会返回到0地址处继续执行，这样就会产生SIGSEGV了.
    int stat = 0;
    waitpid(pid, &stat, WUNTRACED);
    while (stat != 0xb7f) {
        if (ptrace_continue(pid) == -1) {
            printf("error\n");
            return -1;
        }
        waitpid(pid, &stat, WUNTRACED);
    }

    return 0;
}

#elif defined(__i386__)
long ptrace_call(pid_t pid, uint32_t addr, long *params, uint32_t num_params, struct user_regs_struct * regs)
{
    regs->esp -= (num_params) * sizeof(long) ;
    ptrace_writedata(pid, (void *)regs->esp, (uint8_t *)params, (num_params) * sizeof(long));

    long tmp_addr = 0x00;
    regs->esp -= sizeof(long);
    ptrace_writedata(pid, regs->esp, (char *)&tmp_addr, sizeof(tmp_addr));

    regs->eip = addr;

    if (ptrace_setregs(pid, regs) == -1
            || ptrace_continue( pid) == -1) {
        printf("error\n");
        return -1;
    }

    int stat = 0;
    waitpid(pid, &stat, WUNTRACED);
    while (stat != 0xb7f) {
        if (ptrace_continue(pid) == -1) {
            printf("error\n");
            return -1;
        }
        waitpid(pid, &stat, WUNTRACED);
    }

    return 0;
}
#else
#error "Not supported"
#endif

int ptrace_getregs(pid_t pid, struct pt_regs * regs)
{
    if (ptrace(PTRACE_GETREGS, pid, NULL, regs) < 0) {
        perror("ptrace_getregs: Can not get register values");
        return -1;
    }

    return 0;
}

int ptrace_setregs(pid_t pid, struct pt_regs * regs)
{
    if (ptrace(PTRACE_SETREGS, pid, NULL, regs) < 0) {
        perror("ptrace_setregs: Can not set register values");
        return -1;
    }

    return 0;
}

int ptrace_continue(pid_t pid)
{
    if (ptrace(PTRACE_CONT, pid, NULL, 0) < 0) {
        perror("ptrace_cont");
        return -1;
    }

    return 0;
}

int ptrace_attach(pid_t pid)
{
    if (ptrace(PTRACE_ATTACH, pid, NULL, 0) < 0) {
        perror("ptrace_attach");
        return -1;
    }

    int status = 0;
    waitpid(pid, &status , WUNTRACED);

    return 0;
}

int ptrace_detach(pid_t pid)
{
    if (ptrace(PTRACE_DETACH, pid, NULL, 0) < 0) {
        perror("ptrace_detach");
        return -1;
    }

    return 0;
}



long ptrace_retval(struct pt_regs * regs)
{
#if defined(__arm__)
    return regs->ARM_r0;
#elif defined(__i386__)
    return regs->eax;
#else
#error "Not supported"
#endif
}



long ptrace_ip(struct pt_regs * regs)
{
#if defined(__arm__)
    return regs->ARM_pc;
#elif defined(__i386__)
    return regs->eip;
#else
#error "Not supported"
#endif
}

long ptrace_cpsr(struct pt_regs * regs)
{
#if defined(__arm__)
    return regs->ARM_cpsr;
#elif defined(__i386__)
    return regs->eflags;
#else
#error "Not supported"
#endif
}



int ptrace_call_wrapper(pid_t target_pid, const char * func_name, void * func_addr, 
long * parameters, int param_num, struct pt_regs * regs)
{
    DEBUG_PRINT("[+] Calling %s in target process.\n", func_name);
    if (ptrace_call(target_pid, (uint32_t)func_addr, parameters, param_num, regs) == -1)
        return -1;

    if(g_tag ){
        return 0;
    }
    if (ptrace_getregs(target_pid, regs) == -1)
        return -1;
    DEBUG_PRINT("[+] Target process returned from %s, return value=%x,cpsr=%x, pc=%x \n",
            func_name, ptrace_retval(regs),ptrace_cpsr(regs), ptrace_ip(regs));
    return 0;
}



int inject_remote_process(pid_t target_pid, const char *library_path, const char *function_name, 
const char *param, size_t param_size)
{
    int ret = -1;
    void *mmap64_addr, *dlopen_addr, *dlsym_addr, *dlclose_addr, *dlerror_addr, * getpid_addr;
    
    uint8_t *map_base = 0;
    struct pt_regs regs, original_regs;

    /*
    uint8_t *dlopen_param1_ptr, *dlsym_param2_ptr, *saved_r0_pc_ptr, *inject_param_ptr, 
    *remote_code_ptr, *local_code_ptr;
    extern uint32_t _dlopen_addr_s, _dlopen_param1_s, _dlopen_param2_s, _dlsym_addr_s, \
        _dlsym_param2_s, _dlclose_addr_s, _inject_start_s, _inject_end_s, _inject_function_param_s, \
        _saved_cpsr_s, _saved_r0_pc_s;
    uint32_t code_length;
    void *local_handle, *remote_handle, *dlhandle;
    */

    long parameters[16];
    void * inject_entry_addr;
    void * sohandle ;
    int remote_pid = 0;
    char * info;

    DEBUG_PRINT("[+] Injecting process: %d\n", target_pid);

    if (ptrace_attach(target_pid) == -1)
        goto exit;

    if (ptrace_getregs(target_pid, &regs) == -1)
        goto exit;

    DEBUG_PRINT("[+] Target process init regs:r0=%x,cpsr=%x, pc=%x \n",
            ptrace_retval(&regs),ptrace_cpsr(&regs), ptrace_ip(&regs));

    /* save original registers */
    memcpy(&original_regs, &regs, sizeof(regs));

    getpid_addr = get_remote_addr(target_pid, libc_path, (void *)getpid,"getpid");
    DEBUG_PRINT("[+] Remote getpid address: %x\n", getpid_addr);

    if (ptrace_call_wrapper(target_pid, "getpid", getpid_addr, parameters, 0, &regs) == -1)
        goto exit;

    remote_pid = (int)ptrace_retval(&regs);
    DEBUG_PRINT("[+] Remote pid: %u\n", remote_pid);

    mmap64_addr = get_remote_addr(target_pid, libc_path, (void *)mmap,"mmap");
    DEBUG_PRINT("[+] Remote mmap address: %x\n", mmap64_addr);

    /* call mmap */
    parameters[0] = 0;  // addr
    parameters[1] = 0x1000; // size
    parameters[2] = PROT_READ | PROT_WRITE | PROT_EXEC;  // prot
    parameters[3] =  MAP_ANONYMOUS | MAP_PRIVATE; // flags
    parameters[4] = 0; //fd
    parameters[5] = 0; //offset
    parameters[6] = 0; //fd
    parameters[7] = 0; //offset

    if (ptrace_call_wrapper(target_pid, "mmap64", mmap64_addr, parameters, 8, &regs) == -1)
        goto exit;

    map_base = (uint8_t*)ptrace_retval(&regs);

    dlopen_addr = get_remote_addr( target_pid, linker_path, (void *)dlopen ,"dlopen");
    dlsym_addr = get_remote_addr( target_pid, linker_path, (void *)dlsym,"dlsym" );
    dlclose_addr = get_remote_addr( target_pid, linker_path, (void *)dlclose ,"dlclose");
    dlerror_addr = get_remote_addr( target_pid, linker_path, (void *)dlerror,"dlerror" );

    DEBUG_PRINT("[+] Get imports: dlopen: %x, dlsym: %x, dlclose: %x, dlerror: %x\n",
            dlopen_addr, dlsym_addr, dlclose_addr, dlerror_addr);

    printf("library path = %s\n", library_path);
    ptrace_writedata(target_pid, map_base, (uint8_t*)library_path, strlen(library_path) + 1);

    parameters[0] = (unsigned long)map_base;
    parameters[1] = RTLD_NOW| RTLD_GLOBAL;

    if (ptrace_call_wrapper(target_pid, "dlopen", dlopen_addr, parameters, 2, &regs) == -1)
        goto exit;

    sohandle = (void*)ptrace_retval(&regs);

    if(sohandle == 0){
        if (ptrace_call_wrapper(target_pid, "dlerror", dlerror_addr, parameters, 0, &regs) == -1)
            goto exit;
        info = (char*)ptrace_retval(&regs);
        if(info){
            char buf[256] = {0};
            ptrace_readdata(target_pid, info,buf, sizeof(buf) -1 );
            printf("dlopen error:%s\r\n",buf);           
        }    
        goto exit;   
    }

#define FUNCTION_NAME_ADDR_OFFSET       0x100
    ptrace_writedata(target_pid, map_base + FUNCTION_NAME_ADDR_OFFSET, 
    (uint8_t*)function_name, strlen(function_name) + 1);
    parameters[0] = (unsigned long)sohandle;
    parameters[1] = (unsigned long)map_base + FUNCTION_NAME_ADDR_OFFSET;

    if (ptrace_call_wrapper(target_pid, "dlsym", dlsym_addr, parameters, 2, &regs) == -1)
        goto exit;

    inject_entry_addr = (void*)ptrace_retval(&regs);
    DEBUG_PRINT("InjectEntry addr = %p\n", inject_entry_addr);

#define FUNCTION_PARAM_ADDR_OFFSET      0x200
    ptrace_writedata(target_pid, map_base + FUNCTION_PARAM_ADDR_OFFSET,(uint8_t*) param, strlen(param) + 1);
    parameters[0] = (unsigned long)map_base + FUNCTION_PARAM_ADDR_OFFSET;

    g_tag = 0;

    if (ptrace_call_wrapper(target_pid, "InjectEntry", inject_entry_addr, parameters, 1, &regs) == -1)
        goto exit;

    if(g_tag){
        //ptrace_detach(target_pid);
        goto exit;
    }

    int retval = (int)ptrace_retval(&regs);
    DEBUG_PRINT("InjectEntry return value = %x\n", retval);

    printf("Press enter to dlclose and detach\n");
    getchar();
    parameters[0] = (unsigned long)sohandle;

    if (ptrace_call_wrapper(target_pid, "dlclose", (void*)dlclose, parameters, 1, &regs) == -1)
        goto exit;

    /* restore */
    ptrace_setregs(target_pid, &original_regs);
    ptrace_detach(target_pid);
    ret = 0;

exit:
    return ret;
}



//usage: pid/processName libPath functionName parameterString
int main(int argc, char** argv) {
    int ret = 0;
    if(argc < 4){
        printf("example:%s processName modulePath functionName parameter",argv[0]);
        printf("such as:%s httpd /root/injected.so InjectEntry test\r\n",argv[0]);
        return 0;
    }

    void * localHandle = get_module_base(-1, "inject");
    printf("local handle:%p,main:%x,inject_remote_process address:%p\r\n",
    localHandle,main,inject_remote_process);

    for(int i = 0;i < argc;i ++){
        printf("argv[%d]:%s\r\n",i,argv[i]);
    }
    pid_t target_pid = atoi(argv[1]);
    if(target_pid == 0){
        if(IsNumber(argv[1]) == 0){
            target_pid = find_pid_of(argv[1]);
        }
    }
    
    if (-1 == target_pid || target_pid== 0) {
        printf("Can't get the pid of the process:%s\r\n",argv[1]);
        return -1;
    }
    else{
        printf("process:%s pid:%d\r\n",argv[1],target_pid);
    }
    
    //myTest((char*)libc_path); 

    ret = inject_remote_process(target_pid, argv[2], argv[3],  argv[4], strlen(argv[4]) );
    return ret;
}
