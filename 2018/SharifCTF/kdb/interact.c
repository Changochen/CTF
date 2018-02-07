#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <pthread.h>


#define COMMAD_ALLOC 0x13371338
#define COMMAD_READ  0x13371339
#define COMMAD_WRITE 0x1337133A
#define COMMAD_FREE  0x1337133D
#define COMMAD_RALLO 0x1337133F

char buf[0x2000];

struct Chunk{
    char name[0x20];
    unsigned long size;
};

struct Chunk2{
    char name[0x20];
    char* buf;
    unsigned long size;
};

void menu(){
    puts("1. alloc");
    puts("2. read");
    puts("3. write");
    puts("4. free");
    puts("5. realloc");
    puts("6. open ptmx");
    puts("7. exit");
    puts("Choice:");
}

int main(){
    int choice;
    struct Chunk ch1;
    struct Chunk* p1;
    struct Chunk2 ch2;
    struct Chunk2* p2;
    p1=&ch1;
    p2=&ch2;
    p2->buf=buf;
    unsigned long ss;
    int fd;
    int i;
    int res;
    int rs;
    int pid;
    fd=open("/dev/kdb",O_RDWR);
    while(1){
        menu();
        scanf("%d",&choice);
        memset(ch1.name,0,0x20);
        memset(ch2.name,0,0x20);
        memset(buf,0,0x1000);
        switch(choice){
        case 1:
           puts("Name:");
           rs=read(0,p1->name,0x20);
           puts("Size:");
           scanf("%lx",&p1->size);
           res=ioctl(fd,COMMAD_ALLOC,p1);
           printf("Return value:%d\n",res);
           break;
        case 2:
           puts("Name:");
           read(0,p2->name,0x20);
           puts("Size:");
           scanf("%lx",&p2->size);
           res=ioctl(fd,COMMAD_READ,p2);
           printf("Return value:%d\n",res);
           puts(p2->buf);
           for(i=0;i<(p2->size/8);i++){
               if(i%4==0)puts("");
               printf("%16lx ",*((unsigned long*)(p2->buf+8*i)));
           }
           puts("");
           break;
        case 3:
           puts("Name:");
           read(0,p2->name,0x20);
           puts("Size:");
           scanf("%lx",&p2->size);
           puts("Content:");
           read(0,p2->buf,0x1000);
           res=ioctl(fd,COMMAD_WRITE,p2);
           printf("Return value:%d\n",res);
           break;
        case 4:
           puts("Name:");
           read(0,p1->name,0x20);
           res=ioctl(fd,COMMAD_FREE,p1);
           printf("Return value:%d\n",res);
           break; 
        case 5:
           puts("Name:");
           read(0,p2->name,0x20);
           puts("Size:");
           scanf("%lx",&p2->size);
           res=ioctl(fd,COMMAD_RALLO,p2);
           printf("Return value:%d\n",res);
           break;
        case 6:
            open("/dev/ptmx",O_RDWR|O_NOCTTY);
            break;
        case 7:
            return 0;
        }
    }
}
