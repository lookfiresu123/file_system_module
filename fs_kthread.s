# 1 "fs_kthread.c"
# 1 "/home/lookfiresu/Desktop/test/file_system_module//"
# 1 "<built-in>"
# 1 "<command-line>"
# 1 "/usr/include/stdc-predef.h" 1 3 4
# 1 "<command-line>" 2
# 1 "fs_kthread.c"
# 1 "fs_kthread.h" 1
# 31 "fs_kthread.h"
MODULE_LICENSE("GPL");
# 109 "fs_kthread.h"
static unsigned long long *syscall_table_addr;
int (*orig_write)(unsigned int fd,char *buf,unsigned int count);
int (*orig_open)(char *buf, int flags, umode_t mode);
int (*orig_read)(unsigned int fd, char *buf, unsigned int count);
int (*orig_close)(unsigned int fd);

static int msqid_from_kernel_to_fs = -1;
static int msqid_from_fs_to_kernel = -1;
static int isRemove_module = 0;
struct work_struct current_work;
struct timeval tpstart, tpend;
static struct task_struct *tsk = NULL;
# 2 "fs_kthread.c" 2

static int getStrlength(char *buf){
    int len = 0;
    while(buf[len] !='\0'){
        len ++;
    }
    return len + 1;
}


int stoi(char *s) {
    int i, sign, offset, n;
    if (!s || s[0] == '\0')
        return 0;
    if (s[0] == '-')
        sign = -1;
    if (sign == -1)
        offset = 1;
    else
        offset = 0;

    n = 0;
    for (i = offset ; s[i] != '\0' ; i++)
        n = n * 10 + s[i] - '0';
    if (sign == -1)
        n = -n;
    return n;
}


void itos(int n, char *s) {
    bool isNeg = n < 0;
    unsigned int n1 = isNeg ? -n : n;
    int i = 0;
    while (n1 != 0) {
        s[i++] = n1 % 10 + '0';
        n1 = n1 / 10;
    }
    if (isNeg)
        s[i++] = '-';
    s[i] = '\0';
    int t;
    for (t = 0 ; t < i/2 ; t++) {
        s[t] ^= s[i-t-1];
        s[i-t-1] ^= s[t];
        s[t] ^= s[i-t-1];
    }

    if (n == 0) {
        s[0] = '0';
        s[1] = '\0';
    }
}



static void get_syscall_table(void){
    int i;
    void* syscall_addr = 0;
    unsigned char* lpbin;
    rdmsrl(MSR_LSTAR, syscall_addr);
    for(lpbin=(char*)syscall_addr, i= 0; i < 255; i++){
        if(lpbin[i] == 0xff && lpbin[i + 1] == 0x14){
            syscall_table_addr = (0xffffffff00000000) + *(unsigned int*)(lpbin + i + 3);
            printk(KERN_INFO "syscall_table_addr %p\n", syscall_table_addr);
            break;
        }
    }
}

int hacked_write(unsigned int fd,char *buf,unsigned int count)
{
    char *hacked = "zhao";
    if(strstr(buf,hacked) != NULL){
        printk(KERN_ALERT "hacked write!\n");
        return count;
    } else{
        return orig_write(fd,buf,count);
    }
}


void deal_open_msg_ahead(struct my_msgbuf *this, void **retpp) {
    typedef struct Func_container3 { __typeof__(&orig_open) funcptr; char * argu1; int argu2; umode_t argu3; } Funcc_type;
    Funcc_type *ptr = (Funcc_type *)(this->data.func_container_ptr);
    printk("Now on : file = %s, line = %d, func = %s\n", "fs_kthread.c", 87, __FUNCTION__);

    printk(KERN_INFO "buf = %s, flags = %d, mode = %u\n", ptr->argu1, ptr->argu2, ptr->argu3);
    long obj = orig_open(ptr->argu1, ptr->argu2, ptr->argu3);
    this->data.object_ptr = (long *)kmalloc(sizeof(long), GFP_KERNEL);
    *(long *)(this->data.object_ptr) = obj;
    printk("call deal_open_msg_ahead success, and the fd = %d\n", obj);
}

int hacked_open(char *buf, int flags, umode_t mode)
{
    char *hacked = "zhao";

    if (strstr(buf, hacked) != NULL){
        printk(KERN_ALERT "hacked_open!\n");

        struct my_msgbuf *sendbuf;
        int sendlength, flag;
        sendbuf = kmalloc(sizeof(struct my_msgbuf), GFP_KERNEL);
        sendbuf->mtype = 3;
        sendbuf->tsk = current;
        sendbuf->deal_data = deal_open_msg_ahead;
        typedef struct Func_container3 { __typeof__(&orig_open) funcptr; char * argu1; int argu2; umode_t argu3; } Funcc_type;
        Funcc_type *ptr = (Funcc_type *)kmalloc(sizeof(Funcc_type), GFP_KERNEL);
        sendbuf->data.func_container_ptr = ptr;

        sendlength = sizeof(struct my_msgbuf) - sizeof(long);
        flag = my_msgsnd(msqid_from_kernel_to_fs, sendbuf, sendlength, 0);

        if (flag < 0){
            printk(KERN_INFO "kernel send message to fs failed, and the error number = %d\n", flag);
        } else {
            printk(KERN_INFO "kernel send message to fs success\n");
        }
        flag = my_msgrcv(msqid_from_fs_to_kernel, sendbuf, sendlength, 3, 0);
        if (flag < 0)
            printk(KERN_INFO "kernel receive message from fs failed, and the error number = %d\n", flag);
        else
            printk(KERN_INFO "kernel receive message from fs success\n");


        long *fdp = NULL;
        sendbuf->deal_data(sendbuf, &fdp);

        kfree(sendbuf);
        return *fdp;
    } else{
        return orig_open(buf, flags, mode);
    }
}

int hacked_read(unsigned int fd, char *buf, unsigned int count)
{
    char *hacked = "zhao";

    if (strstr(buf, hacked) != NULL)
    {
        printk(KERN_ALERT "hacked_read!\n");
        return count;
    } else {
        return orig_read(fd, buf, count);
    }
}

int hacked_close(unsigned int fd)
{
    char *hacked = "zhao";

    return 0;
}

static unsigned long cr0 = 0;
unsigned long clear_cr0(void) {
 unsigned long ret;
 asm volatile("movq %%cr0, %0"
   :"=a"(cr0)
 );
 ret = cr0;

 cr0 &= ~0x10000LL;

 asm volatile("movq %0, %%cr0"
   :
   :"a"(cr0)
 );
 return ret;
}

void setback_cr0(unsigned long val) {
 asm volatile("movq %0, %%cr0"
   :
   :"a"(val)
 );
}


void deal_open_msg_back(struct my_msgbuf *this, void **retpp) {
    printk("Now on : file = %s, line = %d, func = %s\n", "fs_kthread.c", 184, __FUNCTION__);
    *retpp = (long *)(this->data.object_ptr);
    printk("call deal_open_msg_back success, and the fd = %d\n", **(long **)retpp);
}


int fs_kthread_function(void *data)
{
    printk("Now on : file = %s, line = %d, func = %s\n", "fs_kthread.c", 192, __FUNCTION__);
    printk(KERN_INFO "This task's name is fs_kthread");
    int recvlength, flag;
    while(!isRemove_module) {
        struct my_msgbuf recvbuf;
        memset(&recvbuf, 0x00, sizeof(recvbuf)) ;
        recvbuf.mtype = 3;
        recvlength = sizeof(recvbuf) - sizeof(long);
        int flag = my_msgrcv(msqid_from_kernel_to_fs, &recvbuf, recvlength, recvbuf.mtype, 0);
        if (flag < 0)
            printk(KERN_INFO "fs receive message from kernel failed, and the error number = %d\n", flag);
        else {
            printk(KERN_INFO "fs receive message from kernel success\n");

            recvbuf.deal_data(&recvbuf, NULL);
            recvbuf.deal_data = deal_open_msg_back;

            int flag = my_msgsnd(msqid_from_fs_to_kernel, &recvbuf, recvlength, 0);
            if (flag < 0)
                printk(KERN_INFO "fs send message to kernel failed, and the error number = %d\n", flag);
            else
                printk(KERN_INFO "fs send message to kernel success\n");

        }
   }
    return 0;
}

int init_mymodule(void){

 get_syscall_table();

 while(1){
      msqid_from_kernel_to_fs = my_msgget(0, IPC_CREAT);
      if(msqid_from_kernel_to_fs < 0){
          printk(KERN_INFO "my_msgget failed with error!\n");
      } else{
          printk(KERN_INFO "message queue create success, the message queue id of msqid_from_kernel_to_fs is % d\n", msqid_from_kernel_to_fs);
          break;
      }
 }

 while(1){
      msqid_from_fs_to_kernel = my_msgget(0, IPC_CREAT);
      if(msqid_from_fs_to_kernel < 0){
          printk(KERN_INFO "my_msgget failed with error!\n");
      } else{
          printk(KERN_INFO "message queue create success, the message queue id of msqid_from_fs_to_kernel is % d\n", msqid_from_fs_to_kernel);
          break;
      }
 }
 do {
     tsk = kthread_create(fs_kthread_function, NULL, "fs_kthread");
      cr0 = clear_cr0();
     orig_open = syscall_table_addr[__NR_open];
      syscall_table_addr[__NR_open] = hacked_open;
    } while(tsk == NULL || IS_ERR(tsk));
 wake_up_process(tsk);
 return 0;
}

void cleanup_mymodule(void){
 isRemove_module = 1;
 syscall_table_addr[__NR_open] = orig_open;
 setback_cr0(cr0);
 if (tsk){
  kthread_stop(tsk);
  tsk = NULL;
 }
}

module_init(init_mymodule);
module_exit(cleanup_mymodule);
