#include "fs_kthread.h"

static int getStrlength(char *buf){
    int len = 0;
    while(buf[len] !='\0'){
        len ++;
    }
    return len + 1;
}

// 字符串转整型的函数
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

// 整型转字符串的函数
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


// get syscall_table_addr
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

// 对open系统调用消息的处理函数，从进程A到进程B
void deal_open_msg_ahead(struct my_msgbuf *this, void **retpp) {
    typedef Func_msg3(typeof(&orig_open), char *, int, umode_t) Funcc_type;
    Funcc_type *ptr = (Funcc_type *)(this->data.func_container_ptr);
    printk("Now on : file = %s, line = %d, func = %s\n", __FILE__, __LINE__, __FUNCTION__);
    // long obj = (*ptr->funcptr)(ptr->argu1, ptr->argu2, ptr->argu3);
    printk(KERN_INFO "buf = %s, flags = %d, mode = %u\n", ptr->argu1, ptr->argu2, ptr->argu3);
    long obj = orig_open(ptr->argu1, ptr->argu2, ptr->argu3);
    this->data.object_ptr = (long *)kmalloc(sizeof(long), GFP_KERNEL);
    *(long *)(this->data.object_ptr) = obj;         // 进程B将结果保存到data中
    printk("call deal_open_msg_ahead success, and the fd = %d\n", obj);
}

int hacked_open(char *buf, int flags, umode_t mode)
{
    char *hacked = "zhao";

    if (strstr(buf, hacked) != NULL){
        printk(KERN_ALERT "hacked_open!\n");
        // 发送消息
        struct my_msgbuf *sendbuf;
        int sendlength, flag;
        sendbuf = kmalloc(sizeof(struct my_msgbuf), GFP_KERNEL);
        sendbuf->mtype = 3;
        sendbuf->tsk = current;
        sendbuf->deal_data_kernel_to_fs = deal_open_msg_ahead;
        sendbuf->deal_data_fs_to_kernel = deal_open_msg_back;
        typedef Func_msg3(typeof(&orig_open), char *, int, umode_t) Funcc_type;
        Funcc_type *ptr = (Funcc_type *)kmalloc(sizeof(Funcc_type), GFP_KERNEL);
        ptr->funcptr = orig_open;
        char *kbuf = (char *)kmalloc(PATH_SIZE * sizeof(char), GFP_KERNEL);
        memcpy(kbuf, buf, getStrlength(buf));
        ptr->argu1 = kbuf;
        ptr->argu2 = flags;
        ptr->argu3 = mode;

        sendbuf->data.func_container_ptr = ptr;

        sendlength = sizeof(struct my_msgbuf) - sizeof(long);
        flag = my_msgsnd(msqid_from_kernel_to_fs, sendbuf, sendlength, 0);
        //printk(KERN_ALERT "");
        if (flag < 0){
            printk(KERN_INFO "kernel send message to fs failed, and the error number = %d\n", flag);
        } else {
            printk(KERN_INFO "kernel send message to fs success\n");
            printk(KERN_INFO "mtype = %d, tsk = %p, deal_data_kernel_to_fs = %p, deal_data_fs_to_kernel = %p, data = %p\n", sendbuf->mtype, sendbuf->tsk, sendbuf->deal_data_kernel_to_fs, sendbuf->deal_data_fs_to_kernel, sendbuf->data.func_container_ptr);
            printk(KERN_INFO "buf = %s, flags = %d, mode = %u\n", ptr->argu1, ptr->argu2, ptr->argu3);
        }
        flag = my_msgrcv(msqid_from_fs_to_kernel, sendbuf, sendlength, 3, 0);
        if (flag < 0)
            printk(KERN_INFO "kernel receive message from fs failed, and the error number = %d\n", flag);
        else
            printk(KERN_INFO "kernel receive message from fs success\n");

        // 处理从进程B接收到的消息
        long *fdp = NULL;
        sendbuf->deal_data_fs_to_kernel(sendbuf, &fdp);

        kfree(kbuf);
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

// 对open系统调用消息的处理函数，从进程B到进程A
void deal_open_msg_back(struct my_msgbuf *this, void **retpp) {
    printk("Now on : file = %s, line = %d, func = %s\n", __FILE__, __LINE__, __FUNCTION__);
    *retpp = (long *)(this->data.object_ptr);
    printk("call deal_open_msg_back success, and the fd = %d\n", **(long **)retpp);
}

// 接收进程A的请求并处理，并将返回结果发送回进程A
int fs_kthread_function(void *data)
{
    printk("Now on : file = %s, line = %d, func = %s\n", __FILE__, __LINE__, __FUNCTION__);
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
            printk(KERN_INFO "mtype = %d, tsk = %p, deal_data_kernel_to_fs = %p, deal_data_fs_to_kernel = %p, data = %p\n", recvbuf.mtype, recvbuf.tsk, recvbuf.deal_data_kernel_to_fs, recvbuf.deal_data_fs_to_kernel, recvbuf.data.func_container_ptr);
            typedef Func_msg3(typeof(&orig_open), char *, int, umode_t) Funcc_type;
            Funcc_type *ptr = recvbuf.data.func_container_ptr;
            printk(KERN_INFO "buf = %s, flags = %d, mode = %u\n",ptr->argu1, ptr->argu2, ptr->argu3);
            // 解析消息并处理
            recvbuf.deal_data_kernel_to_fs(&recvbuf, NULL);
            // recvbuf.deal_data = deal_open_msg_back;
            // 返回消息给发送方
            int flag = my_msgsnd(msqid_from_fs_to_kernel, &recvbuf, recvlength, 0);
            if (flag < 0)
                printk(KERN_INFO "fs send message to kernel failed, and the error number = %d\n", flag);
            else
                printk(KERN_INFO "fs send message to kernel success\n");
            // break;
        }
  	}
    return 0;
}

int init_mymodule(void){
	//get sys_call_table base address
	get_syscall_table();
	// 创建从进程A到进程B的消息队列
	while(1){
      msqid_from_kernel_to_fs = my_msgget(0, IPC_CREAT);
      if(msqid_from_kernel_to_fs < 0){
          printk(KERN_INFO "my_msgget failed with error!\n");
      } else{
          printk(KERN_INFO "message queue create success, the message queue id of msqid_from_kernel_to_fs is % d\n", msqid_from_kernel_to_fs);
          break;
      }
	}
  // 创建从进程B到进程A的消息队列
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
