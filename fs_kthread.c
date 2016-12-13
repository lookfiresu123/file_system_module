#include<linux/init.h>
#include<linux/module.h>
#include<linux/sched.h>
#include<linux/ipc_namespace.h>
#include<linux/nsproxy.h>
#include<linux/msg.h>
#include<linux/kthread.h>
#include<linux/unistd.h>
#include<linux/err.h>
#include<linux/types.h>

MODULE_LICENSE("Dual BSD/GPL");

#define TEXT_SIZE 512
#define NAME_SIZE 32

struct my_msgbuf {
    long mtype;
    char owner[NAME_SIZE];
    char mtext[TEXT_SIZE];
};


static int isRemove_module = 0;
static int msqid = -1;
static struct task_struct *tsk1;
static struct task_struct *tsk2;
static unsigned long long *syscall_table_addr;

static int (*msgget)(key_t key, int msgflg);
static int (*msgsnd)(int msqid, const void *msgp, size_t msgsz, int msgflg);
static ssize_t (*msgrcv)(int msqid, void *msgp, size_t msgsz, long msgtyp, int msgflg);
static int (*msgctl)(int msqid, int cmd, struct msqid_ds *buf);

// 文本拷贝（对strcpy的模拟）
static void test_copy(char *dest, char *src) {
    while ((*dest++ = *src++));
}

// 线程1用于创建消息队列并发送消息
static int thread_function_1(void *data) {
    printk(KERN_INFO "This task's name is fs_kernel_thread_1\n");
    int time = 0, sendlength, flag;
    while(!isRemove_module && time < 5) {
        if (msqid == -1) {
            // 若内核中无消息队列，则由该进程创建并获得消息队列号
            unsigned long long *sys_msgget = (int(*)(void))(syscall_table_addr[68]);
            msqid = ((typeof(msgget))sys_msgget)(0, IPC_CREAT | 0666);
            if (msqid == -1)
                printk(KERN_INFO "Message queue create error\n");
            else
                printk(KERN_INFO "Message queue create success, the queue ID is %d\n", msqid);
        }
        // 发送消息
        struct my_msgbuf sendbuf;
        memset(&sendbuf, 0x00, sizeof(sendbuf));
        sendbuf.mtype = 3;
        test_copy(sendbuf.owner, "fs_kernel_thread_1");
        sprintf(&sendbuf.mtext,"This is the No.%d message %s send", ++time, sendbuf.owner);
        sendlength = sizeof(sendbuf) - sizeof(long);
        unsigned long long *sys_msgsnd = (int(*)(void))(syscall_table_addr[69]);
        flag = ((typeof(msgsnd))sys_msgsnd)(msqid, &sendbuf, sendlength, 0);
        if (flag < 0)
            printk(KERN_INFO "Send message error\n");
        else
            printk(KERN_INFO "%s send to message queue %d: mtype = %d, mtext = %s\n", sendbuf.owner, msqid, sendbuf.mtype, sendbuf.mtext);
    }
    return 0;
}

// 线程2用于接收消息
static int thread_function_2(void *data) {
    printk(KERN_INFO "This task's name is fs_kernel_thread_2");
    int time = 0, recvlength, flag;
    while(!isRemove_module && time < 5) {
        // printk(KERN_INFO "The receive process's msqid = %d\n", msqid);
        if (msqid == -1) {
            // printk("Message queue hasn't created because msqid is -1\n");
            continue;// 若内核中无消息队列，则自旋
        }
        // 接收消息
        struct my_msgbuf recvbuf;
        memset(&recvbuf, 0x00, sizeof(recvbuf)) ;
        recvbuf.mtype = 3;
        test_copy(recvbuf.owner, "fs_kernel_thread_2");
        recvlength = sizeof(recvbuf) - sizeof(long);
        unsigned long long *sys_msgrcv = (int(*)(void))(syscall_table_addr[70]);
        flag = ((typeof(msgrcv))sys_msgrcv)(msqid, &recvbuf, recvlength, recvbuf.mtype, 0);
        if (flag < 0)
            printk(KERN_INFO "Receive message error\n");
        else {
            printk(KERN_INFO "%s receive from message queue %d: mtype = %d, mtext = %s\n", recvbuf.owner, msqid, recvbuf.mtype, recvbuf.mtext);
            time++;
        }
    }
    return 0;
}

// 获得系统调用表的基地址
static void get_syscall_table(void) {
    int i;
    void* syscall_addr = 0;
    unsigned char* lpbin;
    rdmsrl(MSR_LSTAR, syscall_addr);
    for(lpbin=(char*)syscall_addr, i= 0; i < 255; i++) {
        if(lpbin[i] == 0xff && lpbin[i + 1] == 0x14) {
            syscall_table_addr = (0xffffffff00000000) + *(unsigned int*)(lpbin + i + 3);
            printk(KERN_INFO "syscall_table_addr %p\n", syscall_table_addr);
            break;
        }
    }
}


static int fs_kthread_init(void) {
    int err;
    printk(KERN_INFO "fs_kernel_thread start!\n");

    // 初始化系统调用表的基地址全局变量syscall_table_addr
    get_syscall_table();

    // 创建两个线程，分别用于发送消息和接受消息
    tsk1 = kthread_create(thread_function_1, NULL, "fs_kernel_thread%d", 1);
    tsk2 = kthread_create(thread_function_2, NULL, "fs_kernel_thread%d", 2);
    if(IS_ERR(tsk1)) {
        printk(KERN_INFO "Create fs_kernel_thread1 failed!\n");
        err= PTR_ERR(tsk1);
        tsk1 = NULL;
        return err;
    }
    if(IS_ERR(tsk2)) {
        printk(KERN_INFO "Create fs_kernel_thread2 failed!\n");
        err= PTR_ERR(tsk2);
        tsk2 = NULL;
        return err;
    }
    wake_up_process(tsk1);
    wake_up_process(tsk2);


    // printk(KERN_INFO "msg_queue's id is % d\n", msqid);
    // printk(KERN_INFO "fs_kernel_thread name is %s\n", tsk->comm);
    // printk(KERN_INFO "create fs_kernel_thread ok!\n");
    return 0;
}

static void fs_kthread_exit(void) {
    isRemove_module = 1;
    if(tsk1) {
        kthread_stop(tsk1);
        tsk1 = NULL;
        printk(KERN_INFO "fs_kernel_thread1 exit!\n");
    }
    if (tsk2) {
        kthread_stop(tsk2);
        tsk2 = NULL;
        printk(KERN_INFO "fs_kernel_thread2 exit!\n");
    }
    unsigned long long *sys_msgctl = (int(*)(void))(syscall_table_addr[71]);
    int flag = ((typeof(msgctl))sys_msgctl)(msqid, IPC_RMID, NULL);
    if (flag == -1)
        printk(KERN_INFO "Message queue %d delete error\n", msqid);
    else
        printk(KERN_INFO "Message queue %d delete success\n", msqid);
}

module_init(fs_kthread_init);
module_exit(fs_kthread_exit);
