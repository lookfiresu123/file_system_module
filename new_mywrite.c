#ifndef MODULE
#define MODULE
#endif

#ifndef __KERNEL__
#define __KERNEL__
#endif
#include <linux/init.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/kernel.h>
#include <asm/unistd.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/ipc_namespace.h>
#include <linux/nsproxy.h>
#include <linux/msg.h>
#include <linux/kthread.h>
#include <linux/unistd.h>
#include <linux/err.h>

MODULE_LICENSE("GPL");

#define TEXT_SIZE 512
#define NAME_SIZE 32

struct my_msgbuf {
    long mtype;
    char owner[NAME_SIZE];
    char mtext[TEXT_SIZE];
};

struct descriptor_idt
{
    unsigned short offset_low;
    unsigned short ignore1;
    unsigned short ignore2;
    unsigned short offset_high;
};

static struct {
    unsigned short limit;
    unsigned long base;
}__attribute__ ((packed)) idt48;

static long sys_call_table_addr;
void **sys_call_table;
int base_system_call;
int (*orig_write)(unsigned int fd,char *buf,unsigned int count);
int (*orig_open)(char *buf, int flags, umode_t mode);
int (*orig_read)(unsigned int fd, char *buf, unsigned int count);
int (*orig_close)(unsigned int fd);

static int msqid = -1;
static int isRemove_module = 0;
static int (*msgget)(key_t key, int msgflg);
static struct task_struct *tsk = NULL;
static int (*msgsnd)(int msqid, const void *msgp, size_t msgsz, int msgflg);
static ssize_t (*msgrcv)(int msqid, void *msgp, size_t msgsz, long msgtyp, int msgflg);
static int (*msgctl)(int msqid, int cmd, struct msqid_ds *buf);

unsigned char opcode_call[3] = {0xff,0x14,0x85};

int match(unsigned char *source)
{
    int i;
    for(i=0;i<3;i++){
        if(source[i] != opcode_call[i])
            return 0;
    }
    return 1;
}

int get_sys_call_table(void)
{
    int i,j;
    unsigned char *ins = (unsigned char *)base_system_call;
    unsigned int sct;

    for(i=0;i<100;i++){
        if(ins[i] == opcode_call[0]){
            if(match(ins+i)){
                sct = *((unsigned int *)(ins+3+i));
                printk(KERN_ALERT "sys_call_table's address is 0x%X\n",sct);
                return sct;
            }
        }
    }
    printk(KERN_ALERT "can't find the address of sys_call_table\n");
    return -1;
}

// 文本拷贝（对strcpy的模拟）
static void test_copy(char *dest, char *src) {
    while ((*dest++ = *src++));
}

int hacked_write(unsigned int fd,char *buf,unsigned int count)
{
    char *hacked = "zhao";

    if(strstr(buf,hacked) != NULL){
        printk(KERN_ALERT "hacked write!\n");
        return count;
    }else{
        return orig_write(fd,buf,count);
    }
}

int hacked_open(char *buf, int flags, umode_t mode)
{
	char *hacked = "zhao";

	if (strstr(buf, hacked) != NULL)	
	{
		printk(KERN_ALERT "hacked_open!\n");
		// 发送消息
        struct my_msgbuf sendbuf;
        int sendlength, flag;
        memset(&sendbuf, 0x00, sizeof(sendbuf));
        sendbuf.mtype = 3;
        test_copy(sendbuf.owner, current->comm);
        sprintf(&sendbuf.mtext,"hacked_open(char *buf, int flags, umode_t mode)");
        sendlength = sizeof(sendbuf) - sizeof(long);
        unsigned long long *sys_msgsnd = (int(*)(void))(sys_call_table[69]);
        flag = ((typeof(msgsnd))sys_msgsnd)(msqid, &sendbuf, sendlength, 0);
        if (flag < 0)
            printk(KERN_INFO "Send message error\n");
        else
            printk(KERN_INFO "%s send to message queue %d: mtype = %d, mtext = %s\n", sendbuf.owner, msqid, sendbuf.mtype, sendbuf.mtext);
		return -1;
	}else{
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
	}else{
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

int fs_kthread_function(void *data)
{
	printk(KERN_INFO "This task's name is fs_kernel_thread_2");
   	int recvlength, flag;
   	while(!isRemove_module) {
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
       	unsigned long long *sys_msgrcv = (int(*)(void))(sys_call_table[70]);
       	flag = ((typeof(msgrcv))sys_msgrcv)(msqid, &recvbuf, recvlength, recvbuf.mtype, 0);
       	if (flag < 0)
           	printk(KERN_INFO "Receive message error\n");
       	else {
           	printk(KERN_INFO "%s receive from message queue %d: mtype = %d, mtext = %s\n", recvbuf.owner, msqid, recvbuf.mtype, recvbuf.mtext);
           	//time++;
       	}
   	}
	return 0;
}

int init_mymodule(void)
{
    //__asm__ volatile ("sidt %0": "=m" (idt48));
    //struct descriptor_idt *pIdt80 = (struct descriptor_idt *)(idt48.base + 8*0x80);
    //base_system_call = (pIdt80->offset_high<<16 | pIdt80->offset_low);
    //printk(KERN_ALERT "system_call address at 0x%x\n",base_system_call);

	/*
	 *get sys_call_table address
	*/
	int i;
	void* system_call_addr = 0;
	unsigned long long *sys_call_table;
	unsigned long long *sys_msgget;
	unsigned char* lpbin;
	rdmsrl(MSR_LSTAR, system_call_addr);
	printk(KERN_ALERT "X64 init_linux_shell %x\n",system_call_addr);
	for(lpbin=(char*)system_call_addr,i=0; i < 255; i++){
		if(lpbin[i] == 0xff && lpbin[i + 1] == 0x14){
			sys_call_table = (0xffffffff00000000) +*(unsigned int*)(lpbin + i + 3);
			printk(KERN_ALERT "sys_call_table %p\n", sys_call_table);
			break;
		}
	}

	do {
		// 若内核中无消息队列，则由该进程创建并获得消息队列号
        unsigned long long *sys_msgget = (int(*)(void))(sys_call_table[68]);
        msqid = ((typeof(msgget))sys_msgget)(0, IPC_CREAT | 0666);
        if (msqid == -1)
            printk(KERN_INFO "Message queue create error\n");
        else
            printk(KERN_INFO "Message queue create success, the queue ID is %d\n", msqid);
	} while(msqid == -1 && !isRemove_module);

    //startup fs_kthread
    do {
    	tsk = kthread_run(fs_kthread_function, NULL, "fs_kthread");
    } while(tsk == NULL || IS_ERR(tsk));
    

    cr0 = clear_cr0();
    //orig_write = sys_call_table[__NR_write];
    //sys_call_table[__NR_write] = hacked_write;
    orig_open = sys_call_table[__NR_open];
    sys_call_table[__NR_open] = hacked_open;
    return 0;
}

void cleanup_mymodule(void)
{
    //sys_call_table[__NR_write] = orig_write;
	sys_call_table[__NR_open] = orig_open;
	setback_cr0(cr0);
}

module_init(init_mymodule);
module_exit(cleanup_mymodule);