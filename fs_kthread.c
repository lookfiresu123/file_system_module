#include "fs_kthread.h"

static int getStrlength(char *buf){
    int len = 0;
    while(buf[len] !='\0'){
        len ++;
    }
    return len + 1;
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
            // printk(KERN_INFO "syscall_table_addr %p\n", syscall_table_addr);
            break;
        }
    }
}

int hacked_write(unsigned int fd,char *buf,unsigned int count)
{
    char *hacked = "zhao";
    if(strstr(buf,hacked) != NULL){
      // printk(KERN_ALERT "hacked write!\n");
        return count;
    } else{
        return orig_write(fd,buf,count);
    }
}

// 对open系统调用消息的处理函数，从kernel到fs
void callback_open(struct my_msgbuf *this) {
    typedef Argus_msg3(char *, int, umode_t) Argus_type;
    Argus_type *ptr = (Argus_type *)(this->argus_ptr);
    long obj = orig_open(ptr->argu1, ptr->argu2, ptr->argu3);// orig_open()函数
    this->object_ptr = (void *)obj;
    printk("call callback_open success, and the fd = %d\n", obj);
    // 返回消息给发送方
    //int sendlength = sizeof(*this) - sizeof(long);
    int sendlength = sizeof(*this);
    this->isend = 1;
    my_msgsendA(this, sendlength);
    printk(KERN_INFO "send message to A success!\n");
    //int flag = my_msgsnd(this->msqid, this, sendlength, 0);

}

// kernel进程
int hacked_open(char *buf, int flags, umode_t mode)
{
  // strcpy(current->comm, "kernel_kthread");
  char *hacked = "zhao";
  long ret;
  if (strstr(buf, hacked) != NULL){
    // printk(KERN_ALERT "hacked_open!\n");
    strcpy(current->comm, "kernel_kthread");
    fs_temp = get_current();
    fs_start = true;
    // 发送消息
    struct my_msgbuf *sendbuf;
    int sendlength, flag;
    sendbuf = kmalloc(sizeof(struct my_msgbuf), GFP_KERNEL);
    //sendbuf->mtype = 3;
    sendbuf->tsk = current;
    sendbuf->callback = callback_open;
    sendbuf->msqid = msqid_from_fs_to_kernel;
    typedef Argus_msg3(char *, int, umode_t) Argus_type;
    Argus_type *ptr = (Argus_type *)kmalloc(sizeof(Argus_type), GFP_KERNEL);
    char *kbuf = (char *)kmalloc(PATH_SIZE * sizeof(char), GFP_KERNEL);
    memcpy(kbuf, buf, getStrlength(buf));
    ptr->argu1 = kbuf;
    ptr->argu2 = flags;
    ptr->argu3 = mode;
    sendbuf->argus_ptr = ptr;
    sendlength = sizeof(struct my_msgbuf);
    //AsendB(sendbuf, sendlength);
    my_msgsendB(sendbuf, sendlength);
    printk(KERN_INFO "send message to B success! and current process is %s\n", current->comm);
    //sendlength = sizeof(struct my_msgbuf) - sizeof(long);
    //flag = my_msgsnd(msqid_from_kernel_to_fs, sendbuf, sendlength, 0);
    //printk(KERN_ALERT "");
    /*
    if (flag < 0){
        printk(KERN_INFO "kernel send message to fs failed, and the error number = %d\n", flag);
    } else {
        printk(KERN_INFO "kernel send message to fs success\n");
        printk(KERN_INFO "buf = %s, flags = %d, mode = %u\n", ptr->argu1, ptr->argu2, ptr->argu3);
    }
    */
    do {
      //flag = my_msgrcv(msqid_from_fs_to_kernel, sendbuf, sendlength, 3, 0);
      //AreceiveB(sendbuf, sendlength);
      my_msgrcvB(sendbuf, sendlength);
      printk("sendbuf->isend = %d\n", sendbuf->isend);
      if (sendbuf->isend == 0)
        sendbuf->callback(sendbuf);
      else
        break;
    } while(1);
    /*
    if (flag < 0)
        printk(KERN_INFO "kernel receive message from fs failed, and the error number = %d\n", flag);
    else
        printk(KERN_INFO "kernel receive message from fs success\n");
    */
    // 处理从进程B接收到的消息
    // long *fdp = (long *)(sendbuf->object_ptr);
    ret = (long)(sendbuf->object_ptr);
    // printk(KERN_INFO "FILE = %s, LINE = %d, FUNC = %s, fd = %d\n", __FILE__, __LINE__, __FUNCTION__, ret);
    kfree(kbuf);
    kfree(sendbuf);
    // printk(KERN_INFO "FILE = %s, LINE = %d, FUNC = %s, fd = %d\n", __FILE__, __LINE__, __FUNCTION__, ret);
    fs_start = false;
    // return ret;
  } else {
    ret = orig_open(buf, flags, mode);
  }
  strcpy(current->comm, "");
  return ret;
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

// fs进程
int fs_kthread_function(void *data)
{
  // printk("Now on : file = %s, line = %d, func = %s\n", __FILE__, __LINE__, __FUNCTION__);
  printk(KERN_INFO "This task's name is fs_kthread, and run do_sys_open()\n");
  printk(KERN_INFO "current->pid = %d\n", get_current()->pid);
  printk(KERN_INFO "-----------------------------------------------------\n");
  int recvlength, flag;
  while(!isRemove_module) {
    strcpy(get_current()->comm, "");
    struct my_msgbuf recvbuf;
    memset(&recvbuf, 0x00, sizeof(recvbuf));
    recvlength = sizeof(recvbuf);
    my_msgrcvA(&recvbuf, recvlength);
    printk(KERN_INFO "receive message from A success!\n");
    // printk(KERN_INFO "fs receive message from kernel success\n");
    typedef Argus_msg3(char *, int, umode_t) Argus_type;
    Argus_type *ptr = recvbuf.argus_ptr;
    printk(KERN_INFO "buf = %s, flags = %d, mode = %u\n",ptr->argu1, ptr->argu2, ptr->argu3);
    // 解析消息并处理
    strcpy(get_current()->comm, "fs_kthread");
    recvbuf.callback(&recvbuf);
    strcpy(get_current()->comm, "");
  }
  return 0;
}

int init_mymodule(void){
	//get sys_call_table base address
	get_syscall_table();
  AB_shmAddr = alloc_pages_exact(maxSize, GFP_KERNEL);
  BA_shmAddr = alloc_pages_exact(maxSize, GFP_KERNEL);
  init_shm();
  init_waitqueue();
  printk(KERN_INFO "AB_shmAddr = %p, msgsendA_begin_addr = %p, msgrcvA_begin_addr = %p\n", AB_shmAddr, msgsendB_begin_addr, msgrcvA_begin_addr);
  printk(KERN_INFO "BA_shmAddr = %p, msgsendB_begin_addr = %p, msgrcvB_begin_addr = %p\n", BA_shmAddr, msgsendA_begin_addr, msgrcvB_begin_addr);
	// 创建从kernel到fs的消息队列
  /*
	while(1){
      msqid_from_kernel_to_fs = my_msgget(0, IPC_CREAT);
      if(msqid_from_kernel_to_fs < 0){
        // printk(KERN_INFO "my_msgget failed with error!\n");
      } else{
        // printk(KERN_INFO "message queue create success, the message queue id of msqid_from_kernel_to_fs is % d\n", msqid_from_kernel_to_fs);
          break;
      }
	}
  	// 创建从fs到kernel的消息队列
	while(1){
      msqid_from_fs_to_kernel = my_msgget(0, IPC_CREAT);
      if(msqid_from_fs_to_kernel < 0){
        // printk(KERN_INFO "my_msgget failed with error!\n");
      } else{
        // printk(KERN_INFO "message queue create success, the message queue id of msqid_from_fs_to_kernel is % d\n", msqid_from_fs_to_kernel);
          break;
      }
	}
  */
  msqid_from_kernel_to_fs = -1;
  msqid_from_fs_to_kernel = -1;
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
