/*
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
#include <linux/gfp.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/ipc_namespace.h>
#include <linux/nsproxy.h>
#include <linux/kthread.h>
#include <linux/unistd.h>
#include <linux/err.h>
#include <linux/fs_struct.h>
#include <linux/path.h>
#include <linux/dcache.h>
#include <linux/fdtable.h>
#include <linux/fcntl.h>
#include <linux/fs.h>
#include <uapi/asm-generic/fcntl.h>
#include <uapi/linux/fcntl.h>
#include <uapi/asm-generic/errno.h>
#include <uapi/asm-generic/resource.h>
#include <linux/spinlock.h>
#include <linux/namei.h>
#include <uapi/linux/limits.h>
#include <linux/compiler.h>
#include <linux/fsnotify.h>

#include "hook.h"
#include "my_msg.h"
*/
// #include "open.h"
#include "hook.h"


MODULE_LICENSE("GPL");

// #define EMBEDDED_NAME_MAX (PATH_MAX - sizeof(struct filename))


static int getStrlength(char *buf){
	int len = 0;
	while(buf[len] !='\0'){
		len++;
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
    	}else{
        		return orig_write(fd,buf,count);
   	}
}

int hacked_open(char *buf, int flags, umode_t mode)
{
	char *hacked = "zhao";

	if (strstr(buf, hacked) != NULL){
		struct my_msgbuf *sendbuf;
    		int sendlength, flag;
    		sendbuf = kmalloc(sizeof(*sendbuf) + sizeof(struct my_msgbuf), GFP_KERNEL);
    		sendbuf->mtype = 3;
    		//adding current to the message would lead to error when "rmmod" the modules
		sprintf(&sendbuf->mtext, "open %s %d %d %p", buf, flags, mode, current);
    		sendlength = sizeof(struct my_msgbuf) - sizeof(long);      	
		flag = my_msgsnd(msqid, sendbuf, sendlength, 0);
    		if (flag < 0)
			printk(KERN_INFO "Send message error! flag is %d\n", flag);				
		else
			printk(KERN_INFO "Send message ok!\n");
		kfree(sendbuf);
		return 3;
	}
	else{
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

char **transform(char *s)
{
	printk(KERN_INFO "message is %s\n", s);
    	char *res[MAX_NUMS_SYSCALL_ARGC];
    	int i = 0, begin = 0, k = 0;
    	while (s[i] != '\0') {
        		if (s[i] == ' ') {
            		char *tmp = (char *)kmalloc(i - begin + 1, GFP_KERNEL);
            		memcpy(tmp, s + begin, i - begin);
            		tmp[i - begin] = '\0';
            		res[k++] = tmp;
            		begin = i + 1;
        		} else if (s[i + 1] == '\0') {
            		char *tmp = (char *)kmalloc(i - begin + 2, GFP_KERNEL);
            		memcpy(tmp, s + begin, i - begin + 1);
            		tmp[i - begin + 1] = '\0';
            		res[k++] = tmp;
        		}
        		++i;
    	}
    	return res;
}

// convert string to unsigned long long by guanjun
ullong_type strtoull(const char *nptr, char **endptr, int base) {
	const char *s = nptr;
	ullong_type acc;
	int c;
	ullong_type cutoff;
	int neg = 0, any, cutlim;

	c = *s++;
	if(c == '-') {
		neg = 1;
		c = *s++;
	} else if(c == '+')
		c = *s++;
	if((base == 0 || base == 16) && c == '0' && (*s == 'x' || *s == 'X')) {
		c = s[1];
		s += 2;
		base = 16;
	}
	if(base == 0)
		base = (c == '0' ? 8 : 10);
	cutoff = (ullong_type)ULLONG_MAX / (ullong_type)base;
	cutlim = (ullong_type)ULLONG_MAX % (ullong_type)base;
	for (acc = 0, any = 0;; c = *s++)
	{
		if(c >= '0' && c <= '9')
			c -= '0';
		else if(c >= 'a' && c <= 'z')
			c -= ('a' - 10);
		else if(c >= 'A' && c <= 'Z')
			c -= ('A' - 10);
		else
			break;
		if(c >= base)
			break;
		if(any < 0 || acc > cutoff || (acc == cutoff && c > cutlim))
			any = -1;
		else {
			any = 1;
			acc *= base;
			acc += c;
		}
	}
	if(any < 0) {
		acc = ULLONG_MAX;
	}else if(neg)
		acc = -acc;
	if(endptr != NULL && endptr != 0)
		*endptr = (char *)(any ? s - 1 : nptr);
	return acc;
}


//convert string to int by guanjun
int atoi(const char *str)
{
	char *temp = str;
	int i = 0;
	int flags = 0;
	unsigned int sum = 0;
	while(*temp == ' ') ++temp;
	if (*temp != '-' && *temp != '+' && (*temp < '0' || *temp > '9'))
		return 0;
	if (*temp == '-')
	{
		flags = 1;
		++temp;
	}else if (*temp == '+')
	{
		++temp;
	}

	while(*temp >= '0' && *temp <= '9')
	{
		if (!flags)
		{
			if (sum > MAX_INT / 10 || (sum == MAX_INT / 10 && (*temp > '7')))
			{
				return MAX_INT;
			}
		} else {
			if (sum > MAX_INT / 10 || (sum == MAX_INT / 10 && (*temp > '8')))
			{
				return MIN_INT;
			}
		}
		sum = sum * 10 + (*temp - '0');
		++temp;
	}

	return flags ? (-sum) : sum;
}

//change the implement of syscall
static inline int build_open_flags(int flags, umode_t mode, struct open_flags *op)
{
	int lookup_flags = 0;
	int acc_mode;

	if (flags & (O_CREAT | __O_TMPFILE))
		op->mode = (mode & S_IALLUGO) | S_IFREG;
	else
		op->mode = 0;

	flags &= ~FMODE_NONOTIFY & ~O_CLOEXEC;

	if (flags & __O_SYNC)
		flags |= O_DSYNC;

	if (flags & __O_TMPFILE) {
		if ((flags & O_TMPFILE_MASK) != O_TMPFILE)
			return -EINVAL;
		acc_mode = MAY_OPEN | ACC_MODE(flags);
		if (!(acc_mode & MAY_WRITE))
			return -EINVAL;
	} else if (flags & O_PATH) {
		flags &= O_DIRECTORY | O_NOFOLLOW | O_PATH;
		acc_mode = 0;
	} else {
		acc_mode = MAY_OPEN | ACC_MODE(flags);
	}

	op->open_flag = flags;

	if (flags & O_TRUNC)
		acc_mode |= MAY_WRITE;
	if (flags & O_APPEND)
		acc_mode |= MAY_APPEND;

	op->acc_mode = acc_mode;

	op->intent = flags & O_PATH ? 0 : LOOKUP_OPEN;

	if (flags & O_CREAT) {
		op->intent |= LOOKUP_CREATE;
		if (flags & O_EXCL)
			op->intent |= LOOKUP_EXCL;
	}

	if (flags & O_DIRECTORY)
		lookup_flags |= LOOKUP_DIRECTORY;
	if (!(flags & O_NOFOLLOW))
		lookup_flags |= LOOKUP_FOLLOW;
	op->lookup_flags = lookup_flags;
	return 0;
}

void final_putname(struct filename *name) {
	if(name->separate) {
		__putname(name->name);
	}else {
		__putname(name);
	}
}

struct filename * getname_flags(char *filename, int flags, int *empty) {
	struct filename *result, *err;
	int len;
	long max;
	char *kname;

	result = __getname();
	if (unlikely(!result))
		return ERR_PTR(-ENOMEM);

	kname = (char *)result + sizeof(*result);
	result->name = kname;
	result->separate = false;
	max = EMBEDDED_NAME_MAX;

recopy:
	len = strncpy_from_user(kname, filename, max);
	if (unlikely(len < 0)) {
		err = ERR_PTR(len);
		goto error;
	}

	if (len == EMBEDDED_NAME_MAX && max == EMBEDDED_NAME_MAX) {
		kname = (char *)result;

		result = kzalloc(sizeof(*result), GFP_KERNEL);
		if (!result) {
			err = ERR_PTR(-ENOMEM);
			result = (struct filename *)kname;
			goto error;
		}
		result->name = kname;
		result->separate = true;
		max = PATH_MAX;
		goto recopy;
	}

	if (unlikely(!len)) {
		if (empty)
			*empty = 1;
		err = ERR_PTR(-ENOENT);
		if (!(flags & LOOKUP_EMPTY))
			goto error;
	}

	err = ERR_PTR(-ENAMETOOLONG);
	if (unlikely(len >= PATH_MAX))
		goto error;

	result->uptr = filename;
	return result;

error:
	final_putname(result);
	return err;
}

//add for get current files_struct from user process
struct files_struct* get_current_files(struct task_struct *tsk) {
	return tsk->files;
}

//add for get current fs_struct from user process
struct fs_struct* get_current_fs(struct task_struct *tsk) {
	return tsk->fs;
}

void __fd_install(struct files_struct *files, unsigned int fd, struct file *file) {
	printk(KERN_ALERT "enter __fd_install\n");
	struct fdtable *fdt;
	//files->file_lock is  a NULL pointer, we should consider this carefully
	printk(KERN_ALERT "enter spin_lock\n");
	spin_lock(&files->file_lock);
	printk(KERN_ALERT "enter files_fdtable\n");
	fdt = files_fdtable(files);
	printk(KERN_ALERT "files_fdtable exec\n");
	rcu_assign_pointer(fdt->fd[fd], file);
	printk(KERN_ALERT "rcu_assign_pointer exec\n");
	spin_unlock(&files->file_lock);
}

int __alloc_fd(struct files_struct *files, unsigned start, unsigned end, unsigned flags) {
	unsigned int fd;
	int error;
	struct fdtable *fdt;

	spin_lock(&files->file_lock);
repeat:
	fdt = files_fdtable(files);
	fd = start;
	if (fd < files->next_fd)
		fd = files->next_fd;

    /* now we didn't consider other conditions
	if (fd < fdt->max_fds)
		fd = find_next_zero_bit(fdt->open_fds, fdt->max_fds, fd);

	error = -EMFILE;
	if (fd >= end)
		goto out;

	error = expand_files(files, fd);
	if (error < 0)
		goto out;

	if (error)
		goto repeat;
	*/

	if (start <= files->next_fd)
		files->next_fd = fd + 1;

	__set_bit(fd, fdt->open_fds);
	if (flags & O_CLOEXEC)
		__set_bit(fd, fdt->close_on_exec);
	else
		__clear_bit(fd, fdt->close_on_exec);
	error = fd;
#if 1
	if (rcu_dereference_raw(fdt->fd[fd]) != NULL) {
		printk(KERN_WARNING "alloc_fd: slot %d not NULL!\n", fd);
		rcu_assign_pointer(fdt->fd[fd], NULL);
	}
#endif

out:
	spin_unlock(&files->file_lock);
	return error;
}

// receive message code
int fs_kthread_function(void *data)
{
	printk(KERN_INFO "This task's name is fs_kthread");
   	int recvlength, flag;
   	while(!kthread_should_stop() && !isRemove_module) {
		struct my_msgbuf recvbuf;
       		if (msqid == -1) continue;
       		memset(&recvbuf, 0x00, sizeof(recvbuf)) ;
       		recvbuf.mtype = 3;
       		recvlength = sizeof(recvbuf) - sizeof(long);
       		flag = my_msgrcv(msqid, &recvbuf, recvlength, recvbuf.mtype, 0);
       		if (flag < 0)
           		printk(KERN_INFO "Receive message error\n");
       		else {
        			//add for taking a try by guanjun
        			const char *msg = recvbuf.mtext;
        			printk(KERN_ALERT "msg is %s\n", msg);
        			int *count;
        			char **argv = argv_split(GFP_KERNEL, msg, count);
        			if (strcmp(argv[0], "open") == 0)
        			{
        				int fd;
        				long ret;	
        				struct task_struct *get_current = (typeof(struct task_struct *))(void *)((ullong_type)strtoull(argv[4], NULL, 16));
        				const char *filename = argv[1];
        				int flags = atoi(argv[2]);
        				umode_t mode = (umode_t)atoi(argv[3]);
        				if(force_o_largefile())
        					flags |= O_LARGEFILE;
        				struct open_flags op;
        				ret = build_open_flags(flags, mode, &op);
        				struct filename *tmp;
        				if(ret == 0) {
        					tmp = getname_flags(filename, 0, NULL);
        					if(IS_ERR(tmp))
        						ret = PTR_ERR(tmp);
        					else {
						printk(KERN_ALERT "current->files is %p\n", get_current->files);
        						fd = __alloc_fd(get_current_files(get_current), 0, task_rlimit(get_current, RLIMIT_NOFILE), flags);
						printk(KERN_ALERT "current->files is %p\n", get_current->files);
        						if(fd >= 0) {
        							/* my_do_filp_open works well when the user is "root", we should consider this situation carefully,
        							  *  marked by guanjun
        							*/
        							struct file *f = my_do_filp_open(AT_FDCWD,tmp,&op,get_current);
							printk(KERN_ALERT "current->files is %p\n", get_current->files);
        							printk(KERN_ALERT "my_do_filp_open exec\n");
        							if(IS_ERR(f)) {
        								printk(KERN_ALERT "create struct file failed!\n");
        								ret = PTR_ERR(f);
        							}else {
        								printk(KERN_ALERT "current->files is %p\n", get_current->files);
        								fsnotify_open(f);
        								printk(KERN_ALERT "fsnotify_open exec\n");
								printk(KERN_ALERT "current->files is %p\n", get_current->files);
        								__fd_install(get_current_files(get_current), fd, f);
        								printk(KERN_ALERT "__fd_install exec, current is %p\n", get_current);
        								ret = fd;
        							}
        						}
        					}
        					printk(KERN_ALERT "ret is %d\n", ret);
        					final_putname(tmp);
        					printk(KERN_ALERT "final_putname exec\n");
        				}
        				printk(KERN_ALERT "fd is %d\n", ret);
        			} else {
        				printk(KERN_ALERT "error!\n");
        			}
       		}
   	}
	return 0;
}

static int __init init_mymodule(void){
	get_syscall_table();
	while(1){
		msqid = my_msgget(0, IPC_CREAT | 0666);
		if(msqid < 0){
			printk(KERN_INFO "msgget failed with error!\n");
		}
		else{
			printk(KERN_INFO "msq_queue's id is % d\n", msqid);
			break;
		}
	}

	do {
    		tsk = kthread_create(fs_kthread_function, NULL, "fs_kthread");
    	} while(IS_ERR(tsk));
    	cr0 = clear_cr0();
    	orig_open = syscall_table_addr[__NR_open];
	syscall_table_addr[__NR_open] = hacked_open;
	wake_up_process(tsk);
	return 0;
}

static void __exit cleanup_mymodule(void){
	isRemove_module = 1;
	syscall_table_addr[__NR_open] = orig_open;
	setback_cr0(cr0);
	if (!IS_ERR(tsk)){
		kthread_stop(tsk);
	}
}

module_init(init_mymodule);
module_exit(cleanup_mymodule);
