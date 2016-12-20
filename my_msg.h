#include<linux/list.h>
#include<linux/security.h>
#include<linux/sched.h>
#include<linux/ipc.h>
#include<linux/kernel.h>

#define DATALEN_MSG ((size_t)PAGE_SIZE - sizeof(struct my_msg_msg))
#define DATALEN_SEG ((size_t)PAGE_SIZE - sizeof(struct my_msg_msgseg))
#define TEXT_SIZE 512
#define msg_ids(ns) ((ns)->ids[1])
#define ipcid_to_idx(id) ((id) % (32768))
#define ipcid_to_seqx(id) ((id) / (32768))
#define my_ipc_rcu_to_struct(p) ((void *)(p + 1))
struct my_ipc_rcu {
	struct rcu_head rcu;
	atomic_t refcount;
};
struct my_msg_msgseg{
    struct my_msg_msgseg *next;
};
struct my_msg_msg{
    struct list_head m_list;
    long m_type;
    size_t m_ts;
    struct my_msg_msgseg* next;
    void *security;
};
struct my_msg_sender{
	struct list_head list;
	struct task_struct *tsk;

};
struct  my_msg_receiver{
    struct list_head r_list;
    struct task_struct *r_tsk;
    int r_mode;
    long r_msgtype;
    long r_maxsize;
    struct my_msg_msg *volatile r_msg;
};

/*
struct my_msgbuf{
    long mtype;
    char mtext[TEXT_SIZE];
};
*/

struct my_msgbuf {
    long mtype;
    char mtext[1];
    struct task_struct *tsk;
    void (*deal_data)(struct my_msgbuf *msgp, void **retpp);                 // 需要在初始化时注册处理函数，用于让接收方或发送方调用并处理该消息中的data_ptr
    struct {
        void *func_container_ptr;
        void *object_ptr;
    } data;
};



struct my_ipc_params{
    key_t key;
    int flg;
    union{
        size_t size;
        int nsems;
    }u;
};
struct my_ipc_ops{
    int (*my_getnew)(struct ipc_namespace *, struct my_ipc_params *);
    int (*my_associate)(struct kern_ipc_perm *, int);
    int (*my_more_checks) (struct kern_ipc_perm *, struct my_ipc_params *);
};

// related to create a new queue
int my_msgget(key_t key, int msgflg);
int my_newque(struct ipc_namespace *ns, struct my_ipc_params *params);
void *my_ipc_rcu_alloc(int size);
void *my_ipc_alloc(int size);
int my_ipc_addid(struct ipc_ids* ids, struct kern_ipc_perm* new, int size);
int my_msg_security(struct kern_ipc_perm *ipcp, int msgflg);
int my_ipcget(struct ipc_namespace *ns, struct ipc_ids *ids, struct my_ipc_ops *ops, struct my_ipc_params *params);
int my_ipcget_new(struct ipc_namespace *ns, struct ipc_ids *ids, struct my_ipc_ops *ops, struct my_ipc_params *params);
int my_ipcget_public(struct ipc_namespace *ns, struct ipc_ids *ids, struct my_ipc_ops *ops, struct my_ipc_params *params);
struct kern_ipc_perm *my_ipc_findkey(struct ipc_ids *ids, key_t key);
int my_ipc_check_perms(struct ipc_namespace *ns, struct kern_ipc_perm *ipcp, struct my_ipc_ops *ops, struct my_ipc_params *params);
void my_msg_rcu_free(struct rcu_head *head);
int my_ipc_buildid(int id, int seq);
void my_ipc_unlock(struct kern_ipc_perm *perm);



// related to send message
long my_msgsnd(int msqid, struct my_msgbuf *msgp, size_t msgsz, int msgflg);
long my_do_msgsnd(int msqid, long mtype, void *mtext, size_t msgsz, int msgflg);
struct my_msg_msg *my_load_msg(const void *src, size_t len);
void my_free_msg(struct my_msg_msg *msg);
struct my_msg_msg *my_alloc_msg(size_t len);
int my_pipelined_send(struct msg_queue *msq, struct my_msg_msg *msg);
void my_ipc_lock_object(struct kern_ipc_perm *perm);
void my_ipc_unlock_object(struct kern_ipc_perm *perm);
int my_ipcperms(struct ipc_namespace *ns, struct kern_ipc_perm *ipcp, short flag);
void my_ss_add(struct msg_queue *msq, struct my_msg_sender *mss);
void my_ss_del(struct my_msg_sender *mss);
int my_ipc_rcu_getref(void *ptr);
void my_ipc_rcu_putref(void *ptr, void (*func)(struct rcu_head *head));
void my_ipc_rcu_free(struct rcu_head *head);
int my_testmsg(struct my_msg_msg *msg, long type, int mode);
struct msg_queue *my_msq_obtain_object_check(struct ipc_namespace *ns,int id);
struct kern_ipc_perm *my_ipc_obtain_object_check(struct ipc_ids *ids, int id);
struct kern_ipc_perm *my_ipc_obtain_object(struct ipc_ids *ids, int id);
int my_ipc_checkid(struct kern_ipc_perm *ipcp, int uid);

// related to receive message
long my_msgrcv(int msqid, struct my_msgbuf * msgp, size_t msgsz, long msgtyp, int msgflg);
long my_do_msg_fill(void *dest, struct my_msg_msg *msg, size_t bufsz);
int my_store_msg(void *dest, struct my_msg_msg *msg, size_t len);
long my_do_msgrcv(int msqid, void *buf, size_t bufsz, long msgtyp, int msgflg, long (*msg_handler)(void *, struct my_msg_msg *, size_t));
struct my_msg_msg *my_prepare_copy(void *buf, size_t bufsz);
int my_convert_mode(long *msgtyp, int msgflg);
void my_free_copy(struct my_msg_msg *copy);
struct my_msg_msg * my_find_msg(struct msg_queue *msq, long *msgtyp, int mode);
struct my_msg_msg *my_copy_msg(struct my_msg_msg *src, struct my_msg_msg *dst);
void my_ss_wakeup(struct list_head *h, int kill);
