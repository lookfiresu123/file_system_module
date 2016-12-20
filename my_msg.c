#include<linux/init.h>
#include<linux/module.h>
#include<linux/nsproxy.h>
#include<linux/kthread.h>
#include<linux/err.h>
#include<linux/types.h>
#include<linux/unistd.h>
#include<linux/msg.h>
#include<linux/security.h>
#include<linux/ipc_namespace.h>
#include<linux/proc_ns.h>
#include<linux/spinlock.h>
#include<linux/list.h>
#include<linux/ipc.h>
#include<linux/slab.h>
#include<linux/cred.h>
#include<linux/audit.h>
#include<linux/uidgid.h>
#include<linux/capability.h>
#include<linux/rcupdate.h>
#include<asm/unistd.h>
#include<asm-generic/memory_model.h>
#include<asm-generic/errno-base.h>
#include<asm-generic/current.h>
#include<linux/errno.h>
#include<linux/mm.h>
#include<linux/idr.h>
#include<linux/kernel.h>
#include<linux/pid.h>
#include<linux/const.h>
#include<linux/gfp.h>
#include<linux/time.h>
#include<linux/idr.h>
#include<linux/gfp.h>
#include<linux/rwsem.h>
#include "my_msg.h"


MODULE_LICENSE("Dual BSD/GPL");
// create a message queue's main code

int my_msgget(key_t key, int msgflg){
    struct ipc_namespace *ns;
    struct my_ipc_ops msg_ops;
    struct my_ipc_params msg_params;
    ns = current->nsproxy->ipc_ns;
    msg_ops.my_getnew = my_newque;
    msg_ops.my_associate = my_msg_security;
    msg_ops.my_more_checks = NULL;
    msg_params.key = key;
    msg_params.flg = msgflg;
    return my_ipcget(ns, &msg_ids(ns), &msg_ops, &msg_params);
}
int my_newque(struct ipc_namespace *ns, struct my_ipc_params *params){
    struct msg_queue *msq;
    int id, retval;
    key_t key = params->key;
    int msgflg = params->flg;
    msq = my_ipc_rcu_alloc(sizeof(*msq));
    if(!msq)
        return -ENOMEM;
    msq->q_perm.mode = msgflg & S_IRWXUGO;
    msq->q_perm.key = key;
    msq->q_perm.security = NULL;
    msq->q_stime = msq->q_rtime = 0;
    msq->q_ctime = get_seconds();
    msq->q_cbytes = msq->q_qnum = 0;
    msq->q_qbytes = ns->msg_ctlmnb;
    msq->q_lspid = msq->q_lrpid = 0;
    INIT_LIST_HEAD(&msq->q_messages);
    INIT_LIST_HEAD(&msq->q_receivers);
    INIT_LIST_HEAD(&msq->q_senders);
    id = my_ipc_addid(&msg_ids(ns), &msq->q_perm, ns->msg_ctlmni);
    if(id < 0){
        my_ipc_rcu_putref(msq, my_msg_rcu_free);
        return id;
    }
    my_ipc_unlock_object(&msq->q_perm);
    rcu_read_unlock();
    return msq->q_perm.id;
}
void *my_ipc_rcu_alloc(int size){
    struct my_ipc_rcu *out= my_ipc_alloc(sizeof(struct my_ipc_rcu) + size);
    if(unlikely(!out))
        return NULL;
    atomic_set(&out->refcount, 1);
    return out + 1;
}
void *my_ipc_alloc(int size){
    void *out;
    out = alloc_pages_exact(size, GFP_KERNEL);
/*

    if(size > PAGE_SIZE)
        out = vmalloc(size);
    else
        out = kmalloc(size, GFP_KERNEL);
*/
    return out;
}
int my_ipc_addid(struct ipc_ids* ids, struct kern_ipc_perm* new, int size){
    kuid_t euid;
    kgid_t egid;
    int id;
    int next_id = ids->next_id;
    if(size > IPCMNI)
        size - IPCMNI;
    if(ids->in_use >= size)
        return -ENOSPC;
    idr_preload(GFP_KERNEL);
    spin_lock_init(&new->lock);
    new->deleted = 0;
    rcu_read_lock();
    spin_lock(&new->lock);
    current_euid_egid(&euid, &egid);
    new->cuid = new->uid = euid;
    new->gid = new->cgid = egid;
    id = idr_alloc(&ids->ipcs_idr, new, (next_id < 0) ? 0 : ipcid_to_idx(next_id), 0, GFP_NOWAIT);
    idr_preload_end();
    if(id < 0){
        spin_unlock(&new->lock);
        rcu_read_unlock();
        return id;
    }
    ids->in_use++;
    if(next_id < 0){
        new->seq = ids->seq++;
        if(ids->seq > ids->seq_max)
            ids->seq = 0;
    }
    else{
        new->seq = ipcid_to_seqx(next_id);
        ids->next_id = -1;
    }
    new->id = my_ipc_buildid(id, new->seq);
    return id;
}
int my_ipc_buildid(int id, int seq){
    return 32768 * seq + id;
}

void my_msg_rcu_free(struct rcu_head *head)
{
	struct my_ipc_rcu *p = container_of(head, struct my_ipc_rcu, rcu);
	struct msg_queue *msq = my_ipc_rcu_to_struct(p);

	//security_msg_queue_free(msq);
	my_ipc_rcu_free(head);
}

int my_msg_security(struct kern_ipc_perm *ipcp, int msgflg){
    struct msg_queue *msq = container_of(ipcp, struct msg_queue, q_perm);
    return 0;
}
int my_ipcget(struct ipc_namespace *ns, struct ipc_ids *ids, struct my_ipc_ops *ops, struct my_ipc_params *params){
    if(params->key == IPC_PRIVATE)
        return my_ipcget_new(ns, ids, ops, params);
    else
        return my_ipcget_public(ns, ids, ops, params);
}
int my_ipcget_new(struct ipc_namespace *ns, struct ipc_ids *ids,struct my_ipc_ops *ops, struct my_ipc_params *params){
	int err;

	down_write(&ids->rwsem);
	err = ops->my_getnew(ns, params);
	up_write(&ids->rwsem);
	return err;
}

/**
 *	my_ipcget_public	-	get an ipc object or create a new one
 *	@ns: namespace
 *	@ids: IPC identifer set
 *	@ops: the actual creation routine to call
 *	@params: its parameters
 *
 *	This routine is called by sys_msgget, sys_semget() and sys_shmget()
 *	when the key is not IPC_PRIVATE.
 *	It adds a new entry if the key is not found and does some permission
 *      / security checkings if the key is found.
 *
 *	On success, the ipc id is returned.
 */
int my_ipcget_public(struct ipc_namespace *ns, struct ipc_ids *ids, struct my_ipc_ops *ops, struct my_ipc_params *params)
{
	struct kern_ipc_perm *ipcp;
	int flg = params->flg;
	int err;

	/*
	 * Take the lock as a writer since we are potentially going to add
	 * a new entry + read locks are not "upgradable"
	 */
	down_write(&ids->rwsem);
	ipcp = my_ipc_findkey(ids, params->key);
	if (ipcp == NULL) {
		/* key not used */
		if (!(flg & IPC_CREAT))
			err = -ENOENT;
		else
			err = ops->my_getnew(ns, params);
	} else {
		/* ipc object has been locked by ipc_findkey() */

		if (flg & IPC_CREAT && flg & IPC_EXCL)
			err = -EEXIST;
		else {
			err = 0;
			if (ops->my_more_checks)
				err = ops->my_more_checks(ipcp, params);
			if (!err)
				/*
				 * ipc_check_perms returns the IPC id on
				 * success
				 */
				err = my_ipc_check_perms(ns, ipcp, ops, params);
		}
		my_ipc_unlock(ipcp);
	}
	up_write(&ids->rwsem);

	return err;
}
void my_ipc_unlock(struct kern_ipc_perm *perm){
    my_ipc_unlock_object(perm);
    rcu_read_unlock();
}

/**
 *	ipc_findkey	-	find a key in an ipc identifier set
 *	@ids: Identifier set
 *	@key: The key to find
 *
 *	Requires ipc_ids.rwsem locked.
 *	Returns the LOCKED pointer to the ipc structure if found or NULL
 *	if not.
 *	If key is found ipc points to the owning ipc structure
 */

struct kern_ipc_perm *my_ipc_findkey(struct ipc_ids *ids, key_t key)
{
	struct kern_ipc_perm *ipc;
	int next_id;
	int total;

	for (total = 0, next_id = 0; total < ids->in_use; next_id++) {
		ipc = idr_find(&ids->ipcs_idr, next_id);

		if (ipc == NULL)
			continue;

		if (ipc->key != key) {
			total++;
			continue;
		}

		rcu_read_lock();
		my_ipc_lock_object(ipc);
		return ipc;
	}

	return NULL;
}


/**
 *	ipc_check_perms	-	check security and permissions for an IPC
 *	@ns: IPC namespace
 *	@ipcp: ipc permission set
 *	@ops: the actual security routine to call
 *	@params: its parameters
 *
 *	This routine is called by sys_msgget(), sys_semget() and sys_shmget()
 *      when the key is not IPC_PRIVATE and that key already exists in the
 *      ids IDR.
 *
 *	On success, the IPC id is returned.
 *
 *	It is called with ipc_ids.rwsem and ipcp->lock held.
 */
int my_ipc_check_perms(struct ipc_namespace *ns, struct kern_ipc_perm *ipcp, struct my_ipc_ops *ops, struct my_ipc_params *params){
	int err;

	if (my_ipcperms(ns, ipcp, params->flg)) {
      printk("File = %s, Line = %d, Func = %s\n", __FILE__, __LINE__, __FUNCTION__);
      err = -EACCES;
  }
	else {
		err = ops->my_associate(ipcp, params->flg);
		if (!err)
			err = ipcp->id;
	}

	return err;
}


// send message's main code
long my_msgsnd(int msqid, struct my_msgbuf *msgp, size_t msgsz, int msgflg){
    long mtype;
    mtype = msgp->mtype;
    return my_do_msgsnd(msqid, mtype, msgp->mtext, msgsz, msgflg);
}
long my_do_msgsnd(int msqid, long mtype, void *mtext, size_t msgsz, int msgflg){
    struct msg_queue *msq;
    struct my_msg_msg *msg;
    int err;
    struct ipc_namespace *ns;
    ns = current->nsproxy->ipc_ns;
    if(msgsz > ns->msg_ctlmax || (long) msgsz < 0 || msqid < 0) {
        printk("File = %s, Line = %d, Func = %s\n", __FILE__, __LINE__, __FUNCTION__);
        // testFunc();
        return -EINVAL;
    }
    if(mtype < 1) {
        // testFunc();
        printk("File = %s, Line = %d, Func = %s\n", __FILE__, __LINE__, __FUNCTION__);
        return -EINVAL;
    }
    msg = my_load_msg(mtext, msgsz);
    if(IS_ERR(msg))
        return PTR_ERR(msg);
    //printk("my_load_msg is ok\n");
    msg->m_type = mtype;
    msg->m_ts = msgsz;
    rcu_read_lock();
    msq = my_msq_obtain_object_check(ns, msqid);
    if(IS_ERR(msq)){
        err = PTR_ERR(msq);
        goto out_unlock1;
    }
    my_ipc_lock_object(&msq->q_perm);
    for(;;){
        struct my_msg_sender s;
        printk("File = %s, Line = %d, Func = %s\n", __FILE__, __LINE__, __FUNCTION__);
        err = -EACCES;

        if(my_ipcperms(ns, &msq->q_perm, S_IWUGO))
            goto out_unlock0;

        if(msq->q_perm.deleted){
            err = -EIDRM;
            goto out_unlock0;
        }
        /*err = security_msg_queue_msgsnd(msq, msg, msgflg);
        if(err)
            goto out_unlock0;
            */
        if(msgsz + msq->q_cbytes <= msq->q_qbytes && 1 + msq->q_qnum <= msq->q_qbytes){
            break;
        }
        if(msgflg & IPC_NOWAIT){
            err = -EAGAIN;
            goto out_unlock0;
        }
        my_ss_add(msq, &s);
        if(!my_ipc_rcu_getref(msg)){
            err = -EIDRM;
            goto out_unlock0;
        }
        my_ipc_unlock_object(&msq->q_perm);
        rcu_read_unlock();
        schedule();
        rcu_read_lock();
        my_ipc_lock_object(&msq->q_perm);
        my_ipc_rcu_putref(msq, my_ipc_rcu_free);
        if(msq->q_perm.deleted){
            err = -EIDRM;
            goto out_unlock0;
        }
        my_ss_del(&s);
        if(signal_pending(current)){
            err = -ERESTARTNOHAND;
            goto out_unlock0;
        }
    }
    msq->q_lspid = task_tgid_vnr(current);
    msq->q_stime = get_seconds();
    if(!my_pipelined_send(msq, msg)){
        list_add_tail(&msg->m_list, &msq->q_messages);
        msq->q_cbytes += msgsz;
        msq->q_qnum++;
        atomic_add(msgsz, &ns->msg_bytes);
        atomic_inc(&ns->msg_hdrs);
    }
    err = 0;
    msg = NULL;
out_unlock0:
    my_ipc_unlock_object(&msq->q_perm);
out_unlock1:
    rcu_read_unlock();
    if(msg != NULL)
        my_free_msg(msg);
    return err;
}
struct my_msg_msg *my_load_msg(const void *src, size_t len){
    struct my_msg_msg *msg;
    struct my_msg_msgseg *seg;
    int err = -EFAULT;
    size_t alen;
    msg = my_alloc_msg(len);
    if(msg == NULL)
        return ERR_PTR(-ENOMEM);
    alen = len < DATALEN_MSG ? len : DATALEN_MSG;
    memcpy(msg + 1, src, alen);
    for(seg = msg->next; seg != NULL; seg = seg->next){
        len -= alen;
        src = (char *)src + alen;
        alen = len < DATALEN_MSG ? len : DATALEN_MSG;
        memcpy(seg + 1, src, alen);
    }
    return msg;
}
void my_free_msg(struct my_msg_msg *msg){
    struct my_msg_msgseg *seg;
    seg = msg->next;
    kfree(msg);
    while(seg != NULL){
        struct my_msg_msgseg *tmp = seg->next;
        kfree(seg);
        seg = tmp;
    }
}
struct my_msg_msg *my_alloc_msg(size_t len){
	struct my_msg_msg *msg;
	struct my_msg_msgseg **pseg;
	size_t alen;
	alen = len < DATALEN_MSG ? len : DATALEN_MSG;
	msg = kmalloc(sizeof(*msg) + alen, GFP_KERNEL);
	if(msg == NULL){
        return NULL;
	}
	msg->next = NULL;
	msg->security = NULL;
	len -= alen;
	pseg = &msg->next;
	while(len > 0){
        struct my_msg_msgseg *seg;
        alen = len < DATALEN_SEG ? len : DATALEN_SEG;
        seg = kmalloc(sizeof(*seg) + alen, GFP_KERNEL);
        if(seg == NULL){
            goto out_err;
        }
        *pseg = seg;
        seg->next = NULL;
        pseg = &seg->next;
        len -= alen;
	}
	return msg;
out_err:
    my_free_msg(msg);
    return NULL;


}
int my_pipelined_send(struct msg_queue *msq, struct my_msg_msg *msg){
    struct my_msg_receiver *msr, *t;
    list_for_each_entry_safe(msr, t, &msq->q_receivers, r_list){
        if(my_testmsg(msg, msr->r_msgtype, msr->r_mode)){
            list_del(&msr->r_list);
            if(msr->r_maxsize < msg->m_ts){
                msr->r_msg = NULL;
                wake_up_process(msr->r_tsk);
               // smp_mb();
                msr->r_msg = ERR_PTR(-E2BIG);
            }
            else{
                msr->r_msg = NULL;
                msq->q_lrpid = task_pid_vnr(msr->r_tsk);
                msq->q_rtime = get_seconds();
                wake_up_process(msr->r_tsk);
                smp_mb();
                msr->r_msg = msg;
                return 1;

            }
        }
    }
    return 0;
}
void my_ipc_lock_object(struct kern_ipc_perm *perm){
	spin_lock(&perm->lock);
}
void my_ipc_unlock_object(struct kern_ipc_perm *perm)
{
    spin_unlock(&perm->lock);
}
struct msg_queue *my_msq_obtain_object_check(struct ipc_namespace *ns, int id){
	struct kern_ipc_perm *ipcp = my_ipc_obtain_object_check(&msg_ids(ns), id);
	if(IS_ERR(ipcp))
		return ERR_CAST(ipcp);

	return container_of(ipcp, struct msg_queue, q_perm);
}
struct kern_ipc_perm *my_ipc_obtain_object_check(struct ipc_ids *ids, int id)
{
	struct kern_ipc_perm *out = my_ipc_obtain_object(ids, id);

	if (IS_ERR(out))
		goto out;

	if (my_ipc_checkid(out, id))
		return ERR_PTR(-EIDRM);
out:
	return out;
}
struct kern_ipc_perm *my_ipc_obtain_object(struct ipc_ids *ids, int id)
{
	struct kern_ipc_perm *out;
	int lid = ipcid_to_idx(id);

	out = idr_find(&ids->ipcs_idr, lid);
	if (!out) {
      // testFunc();
      printk("File = %s, Line = %d, Func = %s\n", __FILE__, __LINE__, __FUNCTION__);
      return ERR_PTR(-EINVAL);
  }

	return out;
}
int my_ipc_checkid(struct kern_ipc_perm *ipcp, int uid)
{
	return uid / (32768) != ipcp->seq;
}

int my_ipcperms(struct ipc_namespace *ns, struct kern_ipc_perm *ipcp, short flag)
{
	kuid_t euid = current_euid();
	int requested_mode, granted_mode;

	requested_mode = (flag >> 6) | (flag >> 3) | flag;
	granted_mode = ipcp->mode;
	if (uid_eq(euid, ipcp->cuid) ||uid_eq(euid, ipcp->uid))
		granted_mode >>= 6;
	else if (in_group_p(ipcp->cgid) || in_group_p(ipcp->gid))
		granted_mode >>= 3;
	/* is there some bit set in requested_mode but not in granted_mode?*/
	if ((requested_mode & ~granted_mode & 0007) &&!ns_capable(ns->user_ns, CAP_IPC_OWNER))
		return -1;

    return 0;
}

void my_ss_add(struct msg_queue *msq, struct my_msg_sender *mss)
{
	mss->tsk = current;
	current->state = TASK_INTERRUPTIBLE;
	list_add_tail(&mss->list, &msq->q_senders);
}
void my_ss_del(struct my_msg_sender *mss)
{
	if (mss->list.next != NULL)
		list_del(&mss->list);
}
int my_ipc_rcu_getref(void *ptr)
{
	struct my_ipc_rcu *p = ((struct my_ipc_rcu *)ptr) - 1;

	return atomic_inc_not_zero(&p->refcount);
}

void my_ipc_rcu_putref(void *ptr, void (*func)(struct rcu_head *head))
{
	struct my_ipc_rcu *p = ((struct my_ipc_rcu *)ptr) - 1;

	if (!atomic_dec_and_test(&p->refcount))
		return;

	call_rcu(&p->rcu, func);
}

void my_ipc_rcu_free(struct rcu_head *head)
{
	struct my_ipc_rcu *p = container_of(head, struct my_ipc_rcu, rcu);

	if (is_vmalloc_addr(p))
		vfree(p);
	else
		kfree(p);
}
int my_testmsg(struct my_msg_msg *msg, long type, int mode)
{
	switch(mode)
	{
		case 1:
		case 5:
			return 1;
		case 4:
			if (msg->m_type <=type)
				return 1;
			break;
		case 2:
			if (msg->m_type == type)
				return 1;
			break;
		case 3:
			if (msg->m_type != type)
				return 1;
			break;
	}
	return 0;
}
// receive message' s main code
long my_msgrcv(int msqid, struct my_msgbuf * msgp, size_t msgsz, long msgtyp, int msgflg)
{
    return my_do_msgrcv(msqid, msgp, msgsz, msgtyp, msgflg, my_do_msg_fill);
}

long my_do_msg_fill(void *dest, struct my_msg_msg *msg, size_t bufsz){
    struct my_msgbuf *msgp = dest;
    size_t msgsz;
    msgp->mtype = msg->m_type;
    msgsz = (bufsz > msg->m_ts) ? msg->m_ts : bufsz;
    if(my_store_msg(msgp->mtext, msg, msgsz))
        return -EFAULT;
    return msgsz;
}
int my_store_msg(void *dest, struct my_msg_msg *msg, size_t len){
    size_t alen;
    struct my_msg_msgseg *seg;
    alen = len < DATALEN_MSG ? len : DATALEN_MSG;
    memcpy(dest, msg + 1, alen);
    for(seg = msg->next; seg != NULL; seg = seg->next){
        len -= alen;
        dest = (char *)dest + alen;
        alen = len < DATALEN_SEG ? len : DATALEN_SEG;
        memcpy(dest, seg + 1, alen);
    }
    return 0;
}
long my_do_msgrcv(int msqid, void *buf, size_t bufsz, long msgtyp, int msgflg,
	       long (*msg_handler)(void *, struct my_msg_msg *, size_t))
{
	int mode;
	struct msg_queue *msq;
	struct ipc_namespace *ns;
	struct my_msg_msg *msg, *copy = NULL;

	ns = current->nsproxy->ipc_ns;

	if (msqid < 0 || (long) bufsz < 0) {
      // testFunc();
      printk("File = %s, Line = %d, Func = %s\n", __FILE__, __LINE__, __FUNCTION__);
      return -EINVAL;
  }

	if (msgflg & MSG_COPY) {
      if ((msgflg & MSG_EXCEPT) || !(msgflg & IPC_NOWAIT)) {
          // testFunc();
          printk("File = %s, Line = %d, Func = %s\n", __FILE__, __LINE__, __FUNCTION__);
          return -EINVAL;
      }
		copy = my_prepare_copy(buf, min_t(size_t, bufsz, ns->msg_ctlmax));
		if (IS_ERR(copy))
			return PTR_ERR(copy);
	}
	mode = my_convert_mode(&msgtyp, msgflg);

	rcu_read_lock();
	msq = my_msq_obtain_object_check(ns, msqid);
	if (IS_ERR(msq)) {
		rcu_read_unlock();
		my_free_copy(copy);
		return PTR_ERR(msq);
	}

	for (;;) {
		struct my_msg_receiver msr_d;
    printk("File = %s, Line = %d, Func = %s\n", __FILE__, __LINE__, __FUNCTION__);
		msg = ERR_PTR(-EACCES);
		if (my_ipcperms(ns, &msq->q_perm, S_IRUGO))
			goto out_unlock1;

		my_ipc_lock_object(&msq->q_perm);

		/* raced with RMID? */
		if (msq->q_perm.deleted) {
			msg = ERR_PTR(-EIDRM);
			goto out_unlock0;
		}

		msg = my_find_msg(msq, &msgtyp, mode);
		if (!IS_ERR(msg)) {
			/*
			 * Found a suitable message.
			 * Unlink it from the queue.
			 */
			if ((bufsz < msg->m_ts) && !(msgflg & MSG_NOERROR)) {
				msg = ERR_PTR(-E2BIG);
				goto out_unlock0;
			}
			/*
			 * If we are copying, then do not unlink message and do
			 * not update queue parameters.
			 */
			if (msgflg & MSG_COPY) {
				msg = my_copy_msg(msg, copy);
				goto out_unlock0;
			}

			list_del(&msg->m_list);
			msq->q_qnum--;
			msq->q_rtime = get_seconds();
			msq->q_lrpid = task_tgid_vnr(current);
			msq->q_cbytes -= msg->m_ts;
			atomic_sub(msg->m_ts, &ns->msg_bytes);
			atomic_dec(&ns->msg_hdrs);
			my_ss_wakeup(&msq->q_senders, 0);

			goto out_unlock0;
		}

		/* No message waiting. Wait for a message */
		if (msgflg & IPC_NOWAIT) {
			msg = ERR_PTR(-ENOMSG);
			goto out_unlock0;
		}

		list_add_tail(&msr_d.r_list, &msq->q_receivers);
		msr_d.r_tsk = current;
		msr_d.r_msgtype = msgtyp;
		msr_d.r_mode = mode;
		if (msgflg & MSG_NOERROR)
			msr_d.r_maxsize = INT_MAX;
		else
			msr_d.r_maxsize = bufsz;
		msr_d.r_msg = ERR_PTR(-EAGAIN);
		current->state = TASK_INTERRUPTIBLE;

		my_ipc_unlock_object(&msq->q_perm);
		rcu_read_unlock();
		schedule();

		/* Lockless receive, part 1:
		 * Disable preemption.  We don't hold a reference to the queue
		 * and getting a reference would defeat the idea of a lockless
		 * operation, thus the code relies on rcu to guarantee the
		 * existence of msq:
		 * Prior to destruction, expunge_all(-EIRDM) changes r_msg.
		 * Thus if r_msg is -EAGAIN, then the queue not yet destroyed.
		 * rcu_read_lock() prevents preemption between reading r_msg
		 * and acquiring the q_perm.lock in ipc_lock_object().
		 */
		rcu_read_lock();

		/* Lockless receive, part 2:
		 * Wait until pipelined_send or expunge_all are outside of
		 * wake_up_process(). There is a race with exit(), see
		 * ipc/mqueue.c for the details.
		 */
		msg = (struct my_msg_msg*)msr_d.r_msg;
		while (msg == NULL) {
			cpu_relax();   // ÓëcpuÏà¹Ø
			msg = (struct my_msg_msg *)msr_d.r_msg;
		}

		/* Lockless receive, part 3:
		 * If there is a message or an error then accept it without
		 * locking.
		 */
		if (msg != ERR_PTR(-EAGAIN))
			goto out_unlock1;

		/* Lockless receive, part 3:
		 * Acquire the queue spinlock.
		 */
		my_ipc_lock_object(&msq->q_perm);

		/* Lockless receive, part 4:
		 * Repeat test after acquiring the spinlock.
		 */
		msg = (struct my_msg_msg*)msr_d.r_msg;
		if (msg != ERR_PTR(-EAGAIN))
			goto out_unlock0;

		list_del(&msr_d.r_list);
		if (signal_pending(current)) {
			msg = ERR_PTR(-ERESTARTNOHAND);
			goto out_unlock0;
		}

		my_ipc_unlock_object(&msq->q_perm);
	}

out_unlock0:
	my_ipc_unlock_object(&msq->q_perm);
out_unlock1:
	rcu_read_unlock();
	if (IS_ERR(msg)) {
		my_free_copy(copy);
		return PTR_ERR(msg);
	}

	bufsz = msg_handler(buf, msg, bufsz);
	my_free_msg(msg);

	return bufsz;
}
struct my_msg_msg *my_prepare_copy(void *buf, size_t bufsz){
    struct my_msg_msg *copy;
    copy = my_load_msg(buf, bufsz);
    if(!IS_ERR(copy))
        copy->m_ts = bufsz;
    return copy;
}
int my_convert_mode(long *msgtyp, int msgflg){
    if(msgflg & MSG_COPY)
        return 5;
    if(*msgtyp == 0)
        return 1;
    if(*msgtyp < 0){
        *msgtyp = -*msgtyp;
        return 4;
    }
    if(msgflg & MSG_EXCEPT)
        return 3;
    return 2;
}
void my_free_copy(struct my_msg_msg *copy){
    if(copy)
        my_free_msg(copy);
}
struct my_msg_msg * my_find_msg(struct msg_queue *msq, long *msgtyp, int mode){
    struct my_msg_msg *msg, *found = NULL;
    long count = 0;
    list_for_each_entry(msg, &msq->q_messages, m_list){
         if(my_testmsg(msg, *msgtyp, mode)){
            if(mode == 4 && msg->m_type != 1){
                *msgtyp = msg->m_type - 1;
                found = msg;
            }else if(mode == 5){
                if(*msgtyp == count)
                    return msg;
            }else
                return msg;
            count ++;
        }
    }
    return found ?: ERR_PTR(-EAGAIN);
}

struct my_msg_msg *my_copy_msg(struct my_msg_msg *src, struct my_msg_msg *dst){
    struct my_msg_msgseg *dst_pseg, *src_pseg;
    size_t len = src->m_ts;
    size_t alen;
    BUG_ON(dst == NULL);
    if(src->m_ts > dst->m_ts) {
        // testFunc();
        printk("File = %s, Line = %d, Func = %s\n", __FILE__, __LINE__, __FUNCTION__);
        return ERR_PTR(-EINVAL);
    }
    alen = len < DATALEN_MSG ? len : DATALEN_MSG;
    memcpy(dst + 1, src + 1, alen);
    for(dst_pseg = dst->next, src_pseg = src->next; src_pseg != NULL; dst_pseg = dst_pseg->next, src_pseg = src_pseg->next){
        len -= alen;
        alen = len < DATALEN_SEG ? len : DATALEN_SEG;
        memcpy(dst_pseg + 1, src_pseg + 1, alen);
    }
    dst->m_type = src->m_type;
    dst->m_ts = src->m_ts;
    return dst;

}
void my_ss_wakeup(struct list_head *h, int kill){
    struct my_msg_sender *mss, *t;
    list_for_each_entry_safe(mss, t, h, list){
        if(kill)
            mss->list.next = NULL;
        wake_up_process(mss->tsk);
    }
}
