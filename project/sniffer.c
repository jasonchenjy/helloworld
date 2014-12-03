/*
 * sniffer skeleton (Linux kernel module)
 *
 * Copyright (C) 2014 Ki Suh Lee <kslee@cs.cornell.edu>
 * based on netslice implementation of Tudor Marian <tudorm@cs.cornell.edu>
 */

#include <linux/module.h>
#include <linux/cdev.h>
#include <linux/types.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/moduleparam.h>
#include <linux/version.h>
#include <linux/netdevice.h>
#include <linux/netfilter_ipv4.h>
#include <linux/inet.h>
#include <linux/mm.h>
#include <linux/udp.h>
#include <linux/fs.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <linux/sched.h>
#include <linux/spinlock.h>
#include <linux/wait.h>
#include <linux/seq_file.h>
#include "sniffer_ioctl.h"

MODULE_AUTHOR("JUNYU CHEN");
MODULE_DESCRIPTION("CS5413 Packet Filter / Sniffer Framework");
MODULE_LICENSE("Dual BSD/GPL");

static dev_t sniffer_dev;
static struct cdev sniffer_cdev;
static int sniffer_minor = 1;
atomic_t refcnt;

static int hook_chain_out = NF_INET_POST_ROUTING;
static int hook_chain = NF_INET_PRE_ROUTING;
static int hook_prio = NF_IP_PRI_FIRST;
struct nf_hook_ops nf_hook_ops;
struct nf_hook_ops nf_hook_ops_post;

struct semaphore dev_sem;
wait_queue_head_t readqueue;
//init_MUTEX (dev_sem);

static char* SIGNATURE= "Hakim";
static struct state_HashMap* STATE_MAP;

// skb buffer between kernel and user space
struct list_head skbs;
struct list_head rule;

// skb wrapper for buffering
struct skb_list 
{
    struct list_head list;
    struct sk_buff *skb;
};

struct list_entry
{
    struct list_head list;
    uint32_t dst_ip;
    uint32_t src_ip;
    uint16_t src_port;
    uint16_t dst_port;
    int action;
    int enable;
};




static inline struct tcphdr * ip_tcp_hdr(struct iphdr *iph)
{
    struct tcphdr *tcph = (void *) iph + iph->ihl*4;
    return tcph;
}

static inline struct udp * ip_udp_hdr(struct iphdr *iph)
{
   
    struct udphdr *udph = (void *) iph + iph->ihl*4;
    return udph;
    
}


/* From kernel to userspace */
static ssize_t 
sniffer_fs_read(struct file *file, char __user *buf, size_t count, loff_t *pos)
{
	//if(down_interruptible(&dev_sem)
	//{
	/*	return -ERESTARTSYS;
	}		
	while(list_empty(&skbs))
	{
		up(&dev_sem);
		if(file->f_flags & O_NONBLOCK)
			return -EAGAIN;
		if(wait_event_interruptible(readqueue, (!list_empty(&skbs))))
			return -ERESTARTSYS;
		if(down_interruptible(&dev_sem))
			return -ERESTARTSYS;

	}
	*/
	if(atomic_read(&refcnt)>0){
		return -EBUSY;
	}	
	atomic_set(&refcnt, 1);
	wait_event_interruptible(readqueue, (!list_empty(&skbs)));
	//down_interruptible(&dev_sem);
	if(list_empty(&skbs)){
		//up(&dev_sem);
		atomic_set(&refcnt, 0);
		return -1;
	}
	struct list_head* p;
	struct list_head* q;
	struct skb_list* entry;
	//list_for_each_safe(p, q, &skbs)
	{
		//entry=list_entry(p, struct skb_list, list);	
		entry=list_entry(skbs.next, struct skb_list, list);
			//memcpy(buf, entry->skb->data, 1);
		copy_to_user(buf, entry->skb->data, entry->skb->len);
		down_interruptible(&dev_sem);
		list_del(skbs.next);
		up(&dev_sem);
		printk(KERN_DEBUG "SEND   %d  !!\n", entry->skb->len);
		//break;	
	}
    	//printk(KERN_DEBUG "Hello World\n");
	//memcpy(buf, "aaaa", 4);
   	//up(&dev_sem);
	//return 0;
	atomic_set(&refcnt, 0);
	return entry->skb->len;
}

static int sniffer_fs_open(struct inode *inode, struct file *file)
{
    printk(KERN_DEBUG "OPEN\n");
    struct cdev *cdev = inode->i_cdev;
    int cindex = iminor(inode);

    if (!cdev) {
        printk(KERN_ERR "cdev error\n");
        return -ENODEV;
    }

    if (cindex != 0) {
        printk(KERN_ERR "Invalid cindex number %d\n", cindex);
        return -ENODEV;
    }

    return 0;
}

static int sniffer_fs_release(struct inode *inode, struct file *file)
{
    return 0;
}

static void add_to_list(uint32_t dst_ip, uint32_t src_ip, uint16_t src_port, uint16_t dst_port, int action, int enable)
{
	int exist=0;
	struct list_head* p;
	struct list_entry* entry;
	list_for_each(p, &rule)
	{
		entry=list_entry(p, struct list_entry, list);
		if(entry->dst_ip==dst_ip && entry->src_ip==src_ip && entry->src_port==src_port && entry->dst_port==dst_port)
		{
			exist=1;
			break;
		}
	}
	if(exist){
		printk(KERN_DEBUG "Find!!! changing\n");
		entry->action=action;
		entry->enable=enable;
	}else{
		entry=(struct list_entry*)vmalloc(sizeof(struct list_entry));
		entry->dst_ip=dst_ip;
		entry->src_ip=src_ip;
		entry->src_port=src_port;
		entry->dst_port=dst_port;
		entry->action=action;
		entry->enable=enable;
		list_add_tail(&entry->list, &rule);
	}
	//if(action==SNIFFER_ACTION_CAPTURE){
		//entry->skb=(struct sk_buff*)vmalloc(sizeof(struct sk_buff));
	//}

}


static long sniffer_fs_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{

    
    struct sniffer_flow_entry *entry=(struct sniffer_flow_entry*)arg;

    long err =0 ;
    
    if (_IOC_TYPE(cmd) != SNIFFER_IOC_MAGIC)
        return -ENOTTY; 
    if (_IOC_NR(cmd) > SNIFFER_IOC_MAXNR)
        return -ENOTTY;
    if (_IOC_DIR(cmd) & _IOC_READ)
        err = !access_ok(VERIFY_WRITE, (void __user *)arg, _IOC_SIZE(cmd));
    if (_IOC_DIR(cmd) & _IOC_WRITE)
        err = !access_ok(VERIFY_READ, (void __user *)arg, _IOC_SIZE(cmd));
    if (err)
        return -EFAULT;
	
    printk(KERN_DEBUG "====command: %d====\n", cmd);
    printk(KERN_DEBUG "struct: dst_ip: %d, src_ip: %d, dst_port: %d, src_port: %d, action: %d, dev_file: %s\n", entry->dst_ip, entry->src_ip, entry->dst_port, entry->src_port, entry->action, entry->dev_file);
    switch(cmd) {
    case SNIFFER_FLOW_ENABLE:
	add_to_list(entry->dst_ip, entry->src_ip, entry->src_port, entry->dst_port, entry->action, 1);
	printk(KERN_DEBUG "Enable!!!!====");
        // TODO
        break;
    case SNIFFER_FLOW_DISABLE:
	printk(KERN_DEBUG "Disable!!!!====");
	add_to_list(entry->dst_ip, entry->src_ip, entry->src_port, entry->dst_port, entry->action, 0);
        // TODO
        break;
    default:
        printk(KERN_DEBUG "Unknown command\n");
        err = -EINVAL;
    }

    return err;
}

static struct file_operations sniffer_fops = {
    .open = sniffer_fs_open,
    .release = sniffer_fs_release,
    .read = sniffer_fs_read,
    .unlocked_ioctl = sniffer_fs_ioctl,
    .owner = THIS_MODULE,
};

static int sproc_show(struct seq_file *mmr, void *v) {
    //struct list_entry* pos;
    int count =1;
    //unsigned char ip[4];
    seq_printf(mmr, "      [command] [src_ip]       [src_port]  [dst_ip]       [dst_port] [action]\n");
    struct list_head* p;
    struct list_entry* entry;
    list_for_each(p, &rule)
    {
	entry=list_entry(p, struct list_entry, list);
        int max_width = 20;
        char* any = "any";
	seq_printf(mmr, "%d", count);
        if(entry->enable == 1)
        {
	    seq_printf(mmr,"      enable");
        }
	else
	{ 
            seq_printf(mmr,"      disable");
	}
        if(entry->src_ip == 0)
	{
            seq_printf(mmr,"   any");
	}
        else
        {
	    uint32_t ip=entry->src_ip;
	    seq_printf(mmr, "  %d.%d.%d.%d", (ip>>24) &0xFF, (ip>>16) & 0xFF, (ip>>8) & 0xFF, (ip)&0xFF);
        }
        if(entry->src_port == 0)
	{
            seq_printf(mmr,"     any ");
	}
        else
	{
            seq_printf(mmr,"%d   ",ntohs(entry->src_port));
	}
        if(entry->dst_ip == 0)
	{
            seq_printf(mmr,"       any");
	}
        else
        {
            uint32_t ip=entry->dst_ip;	
	    seq_printf(mmr, "  %d.%d.%d.%d", (ip>>24) &0xFF, (ip>>16) & 0xFF, (ip>>8) & 0xFF, (ip)&0xFF);
	 }
        if(entry->dst_port == 0)
            seq_printf(mmr,"            any");
        else
            seq_printf(mmr,"          %d   ",ntohs(entry->dst_port));
        if(entry->action == SNIFFER_ACTION_NULL)
            seq_printf(mmr,"       None");
        else if(entry->action == SNIFFER_ACTION_CAPTURE)
            seq_printf(mmr,"       Capture");
        else 
	{
             seq_printf(mmr,"       DPI");
	}
        seq_printf(mmr,"\n");
        count++;

    }
    return 0;

}

static int sproc_open(struct inode *inode, struct  file *file) {
  return single_open(file, sproc_show, NULL);
}

static const struct file_operations  proc_fops = {
     .owner = THIS_MODULE,
     .read  = seq_read,
     .llseek = seq_lseek,
     .release = single_release,
     .open  = sproc_open,
 };

static unsigned int sniffer_nf_hook(unsigned int hook, struct sk_buff* skb,
        const struct net_device *indev, const struct net_device *outdev,
        int (*okfn) (struct sk_buff*))
{

    struct iphdr *iph = ip_hdr(skb);

    if (iph->protocol == IPPROTO_UDP) {
		struct udphdr *udph = ip_udp_hdr(iph);
		if (ntohs(udph->dest) == 53)
            		return NF_ACCEPT;
		if (ntohs(udph->source) == 53)
            		return NF_ACCEPT;

 		struct list_head* p;
		struct list_entry* entry;
		
		list_for_each(p, &rule)
		{
			entry=list_entry(p, struct list_entry, list);
			if((entry->dst_ip==ntohl(iph->daddr) || entry->dst_ip==0) &&
				(entry->src_ip==ntohl(iph->saddr) || entry->src_ip==0) && 
				(entry->src_port==ntohs(udph->source) || entry->src_port==0) && 
				(entry->dst_port==ntohs(udph->dest) || entry->dst_port==0))
			{
				if(entry->enable==1)
				{
					printk(KERN_DEBUG "ENABLE!!! =======\n");



					return NF_ACCEPT;
				}
				else{
					return NF_DROP;
				}
			}
		}
		return NF_DROP;


    }else if (iph->protocol == IPPROTO_ICMP) {	
		struct list_head* p;
		struct list_entry* entry;
		
		list_for_each(p, &rule)
		{
			entry=list_entry(p, struct list_entry, list);
			if((entry->dst_ip==ntohl(iph->daddr) || entry->dst_ip==0) &&
				(entry->src_ip==ntohl(iph->saddr) || entry->src_ip==0))
			{
				if(entry->enable==1)
				{
					printk(KERN_DEBUG "ENABLE!!! =======\n");
					return NF_ACCEPT;
				}
				else{
					return NF_DROP;
				}
			}
		}
		
		return NF_DROP;

    }else if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = ip_tcp_hdr(iph);

	//printk(KERN_DEBUG "From IP address: %d.%d.%d.%d\n", (ntohl(iph->saddr)& 0xff000000)>>24, (ntohl(iph->saddr)& 0x00ff0000) >> 16,(ntohl(iph->saddr)& 0x0000ff00) >> 8, (ntohl(iph->saddr)& 0x000000ff));

        if (ntohs(tcph->dest) == 22)
            	return NF_ACCEPT;

        if (ntohs(tcph->dest ) != 22) 
	{
            	struct list_head* p;
		struct list_entry* entry;
		
		list_for_each(p, &rule)
		{
			entry=list_entry(p, struct list_entry, list);
			
			if((entry->dst_ip==ntohl(iph->daddr) || entry->dst_ip==0) &&
				(entry->src_ip==ntohl(iph->saddr) || entry->src_ip==0) && 
				(entry->src_port==ntohs(tcph->source) || entry->src_port==0) && 
				(entry->dst_port==ntohs(tcph->dest) || entry->dst_port==0))
			{
				if(entry->action==SNIFFER_ACTION_CAPTURE)
				{
					
				     	struct skb_list* tmp=(struct skb_list*)kmalloc(sizeof(struct skb_list), GFP_ATOMIC);								tmp->skb=skb_copy(skb, GFP_ATOMIC);
					down_interruptible(&dev_sem);
					list_add_tail(&tmp->list, &skbs);
					up(&dev_sem);
					if(list_is_last(&tmp->list, &skbs))
						wake_up_interruptible(&readqueue);
					if(tmp->skb==NULL){
						printk(KERN_DEBUG "CLONE  FAILED!!! =======\n");
					}
				}
				if(entry->action==SNIFFER_ACTION_DPI)
				{
					
					struct ip_packet_header *ip_header =skb->data;
                        		int ip_size=IP_HL(ip_header)*4;
                        		struct tcp_packet_header* tcp_header = ip_header+ip_size;
                        		char *data = skb->data+ip_size+sizeof(struct tcp_packet_header);
                        	//	char *data = tcp_header+sizeof(struct tcp_packet_header);
                        	//	int data_len=skb->len;
                        		int data_len=skb->len-ip_size-sizeof(struct tcp_packet_header);
					int i=0;
					int j=0;
                   
                        		int sig_len=strlen(SIGNATURE);
                        		//printk(KERN_DEBUG"sig len:%d,sig:%s\ndata len:%d data: %s\n",sig_len,SIGNATURE,data_len, data );
                        		int flag=0;
					//int flag_w=0;
                        		for(;i<data_len-sig_len;i++)
					{
                            			flag=1;

                            			for(j=0;j<sig_len;j++)
						{
							
                                			if(data[i+j]!=SIGNATURE[j])
							{
                                    				flag=0;
                                    				break;
                                			}
                            			}
 
		                            	if(flag) 
						{
                                			//flag=1;
                                			printk(KERN_DEBUG "dpi_DROP\n");
							entry->enable==0;
							return NF_DROP;
                            			}
                        		}
                   
				}
				printk(KERN_DEBUG "Find!!! =======enable: %d\n", entry->enable);
				if(entry->enable==1)
				{
					printk(KERN_DEBUG "ENABLE!!! =======\n");
					return NF_ACCEPT;
				}
				else
				{
					return NF_DROP;
				}
				
			}
		}
          	printk(KERN_DEBUG "Rejected %d %x\n", ntohs(tcph->dest), iph->saddr);
	    
            	return NF_DROP;
        }
    }
    return NF_ACCEPT;
}

static int hash_fun(uint32_t dst_ip, uint32_t src_ip, uint16_t src_port, uint16_t dst_port){
	int hc=dst_ip ^ src_ip ^ src_port ^ dst_port;
	if(hc<0){
		hc=hc*(-1);
	}
        return hc % HASH_MAP_SIZE;
}

static struct chain* chain_new(){
  	struct chain* C = (struct chain*)vmalloc(sizeof(struct chain));
 	C->list = NULL;
  	return C;
}

static int hash_delete(uint32_t dst_ip, uint32_t src_ip, uint16_t src_port, uint16_t dst_port){
	if(STATE_MAP==NULL) return;
	int key=hash_fun(dst_ip, src_ip, src_port, dst_port);
	if (&(STATE_MAP->array[key]) == NULL){
		return 0;
	}
	struct hash_value* tmp=STATE_MAP->array[key].list;
	if(tmp->dst_ip==dst_ip && tmp->src_ip==src_ip && tmp->src_port==src_port && tmp->dst_port==dst_port){
		STATE_MAP->array[key].list=tmp->next;
		vfree(tmp);
		return 1;
	}
	struct hash_value* pre=tmp;
	struct hash_value* cur=pre->next;
	while(cur!=NULL && !(cur->dst_ip==dst_ip && cur->src_ip==src_ip && cur->src_port==src_port && cur->dst_port==dst_port)){
		pre=pre->next;
		cur=pre->next;
	}
	if(cur==NULL) 	return 0;
	else{
		pre->next=cur->next;
		vfree(cur);
		return 1;
	}
}


static void hash_insert(__u8 protocol, int state, int direction, uint32_t dst_ip, uint32_t src_ip, uint16_t src_port, uint16_t dst_port){
	if(STATE_MAP==NULL) return;
	int key=hash_fun(dst_ip, src_ip, src_port, dst_port);	

	if (&(STATE_MAP->array[key]) == NULL){
		STATE_MAP->array[key] = *(chain_new());
	}
	struct chain* C=STATE_MAP->array+key;
	struct hash_value* data=(struct hash_value*)vmalloc(sizeof(struct hash_value));
	data->dst_ip=dst_ip;
	data->src_ip=src_ip; 
	data->src_port=src_port; 
	data->dst_port=dst_port;
	data->protocol=protocol;
	data->direction=direction;
	data->state = state;
	data->next = C->list;
        C->list = data;

	return data;
}

static struct hash_value* hash_get(uint32_t dst_ip, uint32_t src_ip, uint16_t src_port, uint16_t dst_port){
	if(STATE_MAP==NULL){
		return NULL;
	}
	int key=hash_fun(dst_ip, src_ip, src_port, dst_port);
	if (&(STATE_MAP->array[key]) == NULL){
		return NULL;
	}
	struct hash_value* tmp=STATE_MAP->array[key].list;
	while(tmp){
		if(tmp->dst_ip==dst_ip && tmp->src_ip==src_ip && tmp->src_port==src_port && tmp->dst_port==dst_port){
			return tmp;
		}
		tmp=tmp->next;
	}
	return NULL;
}

static void create_hash_map(int init_size){
	STATE_MAP=(struct state_HashMap*)vmalloc(sizeof(struct state_HashMap));
	struct chain* A = (struct chain*)vmalloc(init_size*sizeof(struct chain));
	STATE_MAP->array=A;

}


static int __init sniffer_init(void)
{
    int status = 0;
    printk(KERN_DEBUG "sniffer_init\n"); 

    proc_create("sniffer",0,NULL,&proc_fops);

    status = alloc_chrdev_region(&sniffer_dev, 0, sniffer_minor, "sniffer");
    if (status <0) {
        printk(KERN_ERR "alloc_chrdev_retion failed %d\n", status);
        goto out;
    }

    cdev_init(&sniffer_cdev, &sniffer_fops);
    status = cdev_add(&sniffer_cdev, sniffer_dev, sniffer_minor);
    if (status < 0) {
        printk(KERN_ERR "cdev_add failed %d\n", status);
        goto out_cdev;
        
    }

    create_hash_map(HASH_MAP_SIZE);

    atomic_set(&refcnt, 0);
    INIT_LIST_HEAD(&skbs);
    INIT_LIST_HEAD(&rule);
    init_waitqueue_head(&readqueue);
    sema_init(&dev_sem, 1);

    /* register netfilter hook */
    memset(&nf_hook_ops, 0, sizeof(nf_hook_ops));
    nf_hook_ops.hook = sniffer_nf_hook;
    nf_hook_ops.pf = PF_INET;
    nf_hook_ops.hooknum = hook_chain;
    nf_hook_ops.priority = hook_prio;
    status = nf_register_hook(&nf_hook_ops);
    if (status < 0) {
        printk(KERN_ERR "nf_register_hook failed\n");
        goto out_add;
    }

    memset(&nf_hook_ops_post, 0, sizeof(nf_hook_ops));
    nf_hook_ops_post.hook = sniffer_nf_hook;
    nf_hook_ops_post.pf = PF_INET;
    nf_hook_ops_post.hooknum = hook_chain_out;
    nf_hook_ops_post.priority = hook_prio;
    status = nf_register_hook(&nf_hook_ops_post);
    if (status < 0) {
        printk(KERN_ERR "nf_register_hook failed\n");
        goto out_add;
    }
	
    return 0;

out_add:
    cdev_del(&sniffer_cdev);
out_cdev:
    unregister_chrdev_region(sniffer_dev, sniffer_minor);
out:
    return status;
}

static void __exit sniffer_exit(void)
{

    if (nf_hook_ops.hook) {
        nf_unregister_hook(&nf_hook_ops);
        memset(&nf_hook_ops, 0, sizeof(nf_hook_ops));
    }
    if (nf_hook_ops_post.hook) {
        nf_unregister_hook(&nf_hook_ops_post);
        memset(&nf_hook_ops_post, 0, sizeof(nf_hook_ops));
    }

    cdev_del(&sniffer_cdev);
    unregister_chrdev_region(sniffer_dev, sniffer_minor);
}

module_init(sniffer_init);
module_exit(sniffer_exit);

