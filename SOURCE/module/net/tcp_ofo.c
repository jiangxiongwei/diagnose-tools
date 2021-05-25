/*
 * Linux内核诊断工具--内核态tcp-ofo功能
 *
 * Copyright (C) 2021 Alibaba Ltd.
 *
 * 作者: Xiongwei Jiang <xiongwei.jiang@linux.alibaba.com>
 *
 * License terms: GNU General Public License (GPL) version 3
 *
 */

#include <linux/module.h>
#include <linux/stacktrace.h>
#include <linux/hrtimer.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/timex.h>
#include <linux/tracepoint.h>
#include <trace/events/irq.h>
#include <linux/proc_fs.h>
#include <linux/init.h>
#include <linux/sysctl.h>
#include <trace/events/napi.h>
#include <linux/rtc.h>
#include <linux/time.h>
#include <linux/version.h>
#include <linux/net.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/netfilter.h>
#include <linux/skbuff.h>
#include <net/tcp.h>

#include <net/inet_connection_sock.h>
#include <net/sock.h>
#include <net/ip.h>
#include <net/tcp.h>

#include "internal.h"
#include "net_internal.h"
#include "pub/trace_file.h"
#include "pub/kprobe.h"
#include "pub/trace_point.h"

#include "uapi/tcp_ofo.h"

#define FLAG_DATA		0x01 /* Incoming frame contained data.		*/
#define FLAG_WIN_UPDATE		0x02 /* Incoming ACK was a window update.	*/
#define FLAG_DATA_ACKED		0x04 /* This ACK acknowledged new data.		*/
#define FLAG_RETRANS_DATA_ACKED	0x08 /* "" "" some of which was retransmitted.	*/
#define FLAG_SYN_ACKED		0x10 /* This ACK acknowledged SYN.		*/
#define FLAG_DATA_SACKED	0x20 /* New SACK.				*/
#define FLAG_ECE		0x40 /* ECE in this ACK				*/
#define FLAG_LOST_RETRANS	0x80 /* This ACK marks some retransmission lost */
#define FLAG_SLOWPATH		0x100 /* Do not skip RFC checks for window update.*/
#define FLAG_ORIG_SACK_ACKED	0x200 /* Never retransmitted data are (s)acked	*/
#define FLAG_SND_UNA_ADVANCED	0x400 /* Snd_una was changed (!= FLAG_DATA_ACKED) */
#define FLAG_DSACKING_ACK	0x800 /* SACK blocks contained D-SACK info */
#define FLAG_SACK_RENEGING	0x2000 /* snd_una advanced to a sacked seq */
#define FLAG_UPDATE_TS_RECENT	0x4000 /* tcp_replace_ts_recent() */

#define FLAG_ACKED		(FLAG_DATA_ACKED|FLAG_SYN_ACKED)
#define FLAG_NOT_DUP		(FLAG_DATA|FLAG_WIN_UPDATE|FLAG_ACKED)
#define FLAG_CA_ALERT		(FLAG_DATA_SACKED|FLAG_ECE)
#define FLAG_FORWARD_PROGRESS	(FLAG_ACKED|FLAG_DATA_SACKED)

#define TCP_REMNANT (TCP_FLAG_FIN|TCP_FLAG_URG|TCP_FLAG_SYN|TCP_FLAG_PSH)
#define TCP_HP_BITS (~(TCP_RESERVED_BITS|TCP_FLAG_PSH))

__maybe_unused static atomic64_t diag_nr_running = ATOMIC64_INIT(0);
struct diag_tcp_ofo_settings tcp_ofo_settings;

__maybe_unused static int tcp_ofo_alloced = 0;
__maybe_unused static atomic64_t diag_alloc_count = ATOMIC64_INIT(0);
__maybe_unused static atomic64_t diag_nr_tcp_ofo_skb = ATOMIC64_INIT(0);
//__maybe_unused static atomic64_t diag_nr_tcp_rtx_synack = ATOMIC64_INIT(0);
//__maybe_unused static atomic64_t diag_tcp_dupack = ATOMIC64_INIT(0);
//__maybe_unused static atomic64_t diag_tcp_send_dupack = ATOMIC64_INIT(0);

__maybe_unused static struct rb_root diag_tcp_ofo_tree = RB_ROOT;
__maybe_unused static DEFINE_SPINLOCK(diag_tcp_ofo_tree_lock);

struct diag_tcp_ofo {
	struct rb_node rb_node;
	struct list_head list;
	int src_addr;
	int src_port;
	int dest_addr;
	int dest_port;
	int syncack_count;
	int skb_count;
};

static struct diag_variant_buffer tcp_ofo_variant_buffer;

__maybe_unused static void clean_data(void)
{
	unsigned long flags;
	struct list_head header;
	struct rb_node *node;

	INIT_LIST_HEAD(&header);
	spin_lock_irqsave(&diag_tcp_ofo_tree_lock, flags);

	for (node = rb_first(&diag_tcp_ofo_tree); node; node = rb_next(node)) {
		struct diag_tcp_ofo *this = container_of(node,
				struct diag_tcp_ofo, rb_node);

		rb_erase(&this->rb_node, &diag_tcp_ofo_tree);
		INIT_LIST_HEAD(&this->list);
		list_add_tail(&this->list, &header);
	}
	diag_tcp_ofo_tree = RB_ROOT;

	spin_unlock_irqrestore(&diag_tcp_ofo_tree_lock, flags);

	while (!list_empty(&header)) {
		struct diag_tcp_ofo *this = list_first_entry(&header, struct diag_tcp_ofo, list);

		list_del_init(&this->list);
		kfree(this);
	}
}

__maybe_unused static int compare_desc(struct diag_tcp_ofo *desc, struct diag_tcp_ofo *this)
{
	if (desc->src_addr < this->src_addr)
		return -1;
	if (desc->src_addr > this->src_addr)
		return 1;
	if (desc->src_port < this->src_port)
		return -1;
	if (desc->src_port > this->src_port)
		return 1;
	if (desc->dest_addr < this->dest_addr)
		return -1;
	if (desc->dest_addr > this->dest_addr)
		return 1;
	if (desc->dest_port < this->dest_port)
		return -1;
	if (desc->dest_port > this->dest_port)
		return 1;

	return 0;
}

__maybe_unused static struct diag_tcp_ofo *__find_alloc_desc(struct diag_tcp_ofo *desc)
{
	struct diag_tcp_ofo *this;
	struct rb_node **node, *parent;
	int compare_ret;

	node = &diag_tcp_ofo_tree.rb_node;
	parent = NULL;

	while (*node != NULL)
	{
		parent = *node;
		this = container_of(parent, struct diag_tcp_ofo, rb_node);
		compare_ret = compare_desc(desc, this);

		if (compare_ret < 0)
			node = &parent->rb_left;
		else if (compare_ret > 0)
			node = &parent->rb_right;
		else
		{
			return this;
		}
	}

	this = kmalloc(sizeof(struct diag_tcp_ofo), GFP_ATOMIC);
	if (!this) {
		atomic64_inc_return(&diag_alloc_count);
		return this;
	}

	memset(this, 0, sizeof(struct diag_tcp_ofo));
	this->src_addr = desc->src_addr;
	this->src_port = desc->src_port;
	this->dest_addr = desc->dest_addr;
	this->dest_port = desc->dest_port;
	rb_link_node(&this->rb_node, parent, node);
	rb_insert_color(&this->rb_node, &diag_tcp_ofo_tree);

	return this;
}

#if !defined(CENTOS_3_10_862) && !defined(CENTOS_3_10_957) \
	&& !defined(CENTOS_3_10_1062) && !defined(CENTOS_3_10_1127) \
	&& !defined(ALIOS_7U)
int diag_tcp_ofo_init(void)
{
	return 0;
}

void diag_tcp_ofo_exit(void)
{
}
#elif LINUX_VERSION_CODE < KERNEL_VERSION(5, 3, 0)
__maybe_unused static void trace_tcp_data_queue_ofo(struct sock *sk, struct sk_buff *skb)
{
	unsigned long flags;
	struct diag_tcp_ofo *desc;
	struct diag_tcp_ofo tmp;
	struct inet_sock *sock = inet_sk(sk);

	if (!tcp_ofo_settings.activated)
		return;

	if (sk->sk_protocol == IPPROTO_TCP) {
		/* TODO #if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 33) */
		tmp.src_port = be16_to_cpu(sock->inet_num);
		tmp.dest_port = be16_to_cpu(sock->inet_dport);
		tmp.src_addr = sock->inet_rcv_saddr;
		tmp.dest_addr = sock->inet_daddr;
	} else {
		return;
	}

	spin_lock_irqsave(&diag_tcp_ofo_tree_lock, flags);
	if (tcp_ofo_settings.verbose & 1) {
		struct tcp_ofo_trace trace;
		unsigned long flags;

		trace.et_type = et_tcp_ofo_trace;
		do_gettimeofday(&trace.tv);
		trace.src_addr = tmp.src_addr;
		trace.src_port = tmp.src_port;
		trace.dest_addr = tmp.dest_addr;
		trace.dest_port = tmp.dest_port;
		diag_variant_buffer_spin_lock(&tcp_ofo_variant_buffer, flags);
		diag_variant_buffer_reserve(&tcp_ofo_variant_buffer, sizeof(struct tcp_ofo_trace));
		diag_variant_buffer_write_nolock(&tcp_ofo_variant_buffer, &trace, sizeof(struct tcp_ofo_trace));
		diag_variant_buffer_seal(&tcp_ofo_variant_buffer);
		diag_variant_buffer_spin_unlock(&tcp_ofo_variant_buffer, flags);
	}

}


#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 18, 0)
#if !defined(ALIOS_3000_010) && !defined(ALIOS_3000_012) \
	&& !defined(ALIOS_3000_013) && !defined(ALIOS_3000_014) \
  && !defined(ALIOS_3000_015) && !defined(ALIOS_3000_016) \
	&& !defined(ALIOS_3000_018) && !defined(ALIOS_3000_018_ECSVM)
int *orig_sysctl_tcp_dsack;
int *orig_sysctl_tcp_rmem;
#endif

static void (*orig__tcp_ecn_check_ce)(struct tcp_sock *tp, const struct sk_buff *skb);
static int (*orig_tcp_try_rmem_schedule)(struct sock *sk, struct sk_buff *skb, unsigned int size); 
static bool (*orig_tcp_try_coalesce)(struct sock *sk, struct sk_buff *to, struct sk_buff *from, bool *fragstolen);
static void (*orig_tcp_dsack_extend)(struct sock *sk, u32 seq, u32 end_seq); 

DEFINE_ORIG_FUNC(int, tcp_data_queue_ofo, 2, struct sock *, sk, struct sk_buff *, skb);

static void tcp_dsack_set(struct sock *sk, u32 seq, u32 end_seq)
{
	struct tcp_sock *tp = tcp_sk(sk);
#if defined(ALIOS_3000_010) || defined(ALIOS_3000_012) \
  || defined(ALIOS_3000_013) || defined(ALIOS_3000_014) \
  || defined(ALIOS_3000_015) || defined(ALIOS_3000_016) \
	|| defined(ALIOS_3000_018) || defined(ALIOS_3000_018_ECSVM)
	if (tcp_is_sack(tp) && sock_net(sk)->ipv4.sysctl_tcp_dsack) {
#else
	if (tcp_is_sack(tp) && *orig_sysctl_tcp_dsack) {
#endif
		int mib_idx;
		if (before(seq, tp->rcv_nxt))
			mib_idx = LINUX_MIB_TCPDSACKOLDSENT;
		else
			mib_idx = LINUX_MIB_TCPDSACKOFOSENT;

		NET_INC_STATS_BH(sock_net(sk), mib_idx);
		tp->rx_opt.dsack = 1;
		tp->duplicate_sack[0].start_seq = seq;
		tp->duplicate_sack[0].end_seq = end_seq;
	}

}

static int __tcp_grow_window(const struct sock *sk, const struct sk_buff *skb) 
{
	struct tcp_sock *tp = tcp_sk(sk);
	/* Optimize this! */
#if defined(ALIOS_3000_010) || defined(ALIOS_3000_012) \
  || defined(ALIOS_3000_013) || defined(ALIOS_3000_014) \
  || defined(ALIOS_3000_015) || defined(ALIOS_3000_016) \
	|| defined(ALIOS_3000_018) || defined(ALIOS_3000_018_ECSVM)
	int truesize = tcp_win_from_space(sk, skb->truesize) >> 1;
	int window = tcp_win_from_space(sk, sock_net(sk)->ipv4.sysctl_tcp_rmem[2]) >> 1;
#else
	int truesize = tcp_win_from_space(skb->truesize) >> 1;
	int window = tcp_win_from_space(*orig_sysctl_tcp_rmem[2]) >> 1;
#endif

	while (tp->rcv_ssthresh <= window) {
		if (truesize <= skb->len)
			return 2 * inet_csk(sk)->icsk_ack.rcv_mss;
		
		truesize >>= 1;
		window >>= 1;
	}
	return 0;
}

static void tcp_grow_window(struct sock *sk, const struct sk_buff *skb)
{




}

static void diag_tcp_data_queue_ofo(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *skb1;
	u32 seq, end_seq;

	TCP_ECN_check_ce(tp, skb);

	if (unlikely(tcp_try_rmem_schedule(sk, skb, skb->truesize))) {
		NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_TCPOFODROP);
		__kfree_skb(skb);
		return;
	}

	/* Disable header prediction. */
	tp->pred_flags = 0;
	inet_csk_schedule_ack(sk);

	NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_TCPOFOQUEUE);
	SOCK_DEBUG(sk, "out of order segment: rcv_next %X seq %X - %X\n",
		tp->rcv_nxt, TCP_SKB_CB(skb)->seq, TCP_SKB_CB(skb)->end_seq);

	skb1 = skb_peek_tail(&tp->out_of_order_queue);
	if (!skb1) {
		/* Initial out of order segment, build 1 SACK. */
		if (tcp_is_sack(tp)) {
			tp->rx_opt.num_sacks = 1;
			tp->selective_acks[0].start_seq = TCP_SKB_CB(skb)->seq;
			tp->selective_acks[0].end_seq =
				TCP_SKB_CB(skb)->end_seq;
		}
		__skb_queue_head(&tp->out_of_order_queue, skb);
		goto end;
	}

	seq = TCP_SKB_CB(skb)->seq;
	end_seq = TCP_SKB_CB(skb)->end_seq;

	if (seq == TCP_SKB_CB(skb1)->end_seq) {
		bool fragstolen;

		if (!tcp_try_coalesce(sk, skb1, skb, &fragstolen)) {
			__skb_queue_after(&tp->out_of_order_queue, skb1, skb);
		} else {
			kfree_skb_partial(skb, fragstolen);
			skb = NULL;
		}

		if (!tp->rx_opt.num_sacks ||
		    tp->selective_acks[0].end_seq != seq)
			goto add_sack;

		/* Common case: data arrive in order after hole. */
		tp->selective_acks[0].end_seq = end_seq;
		goto end;
	}

	/* Find place to insert this segment. */
	while (1) {
		if (!after(TCP_SKB_CB(skb1)->seq, seq))
			break;
		if (skb_queue_is_first(&tp->out_of_order_queue, skb1)) {
			skb1 = NULL;
			break;
		}
		skb1 = skb_queue_prev(&tp->out_of_order_queue, skb1);
	}

	/* Do skb overlap to previous one? */
	if (skb1 && before(seq, TCP_SKB_CB(skb1)->end_seq)) {
		if (!after(end_seq, TCP_SKB_CB(skb1)->end_seq)) {
			/* All the bits are present. Drop. */
			NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_TCPOFOMERGE);
			__kfree_skb(skb);
			skb = NULL;
			tcp_dsack_set(sk, seq, end_seq);
			goto add_sack;
		}
		if (after(seq, TCP_SKB_CB(skb1)->seq)) {
			/* Partial overlap. */
			tcp_dsack_set(sk, seq,
				      TCP_SKB_CB(skb1)->end_seq);
		} else {
			if (skb_queue_is_first(&tp->out_of_order_queue,
					       skb1))
				skb1 = NULL;
			else
				skb1 = skb_queue_prev(
					&tp->out_of_order_queue,
					skb1);
		}
	}
	if (!skb1)
		__skb_queue_head(&tp->out_of_order_queue, skb);
	else
		__skb_queue_after(&tp->out_of_order_queue, skb1, skb);

	/* And clean segments covered by new one as whole. */
	while (!skb_queue_is_last(&tp->out_of_order_queue, skb)) {
		skb1 = skb_queue_next(&tp->out_of_order_queue, skb);

		if (!after(end_seq, TCP_SKB_CB(skb1)->seq))
			break;
		if (before(end_seq, TCP_SKB_CB(skb1)->end_seq)) {
			orig_tcp_dsack_extend(sk, TCP_SKB_CB(skb1)->seq,
					 end_seq);
			break;
		}
		__skb_unlink(skb1, &tp->out_of_order_queue);
		orig_tcp_dsack_extend(sk, TCP_SKB_CB(skb1)->seq,
				 TCP_SKB_CB(skb1)->end_seq);
		NET_INC_STATS_BH(sock_net(sk), LINUX_MIB_TCPOFOMERGE);
		__kfree_skb(skb1);
	}

add_sack:
	if (tcp_is_sack(tp))
		tcp_sack_new_ofo_skb(sk, seq, end_seq);
end:
	if (skb)
		skb_set_owner_r(skb, sk);
}

static int __activate_tcp_ofo(void)
{
	int ret = 0;

	ret = alloc_diag_variant_buffer(&tcp_ofo_variant_buffer);
	if (ret)
		goto out_variant_buffer;
	tcp_ofo_alloced = 1;

	JUMP_CHECK(tcp_data_queue_ofo);

	clean_data();
	atomic64_set(&diag_alloc_count, 0);
	get_online_cpus();
	mutex_lock(orig_text_mutex);
	JUMP_INSTALL(tcp_data_queue_ofo);
	mutex_unlock(orig_text_mutex);
	put_online_cpus();

	return 1;
out_variant_buffer:
	return 0;
}

static void __deactivate_tcp_ofo(void)
{
	get_online_cpus();
	mutex_lock(orig_text_mutex);
	JUMP_REMOVE(tcp_data_queue_ofo);
	mutex_unlock(orig_text_mutex);
	put_online_cpus();

	synchronize_sched();
	msleep(20);
	while (atomic64_read(&diag_nr_running) > 0)
	{
		msleep(10);
	}

	clean_data();
}

static int lookup_syms(void)
{
	LOOKUP_SYMS(_tcp_ecn_check_ce);
	LOOKUP_SYMS(tcp_try_rmem_schedule);
	LOOKUP_SYMS(tcp_try_coalesce);
	LOOKUP_SYMS(tcp_dsack_extend);

	return 0;
}

static void jump_init(void)
{
	JUMP_INIT(tcp_data_queue_ofo);
}
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
int *orig_sysctl_tcp_dsack;
int *orig_sysctl_tcp_rmem;

static void (*orig__tcp_ecn_check_ce)(struct tcp_sock *tp, const struct sk_buff *skb);
static int (*orig_tcp_try_rmem_schedule)(struct sock *sk, struct sk_buff *skb, unsigned int size);
static bool (*orig_tcp_try_coalesce)(struct sock *sk, struct sk_buff *to, struct sk_buff *from, bool *fragstolen);
static void (*orig_tcp_dsack_extend)(struct sock *sk, u32 seq, u32 end_seq);

DEFINE_ORIG_FUNC(int, tcp_data_queue_ofo, 2, struct sock *, sk, struct sk_buff *, skb);


static void tcp_dsack_set(struct sock *sk, u32 seq, u32 end_seq)
{
	struct tcp_sock *tp = tcp_sk(sk);

	if (tcp_is_sack(tp) && *orig_sysctl_tcp_dsack) {
		int mib_idx;
		if (before(seq, tp->rcv_nxt))
			mib_idx = LINUX_MIB_TCPDSACKOLDSENT;
		else
			mib_idx = LINUX_MIB_TCPDSACKOFOSENT;

		NET_INC_STATS(sock_net(sk), mib_idx);
		tp->rx_opt.dsack = 1;
		tp->duplicate_sack[0].start_seq = seq;
		tp->duplicate_sack[0].end_seq = end_seq;
	}

}

static int __tcp_grow_window(const struct sock *sk, const struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);
	/* Optimize this! */
	int truesize = tcp_win_from_space(skb->truesize) >> 1;
	int window = tcp_win_from_space(*orig_sysctl_tcp_rmem[2]) >> 1;

	while (tp->rcv_ssthresh <= window) {
		if (truesize <= skb->len)
			return 2 * inet_csk(sk)->icsk_ack.rcv_mss;
		truesize >>= 1;
		window >>= 1;
	}
	return 0;
}

static void tcp_grow_window(struct sock *sk, const struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);

	/* Check #1 */
	if (tp->rcv_ssthresh < tp->window_clamp &&
		(int)tp->rcv_ssthresh < tcp_space(sk) &&
		!tcp_under_memory_pressure(sk)) {
		int incr;
		/* Check #2. Increase window, if skb with such overhead
		 * will fit to rcvbuf in future.
		 */
		if (tcp_win_from_space(skb->truesize) <= skb->len)
			incr = 2 * tp->advmss;
		else
			incr = __tcp_grow_window(sk, skb);
		if (incr) {
			incr = max_t(int, incr, 2 * skb->len);
			tp->rcv_ssthresh = min(tp->rcv_ssthresh + incr,
				tp->window_clamp);
			inet_csk(sk)->icsk_ack.quick |= 1;
		}
	}
}

static inline bool tcp_sack_extend(struct tcp_sack_block *sp, u32 seq,
				  u32 end_seq)
{
	if (!after(seq, sp->end_seq) && !after(sp->start_seq, end_seq)) {
		if (before(seq, sp->start_seq))
			sp->start_seq = seq;
		if (after(end_seq, sp->end_seq))
			sp->end_seq = end_seq;
		return true;
	}
	return false;
}

/* These routines update the SACK block as out-of-order packets arrive or
 *  * in-order packets close up the sequence space.
 *   */
static void tcp_sack_maybe_coalesce(struct tcp_sock *tp)
{
	int this_sack;
	struct tcp_sack_block *sp = &tp->selective_acks[0];
	struct tcp_sack_block *swalk = sp + 1;

	/* See if the recent change to the first SACK eats into
 * 	 * or hits the sequence space of other SACK blocks, if so coalesce.
 * 	 	 */
	for (this_sack = 1; this_sack < tp->rx_opt.num_sacks;) {
		if (tcp_sack_extend(sp, swalk->start_seq, swalk->end_seq)) {
			int i;

			/* Zap SWALK, by moving every further SACK up by one slot.
 * 			 * Decrease num_sacks.
 * 			 			 */
			tp->rx_opt.num_sacks--;
			for (i = this_sack; i < tp->rx_opt.num_sacks; i++)
				sp[i] = sp[i + 1];
			continue;
		}
		this_sack++, swalk++;
	}
}

static void tcp_sack_new_ofo_skb(struct sock *sk, u32 seq, u32 end_seq)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct tcp_sack_block *sp = &tp->selective_acks[0];
	int cur_sacks = tp->rx_opt.num_sacks;
	int this_sack;

	if (!cur_sacks)
		goto new_sack;

	for (this_sack = 0; this_sack < cur_sacks; this_sack++, sp++) {
		if (tcp_sack_extend(sp, seq, end_seq)) {
			/* Rotate this_sack to the first one. */
			for (; this_sack > 0; this_sack--, sp--)
				swap(*sp, *(sp - 1));
			if (cur_sacks > 1)
				tcp_sack_maybe_coalesce(tp);
			return;
		}
	}

	/* Could not find an adjacent existing SACK, build a new one,
 * 	 * put it at the front, and shift everyone else down.  We
 * 	 	 * always know there is at least one SACK present already here.
 * 	 	 	 *
 * 	 	 	 	 * If the sack array is full, forget about the last one.
 * 	 	 	 	 	 */
	if (this_sack >= TCP_NUM_SACKS) {
		this_sack--;
		tp->rx_opt.num_sacks--;
		sp--;
	}
	for (; this_sack > 0; this_sack--, sp--)
		*sp = *(sp - 1);

new_sack:
	/* Build the new head SACK, and we're done. */
	sp->start_seq = seq;
	sp->end_seq = end_seq;
	tp->rx_opt.num_sacks++;
}


static void diag_tcp_data_queue_ofo(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct rb_node **p, *q, *parent;
	struct sk_buff *skb1;
	u32 seq, end_seq;
	bool fragstolen;

//	orig_tcp_ecn_check_ce(tp, skb);
	if (tp->ecn_flags & TCP_ECN_OK)
		orig__tcp_ecn_check_ce(tp, skb);

	if (unlikely(orig_tcp_try_rmem_schedule(sk, skb, skb->truesize))) {
		NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPOFODROP);
		orig_tcp_drop(sk, skb);
		return;
	}

	/* Disable header prediction. */
	tp->pred_flags = 0;
	inet_csk_schedule_ack(sk);
	
	NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPOFOQUEUE);
	seq = TCP_SKB_CB(skb)->seq;
	end_seq = TCP_SKB_CB(skb)->end_seq;
	SOCK_DEBUG(sk, "out of order segment: rcv_next %X seq %X - %X\n",
		tp->rcv_nxt, seq, end_seq);

	p = &tp->out_of_order_queue.rb_node;
	if (RB_EMPTY_ROOT(&tp->out_of_order_queue)) {
		/* Initial out of order segment, build 1 SACK. */
		if (tcp_is_sack(tp)) {
			tp->rx_opt.num_sacks = 1;
			tp->selective_acks[0].start_seq = seq;
			tp->selective_acks[0].end_seq = end_seq;
		}
		rb_link_node(&skb->rbnode, NULL, p);
		rb_insert_color(&skb->rbnode, &tp->out_of_order_queue);
		tp->ooo_last_skb = skb;
		goto end;
	}
	
	/* In the typical case, we are adding an skb to the end of the list.
	 * Use of ooo_last_skb avoids the O(Log(N)) rbtree lookup.
	 */
	if (orig_tcp_try_coalesce(sk, tp->ooo_last_skb, skb, &fragstolen)) {
coalesce_done:
		/* tcp_grow_window TBD*/
		tcp_grow_window(sk, skb);
		kfree_skb_partial(skb, fragstolen);
		skb = NULL;
		goto add_sack;
	}
	/* Can avoid an rbtree lookup if we are adding skb after ooo_last_skb */
	if (!before(seq, TCP_SKB_CB(tp->ooo_last_skb)->end_seq)) {
		parent = &tp->ooo_last_skb->rbnode;
		p = &parent->rb_right;
		goto insert;
	}

	/* Find place to insert this segment. Handle overlaps on the way. */
	parent = NULL;
	while (*p) {
		parent = *p;
		skb1 = rb_entry(parent, struct sk_buff, rbnode);
		if (before(seq, TCP_SKB_CB(skb1)->seq)) {
			p = &parent->rb_left;
			continue;
		}
		if (before(seq, TCP_SKB_CB(skb1)->end_seq)) {
			if (!after(end_seq, TCP_SKB_CB(skb1)->end_seq)) {
				/* All the bits are present. Drop. */
				NET_INC_STATS(sock_net(sk),
					LINUX_MIB_TCPOFOMERGE);
				__kfree_skb(skb);
				skb = NULL;
				tcp_dsack_set(sk, seq, end_seq);
				goto add_sack;
			}
			if (after(seq, TCP_SKB_CB(skb1)->seq)) {
				/* Partial overlap. */
				tcp_dsack_set(sk, seq, TCP_SKB_CB(skb1)->end_seq);
			} else {
				/* skb's seq == skb1's seq and skb covers skb1.
				 * Replace skb1 with skb.
				 */
				rb_replace_node(&skb1->rbnode, &skb->rbnode,
					&tp->out_of_order_queue);
				orig_tcp_dsack_extend(sk,
					TCP_SKB_CB(skb1)->seq,
					TCP_SKB_CB(skb1)->end_seq);
				NET_INC_STATS(sock_net(sk),
					LINUX_MIB_TCPOFOMERGE);
				__kfree_skb(skb1);
				goto merge_right;
			}
			
		} else if (orig_tcp_try_coalesce(sk, skb1, skb, &fragstolen)) {
				goto coalesce_done;
		}
		p = &parent->rb_right;
	}
insert:
	/* Insert segment into RB tree. */
	rb_link_node(&skb->rbnode, parent, p);
	rb_insert_color(&skb->rbnode, &tp->out_of_order_queue);

merge_right:
	/* Remove other segments covered by skb. */
	while ((q = rb_next(&skb->rbnode)) != NULL) {
		skb1 = rb_entry(q, struct sk_buff, rbnode);

		if (!after(end_seq, TCP_SKB_CB(skb1)->seq))
			break;
		if (before(end_seq, TCP_SKB_CB(skb1)->end_seq)) {
			orig_tcp_dsack_extend(sk, TCP_SKB_CB(skb1)->seq,
				end_seq);
			break;
		}
		rb_erase(&skb1->rbnode, &tp->out_of_order_queue);
		orig_tcp_dsack_extend(sk, TCP_SKB_CB(skb1)->seq,
			TCP_SKB_CB(skb1)->end_seq);
		NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPOFOMERGE);
		orig_tcp_drop(sk, skb1);
	}
	/* If there is no skb after us, we are the last_skb ! */
	if (!q)
		tp->ooo_last_skb = skb;

add_sack:
	if (tcp_is_sack(tp))
		tcp_sack_new_ofo_skb(sk, seq, end_seq);
end:
	if (skb) {
		tcp_grow_window(sk, skb);
		skb_set_owner_r(skb, sk);
	}
	trace_tcp_data_queue_ofo(sk, skb);
}


int new_tcp_data_queue_ofo(struct sock *sk, struct sk_buff *skb)
{
	int ret;

	atomic64_inc_return(&diag_nr_running);
	ret = diag_tcp_data_queue_ofo(sk, skb);
	atomic64_dec_return(&diag_nr_running);

	return ret;
}

static int __activate_tcp_retrans(void)
{
	int ret = 0;

	ret = alloc_diag_variant_buffer(&tcp_ofo_variant_buffer);
	if (ret)
		goto out_variant_buffer;
	tcp_ofo_alloced = 1;

	JUMP_CHECK(tcp_data_queue_ofo);

	clean_data();
	atomic64_set(&diag_alloc_count, 0);
	get_online_cpus();
	mutex_lock(orig_text_mutex);
	JUMP_INSTALL(tcp_data_queue_ofo);
	mutex_unlock(orig_text_mutex);
	put_online_cpus();

	return 1;
out_variant_buffer:
	return 0;
}

static void __deactivate_tcp_retrans(void)
{
	get_online_cpus();
	mutex_lock(orig_text_mutex);
	JUMP_REMOVE(tcp_data_queue_ofo);
	mutex_unlock(orig_text_mutex);
	put_online_cpus();

	synchronize_sched();
	msleep(20);
	while (atomic64_read(&diag_nr_running) > 0)
	{
		msleep(10);
	}

	clean_data();
}

static int lookup_syms(void)
{

	/* TCP OFO */

	LOOKUP_SYMS(__tcp_ecn_check_ce);
	LOOKUP_SYMS(tcp_try_rmem_schedule);
	LOOKUP_SYMS(tcp_drop);
	LOOKUP_SYMS(tcp_try_coalesce);
	LOOKUP_SYMS(tcp_dsack_extend);

	

	return 0;
}

static void jump_init(void)
{
//	JUMP_INIT(tcp_rtx_synack);
//	JUMP_INIT(__tcp_retransmit_skb);
	JUMP_INIT(tcp_data_queue_ofo);
}
#endif

static void do_dump(void)
{
	unsigned long flags;
	struct list_head header;
	struct rb_node *node;
	struct tcp_ofo_summary summary;
	struct tcp_ofo_detail detail;

	INIT_LIST_HEAD(&header);
	spin_lock_irqsave(&diag_tcp_ofo_tree_lock, flags);

	for (node = rb_first(&diag_tcp_ofo_tree); node; node = rb_next(node)) {
		struct diag_tcp_ofo *this = container_of(node,
				struct diag_tcp_ofo, rb_node);

		rb_erase(&this->rb_node, &diag_tcp_ofo_tree);
		INIT_LIST_HEAD(&this->list);
		list_add_tail(&this->list, &header);
	}
	diag_tcp_ofo_tree = RB_ROOT;

	spin_unlock_irqrestore(&diag_tcp_ofo_tree_lock, flags);

	synchronize_sched();

	summary.et_type = et_tcp_ofo_summary;
	summary.alloc_count = atomic64_read(&diag_alloc_count);
//	summary.nr_tcp_retransmit_skb = atomic64_read(&diag_nr_tcp_retransmit_skb);
//	summary.nr_tcp_rtx_synack = atomic64_read(&diag_nr_tcp_rtx_synack);
//	summary.tcp_dupack = atomic64_read(&diag_tcp_dupack);
//	summary.tcp_send_dupack = atomic64_read(&diag_tcp_send_dupack);
	diag_variant_buffer_spin_lock(&tcp_ofo_variant_buffer, flags);
	diag_variant_buffer_reserve(&tcp_ofo_variant_buffer, sizeof(struct tcp_ofo_summary));
	diag_variant_buffer_write_nolock(&tcp_ofo_variant_buffer, &summary, sizeof(struct tcp_ofo_summary));
	diag_variant_buffer_seal(&tcp_ofo_variant_buffer);
	diag_variant_buffer_spin_unlock(&tcp_ofo_variant_buffer, flags);

	detail.et_type = et_tcp_ofo_detail;
	while (!list_empty(&header)) {
		struct diag_tcp_ofo *this = list_first_entry(&header, struct diag_tcp_ofo, list);

		detail.src_addr = this->src_addr;
		detail.src_port = this->src_port;
		detail.dest_addr = this->dest_addr;
		detail.dest_port = this->dest_port;
//		detail.syncack_count = this->syncack_count;
		detail.skb_count = this->skb_count;

		diag_variant_buffer_spin_lock(&tcp_ofo_variant_buffer, flags);
		diag_variant_buffer_reserve(&tcp_ofo_variant_buffer, sizeof(struct tcp_ofo_detail));
		diag_variant_buffer_write_nolock(&tcp_ofo_variant_buffer, &detail, sizeof(struct tcp_ofo_detail));
		diag_variant_buffer_seal(&tcp_ofo_variant_buffer);
		diag_variant_buffer_spin_unlock(&tcp_ofo_variant_buffer, flags);

		list_del_init(&this->list);
		kfree(this);
	}

	atomic64_set(&diag_nr_tcp_ofo_skb, 0);
//	atomic64_set(&diag_nr_tcp_rtx_synack, 0);
//	atomic64_set(&diag_tcp_dupack, 0);
}

int activate_tcp_ofo(void)
{
	if (!tcp_ofo_settings.activated)
		tcp_ofo_settings.activated = __activate_tcp_ofo();

	return tcp_ofo_settings.activated;
}

int deactivate_tcp_ofo(void)
{
	if (tcp_ofo_settings.activated)
		__deactivate_tcp_ofo();
	tcp_ofo_settings.activated = 0;

	return 0;
}

int tcp_ofo_syscall(struct pt_regs *regs, long id)
{
	int __user *user_ptr_len;
	size_t __user user_buf_len;
	void __user *user_buf;
	int ret = 0;
	struct diag_tcp_ofo_settings settings;

	switch (id) {
	case DIAG_TCP_OFO_SET:
		user_buf = (void __user *)SYSCALL_PARAM1(regs);
		user_buf_len = (size_t)SYSCALL_PARAM2(regs);

		if (user_buf_len != sizeof(struct diag_tcp_ofo_settings)) {
			ret = -EINVAL;
		} else if (tcp_ofo_settings.activated) {
			ret = -EBUSY;
		} else {
			ret = copy_from_user(&settings, user_buf, user_buf_len);
			if (!ret) {
				tcp_ofo_settings = settings;
			}
		}
		break;
	case DIAG_TCP_OFO_SETTINGS:
		user_buf = (void __user *)SYSCALL_PARAM1(regs);
		user_buf_len = (size_t)SYSCALL_PARAM2(regs);

		if (user_buf_len != sizeof(struct diag_tcp_ofo_settings)) {
			ret = -EINVAL;
		} else {
			settings.activated = tcp_ofo_settings.activated;
			settings.verbose = tcp_ofo_settings.verbose;
			ret = copy_to_user(user_buf, &settings, user_buf_len);
		}
		break;
	case DIAG_TCP_OFO_DUMP:
		user_ptr_len = (void __user *)SYSCALL_PARAM1(regs);
		user_buf = (void __user *)SYSCALL_PARAM2(regs);
		user_buf_len = (size_t)SYSCALL_PARAM3(regs);

		if (!tcp_ofo_alloced) {
			ret = -EINVAL;
		} else {
			do_dump();
			ret = copy_to_user_variant_buffer(&tcp_ofo_variant_buffer,
					user_ptr_len, user_buf, user_buf_len);
			record_dump_cmd("tcp-retrans");
		}
		break;
	default:
		ret = -ENOSYS;
		break;
	}

	return ret;
}

long diag_ioctl_tcp_ofo(unsigned int cmd, unsigned long arg)
{
	int ret = 0;
	struct diag_tcp_ofo_settings settings;
	struct diag_ioctl_dump_param dump_param;

	switch (cmd) {
	case CMD_TCP_OFO_SET:
		if (tcp_ofo_settings.activated) {
			ret = -EBUSY;
		} else {
			ret = copy_from_user(&settings, (void *)arg, sizeof(struct diag_tcp_ofo_settings));
			if (!ret) {
				tcp_ofo_settings = settings;
			}
		}
		break;
	case CMD_TCP_OFO_SETTINGS:
		settings.activated = tcp_ofo_settings.activated;
		settings.verbose = tcp_ofo_settings.verbose;
		ret = copy_to_user((void *)arg, &settings, sizeof(struct diag_tcp_ofo_settings));
		break;
	case CMD_TCP_OFO_DUMP:
		ret = copy_from_user(&dump_param, (void *)arg, sizeof(struct diag_ioctl_dump_param));

		if (!tcp_OFO_alloced) {
			ret = -EINVAL;
		} else if (!ret){
			do_dump();
			ret = copy_to_user_variant_buffer(&tcp_ofo_variant_buffer,
					dump_param.user_ptr_len, dump_param.user_buf, dump_param.user_buf_len);
			record_dump_cmd("tcp-ofo");
		}
		break;
	default:
		ret = -ENOSYS;
		break;
	}

	return ret;
}

int diag_tcp_ofo_init(void)
{
	if (lookup_syms())
		return -EINVAL;

	init_diag_variant_buffer(&tcp_ofo_variant_buffer, 1 * 1024 * 1024);
	jump_init();

	if (tcp_ofo_settings.activated)
		tcp_ofo_settings.activated = __activate_tcp_ofo();

	return 0;
}

void diag_tcp_ofo_exit(void)
{
	if (tcp_ofo_settings.activated)
		__deactivate_tcp_ofo();
	tcp_ofo_settings.activated = 0;
	destroy_diag_variant_buffer(&tcp_ofo_variant_buffer);

	return;
}
#endif
