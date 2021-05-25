/*
 * Linux内核诊断工具--用户接口API
 *
 * Copyright (C) 2021 Alibaba Ltd.
 *
 * 作者: Xiongwei Jiang <xiongwei.jiang@linux.alibaba.com>
 *
 * License terms: GNU General Public License (GPL) version 3
 *
 */

#ifndef UAPI_TCP_OFO_H
#define UAPI_TCP_OFO_H

#include <linux/ioctl.h>
int tcp_ofo_syscall(struct pt_regs *regs, long id);

#define DIAG_TCP_OFO_SET (DIAG_BASE_SYSCALL_TCP_OFO)
#define DIAG_TCP_OFO_SETTINGS (DIAG_TCP_OFO_SET + 1)
#define DIAG_TCP_OFO_DUMP (DIAG_TCP_OFO_SETTINGS + 1)

struct diag_tcp_ofo_settings {
	unsigned int activated;
	unsigned int verbose;
	unsigned int saddr;
	unsigned int sport;
	unsigned int daddr;
	unsigned int dport;
};

struct tcp_ofo_summary {
	int et_type;
	unsigned long alloc_count;
	unsigned long nr_tcp_ofo_skb;
//	unsigned long nr_tcp_rtx_synack;
//	unsigned long tcp_dupack;
//	unsigned long tcp_send_dupack;
};

struct tcp_ofo_detail {
	int et_type;
	int src_addr;
	int src_port;
	int dest_addr;
	int dest_port;
//	int syncack_count;
	int skb_count;
};

struct tcp_ofo_trace {
	int et_type;
	int src_addr;
	int src_port;
	int dest_addr;
	int dest_port;
	int sync_or_skb;
	struct timeval tv;
};

#define CMD_TCP_OFO_SET (0)
#define CMD_TCP_OFO_SETTINGS (CMD_TCP_OFO_SET + 1)
#define CMD_TCP_OFO_DUMP (CMD_TCP_OFO_SETTINGS + 1)
#define DIAG_IOCTL_TCP_OFO_SET _IOWR(DIAG_IOCTL_TYPE_TCP_OFO, CMD_TCP_OFO_SET, struct diag_tcp_ofo_settings)
#define DIAG_IOCTL_TCP_OFO_SETTINGS _IOWR(DIAG_IOCTL_TYPE_TCP_OFO, CMD_TCP_OFO_SETTINGS, struct diag_tcp_ofo_settings)
#define DIAG_IOCTL_TCP_OFO_SET_DUMP _IOWR(DIAG_IOCTL_TYPE_TCP_OFO, CMD_TCP_OFO_DUMP, struct diag_ioctl_dump_param)

#endif /* UAPI_TCP_OFO_H */
