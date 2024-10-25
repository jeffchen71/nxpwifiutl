/*
 * nl80211 userspace tool
 *
 * Copyright 2007, 2008	Johannes Berg <johannes@sipsolutions.net>
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <net/if.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdbool.h>
#include <linux/netlink.h>
#include "nl80211.h"
#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include <netlink/msg.h>
#include <netlink/attr.h>
#include <limits.h>
#include <endian.h>

#define NXPWIFIUTL_VER "0.1"
/** Find number of elements */
#define NELEMENTS(x) (sizeof(x)/sizeof(x[0]))

#define NXP_OUI	0x006037

#define HS_OFFLOAD_ARP 0x1
#define HS_OFFLOAD_PING 0x2
#define HS_WAKEON_MDNS 0x4

#define NXPWIFI_MAX_ARGC 10
#define NXPWIFI_MAX_CMD_NAME_SIZE 32

enum nxpwifi_vendor_commands {
	NXPWIFI_VENDOR_CMD_HSCFG,
	NXPWIFI_VENDOR_CMD_SLEEPPD,
	NXPWIFI_VENDOR_CMD_CLOCKSYNC,
	NXPWIFI_VENDOR_CMD_HSOFFLOAD,
	NXPWIFI_VENDOR_CMD_CHANNELSWITCH = 6,
	NXPWIFI_VENDOR_CMD_ANTCFG = 7,
	NXPWIFI_VENDOR_CMD_EDMAC_CFG = 8,
	NXPWIFI_VENDOR_CMD_VHT_CFG = 9,
	NXPWIFI_VENDOR_CMD_TXPOWER_LIMIT = 10
};

enum nxpwifiutl_rawdata_attrs {
	NXPWIFI_HSCFG = 1,
	NXPWIFI_SLEEPPD,
	NXPWIFI_CLKSYNC_CFG,
	NXPWIFI_HS_OFFLOAD,
	NXPWIFI_INDRST_CFG,
	NXPWIFI_ATTR_CSI_CONFIG,
	NXPWIFI_ATTR_MAC_ADDR,
	NXPWIFI_ATTR_CHSWITCH,
	NXPWIFI_ATTR_ANTENNA_MODE,
	NXPWIFI_ATTR_SAD_EVAL_TIME,
	NXPWIFI_ATTR_TXPWR_LIMIT,
	NXPWIFI_ATTR_MAX
};

enum nxpwifi_edmac_attrs {
	NXPWIFI_EDMAC_CTRL_2G = 1,
	NXPWIFI_EDMAC_OFFSET_2G,
	NXPWIFI_EDMAC_CTRL_5G,
	NXPWIFI_EDMAC_OFFSET_5G,
	NXPWIFI_EDMAC_TXQ_LOCK,
	NXPWIFI_EDMAC_MAX
};

enum nxpwifi_host_cmds {
	NXPWIFI_CMD_CH_TRPC = 0x00FB,
	NXPWIFI_CMD_ED_CTRL = 0x0130
};


enum nxpwifi_vht_attrs {
	NXPWIFI_VHT_BAND = 1,
	NXPWIFI_VHT_TXRX,
	NXPWIFI_VHT_BW,
	NXPWIFI_VHT_CAP,
	NXPWIFI_VHT_TXMCS,
	NXPWIFI_VHT_RXMCS,
	NXPWIFI_VHT_MAX
};

#define PROPRIETARY_TLV_BASE_ID 0x0100
#define TLV_TYPE_CHAN_TRPC_CONFIG (PROPRIETARY_TLV_BASE_ID + 137)

struct nl80211_state {
	struct nl_sock *nl_sock;
	int nl80211_id;
};


struct command_node {
    char *name;
    int (*handler) (int, char **);
};

struct nxpwifiutl_hs_cfg {
	unsigned char action;
    unsigned int  conditions;
    unsigned int  gpio;
    unsigned int  gap;
} __attribute__((packed));

struct nxpwifiutl_sleeppd_cfg {
	uint8_t		action;
    uint16_t	sleeppd;
} __attribute__((packed));

struct nxpwifiutl_hs_offload {
	uint8_t		action;
    uint8_t		offload;
} __attribute__((packed));

struct nxpwifiutl_chan_switch {
	uint8_t mode;
	uint8_t chan_switch_mode;
	uint8_t new_oper_class;
    uint8_t new_channel_num;
	uint8_t chan_switch_count;
	union {
		uint8_t bandwidth;
		uint8_t num_pkts;
		uint8_t num_retry_pkts;
	} bw_retry;
} __attribute__((packed));

struct nxpwifiutl_edmac_cfg {
	uint16_t ed_2g_enable;
	uint16_t ed_2g_offset;
	uint16_t ed_5g_enable;
	uint16_t ed_5g_offset;
	uint32_t ed_txq_lock;
} __attribute__((packed));

struct nxpwifiutl_iehdr
{
	uint16_t type;
	uint16_t len;
} __attribute__((packed));

struct nxpwifiutl_mod_group
{
	uint8_t mod_group;
	uint8_t power;
} __attribute__((packed));

struct nxpwifiutl_chtrpc_cfg {
	struct nxpwifiutl_iehdr hdr;
	uint16_t start_freq;
	uint8_t width;
	uint8_t chan_num;
	struct nxpwifiutl_mod_group mod_group[];
} __attribute__((packed));

struct nxpwifiutl_hs_offload hsoffload = {0};

static int process_hscfg(int argc, char *argv[]);
static int process_sleeppd(int argc, char *argv[]);
static int process_hsoffload(int argc, char *argv[]);
static int process_channel_switch(int argc, char *argv[]);
static int process_antenna_cfg(int argc, char *argv[]);
static int process_edmac_cfg(int argc, char *argv[]);
static int process_hostcmd(int argc, char *argv[]);

char *nxpwifi_config_get_line(FILE* fp, char *str, int size, int *lineno);
static int process_vht_cfg(int argc, char *argv[]);

struct command_node command_list[] = {
    {"hscfg",           process_hscfg},
    {"sleeppd",         process_sleeppd},
	{"hsoffload",		process_hsoffload},
	{"channel_switch",	process_channel_switch},
	{"antcfg",			process_antenna_cfg},
	{"edmac_cfg",		process_edmac_cfg},
	{"hostcmd",			process_hostcmd},
	{"vhtcfg",		process_vht_cfg}
};

static char    *usage[] = {
    "Usage: ",
    "   nxpwifiutl <ifname> <cmd> [...]",
    "   where",
    "   ifname : wireless network interface name, such as mlanX or uapX",
    "   cmd :",
    "         hscfg",
};

static 	struct nl80211_state nlstate;

static void register_handler(int (*handler)(struct nl_msg *, void *), void *data);
static int valid_handler(struct nl_msg *msg, void *arg);
static int print_hscfg_response(struct nl_msg *msg, void *arg);
static int print_sleeppd_response(struct nl_msg *msg, void *arg);

static uint32_t bytes_to_unit32(uint8_t *bytes)
{
	uint32_t thirty_two;
    thirty_two = bytes[0] | (uint32_t)bytes[1] << 8
        | (uint32_t)bytes[2] << 16 | (uint32_t)bytes[+3] << 24;
	
	return thirty_two;
}

static int parse_argument(char *argstr, char *args,int *arg)
{
	int ret = 0;

	if(strstr(argstr, args)) {
		argstr += strlen(args);
		sscanf(argstr, "%d", arg);
		ret = 1;
	}

	return ret;
}

static int print_hscfg_response(struct nl_msg *msg, void *arg)
{
	struct nlattr *attr;
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	uint8_t *data;
	int len;
	uint32_t conditions, gpio, gap;

	attr = nla_find(genlmsg_attrdata(gnlh, 0),
			genlmsg_attrlen(gnlh, 0),
			NL80211_ATTR_VENDOR_DATA);
	if (!attr) {
		fprintf(stderr, "vendor data attribute missing!\n");
		return NL_SKIP;
	}

	data = (uint8_t *) nla_data(attr);
	len = nla_len(attr);

	conditions = bytes_to_unit32(data + 4);
	gpio = bytes_to_unit32(data + 8);
	gap = bytes_to_unit32(data + 12);

	fprintf(stdout, "host sleep configuration. conditions: %x gpio: %d gap: %d\n", conditions, gpio, gap);

	return NL_OK;
}

static int print_sleeppd_response(struct nl_msg *msg, void *arg)
{
	struct nlattr *attr;
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	uint8_t *data;
	int len;
	uint16_t sleep_pd;

	attr = nla_find(genlmsg_attrdata(gnlh, 0),
			genlmsg_attrlen(gnlh, 0),
			NL80211_ATTR_VENDOR_DATA);
	if (!attr) {
		fprintf(stderr, "vendor data attribute missing!\n");
		return NL_SKIP;
	}

	data = (uint8_t *) nla_data(attr);
	len = nla_len(attr);

	sleep_pd = (*(data + 5) << 8) + *(data + 4);

	fprintf(stdout, "sleep period: %d\n", sleep_pd);

	return NL_OK;
}

static int print_hsoffload_response(struct nl_msg *msg, void *arg)
{
	struct nlattr *attr;
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	uint8_t *data;
	int len;

	attr = nla_find(genlmsg_attrdata(gnlh, 0),
			genlmsg_attrlen(gnlh, 0),
			NL80211_ATTR_VENDOR_DATA);
	if (!attr) {
		fprintf(stderr, "vendor data attribute missing!\n");
		return NL_SKIP;
	}

	data = (uint8_t *) nla_data(attr);
	len = nla_len(attr);

	hsoffload.offload = *(data + 4);

	return NL_OK;
}

static int print_antcfg_response(struct nl_msg *msg, void *arg)
{
	struct nlattr *attr;
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	uint16_t *ant_mode;
	int len;
	uint8_t *data;
	struct nlattr *tb_vendor[NXPWIFI_ATTR_MAX + 1];

	attr = nla_find(genlmsg_attrdata(gnlh, 0),
			genlmsg_attrlen(gnlh, 0),
			NL80211_ATTR_VENDOR_DATA);
	if (!attr) {
		fprintf(stderr, "vendor data attribute missing!\n");
		return NL_SKIP;
	}

	nla_parse_nested(tb_vendor, NXPWIFI_ATTR_MAX, attr, NULL);

	if (tb_vendor[NXPWIFI_ATTR_ANTENNA_MODE]) {
		ant_mode = (uint16_t *) nla_data(tb_vendor[NXPWIFI_ATTR_ANTENNA_MODE]);
		fprintf(stdout, "antenna mode: %d\n", *ant_mode);
	} else {
		fprintf(stderr, "ANT mode attribute missing!\n");		
	}

	return NL_OK;
}

static int print_vhtcfg_response(struct nl_msg *msg, void *arg)
{
	struct nlattr *attr;
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	uint32_t *band, *txrx, *bw, *vhtcap, *txmcs, *rxmcs;
	int len;
	uint8_t *data;
	struct nlattr *tb_vendor[NXPWIFI_VHT_MAX + 1];

	attr = nla_find(genlmsg_attrdata(gnlh, 0),
			genlmsg_attrlen(gnlh, 0),
			NL80211_ATTR_VENDOR_DATA);
	if (!attr) {
		fprintf(stderr, "vendor data attribute missing!\n");
		return NL_SKIP;
	}

	nla_parse_nested(tb_vendor, NXPWIFI_VHT_MAX, attr, NULL);

	if (tb_vendor[NXPWIFI_VHT_BAND]) {
		band = (uint32_t *) nla_data(tb_vendor[NXPWIFI_VHT_BAND]);
	} else {
		fprintf(stderr, "band attribute missing!\n");		
	}

	if (tb_vendor[NXPWIFI_VHT_TXRX]) {
		txrx = (uint32_t *) nla_data(tb_vendor[NXPWIFI_VHT_TXRX]);
		fprintf(stdout, "txrx: %d\n", *txrx);
	} else {
		fprintf(stderr, "txrx attribute missing!\n");		
	}

	if (tb_vendor[NXPWIFI_VHT_BW]) {
		bw = (uint32_t *) nla_data(tb_vendor[NXPWIFI_VHT_BW]);
		fprintf(stdout, "bw: %d\n", *bw);
	} else {
		fprintf(stderr, "bw attribute missing!\n");		
	}

	if (tb_vendor[NXPWIFI_VHT_CAP]) {
		vhtcap = (uint32_t *) nla_data(tb_vendor[NXPWIFI_VHT_CAP]);
		fprintf(stdout, "vhtcap: %d\n", *vhtcap);
	} else {
		fprintf(stderr, "vhtcap attribute missing!\n");		
	}

	if (tb_vendor[NXPWIFI_VHT_TXMCS]) {
		txmcs = (uint32_t *) nla_data(tb_vendor[NXPWIFI_VHT_TXMCS]);
		fprintf(stdout, "TX MCS map: %d\n", *txmcs);
	} else {
		fprintf(stderr, "txmcs attribute missing!\n");		
	}

	if (tb_vendor[NXPWIFI_VHT_RXMCS]) {
		rxmcs = (uint32_t *) nla_data(tb_vendor[NXPWIFI_VHT_RXMCS]);
		fprintf(stdout, "RX MCS map: %d\n", *rxmcs);
	} else {
		fprintf(stderr, "rxmcs attribute missing!\n");		
	}

	return NL_OK;
}

static int print_edmac_cfg_response(struct nl_msg *msg, void *arg)
{
	struct nlattr *attr;
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	uint16_t *attr_data;
	uint32_t *txq_lock;
	int len;
	uint8_t *data;
	struct nlattr *tb_vendor[NXPWIFI_EDMAC_MAX + 1];

	attr = nla_find(genlmsg_attrdata(gnlh, 0),
			genlmsg_attrlen(gnlh, 0),
			NL80211_ATTR_VENDOR_DATA);
	if (!attr) {
		fprintf(stderr, "vendor data attribute missing!\n");
		return NL_SKIP;
	}

	nla_parse_nested(tb_vendor, NXPWIFI_EDMAC_MAX, attr, NULL);

	if (tb_vendor[NXPWIFI_EDMAC_CTRL_2G]) {
		attr_data = (uint16_t *) nla_data(tb_vendor[NXPWIFI_EDMAC_CTRL_2G]);
		fprintf(stdout, "edmac_2G:0x%02x\n", *attr_data);
	}

	if (tb_vendor[NXPWIFI_EDMAC_OFFSET_2G]) {
		attr_data = (uint16_t *) nla_data(tb_vendor[NXPWIFI_EDMAC_OFFSET_2G]);
		fprintf(stdout, "offset_2G:0x%02x\n", *attr_data);
	}

	if (tb_vendor[NXPWIFI_EDMAC_CTRL_5G]) {
		attr_data = (uint16_t *) nla_data(tb_vendor[NXPWIFI_EDMAC_CTRL_5G]);
		fprintf(stdout, "edmac_5G:0x%02x\n", *attr_data);
	}

	if (tb_vendor[NXPWIFI_EDMAC_OFFSET_5G]) {
		attr_data = (uint16_t *) nla_data(tb_vendor[NXPWIFI_EDMAC_OFFSET_5G]);
		fprintf(stdout, "offset_5G:0x%02x\n", *attr_data);
	}

	if (tb_vendor[NXPWIFI_EDMAC_TXQ_LOCK]) {
		txq_lock = (uint32_t *) nla_data(tb_vendor[NXPWIFI_EDMAC_TXQ_LOCK]);
		fprintf(stdout, "txq_lock:0x%02x\n", *txq_lock);
	}

	return NL_OK;
}

static int print_txpwrlimit_response(struct nl_msg *msg, void *arg)
{
	struct nlattr *attr;
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	uint8_t *attr_data;
	int len;
	uint8_t *data;
	struct nlattr *tb_vendor[NXPWIFI_ATTR_MAX + 1];
	struct nxpwifiutl_chtrpc_cfg *chtrpc_tlv;
	int left_len, i;
	int mod_num = 0;

	attr = nla_find(genlmsg_attrdata(gnlh, 0),
			genlmsg_attrlen(gnlh, 0),
			NL80211_ATTR_VENDOR_DATA);
	if (!attr) {
		fprintf(stderr, "vendor data attribute missing!\n");
		return NL_SKIP;
	}

	nla_parse_nested(tb_vendor, NXPWIFI_ATTR_MAX, attr, NULL);

	if (!tb_vendor[NXPWIFI_ATTR_TXPWR_LIMIT]) {
		fprintf(stderr, "TX Power Limit attribute missing!\n");
		return NL_SKIP;
	}

	attr_data = (uint8_t *)nla_data(tb_vendor[NXPWIFI_ATTR_TXPWR_LIMIT]);
	chtrpc_tlv = (struct nxpwifiutl_chtrpc_cfg *)(attr_data + 4);
	/* Process result */
	printf("------------------------------------------------------------------------------------\n");
	printf("Get txpwrlimit: sub_band=0x%x len=%d\n", *((uint16_t *)attr_data + 1), nla_len(tb_vendor[NXPWIFI_ATTR_TXPWR_LIMIT]));
	left_len = nla_len(tb_vendor[NXPWIFI_ATTR_TXPWR_LIMIT]) - 4;

	while (left_len >= (int)sizeof(struct nxpwifiutl_iehdr))
	{
		switch (le16toh(chtrpc_tlv->hdr.type))
		{
		case TLV_TYPE_CHAN_TRPC_CONFIG:
			printf("StartFreq: %d\n", le16toh(chtrpc_tlv->start_freq));
			printf("ChanNum:   %d\n", chtrpc_tlv->chan_num);
			mod_num = (chtrpc_tlv->hdr.len - 4) / sizeof(struct nxpwifiutl_mod_group);
			printf("Pwr:");
			for (i = 0; i < mod_num; i++)
			{
				if (i == (mod_num - 1))
					printf("%d,%d", chtrpc_tlv->mod_group[i].mod_group, chtrpc_tlv->mod_group[i].power);
				else
					printf("%d,%d,", chtrpc_tlv->mod_group[i].mod_group, chtrpc_tlv->mod_group[i].power);
			}
			printf("\n \n");
			break;
		default:
			break;
		}
		left_len -= (chtrpc_tlv->hdr.len + sizeof(struct nxpwifiutl_iehdr));
		chtrpc_tlv = (struct nxpwifiutl_chtrpc_cfg *)((uint8_t *)chtrpc_tlv + chtrpc_tlv->hdr.len + sizeof(struct nxpwifiutl_iehdr));
	}

	return NL_OK;
}

/**
 *  @brief Process hscfg configuration
 *  @param argc   Number of arguments
 *  @param argv   A pointer to arguments array
 *  @return     0--success, otherwise--fail
 */
static int process_hscfg(int argc, char *argv[])
{
    __u8 *buffer = NULL;
	struct nl_msg *msg;
	signed long long devidx = 0;
	unsigned char action;
	struct nxpwifiutl_hs_cfg hscfg ={0};
	struct nl_cb *cb;

	msg = nlmsg_alloc();
	if (!msg) {
		fprintf(stderr, "failed to allocate netlink message\n");
		return 1;
	}

    if ( NULL == genlmsg_put(msg, 0, 0, nlstate.nl80211_id, 0,
	            0, NL80211_CMD_VENDOR, 0))
        goto nla_put_failure;

	devidx = if_nametoindex(argv[1]);

    if (devidx == 0) {
        if (errno == ENODEV )
            fprintf(stderr, "No interface found with given name\n");
        goto nla_put_failure;
    }

	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, devidx);

	NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_ID, NXP_OUI);
	NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_SUBCMD, NXPWIFI_VENDOR_CMD_HSCFG);

	if (argc >= 4)
		sscanf(argv[3], "0x%x", &hscfg.conditions);

	if (argc >= 5)
		sscanf(argv[4], "%d", &hscfg.gpio);

	if (argc >= 6)
		sscanf(argv[5], "%d", &hscfg.gap);

	if (argc == 3) {
		cb = nl_cb_alloc(NL_CB_DEBUG);
		hscfg.action = 0;
		register_handler(print_hscfg_response, (void *) false);
		nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, valid_handler, NULL);
	} else
		hscfg.action = 1;

	NLA_PUT(msg, NL80211_ATTR_VENDOR_DATA, sizeof(hscfg), &hscfg);
	
	nl_send_auto(nlstate.nl_sock, msg);

	if (hscfg.action == 0)
		nl_recvmsgs(nlstate.nl_sock, cb);

    return 0;
nla_put_failure:

    return 1;
}

/**
 *  @brief Process sleep period configuration for PPS/uAPSD.
 *  @param argc   Number of arguments
 *  @param argv   A pointer to arguments array
 *  @return     0--success, otherwise--fail
 */
static int process_sleeppd(int argc, char *argv[])
{
    __u8 *buffer = NULL;
	struct nl_msg *msg;
	signed long long devidx = 0;
	unsigned char action;
	struct nxpwifiutl_sleeppd_cfg sleepd_cfg ={0};
	struct nl_cb *cb;

	if ((argc > 4) || (argc < 3)) {
		fprintf(stderr, "wrong argument numbers.\n");
		return 1;
	}

	msg = nlmsg_alloc();
	if (!msg) {
		fprintf(stderr, "failed to allocate netlink message\n");
		return 1;
	}

    if ( NULL == genlmsg_put(msg, 0, 0, nlstate.nl80211_id, 0,
	            0, NL80211_CMD_VENDOR, 0))
        goto nla_put_failure;

	devidx = if_nametoindex(argv[1]);

    if (devidx == 0) {
		if (errno == ENODEV )
			fprintf(stderr, "No interface found with given name\n");
        goto nla_put_failure;
    }

	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, devidx);

	NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_ID, NXP_OUI);
	NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_SUBCMD, NXPWIFI_VENDOR_CMD_SLEEPPD);

	if (argc == 3) {
		cb = nl_cb_alloc(NL_CB_DEFAULT);
		sleepd_cfg.action = 0;
		register_handler(print_sleeppd_response, (void *) false);
		nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, valid_handler, NULL);
	} else {
		sleepd_cfg.action = 1;
		sscanf(argv[3], "%d", &sleepd_cfg.sleeppd);
	}

	NLA_PUT(msg, NL80211_ATTR_VENDOR_DATA, sizeof(sleepd_cfg), &sleepd_cfg);
	
	nl_send_auto(nlstate.nl_sock, msg);

	if (sleepd_cfg.action == 0)
		nl_recvmsgs(nlstate.nl_sock, cb);

    return 0;
nla_put_failure:

    return 1;
}

/**
 *  @brief Process the configuration for auto_arp and auto_ping.
 *  @param argc   Number of arguments
 *  @param argv   A pointer to arguments array
 *  @return     0--success, otherwise--fail
 */
static int process_hsoffload(int argc, char *argv[])
{
    __u8 *buffer = NULL;
	struct nl_msg *msg;
	signed long long devidx = 0;
	unsigned char action;
	struct nl_cb *cb;
	int auto_arp = 0, auto_ping = 0, wake_on_mdns = 0;
	char *rdargv[3];
    struct nlattr *currattr;
	int rem;

	if ((argc > 6) || (argc < 3)) {
		fprintf(stderr, "wrong argument numbers.\n");
		return 1;
	}

	msg = nlmsg_alloc();
	if (!msg) {
		fprintf(stderr, "failed to allocate netlink message\n");
		return 1;
	}

    if ( NULL == genlmsg_put(msg, 0, 0, nlstate.nl80211_id, 0,
	            0, NL80211_CMD_VENDOR, 0))
        goto nla_put_failure;

	devidx = if_nametoindex(argv[1]);

    if (devidx == 0) {
        if (errno == ENODEV)
            fprintf(stderr, "%s: %s\n", strerror(errno), argv[1]);

        goto nla_put_failure;
    }

	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, devidx);

	NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_ID, NXP_OUI);
	NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_SUBCMD, NXPWIFI_VENDOR_CMD_HSOFFLOAD);

	if (argc == 3) {
		cb = nl_cb_alloc(NL_CB_DEFAULT);
		hsoffload.action = 0;
		register_handler(print_hsoffload_response, (void *) false);
		nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, valid_handler, NULL);
	} else {
		rdargv[0] = argv[0];
		rdargv[1] = argv[1];
		rdargv[2] = NULL;
		process_hsoffload(3, rdargv);
		hsoffload.action = 1;

		while (argc >= 4) {
			if (parse_argument(argv[argc -1], "autoarp=", &auto_arp)) {
				if(auto_arp)
					hsoffload.offload |= HS_OFFLOAD_ARP;
				else
					hsoffload.offload &= ~HS_OFFLOAD_ARP;
			}

			if (parse_argument(argv[argc -1], "autoping=", &auto_ping)) {
				if(auto_ping)
					hsoffload.offload |= HS_OFFLOAD_PING;
				else
					hsoffload.offload &= ~HS_OFFLOAD_PING;
			}

			if (parse_argument(argv[argc -1], "wakeonmdns=", &wake_on_mdns)) {
				if(wake_on_mdns)
					hsoffload.offload |= HS_WAKEON_MDNS;
				else
					hsoffload.offload &= ~HS_WAKEON_MDNS;
			}

			argc--;
		}
	}

	NLA_PUT(msg, NL80211_ATTR_VENDOR_DATA, sizeof(hsoffload), &hsoffload);

	nlmsg_for_each_attr(currattr, nlmsg_hdr(msg), NLMSG_HDRLEN, rem)
	{
		printf("type:%d len:%d\n", currattr->nla_type, currattr->nla_len);
	}

	nl_send_auto(nlstate.nl_sock, msg);

	if (hsoffload.action == 0) {
		nl_recvmsgs(nlstate.nl_sock, cb);

		if (argv[2] != NULL) {
			printf("Auto-arp is ");

			if(hsoffload.offload & HS_OFFLOAD_ARP)
				printf("enabled, ");
			else
				printf("disabled, ");

			printf("Auto-ping is ");

			if (hsoffload.offload & HS_OFFLOAD_PING)
				printf("enabled, ");
			else
				printf("disabled, ");

			printf("Wake-on-mDNS is ");

			if (hsoffload.offload & HS_WAKEON_MDNS)
				printf("enabled");
			else
				printf("disabled");

			printf(".\n");
		}
	}

    return 0;
nla_put_failure:

    return 1;
}

/**
 *  @brief Process the configuration for channel switch.
 *  @param argc   Number of arguments
 *  @param argv   A pointer to arguments array
 *  @return     0--success, otherwise--fail
 */
static int process_channel_switch(int argc, char *argv[])
{
    __u8 *buffer = NULL;
	struct nl_msg *msg = NULL, *nested = NULL;
	signed long long devidx = 0;
	unsigned char action;
	struct nl_cb *cb;
	uint8_t band;
	unsigned int switch_mode, class, channel, switch_count, bw_pktno, mode; 
	int count = 0;
	struct nxpwifiutl_chan_switch chsw_cfg;
    struct nlattr *opts = NULL, *currattr;
	int rem;

	if (argc > 9) {
		fprintf(stderr, "Too many arguments\n");
		return 1;
	}

	if (argc < 6) {
		fprintf(stderr, "Too few arguments\n");
		return 1;
	}

	msg = nlmsg_alloc();
	if (!msg) {
		fprintf(stderr, "failed to allocate netlink message\n");
		return 1;
	}

	nested = nlmsg_alloc();
	if (!nested) {
		nlmsg_free(msg);
		fprintf(stderr, "failed to allocate nested netlink message\n");
		return 1;
	}

    if ( NULL == genlmsg_put(msg, 0, 0, nlstate.nl80211_id, 0,
	            0, NL80211_CMD_VENDOR, 0))
        goto nla_put_failure;

	devidx = if_nametoindex(argv[1]);

    if (devidx == 0) {
        if (errno == ENODEV)
            fprintf(stderr, "%s: %s\n", strerror(errno), argv[1]);

        goto nla_put_failure;
    }

	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, devidx);

	NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_ID, NXP_OUI);
	NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_SUBCMD, NXPWIFI_VENDOR_CMD_CHANNELSWITCH);

	count = sscanf(argv[3], "%u", &switch_mode);
	chsw_cfg.chan_switch_mode = (uint8_t)switch_mode;
	count = sscanf(argv[4], "%u", &class);
	chsw_cfg.new_oper_class = (uint8_t)class;
	
    count = sscanf(argv[5], "%u", &channel);
	chsw_cfg.new_channel_num = (uint8_t)channel;

	count = sscanf(argv[6], "%u", &switch_count);
	chsw_cfg.chan_switch_count = (uint8_t)switch_count;

	if (argc >= 8) {
		sscanf(argv[7], "%d", &bw_pktno);
	}

	if (argc >= 9)
		sscanf(argv[8], "%d", &mode);

	if (argc == 7) {
		memset(&chsw_cfg.bw_retry, 0, sizeof(chsw_cfg.bw_retry));
		chsw_cfg.bw_retry.bandwidth = 0;
		chsw_cfg.mode = 0;
		if (chsw_cfg.chan_switch_count == 0) {
			fprintf(stderr, "Invalid arguments\n");
			goto nla_put_failure;
		}		
	}

	if (argc == 8) {
		if (chsw_cfg.chan_switch_count != 0)
			chsw_cfg.bw_retry.bandwidth = (uint8_t)bw_pktno;
		else
			chsw_cfg.bw_retry.num_pkts = (uint8_t)bw_pktno;
		chsw_cfg.mode = 0;
	}

	if (argc == 9) {
		chsw_cfg.mode = (uint8_t)mode;
		chsw_cfg.bw_retry.num_retry_pkts = (uint8_t)bw_pktno;
	}

	NLA_PUT(nested, 7, sizeof(chsw_cfg), &chsw_cfg);
	nla_put_nested(msg, NL80211_ATTR_VENDOR_DATA, nested);

	count = nl_send_auto(nlstate.nl_sock, msg);

    if (count < 0) {
        fprintf(stderr, "failed to sent MSG: %s\n", strerror(count));
		goto nla_put_failure;
	}

	nlmsg_free(nested);
	nlmsg_free(msg);

	return 0;
nla_put_failure:
	nlmsg_free(nested);
	nlmsg_free(msg);

    return 1;
}

/**
 *  @brief Process the configuration for channel switch.
 *  @param argc   Number of arguments
 *  @param argv   A pointer to arguments array
 *  @return     0--success, otherwise--fail
 */
static int process_antenna_cfg(int argc, char *argv[])
{
    __u8 *buffer = NULL;
	struct nl_msg *msg = NULL, *nested = NULL;
	signed long long devidx = 0;
	unsigned char action;
	struct nl_cb *cb;
	int count = 0;
	unsigned int ant_mode = 0, eval_time;

	if (argc > 5) {
		fprintf(stderr, "Too many arguments\n");
		return 1;
	}

	if (argc < 3) {
		fprintf(stderr, "Too few arguments\n");
		return 1;
	}

	msg = nlmsg_alloc();
	if (!msg) {
		fprintf(stderr, "failed to allocate netlink message\n");
		return 1;
	}

	nested = nlmsg_alloc();
	if (!nested) {
		nlmsg_free(msg);
		fprintf(stderr, "failed to allocate nested netlink message\n");
		return 1;
	}

    if ( NULL == genlmsg_put(msg, 0, 0, nlstate.nl80211_id, 0,
	            0, NL80211_CMD_VENDOR, 0))
        goto nla_put_failure;

	devidx = if_nametoindex(argv[1]);

    if (devidx == 0) {
        if (errno == ENODEV)
            fprintf(stderr, "%s: %s\n", strerror(errno), argv[1]);

        goto nla_put_failure;
    }

	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, devidx);

	NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_ID, NXP_OUI);
	NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_SUBCMD, NXPWIFI_VENDOR_CMD_ANTCFG);

	if (argc >= 4) {
		count = sscanf(argv[3], "%u", &ant_mode);
		NLA_PUT_U16(nested, NXPWIFI_ATTR_ANTENNA_MODE, (uint16_t)ant_mode);

		if (argc > 4) {
			count = sscanf(argv[4], "%u", &eval_time);
			NLA_PUT_U16(nested, NXPWIFI_ATTR_SAD_EVAL_TIME, (uint16_t)eval_time);
		}

		nla_put_nested(msg, NL80211_ATTR_VENDOR_DATA, nested);
	} else {
		cb = nl_cb_alloc(NL_CB_DEFAULT);
		register_handler(print_antcfg_response, (void *) false);
		nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, valid_handler, NULL);
	}

	count = nl_send_auto(nlstate.nl_sock, msg);

    if (count < 0) {
        fprintf(stderr, "failed to sent MSG: %s\n", strerror(count));
		goto nla_put_failure;
	}

	if (argc == 3)
		nl_recvmsgs(nlstate.nl_sock, cb);

	nlmsg_free(nested);
	nlmsg_free(msg);

	return 0;
nla_put_failure:
	nlmsg_free(nested);
	nlmsg_free(msg);

    return 1;
}

/**
 *  @brief Process the configuration for EDMAC.
 *  @param argc   Number of arguments
 *  @param argv   A pointer to arguments array
 *  @return     0--success, otherwise--fail
 */
static int process_edmac_cfg(int argc, char *argv[])
{
    __u8 *buffer = NULL;
	struct nl_msg *msg = NULL;
	signed long long devidx = 0;
	unsigned char action;
	struct nl_cb *cb;
	int count = 0;
	unsigned int ed_ctrl_2g = 0, ed_ctrl_5g, ed_bitmap_txq_lock;
	int ed_offset_2g, ed_offset_5g;
	struct nlattr *nested;
	if (argc > 8) {
		fprintf(stderr, "Too many arguments\n");
		return 1;
	} else if (argc < 3) {
		fprintf(stderr, "Too few arguments\n");
		return 1;
	} else if ((argc != 8 ) && (argc != 3)) {
		fprintf(stderr, "wrong argument numbers.\n");
		return 1;
	}

	msg = nlmsg_alloc();
	if (!msg) {
		fprintf(stderr, "failed to allocate netlink message\n");
		return 1;
	}

    if ( NULL == genlmsg_put(msg, 0, 0, nlstate.nl80211_id, 0,
	            0, NL80211_CMD_VENDOR, 0))
        goto nla_put_failure;

	devidx = if_nametoindex(argv[1]);

    if (devidx == 0) {
        if (errno == ENODEV)
            fprintf(stderr, "%s: %s\n", strerror(errno), argv[1]);

        goto nla_put_failure;
    }

	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, devidx);

	NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_ID, NXP_OUI);
	NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_SUBCMD, NXPWIFI_VENDOR_CMD_EDMAC_CFG);

	if (argc == 8) {
		nested = nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA);
		count = sscanf(argv[3], "0x%x", &ed_ctrl_2g);
		NLA_PUT_U16(msg, NXPWIFI_EDMAC_CTRL_2G, (uint16_t)ed_ctrl_2g);
		count = sscanf(argv[4], "0x%x", &ed_offset_2g);
		NLA_PUT_S16(msg, NXPWIFI_EDMAC_OFFSET_2G, (int16_t)ed_offset_2g);
		count = sscanf(argv[5], "0x%x", &ed_ctrl_5g);
		NLA_PUT_U16(msg, NXPWIFI_EDMAC_CTRL_5G, (uint16_t)ed_ctrl_5g);
		count = sscanf(argv[6], "0x%x", &ed_offset_5g);
		NLA_PUT_S16(msg, NXPWIFI_EDMAC_OFFSET_5G, (int16_t)ed_offset_5g);

		count = sscanf(argv[7], "0x%x", &ed_bitmap_txq_lock);
		NLA_PUT_U32(msg, NXPWIFI_EDMAC_TXQ_LOCK, (uint32_t)ed_bitmap_txq_lock);
		nla_nest_end(msg, nested);
	} else {
		cb = nl_cb_alloc(NL_CB_DEFAULT);
		register_handler(print_edmac_cfg_response, (void *) false);
		nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, valid_handler, NULL);
	}

	count = nl_send_auto(nlstate.nl_sock, msg);

    if (count < 0) {
        fprintf(stderr, "failed to sent MSG: %s\n", strerror(count));
		goto nla_put_failure;
	}

	if (argc == 3)
		nl_recvmsgs(nlstate.nl_sock, cb);

	nlmsg_free(msg);

	return 0;
nla_put_failure:
	nlmsg_free(msg);

    return 1;
}

/**
 *  @brief Convert char to hex integer
 *
 *  @param chr      Char
 *  @return         Hex integer
 */
unsigned char hexc2bin(char chr)
{
    if (chr >= '0' && chr <= '9')
        chr -= '0';
    else if (chr >= 'A' && chr <= 'F')
        chr -= ('A' - 10);
    else if (chr >= 'a' && chr <= 'f')
        chr -= ('a' - 10);

    return chr;
}

unsigned int a2hex_or_atoi(char *value)
{
	int count = 0;
	unsigned int hexno;

	count = sscanf(value, "0x%x", &hexno);

	if (count > 0) {
		return hexno;
    } else {
        return (unsigned int)atoi(value);
    }
}
/** Command buffer max length */
#define BUFFER_LENGTH       (4 * 1024)

/**
 *  @brief get hostcmd data
 *
 *  @param ln           A pointer to line number
 *  @param buf          A pointer to hostcmd data
 *  @param size         A pointer to the return size of hostcmd buffer
 *  @return             MLAN_STATUS_SUCCESS
 */
static int nxpwifi_get_hostcmd_data(FILE *fp, int *ln, unsigned char *buf, unsigned short *size)
{
    int   errors = 0, i;
    char    line[512], *pos, *pos1, *pos2, *pos3;
    unsigned short   len;


    while ((pos = nxpwifi_config_get_line(fp, line, sizeof(line), ln))) {
        (*ln)++;
        if (strcmp(pos, "}") == 0) {
            break;
        }

        pos1 = strchr(pos, ':');
        if (pos1 == NULL) {
            printf("Line %d: Invalid hostcmd line '%s'\n", *ln, pos);
            errors++;
            continue;
        }
        *pos1++ = '\0';
        pos2 = strchr(pos1, '=');
        if (pos2 == NULL) {
            printf("Line %d: Invalid hostcmd line '%s'\n", *ln, pos);
            errors++;
            continue;
        }
        *pos2++ = '\0';

        len = a2hex_or_atoi(pos1);

        if (len < 1 || len > BUFFER_LENGTH) {
            printf("Line %d: Invalid hostcmd line '%s'\n", *ln, pos);
            errors++;
            continue;
        }

        *size += len;

        if (*pos2 == '"') {
            pos2++;
            pos3 = strchr(pos2, '"');
            if (pos3 == NULL) {
                printf("Line %d: invalid quotation '%s'\n", *ln, pos);
                errors++;
                continue;
            }
            *pos3 = '\0';
            memset(buf, 0, len);
			len = strlen(pos2) < len ? strlen(pos2) : len;
            memmove(buf, &pos2, len);
            buf += len;
        }
        else if (*pos2 == '\'') {
            pos2++;
            pos3 = strchr(pos2, '\'');
            if (pos3 == NULL) {
                printf("Line %d: invalid quotation '%s'\n", *ln, pos);
                errors++;
                continue;
            }
            *pos3 = ',';
            for (i=0; i<len; i++) {
                pos3 = strchr(pos2, ',');
                if (pos3 != NULL) {
                    *pos3 = '\0';
                    *buf++ = (unsigned char)a2hex_or_atoi(pos2);
                    pos2 = pos3 + 1;
                }
                else
                    *buf++ = 0;
            }
        }
        else if (*pos2 == '{') {
            unsigned short tlvlen = 0, tmp_tlvlen;
            nxpwifi_get_hostcmd_data(fp, ln, buf+len, &tlvlen);
            tmp_tlvlen = tlvlen;
            while (len--) {
                *buf++ = (unsigned char)(tmp_tlvlen & 0xff);
                tmp_tlvlen >>= 8;
            }
            *size += tlvlen;
            buf += tlvlen;
        }
        else {
            unsigned int value = a2hex_or_atoi(pos2);
            while (len--) {
                *buf++ = (unsigned char)(value & 0xff);
                value >>= 8;
            }
        }
    }
    return 0;
}

/**
 *  @brief Get one line from the File
 *
 *  @param fp       File handler
 *  @param str      Storage location for data.
 *  @param size     Maximum number of characters to read.
 *  @param lineno   A pointer to return current line number
 *  @return         returns string or NULL
 */
char *nxpwifi_config_get_line(FILE* fp, char *str, int size, int *lineno)
{
    char *start, *end;
    int out, next_line;

    if (!fp || !str)
        return NULL;

    do {
read_line:
        if (!fgets(str, size, fp))
            break;
        start = str;
        start[size - 1] = '\0';
        end = start + strlen(str);
        (*lineno)++;

        out = 1;
        while (out && (start < end)) {
            next_line = 0;
            /* Remove empty lines and lines starting with # */
            switch (start[0]) {
            case ' ':  /* White space */
            case '\t': /* Tab */
                start ++;
                break;
            case '#':
            case '\n':
            case '\0':
                next_line = 1;
                break;
            case '\r':
                if (start[1] == '\n')
                    next_line = 1;
                else
                    start ++;
                break;
            default:
                out = 0;
                break;
            }
            if (next_line)
                goto read_line;
        }

        /* Remove # comments unless they are within a double quoted
         * string. Remove trailing white space. */
        end = strstr(start, "\"");
        if (end) {
            end = strstr(end + 1, "\"");
            if (!end)
                end = start;
        } else
            end = start;

        end = strstr(end + 1, "#");
        if (end)
            *end-- = '\0';
        else
            end = start + strlen(start) - 1;

        out = 1;
        while (out && (start < end)) {
            switch (*end) {
            case ' ':  /* White space */
            case '\t': /* Tab */
            case '\n':
            case '\r':
                *end = '\0';
                end --;
                break;
            default:
                out = 0;
                break;
            }
        }

        if (*start == '\0')
            continue;

        return start;
    } while(1);

    return NULL;
}

/**
 *  @brief Prepare host-command buffer
 *  @param fp       File handler
 *  @param cmd_name Command name
 *  @param buf      A pointer to comand buffer
 *  @return         MLAN_STATUS_SUCCESS--success, otherwise--fail
 */
static int prepare_host_cmd_buffer(FILE* fp, char *cmd_name, unsigned char *buf, uint16_t *len, unsigned short *hostcmd)
{
    char        line[256], cmdname[256], *pos, cmdcode[10];
    int     ln = 0, count = 0;
    int     cmdname_found = 0, cmdcode_found = 0;
	unsigned short cmd;

    snprintf(cmdname, sizeof(cmdname), "%s={", cmd_name);
    cmdname_found = 0;
    while ((pos = nxpwifi_config_get_line(fp, line, sizeof(line), &ln))) {
        if (strcmp(pos, cmdname) == 0) {
            cmdname_found = 1;
            snprintf(cmdcode, sizeof(cmdcode), "CmdCode=");
            cmdcode_found = 0;
            while ((pos = nxpwifi_config_get_line(fp, line, sizeof(line), &ln))) {
                if (strncmp(pos, cmdcode, strlen(cmdcode)) == 0) {
                    cmdcode_found = 1;

                 	*hostcmd = a2hex_or_atoi(pos+strlen(cmdcode));

                    nxpwifi_get_hostcmd_data(fp, &ln, buf, len);
                    break;
                }
            }
            if (!cmdcode_found) {
                fprintf(stderr, "mlanutl: CmdCode not found in conf file\n");
                return 1;
            }
            break;
        }
    }

    if (!cmdname_found){
        fprintf(stderr, "mlanutl: cmdname '%s' is not found in conf file\n",cmd_name);
        return 1;
    }

    return 0;
}

static int process_chtrpc_cfg(signed long long devidx, unsigned char *buffer, uint16_t cmd_len)
{
	struct nl_msg *msg;
	struct nl_cb *cb;

	msg = nlmsg_alloc();
	if (!msg)
	{
		fprintf(stderr, "failed to allocate netlink message\n");
		return 1;
	}

	printf("cmd len %d\n", cmd_len);
	if (NULL == genlmsg_put(msg, 0, 0, nlstate.nl80211_id, 0,
				0, NL80211_CMD_VENDOR, 0))
		goto nla_put_failure;

	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, devidx);

	NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_ID, NXP_OUI);
	NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_SUBCMD, NXPWIFI_VENDOR_CMD_TXPOWER_LIMIT);

	NLA_PUT(msg, NL80211_ATTR_VENDOR_DATA, cmd_len, buffer);

	if (cmd_len == 4)
	{
		cb = nl_cb_alloc(NL_CB_DEFAULT);
		register_handler(print_txpwrlimit_response, (void *)false);
		nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, valid_handler, NULL);
	}

	nl_send_auto(nlstate.nl_sock, msg);

	if (cmd_len == 4)
		nl_recvmsgs(nlstate.nl_sock, cb);

	return 0;
nla_put_failure:
	nlmsg_free(msg);

	return 1;
}

/**
 *  @brief Process hostcmd command
 *  @param argc   Number of arguments
 *  @param argv   A pointer to arguments array
 *  @return     MLAN_STATUS_SUCCESS--success, otherwise--fail
 */
static int process_hostcmd(int argc, char *argv[])
{
    unsigned char *buffer = NULL, *raw_buf = NULL;
    struct eth_priv_cmd *cmd = NULL;
    struct ifreq ifr;
    FILE *fp = NULL;
    FILE *fp_raw = NULL;
    FILE *fp_dtsi = NULL;
    char cmdname[256];
    bool call_ioctl = true;
    unsigned int buf_len = 0, i, j, k;
    char *line = NULL, *pos = NULL;
    int li = 0, blk_count = 0, ob = 0;
    int ret = 0;
	char *argv1[NXPWIFI_MAX_ARGC];
	char edmac_cmd[NXPWIFI_MAX_CMD_NAME_SIZE];
	char ed_2g_enable[NXPWIFI_MAX_CMD_NAME_SIZE], ed_2g_offset[NXPWIFI_MAX_CMD_NAME_SIZE], ed_5g_enable[NXPWIFI_MAX_CMD_NAME_SIZE], ed_5g_offset[NXPWIFI_MAX_CMD_NAME_SIZE], ed_txq_lock[NXPWIFI_MAX_CMD_NAME_SIZE];
	struct nxpwifiutl_edmac_cfg *edmac_cfg;
	uint16_t cmd_len, hostcmd;
	signed long long devidx = 0;

    struct cmd_node {
        char cmd_string[256];
        struct cmd_node *next;
    };
    struct cmd_node *command = NULL, *header = NULL, *new_node = NULL;

    if (argc < 5) {
        printf("Error: invalid no of arguments\n");
        printf("Syntax: ./nxpwifiutl mlanX hostcmd <hostcmd.conf> <cmdname>\n");
        return 1;
    }

    snprintf(cmdname, sizeof(cmdname),"%s", argv[4]);

    if (!strcmp(cmdname, "generate_raw")) {
        call_ioctl = false;
    }
    if (!call_ioctl && argc != 6) {
        printf("Error: invalid no of arguments\n");
        printf("Syntax: ./nxpwifiutl mlanX hostcmd <hostcmd.conf> %s <raw_data_file>\n", cmdname);
		return 1;
    }

    fp = fopen(argv[3], "r");
    if (fp == NULL) {
        fprintf(stderr, "Cannot open file %s\n", argv[3]);
		return 1;
    }

    /* Initialize buffer */
    buffer = (unsigned char *) malloc(BUFFER_LENGTH);
    if (!buffer) {
        printf("ERR:Cannot allocate buffer for command!\n");
        fclose(fp);
		return 1;
    }
    memset(buffer, 0, BUFFER_LENGTH);

    if (call_ioctl) {
        if ( 0 != prepare_host_cmd_buffer(fp, cmdname, buffer, &cmd_len, &hostcmd)) {
            fclose(fp);
            ret = 1;
			printf("parse command failed\n");
            goto done;
        }
        fclose(fp);
    }

	switch (hostcmd) {
		case NXPWIFI_CMD_ED_CTRL:
			argv1[1] = argv[1];
			strcpy(edmac_cmd, "edmac_cfg");
			argv1[2] = edmac_cmd;

			if (cmd_len == 0) {
				process_edmac_cfg(3, argv1);
			} else {
				edmac_cfg = (struct nxpwifiutl_edmac_cfg *)buffer;
				sprintf(ed_2g_enable, "0x%x", edmac_cfg->ed_2g_enable);
				argv1[3] = ed_2g_enable;
				sprintf(ed_2g_offset, "0x%x", edmac_cfg->ed_2g_offset);
				argv1[4] = ed_2g_offset;
				sprintf(ed_5g_enable, "0x%x", edmac_cfg->ed_5g_enable);
				argv1[5] = ed_5g_enable;
				sprintf(ed_5g_offset, "0x%x", edmac_cfg->ed_5g_offset);
				argv1[6] = ed_5g_offset;
				sprintf(ed_txq_lock, "0x%x", edmac_cfg->ed_txq_lock);
				argv1[7] = ed_txq_lock;
				process_edmac_cfg(8, argv1);
			}
		break;
		case NXPWIFI_CMD_CH_TRPC:
			devidx = if_nametoindex(argv[1]);

			if (devidx == 0)
			{
				if (errno == ENODEV)
					fprintf(stderr, "%s: %s\n", strerror(errno), argv[1]);
				ret = 1;
				goto done;
			}

			process_chtrpc_cfg(devidx, buffer, cmd_len);
			break;
		default:
		break;
	}
done:
    while (header) {
        command = header;
        header = header->next;
        free(command);
    }
    if (line)
        free(line);
    if (buffer)
        free(buffer);
    if (cmd)
        free(cmd);
    return ret;
}

static int process_vht_cfg(int argc, char *argv[])
{
    __u8 *buffer = NULL;
	struct nl_msg *msg = NULL;
	signed long long devidx = 0;
	unsigned char action;
	struct nl_cb *cb;
	int count = 0;
	unsigned int band = 0, txrx, bw, vhtcap, txmcs, rxmcs;
	struct nlattr *nested;
	char *tmp;
	if (argc < 5) {
		fprintf(stderr, "Too few arguments\n");
		return 1;
	} else if (argc > 9 ) {
		fprintf(stderr, "Too many arguments\n");
		return 1;
	}

	msg = nlmsg_alloc();
	if (!msg) {
		fprintf(stderr, "failed to allocate netlink message\n");
		return 1;
	}

    if ( NULL == genlmsg_put(msg, 0, 0, nlstate.nl80211_id, 0,
	            0, NL80211_CMD_VENDOR, 0))
        goto nla_put_failure;

	devidx = if_nametoindex(argv[1]);

    if (devidx == 0) {
        if (errno == ENODEV)
            fprintf(stderr, "%s: %s\n", strerror(errno), argv[1]);

        goto nla_put_failure;
    }

	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, devidx);
	NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_ID, NXP_OUI);
	NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_SUBCMD, NXPWIFI_VENDOR_CMD_VHT_CFG);

	nested = nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA);
	count = sscanf(argv[3], "%d", &band);
	NLA_PUT_U32(msg, NXPWIFI_VHT_BAND, (uint32_t)band);
	count = sscanf(argv[4], "%d", &txrx);
	NLA_PUT_U32(msg, NXPWIFI_VHT_TXRX, (uint32_t)txrx);

	if (argc >= 7) {
		count = sscanf(argv[5], "%d", &bw);
		NLA_PUT_U32(msg, NXPWIFI_VHT_BW, (uint32_t)bw);
		count = sscanf(argv[6], "0x%x", &vhtcap);
		NLA_PUT_U32(msg, NXPWIFI_VHT_CAP, (uint32_t)vhtcap);

		if (argc == 8) {
		}

		if (argc == 9) {
			count = sscanf(argv[7], "0x%x", &txmcs);
			NLA_PUT_U32(msg, NXPWIFI_VHT_TXMCS, (uint32_t)txmcs);
			count = sscanf(argv[8], "0x%x", &rxmcs);
			NLA_PUT_U32(msg, NXPWIFI_VHT_RXMCS, (uint32_t)rxmcs);
		}
	} 
	
	if (argc == 5) {
		cb = nl_cb_alloc(NL_CB_DEFAULT);
		register_handler(print_vhtcfg_response, (void *) false);
		nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, valid_handler, NULL);
	} 

	nla_nest_end(msg, nested);

	count = nl_send_auto(nlstate.nl_sock, msg);

    if (count < 0) {
        fprintf(stderr, "failed to sent MSG: %s\n", strerror(count));
		goto nla_put_failure;
	}

	if (argc == 5)
		nl_recvmsgs(nlstate.nl_sock, cb);

	nlmsg_free(msg);

	return 0;
nla_put_failure:
	nlmsg_free(msg);

    return 1;
}


static void nl80211_cleanup(struct nl80211_state *state)
{
	nl_socket_free(state->nl_sock);
}

static int finish_handler(struct nl_msg *msg, void *arg)
{
	int *ret = arg;
	*ret = 0;
	return NL_SKIP;
}

static int ack_handler(struct nl_msg *msg, void *arg)
{
	int *ret = arg;
	*ret = 0;
	return NL_STOP;
}

static int (*registered_handler)(struct nl_msg *, void *);
static void *registered_handler_data;

static void register_handler(int (*handler)(struct nl_msg *, void *), void *data)
{
	registered_handler = handler;
	registered_handler_data = data;
}

static int valid_handler(struct nl_msg *msg, void *arg)
{
	if (registered_handler)
		return registered_handler(msg, registered_handler_data);

	return NL_OK;
}

static int nl80211_init(struct nl80211_state *state)
{
	int err;

	state->nl_sock = nl_socket_alloc();
	if (!state->nl_sock) {
		fprintf(stderr, "Failed to allocate netlink socket.\n");
		return -ENOMEM;
	}

	if (genl_connect(state->nl_sock)) {
		fprintf(stderr, "Failed to connect to generic netlink.\n");
		err = -ENOLINK;
		goto out_handle_destroy;
	}

	nl_socket_set_buffer_size(state->nl_sock, 8192, 8192);

	/* try to set NETLINK_EXT_ACK to 1, ignoring errors */
	err = 1;
	setsockopt(nl_socket_get_fd(state->nl_sock), SOL_NETLINK,
		   NETLINK_EXT_ACK, &err, sizeof(err));

	state->nl80211_id = genl_ctrl_resolve(state->nl_sock, "nl80211");
	if (state->nl80211_id < 0) {
		fprintf(stderr, "nl80211 not found.\n");
		err = -ENOENT;
		goto out_handle_destroy;
	}

	return 0;

 out_handle_destroy:
	nl_socket_free(state->nl_sock);
	return err;
}

/**
 *  @brief Display usage
 *
 *  @return       NA
 */
static void display_usage(void)
{
    __u32 i;
    for (i = 0; i < NELEMENTS(usage); i++)
        fprintf(stderr, "%s\n", usage[i]);
}

/**
 *  @brief Find and execute command
 *
 *  @param argc     Number of arguments
 *  @param argv     A pointer to arguments array
 *  @return         MLAN_STATUS_SUCCESS for success, otherwise failure
 */
static int
process_command(int argc, char *argv[])
{
    int i = 0, ret = 0;
    struct command_node *node = NULL;

    for (i = 0; i < (int)NELEMENTS(command_list); i++) {
        node = &command_list[i];
        if (!strcasecmp(node->name, argv[2])) {
            ret = node->handler(argc, argv);
            break;
        }
    }

    return ret;
}

/********************************************************
			Global Functions
********************************************************/
/**
 *  @brief Entry function for nxpwifiutl
 *  @param argc     Number of arguments
 *  @param argv     A pointer to arguments array
 *  @return         MLAN_STATUS_SUCCESS--success, otherwise--fail
 */
int main(int argc, char *argv[])
{
	int err, ret;

    if((argc == 2) && (strcmp(argv[1], "-v")==0)){
        fprintf(stdout, "NXP wifiutl version %s\n", NXPWIFIUTL_VER);
        exit(0);
    }
    if (argc < 3) {
        fprintf(stderr, "Invalid number of parameters!\n");
        display_usage();
        exit(1);
    }

	err = nl80211_init(&nlstate);
	if (err)
		return 1;

    ret = process_command(argc, argv);

    if (ret != 0) {
        //ret = process_generic(argc, argv);
        if (ret) {
            display_usage();
            err = 1;
        }
    }

	nl80211_cleanup(&nlstate);
    return err;
}
