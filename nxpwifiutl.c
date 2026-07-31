/*
 * nl80211 userspace tool
 *
 * Copyright 2025    Jeff Chen <jeff.chen_1@nxp.com>
 */
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
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
#include <ctype.h>

#define NXPWIFIUTL_VER "1.4"
/** Find number of elements */
#define NELEMENTS(x) (sizeof(x) / sizeof(x[0]))
#define NXP_OUI 0x006037
#define HS_OFFLOAD_ARP 0x1
#define HS_OFFLOAD_PING 0x2
#define HS_WAKEON_MDNS 0x4
#define NXPWIFI_MAX_ARGC 10
#define NXPWIFI_MAX_CMD_NAME_SIZE 32

#define HOST_ACT_GEN_GET 0
#define HOST_ACT_GEN_SET 1

enum nxpwifi_vendor_commands {
	NXPWIFI_VENDOR_CMD_HSCFG,
	NXPWIFI_VENDOR_CMD_SLEEPPD,
	NXPWIFI_VENDOR_CMD_CLOCKSYNC,
	NXPWIFI_VENDOR_CMD_HSOFFLOAD,
	NXPWIFI_VENDOR_CMD_INDRST,
	NXPWIFI_VENDOR_CMD_CSI_CFG,
	NXPWIFI_VENDOR_CMD_CHANNELSWITCH,
	NXPWIFI_VENDOR_CMD_ANTCFG,
	NXPWIFI_VENDOR_CMD_EDMAC_CFG,
	NXPWIFI_VENDOR_CMD_VHT_CFG,
	NXPWIFI_VENDOR_CMD_TXPOWER_LIMIT,
	NXPWIFI_VENDOR_CMD_TWT_CFG,
	NXPWIFI_VENDOR_CMD_DFS_TESTING
};

enum nxpwifiutl_rawdata_attrs {
	NXPWIFI_HSCFG = 1,
	NXPWIFI_SLEEPPD,
	NXPWIFI_CLKSYNC_CFG,
	NXPWIFI_INDRST_CFG,
	NXPWIFI_ATTR_MAC_ADDR,
	NXPWIFI_ATTR_CHSWITCH,
	NXPWIFI_ATTR_TXPWR_LIMIT,
	NXPWIFI_ATTR_MAX
};
/**
 * CSI vendor attribute enum (dedicated)
 */
enum nxpwifi_csi_attrs {
	NXPWIFI_ATTR_CSI_CONFIG = 1,
	NXPWIFI_ATTR_CSI_MAX
};
enum nxpwifi_antenna_attrs {
	NXPWIFI_ANTENNA_MODE = 1,
	NXPWIFI_SAD_EVAL_TIME,
	NXPWIFI_ANTENNA_ATTR_MAX
};
enum nxpwifi_edmac_attrs {
	NXPWIFI_EDMAC_CTRL_2G = 1,
	NXPWIFI_EDMAC_OFFSET_2G,
	NXPWIFI_EDMAC_CTRL_5G,
	NXPWIFI_EDMAC_OFFSET_5G,
	NXPWIFI_EDMAC_TXQ_LOCK,
	NXPWIFI_EDMAC_MAX
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

enum nxpwifi_twt_attrs {
	NXPWIFI_TWT_SETUP = 1,
	NXPWIFI_TWT_TEARDOWN,
	NXPWIFI_TWT_INFORMATION,
	NXPWIFI_TWT_BTWT_AP_CFG_GET,
	NXPWIFI_TWT_BTWT_AP_CFG_SET,
	NXPWIFI_TWT_MAX
};

enum nxpwifi_dfs_test_attrs {
	NXPWIFI_DFS_TEST_ATTR_UNSPEC,
	NXPWIFI_DFS_TEST_ATTR_USER_CAC_PD,
	NXPWIFI_DFS_TEST_ATTR_USER_NOP_PD,
	NXPWIFI_DFS_TEST_ATTR_NO_CHAN_CHANGE,
	NXPWIFI_DFS_TEST_ATTR_FIXED_CHAN_NUM,
	NXPWIFI_DFS_TEST_ATTR_CAC_RESTART
};

enum nxpwifi_hs_offload_attrs {
    NXPWIFI_HS_OFFLOAD_UNSPEC,
    NXPWIFI_HS_OFFLOAD_ACTION,
    NXPWIFI_HS_OFFLOAD_FLAGS,

    __NXPWIFI_HS_OFFLOAD_AFTER_LAST,
    NXPWIFI_HS_OFFLOAD_NUM =
        __NXPWIFI_HS_OFFLOAD_AFTER_LAST,
    NXPWIFI_HS_OFFLOAD_MAX =
        __NXPWIFI_HS_OFFLOAD_AFTER_LAST - 1
};

enum nxpwifi_host_cmds {
	NXPWIFI_CMD_ED_CTRL = 0x0130,
	NXPWIFI_CMD_CH_TRPC = 0x00FB
};
struct nl80211_state {
	struct nl_sock *nl_sock;
	int nl80211_id;
};
struct command_node {
	char *name;
	int (*handler)(int, char **);
};

struct nxpwifiutl_hs_cfg {
	unsigned char action;
	unsigned int conditions;
	unsigned int gpio;
	unsigned int gap;
} __attribute__((packed));

struct nxpwifiutl_sleeppd_cfg {
	uint8_t action;
	uint16_t sleeppd;
} __attribute__((packed));

struct nxpwifiutl_hs_offload {
	uint8_t action;
	uint8_t offload;
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

struct nxpwifiutl_iehdr {
	uint16_t type;
	uint16_t len;
} __attribute__((packed));

struct nxpwifiutl_mod_group {
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

#define CSI_FILTER_MAX 16
#define CSI_FILTER_SIZE 9

struct nxpwifiutl_csi_filter {
	uint8_t mac_addr[6];
	uint8_t pkt_type;
	uint8_t subtype;
	uint8_t flags;
} __attribute__((packed));

struct nxpwifiutl_csi_cfg {
	uint16_t csi_enable;
	uint8_t head_id[4];
	uint8_t tail_id[4];
	uint8_t csi_filter_cnt;
	uint8_t chip_id;
	struct nxpwifiutl_csi_filter csi_filter[CSI_FILTER_MAX];
} __attribute__((packed));

struct nxpwifiutl_gpio_tsf_latch {
	uint8_t mode;
	uint8_t role;
	uint8_t pin;
	uint8_t level;
	uint16_t width;
} __attribute__((packed));

struct nxpwifiutl_ireset_cfg {
	uint8_t ir_mode;
	uint8_t gpio_pin;
} __attribute__((packed));

 /* userspace payload (must match vendor side struct) */
struct nxpwifiutl_twt_setup {
	uint8_t implicit;
	uint8_t announced;
	uint8_t trigger_enabled;
	uint8_t twt_info_disabled;
	uint8_t negotiation_type;
	uint8_t twt_wakeup_duration;
	uint8_t flow_identifier;
	uint8_t hard_constraint;
	uint8_t twt_exponent;
	uint16_t twt_mantissa;
	uint8_t twt_request;
	uint16_t bcn_miss_threshold;
} __attribute__((packed));

struct nxpwifiutl_twt_teardown {
	uint8_t negotiation_type;
	uint8_t flow_identifier;
	uint8_t teardown_all_twt; /* 1: all, 0: only selected flow */
} __attribute__((packed));

/* ===== BTWT AP config（userspace mirror driver） ===== */
#define BTWT_AGREEMENT_MAX 5
struct nxpwifiutl_btwt_set {
	uint8_t btwt_id;
	uint16_t ap_bcast_mantissa; /* LE16 on the wire */
	uint8_t ap_bcast_exponent;
	uint8_t nominalwake;
} __attribute__((packed));

struct nxpwifiutl_twt_information {
	uint8_t flow_identifier;
	uint32_t suspend_duration; /* ms; 0 = suspend forever */
} __attribute__((packed));

struct nxpwifiutl_btwt_ap_config {
	uint8_t ap_bcast_bet_sta_wait;
	uint16_t ap_bcast_offset; /* LE16 on the wire */
	uint8_t bcast_twtli;
	uint8_t count; /* number of valid entries in btwt_sets */
} __attribute__((packed));

/* Request for BTWT AP config GET (mirror kernel vendor req) */
struct nxpwifiutl_btwt_ap_cfg_req {
	uint8_t ap_bcast_bet_sta_wait;
	uint16_t ap_bcast_offset; /* LE16 on the wire */
	uint8_t bcast_twtli;
	uint8_t count; /* 1..5 */
} __attribute__((packed));

/* Request for BTWT AP config SET */
struct nxpwifiutl_btwt_ap_cfg_set {
	uint8_t ap_bcast_bet_sta_wait;
	uint16_t ap_bcast_offset; /* LE16 on the wire */
	uint8_t bcast_twtli;
	uint8_t count; /* 1..BTWT_AGREEMENT_MAX */
} __attribute__((packed));

struct nxpwifiutl_hs_offload hsoffload = {0};
static struct nl80211_state nlstate;
static void register_handler(int (*handler)(struct nl_msg *, void *),
			     void *data);
static int valid_handler(struct nl_msg *msg, void *arg);
static int print_hscfg_response(struct nl_msg *msg, void *arg);
static int print_sleeppd_response(struct nl_msg *msg, void *arg);
static int print_btwt_ap_config_response(struct nl_msg *msg, void *arg);
static void dump_vendor_msg_attrs(struct nl_msg *msg);
static int process_hscfg(int argc, char *argv[]);
static int process_sleeppd(int argc, char *argv[]);
static int process_hsoffload(int argc, char *argv[]);
/* dump flag & helpers */
static bool g_dump_nlmsg = false;
static int send_msg(struct nl_msg *msg);
static void parse_dump_arg(int *argc, char *argv[]);

static int process_channel_switch(int argc, char *argv[]);
static int process_antenna_cfg(int argc, char *argv[]);
static int process_edmac_cfg(int argc, char *argv[]);
static int process_hostcmd(int argc, char *argv[]);
static char *nxpwifi_config_get_line(FILE *fp, char *str, int size,
				     int *lineno);
static int process_vht_cfg(int argc, char *argv[]);
static int process_csi_cfg(int argc, char *argv[]);
static int process_clocksync(int argc, char *argv[]);
static int process_irst(int argc, char *argv[]);
static int process_twt_cfg(int argc, char *argv[]);
static int process_twt_teardown(int argc, char *argv[]);
static int process_twt_information(int argc, char *argv[]);
static int process_twt_conf(int argc, char *argv[]);
static int send_twt_setup_msg(const char *ifname, const void *setup);
static int send_twt_teardown_msg(const char *ifname, const void *teardown);
static int send_twt_information_msg(const char *ifname, const void *info);
static int send_btwt_ap_config_get_msg(const char *ifname, const void *req);
static int send_btwt_ap_config_set_msg(const char *ifname, const void *req,
				       size_t len);
static int parse_twt_conf(const char *filename,
			  struct nxpwifiutl_twt_setup *setup,
			  struct nxpwifiutl_twt_teardown *teardown);
static int parse_twt_section(const char *filename, const char *section,
			     struct nxpwifiutl_twt_setup *s,
			     struct nxpwifiutl_twt_teardown *td,
			     struct nxpwifiutl_twt_information *inf);
static int process_dfstesting(int argc, char *argv[]);

struct command_node command_list[] = {
    {"hscfg", process_hscfg},
    {"sleeppd", process_sleeppd},
    {"hsoffload", process_hsoffload},
    {"channel_switch", process_channel_switch},
    {"antcfg", process_antenna_cfg},
    {"edmac_cfg", process_edmac_cfg},
    {"hostcmd", process_hostcmd},
    {"vhtcfg", process_vht_cfg},
    {"csi", process_csi_cfg},
    {"clocksync", process_clocksync},
    {"indrstcfg", process_irst},
    {"twt", process_twt_cfg},
    {"twt_teardown", process_twt_teardown},
    {"twt_information", process_twt_information},
    {"twt_conf", process_twt_conf},
    {"dfstesting", process_dfstesting},
};

static struct nla_policy antenna_policy[NXPWIFI_ANTENNA_ATTR_MAX + 1] = {
    [NXPWIFI_ANTENNA_MODE] = {.type = NLA_U16},
    [NXPWIFI_SAD_EVAL_TIME] = {.type = NLA_U16},
};

static char *usage[] = {
    "Usage:",
    " nxpwifiutl <ifname> <cmd> [args...]",
    " where:",
    " ifname : wireless network interface name, such as mlanX or uapX",
    " cmd : one of the following commands",
    " hscfg : Host sleep configuration",
    " sleeppd : Sleep period configuration",
    " hsoffload : Auto ARP / Ping / Wake-on-mDNS offload",
    " channel_switch : Channel switch configuration",
    " antcfg : Antenna configuration",
    " vhtcfg : VHT (802.11ac) IE configuration",
    " dfstesting : DFS testing configuration (GET/SET)",
    " Examples:",
    " nxpwifiutl mlan0 vhtcfg 2 1",
    " -> Get current VHT configuration in 5GHz for STA",
    " nxpwifiutl mlan0 vhtcfg 2 2 0 0x000001f0 0xfff5 0xfffa",
    " -> Set VHT capabilities with MCS map for STA",
    " nxpwifiutl mlan0 dfstesting",
    " -> GET: dump current DFS testing parameters (user_cac_pd / user_nop_pd / no_chan_change / fixed_chan_num / cac_restart)",
    " nxpwifiutl mlan0 dfstesting 60 0 0 0 1",
    " -> SET: CAC=60s, keep default NOP, allow channel change, no fixed channel, auto restart CAC",
    " nxpwifiutl mlan0 dfstesting 0 120 0 64 0",
    " -> SET: use default CAC, NOP=120s, change to fixed channel 64 on radar, no auto restart",
    " csi : CSI (Channel State Information) configuration",
    " clocksync : GPIO TSF latch configuration",
    " indrstcfg : Independent reset configuration",
    " twt : 802.11ax TWT Setup (12 params)",
    "   nxpwifiutl <ifname> twt <implicit> <announced> <trigger_enabled> "
    "<twt_info_disabled> "
    "<negotiation_type> <twt_wakeup_duration> <flow_identifier> "
    "<hard_constraint> <twt_exponent> "
    "<twt_mantissa> <twt_request> <bcn_miss_threshold>",
    "   or from conf section:",
    "   nxpwifiutl <ifname> twt <conf_file> "
     "<twt_setup|twt_teardown|twt_information>",
    "     e.g. nxpwifiutl mlan0 twt twt.conf twt_setup",
    "          nxpwifiutl mlan0 twt twt.conf twt_teardown",
    "          nxpwifiutl mlan0 twt twt.conf twt_information",
    " twt_teardown : 802.11ax TWT Teardown",
    "   nxpwifiutl <ifname> twt_teardown <negotiation_type> <flow_id> "
    "<teardown_all>",
    " twt_conf : load TWT setup/teardown from conf file",
    "",
    " CSI command usage:",
    "   nxpwifiutl <ifname> csi <0|1>",
    "     -> 1: enable CSI with default/last config; 0: disable CSI",
    "   nxpwifiutl <ifname> csi <config_file>",
    "     -> Load CSI config from file (see format below)",
    "   (You can append --dump/dump=1 to print outgoing nl80211 vendor "
    "message)",
    " CSI config file format (INI-like, byte-hex lists):",
    " Examples:",
    "   nxpwifiutl mlan0 csi 1",
    "   nxpwifiutl mlan0 csi csi.conf",
    "",
    " hostcmd : Send raw hostcmd from config file",
    " Examples:",
    " edmac configuration: Get current VHT",
    " ./nxpwifiutl mlan0 hostcmd ed_mac_ctrl_V2_nw61x.conf",
    " ed_mac_ctrl_v2_get",
    " ./nxpwifiutl mlan0 hostcmd txpwrlimit_cfg.conf",
    " txpwrlimit_2g_cfg_set",
    "",
    " Optional:",
    "   Append --dump | --no-dump | dump=1 | dump=0 after <cmd> to control "
    "printing of outgoing nl80211 vendor messages"};
#define PROPRIETARY_TLV_BASE_ID 0x0100
#define TLV_TYPE_CHAN_TRPC_CONFIG (PROPRIETARY_TLV_BASE_ID + 137)

/* Map nl80211 outer attributes to names */
static const char *nl80211_attr_name(uint16_t t)
{
	switch (t) {
	case NL80211_ATTR_IFINDEX:
		return "NL80211_ATTR_IFINDEX";
	case NL80211_ATTR_VENDOR_ID:
		return "NL80211_ATTR_VENDOR_ID";
	case NL80211_ATTR_VENDOR_SUBCMD:
		return "NL80211_ATTR_VENDOR_SUBCMD";
	case NL80211_ATTR_VENDOR_DATA:
		return "NL80211_ATTR_VENDOR_DATA (nested)";
	default:
		return NULL;
	}
}
/* Map vendor attributes to names */
static const char *nxpwifi_vendor_attr_name(uint16_t t)
{
	switch (t) {
	case NXPWIFI_HSCFG:
		return "NXPWIFI_HSCFG";
	case NXPWIFI_SLEEPPD:
		return "NXPWIFI_SLEEPPD";
	case NXPWIFI_CLKSYNC_CFG:
		return "NXPWIFI_CLKSYNC_CFG";
	case NXPWIFI_INDRST_CFG:
		return "NXPWIFI_INDRST_CFG";
	case NXPWIFI_ATTR_MAC_ADDR:
		return "NXPWIFI_ATTR_MAC_ADDR";
	case NXPWIFI_ATTR_CHSWITCH:
		return "NXPWIFI_ATTR_CHSWITCH";
	case NXPWIFI_ATTR_TXPWR_LIMIT:
		return "NXPWIFI_ATTR_TXPWR_LIMIT";
	default:
		return NULL;
	}
}
/* Map csi config attributes to names */
static const char *nxpwifi_csi_attr_name(uint16_t t)
{
	switch (t) {
	case NXPWIFI_ATTR_CSI_CONFIG:
		return "NXPWIFI_ATTR_CSI_CONFIG";
	default:
		return NULL;
	}
}
/* Print attribute info with flags */
static void print_attr_type_len(const struct nlattr *attr, const char *prefix,
				const char *name)
{
	uint16_t raw = attr->nla_type;
	uint16_t type = raw & NLA_TYPE_MASK;
	bool is_nested = raw & NLA_F_NESTED;
	bool is_netbyte = raw & NLA_F_NET_BYTEORDER;
	printf("%s type=%u len=%u", prefix, type, attr->nla_len);
	if (type == NL80211_ATTR_VENDOR_ID)
		printf(" vendor_id=0x%08x\n", nla_get_u32(attr));
	if (type == NL80211_ATTR_VENDOR_SUBCMD)
		printf(" subcmd=%u\n", nla_get_u32(attr));
	if (name)
		printf(" (%s)", name);
	if (is_nested || is_netbyte) {
		printf(" [flags:");
		if (is_nested)
			printf(" NESTED");
		if (is_netbyte)
			printf(" NET_BYTEORDER");
		printf("]");
	}
	printf("\n");
}
/* Dump nl80211 and vendor attributes */
static void dump_vendor_msg_attrs(struct nl_msg *msg)
{
	struct nlmsghdr *nlh = nlmsg_hdr(msg);
	struct genlmsghdr *ghdr = nlmsg_data(nlh);
	struct nlattr *attr;
	int rem;
	printf("---- Dump TX message (manual parse) ----\n");
	nla_for_each_attr(attr, genlmsg_attrdata(ghdr, 0),
			  genlmsg_attrlen(ghdr, 0), rem)
	{
		uint16_t type = nla_type(attr);
		const char *name = nl80211_attr_name(type);
		print_attr_type_len(attr, "nl80211", name);
		if (type == NL80211_ATTR_VENDOR_DATA) {
			struct nlattr *vattr;
			int vrem;
			nla_for_each_attr(vattr, nla_data(attr), nla_len(attr),
					  vrem)
			{
				uint16_t vtype = nla_type(vattr);
				const char *vname =
				    nxpwifi_csi_attr_name(vtype);
				print_attr_type_len(vattr, " vendor", vname);
			}
		}
	}
	printf("---- Dump TX message (nl_msg_dump) ----\n");
	nl_msg_dump(msg, stdout);
}

/* Wrapper for sending message, with optional dump */
static int send_msg(struct nl_msg *msg)
{
	if (g_dump_nlmsg && msg)
		dump_vendor_msg_attrs(msg);
	return nl_send_auto(nlstate.nl_sock, msg);
}

/* Parse optional dump flag placed after <ifname> <cmd> */
static void parse_dump_arg(int *argc, char *argv[])
{
	for (int i = 0; i < *argc; i++) {
		if (i < 3) /* only look at tokens after <ifname> <cmd> */
			continue;
		char *arg = argv[i];
		if (!strcmp(arg, "--dump")) {
			g_dump_nlmsg = true;
		} else if (!strcmp(arg, "--no-dump")) {
			g_dump_nlmsg = false;
		} else if (!strncmp(arg, "dump=", 5)) {
			g_dump_nlmsg = atoi(arg + 5) != 0;
		} else {
			continue;
		}
		/* remove this flag from argv to avoid breaking existing parsers
		 */
		for (int j = i; j < *argc - 1; j++)
			argv[j] = argv[j + 1];
		(*argc)--;
		i--;
	}
}

static uint32_t bytes_to_unit32(uint8_t *bytes)
{
	uint32_t thirty_two;
	thirty_two = bytes[0] | (uint32_t)bytes[1] << 8 |
	    (uint32_t)bytes[2] << 16 | (uint32_t)bytes[+3] << 24;
	return thirty_two;
}
static int parse_argument(char *argstr, char *args, int *arg)
{
	int ret = 0;
	if (strstr(argstr, args)) {
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
	attr = nla_find(genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0),
			NL80211_ATTR_VENDOR_DATA);
	if (!attr) {
		fprintf(stderr, "vendor data attribute missing!\n");
		return NL_SKIP;
	}
	data = (uint8_t *)nla_data(attr);
	len = nla_len(attr);
	conditions = bytes_to_unit32(data + 4);
	gpio = bytes_to_unit32(data + 8);
	gap = bytes_to_unit32(data + 12);
	fprintf(stdout,
		"host sleep configuration. conditions: %x gpio: %d gap: %d\n",
		conditions, gpio, gap);
	return NL_OK;
}
static int print_sleeppd_response(struct nl_msg *msg, void *arg)
{
	struct nlattr *attr;
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	uint8_t *data;
	int len;
	uint16_t sleep_pd;
	attr = nla_find(genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0),
			NL80211_ATTR_VENDOR_DATA);
	if (!attr) {
		fprintf(stderr, "vendor data attribute missing!\n");
		return NL_SKIP;
	}
	data = (uint8_t *)nla_data(attr);
	len = nla_len(attr);
	sleep_pd = (*(data + 5) << 8) + *(data + 4);
	fprintf(stdout, "sleep period: %d\n", sleep_pd);
	return NL_OK;
}

static int print_hsoffload_response(struct nl_msg *msg, void *arg)
{
    struct nlattr *tb[NXPWIFI_HS_OFFLOAD_MAX + 1];
    struct nlattr *vendor_data;
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));

    vendor_data = nla_find(genlmsg_attrdata(gnlh, 0),
                   genlmsg_attrlen(gnlh, 0),
                   NL80211_ATTR_VENDOR_DATA);
    if (!vendor_data)
        return NL_SKIP;

    if (nla_parse(tb, NXPWIFI_HS_OFFLOAD_MAX,
              (struct nlattr *)nla_data(vendor_data),
              nla_len(vendor_data),
              NULL) < 0)
        return NL_SKIP;

    if (!tb[NXPWIFI_HS_OFFLOAD_FLAGS])
        return NL_SKIP;

    uint8_t flags = nla_get_u8(tb[NXPWIFI_HS_OFFLOAD_FLAGS]);

    printf("Auto-ARP: %s\n",
        (flags & HS_OFFLOAD_ARP) ? "enabled" : "disabled");
    printf("Auto-PING: %s\n",
        (flags & HS_OFFLOAD_PING) ? "enabled" : "disabled");
    printf("Wake-on-mDNS: %s\n",
        (flags & HS_WAKEON_MDNS) ? "enabled" : "disabled");

    return NL_OK;
}

static int print_antcfg_response(struct nl_msg *msg, void *arg)
{
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	struct nlattr *attr;
	struct nlattr *tb[NXPWIFI_ANTENNA_ATTR_MAX + 1];
	uint16_t ant_mode;
	attr = nla_find(genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0),
			NL80211_ATTR_VENDOR_DATA);
	if (!attr) {
		fprintf(stderr, "vendor data attribute missing!\n");
		return NL_SKIP;
	}
	if (nla_parse_nested(tb, NXPWIFI_ANTENNA_ATTR_MAX, attr, NULL) < 0) {
		fprintf(stderr, "failed to parse nested antenna attributes\n");
		return NL_SKIP;
	}
	if (tb[NXPWIFI_ANTENNA_MODE]) {
		ant_mode = nla_get_u16(tb[NXPWIFI_ANTENNA_MODE]);
		printf("antenna mode: %u\n", ant_mode);
	} else {
		fprintf(stderr, "antenna mode attribute missing!\n");
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
	attr = nla_find(genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0),
			NL80211_ATTR_VENDOR_DATA);
	if (!attr) {
		fprintf(stderr, "vendor data attribute missing!\n");
		return NL_SKIP;
	}
	nla_parse_nested(tb_vendor, NXPWIFI_VHT_MAX, attr, NULL);
	if (tb_vendor[NXPWIFI_VHT_BAND]) {
		band = (uint32_t *)nla_data(tb_vendor[NXPWIFI_VHT_BAND]);
		fprintf(stdout, "band: %d\n", *band);
	} else {
		fprintf(stderr, "band attribute missing!\n");
	}
	if (tb_vendor[NXPWIFI_VHT_TXRX]) {
		txrx = (uint32_t *)nla_data(tb_vendor[NXPWIFI_VHT_TXRX]);
		fprintf(stdout, "txrx: %d\n", *txrx);
	} else {
		fprintf(stderr, "txrx attribute missing!\n");
	}
	if (tb_vendor[NXPWIFI_VHT_BW]) {
		bw = (uint32_t *)nla_data(tb_vendor[NXPWIFI_VHT_BW]);
		fprintf(stdout, "bw: %0x\n", *bw);
	} else {
		fprintf(stderr, "bw attribute missing!\n");
	}
	if (tb_vendor[NXPWIFI_VHT_CAP]) {
		vhtcap = (uint32_t *)nla_data(tb_vendor[NXPWIFI_VHT_CAP]);
		fprintf(stdout, "vhtcap: %0x\n", *vhtcap);
	} else {
		fprintf(stderr, "vhtcap attribute missing!\n");
	}
	if (tb_vendor[NXPWIFI_VHT_TXMCS]) {
		txmcs = (uint32_t *)nla_data(tb_vendor[NXPWIFI_VHT_TXMCS]);
		fprintf(stdout, "TX MCS map: %0x\n", *txmcs);
	} else {
		fprintf(stderr, "txmcs attribute missing!\n");
	}
	if (tb_vendor[NXPWIFI_VHT_RXMCS]) {
		rxmcs = (uint32_t *)nla_data(tb_vendor[NXPWIFI_VHT_RXMCS]);
		fprintf(stdout, "RX MCS map: %0x\n", *rxmcs);
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
	attr = nla_find(genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0),
			NL80211_ATTR_VENDOR_DATA);
	if (!attr) {
		fprintf(stderr, "vendor data attribute missing!\n");
		return NL_SKIP;
	}
	nla_parse_nested(tb_vendor, NXPWIFI_EDMAC_MAX, attr, NULL);
	if (tb_vendor[NXPWIFI_EDMAC_CTRL_2G]) {
		attr_data =
		    (uint16_t *)nla_data(tb_vendor[NXPWIFI_EDMAC_CTRL_2G]);
		fprintf(stdout, "edmac_2G:0x%02x\n", *attr_data);
	}
	if (tb_vendor[NXPWIFI_EDMAC_OFFSET_2G]) {
		attr_data =
		    (uint16_t *)nla_data(tb_vendor[NXPWIFI_EDMAC_OFFSET_2G]);
		fprintf(stdout, "offset_2G:0x%02x\n", *attr_data);
	}
	if (tb_vendor[NXPWIFI_EDMAC_CTRL_5G]) {
		attr_data =
		    (uint16_t *)nla_data(tb_vendor[NXPWIFI_EDMAC_CTRL_5G]);
		fprintf(stdout, "edmac_5G:0x%02x\n", *attr_data);
	}
	if (tb_vendor[NXPWIFI_EDMAC_OFFSET_5G]) {
		attr_data =
		    (uint16_t *)nla_data(tb_vendor[NXPWIFI_EDMAC_OFFSET_5G]);
		fprintf(stdout, "offset_5G:0x%02x\n", *attr_data);
	}
	if (tb_vendor[NXPWIFI_EDMAC_TXQ_LOCK]) {
		txq_lock =
		    (uint32_t *)nla_data(tb_vendor[NXPWIFI_EDMAC_TXQ_LOCK]);
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
	attr = nla_find(genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0),
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
	len = nla_len(tb_vendor[NXPWIFI_ATTR_TXPWR_LIMIT]);

	chtrpc_tlv = (struct nxpwifiutl_chtrpc_cfg *)attr_data;
	/* Process result */
	printf("---------------------------------------------------------------"
	       "-----------\n");
	printf("Get txpwrlimit: sub_band=0x%x len=%d\n",
	       *((uint16_t *)attr_data + 1),
	       nla_len(tb_vendor[NXPWIFI_ATTR_TXPWR_LIMIT]));
	left_len = nla_len(tb_vendor[NXPWIFI_ATTR_TXPWR_LIMIT]) - 4;
	while (left_len >= (int)sizeof(struct nxpwifiutl_iehdr)) {
		switch (le16toh(chtrpc_tlv->hdr.type)) {
		case TLV_TYPE_CHAN_TRPC_CONFIG:
			printf("StartFreq: %d\n",
			       le16toh(chtrpc_tlv->start_freq));
			printf("ChanNum: %d\n", chtrpc_tlv->chan_num);
			mod_num = (chtrpc_tlv->hdr.len - 4) /
			    sizeof(struct nxpwifiutl_mod_group);
			printf("Pwr:");
			for (i = 0; i < mod_num; i++) {
				if (i == (mod_num - 1))
					printf(
					    "%d,%d",
					    chtrpc_tlv->mod_group[i].mod_group,
					    chtrpc_tlv->mod_group[i].power);
				else
					printf(
					    "%d,%d,",
					    chtrpc_tlv->mod_group[i].mod_group,
					    chtrpc_tlv->mod_group[i].power);
			}
			printf("\n \n");
			break;
		default:
			break;
		}
		left_len -=
		    (chtrpc_tlv->hdr.len + sizeof(struct nxpwifiutl_iehdr));
		chtrpc_tlv =
		    (struct nxpwifiutl_chtrpc_cfg
			 *)((uint8_t *)chtrpc_tlv + chtrpc_tlv->hdr.len +
			    sizeof(struct nxpwifiutl_iehdr));
	}
	return NL_OK;
}

static int send_twt_information_msg(const char *ifname, const void *info)
{
	struct nl_msg *msg = nlmsg_alloc();
	struct nlattr *nested;
	int ifindex, sent, ack;
	if (!msg)
	{
		fprintf(stderr, "alloc netlink msg failed\n");
		return 1;
	}
	genlmsg_put(msg, 0, 0, nlstate.nl80211_id, 0, 0, NL80211_CMD_VENDOR,
		     0);
	ifindex = if_nametoindex(ifname);
	if (ifindex == 0)
	{
		fprintf(stderr, "%s: %s\n", strerror(errno), ifname);
		nlmsg_free(msg);
		return 1;
	}
	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, ifindex);
	NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_ID, NXP_OUI);
	NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_SUBCMD,
		     NXPWIFI_VENDOR_CMD_TWT_CFG);
	nested = nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA);
	if (!nested)
		goto nla_put_failure;
	NLA_PUT(msg, NXPWIFI_TWT_INFORMATION,
		 +sizeof(struct nxpwifiutl_twt_information), info);
	nla_nest_end(msg, nested);
	sent = send_msg(msg);
	if (sent < 0)
	{
		fprintf(stderr, "send twt information failed: %s\n",
			strerror(sent));
		goto nla_put_failure;
	}
	ack = nl_wait_for_ack(nlstate.nl_sock);
	if (ack < 0)
	{
		fprintf(stderr, "twt information ack error: %s\n",
			nl_geterror(ack));
		goto nla_put_failure;
	}
	nlmsg_free(msg);
	return 0;
nla_put_failure :
	nlmsg_free(msg);
	return 1;
}

/* ===== 解析 & 列印 BTWT AP config 的回覆 ===== */
static int print_btwt_ap_config_response(struct nl_msg *msg, void *arg)
{
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	struct nlattr *attr;
	uint8_t *data;
	int len, i, n;
	struct nxpwifiutl_btwt_ap_config cfg;
	attr = nla_find(genlmsg_attrdata(gnlh, 0), +genlmsg_attrlen(gnlh, 0),
			NL80211_ATTR_VENDOR_DATA);
	if (!attr) {
		fprintf(stderr, "vendor data attribute missing!\n");
		return NL_SKIP;
	}
	data = (uint8_t *)nla_data(attr);
	len = nla_len(attr);
	if (len < (int)sizeof(cfg)) {
		fprintf(stderr,
			"BTWT AP config payload too short: %d (need >= %zu)\n",
			len, sizeof(cfg));
		return NL_SKIP;
	}
	/* 直接複製一份到本地端結構，便於端序轉換與列印 */
	memcpy(&cfg, data, sizeof(cfg));
	printf("BTWT AP config:\n");
	printf("  ap_bcast_bet_sta_wait: %u\n", cfg.ap_bcast_bet_sta_wait);
	printf("  Ap_Bcast_Offset:       %u\n", le16toh(cfg.ap_bcast_offset));
	printf("  bcastTWTLI:            %u\n", cfg.bcast_twtli);
	printf("  count:                 %u\n", cfg.count);
	n = cfg.count;
	if (n > BTWT_AGREEMENT_MAX)
		n = BTWT_AGREEMENT_MAX;
	for (i = 0; i < n; i++) {
		const struct nxpwifiutl_btwt_set *s =
		    (struct nxpwifiutl_btwt_set *)&cfg + 1;
		printf("  [Set %d]\n", i);
		printf("    btwtId:            %u\n", s->btwt_id);
		printf("    Ap_Bcast_Mantissa: %u\n",
		       le16toh(s->ap_bcast_mantissa));
		printf("    Ap_Bcast_Exponent: %u\n", s->ap_bcast_exponent);
		printf("    nominalwake:       %u\n", s->nominalwake);
	}
	return NL_OK;
}


/* Holds parsed dfstesting values from a vendor reply */
struct dfstesting_resp {
    bool have_cac_pd;
    bool have_nop_pd;
    bool have_no_change;
    bool have_fixed_chan;
    bool have_cac_restart;

    uint32_t user_cac_pd;     /* seconds */
    uint32_t user_nop_pd;     /* seconds */
    uint8_t  no_chan_change;  /* 0/1 */
    uint32_t fixed_chan_num;  /* 0 or 1..255 */
    uint8_t  cac_restart;     /* 0/1 */
};

/* libnl callback to parse the vendor reply for dfstesting */
static int dfstesting_reply_cb(struct nl_msg *msg, void *arg)
{
    struct dfstesting_resp *r = (struct dfstesting_resp *)arg;
    struct nlmsghdr *nlh = nlmsg_hdr(msg);
    struct genlmsghdr *ghdr = (struct genlmsghdr *)nlmsg_data(nlh);
    struct nlattr *attrs[NL80211_ATTR_MAX + 1];

    if (nla_parse(attrs, NL80211_ATTR_MAX,
                  genlmsg_attrdata(ghdr, 0),
                  genlmsg_attrlen(ghdr, 0),
                  NULL)) {
        return NL_STOP;
    }

    if (!attrs[NL80211_ATTR_VENDOR_DATA])
        return NL_STOP;

    /* Parse nested vendor data. We assume vendor attr IDs < 256. */
    struct nlattr *tb[256] = {0};
    struct nlattr *vd = attrs[NL80211_ATTR_VENDOR_DATA];

    if (nla_parse(tb, 255, nla_data(vd), nla_len(vd), NULL))
        return NL_STOP;

    if (tb[NXPWIFI_DFS_TEST_ATTR_USER_CAC_PD]) {
        r->user_cac_pd = nla_get_u32(tb[NXPWIFI_DFS_TEST_ATTR_USER_CAC_PD]);
        r->have_cac_pd = true;
    }
    if (tb[NXPWIFI_DFS_TEST_ATTR_USER_NOP_PD]) {
        r->user_nop_pd = nla_get_u32(tb[NXPWIFI_DFS_TEST_ATTR_USER_NOP_PD]);
        r->have_nop_pd = true;
    }
    if (tb[NXPWIFI_DFS_TEST_ATTR_NO_CHAN_CHANGE]) {
        r->no_chan_change = nla_get_u8(tb[NXPWIFI_DFS_TEST_ATTR_NO_CHAN_CHANGE]);
        r->have_no_change = true;
    }
    if (tb[NXPWIFI_DFS_TEST_ATTR_FIXED_CHAN_NUM]) {
        r->fixed_chan_num = nla_get_u32(tb[NXPWIFI_DFS_TEST_ATTR_FIXED_CHAN_NUM]);
        r->have_fixed_chan = true;
    }
    if (tb[NXPWIFI_DFS_TEST_ATTR_CAC_RESTART]) {
        r->cac_restart = nla_get_u8(tb[NXPWIFI_DFS_TEST_ATTR_CAC_RESTART]);
        r->have_cac_restart = true;
    }

    return NL_OK; /* continue if there are more messages */
}

/**
 * @brief Process hscfg configuration
 * @param argc Number of arguments
 * @param argv A pointer to arguments array
 * @return 0--success, otherwise--fail
 */
static int process_hscfg(int argc, char *argv[])
{
	__u8 *buffer = NULL;
	struct nl_msg *msg;
	signed long long devidx = 0;
	unsigned char action;
	struct nxpwifiutl_hs_cfg hscfg = {0};
	struct nl_cb *cb;
	msg = nlmsg_alloc();
	if (!msg) {
		fprintf(stderr, "failed to allocate netlink message\n");
		return 1;
	}
	if (NULL ==
	    genlmsg_put(msg, 0, 0, nlstate.nl80211_id, 0, 0, NL80211_CMD_VENDOR,
			0))
		goto nla_put_failure;
	devidx = if_nametoindex(argv[1]);
	if (devidx == 0) {
		if (errno == ENODEV)
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
		cb = nl_cb_alloc(NL_CB_DEFAULT);
		hscfg.action = 0;
		register_handler(print_hscfg_response, (void *)false);
		nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, valid_handler, NULL);
	} else
		hscfg.action = 1;
	NLA_PUT(msg, NL80211_ATTR_VENDOR_DATA, sizeof(hscfg), &hscfg);
	send_msg(msg);
	if (hscfg.action == 0) {
		nl_recvmsgs(nlstate.nl_sock, cb);
		nl_cb_put(cb);
	}
	return 0;
nla_put_failure:
	return 1;
}
/**
 * @brief Process sleep period configuration for PPS/uAPSD.
 * @param argc Number of arguments
 * @param argv A pointer to arguments array
 * @return 0--success, otherwise--fail
 */
static int process_sleeppd(int argc, char *argv[])
{
	__u8 *buffer = NULL;
	struct nl_msg *msg;
	signed long long devidx = 0;
	unsigned char action;
	struct nxpwifiutl_sleeppd_cfg sleepd_cfg = {0};
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
	if (NULL ==
	    genlmsg_put(msg, 0, 0, nlstate.nl80211_id, 0, 0, NL80211_CMD_VENDOR,
			0))
		goto nla_put_failure;
	devidx = if_nametoindex(argv[1]);
	if (devidx == 0) {
		if (errno == ENODEV)
			fprintf(stderr, "No interface found with given name\n");
		goto nla_put_failure;
	}
	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, devidx);
	NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_ID, NXP_OUI);
	NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_SUBCMD,
		    NXPWIFI_VENDOR_CMD_SLEEPPD);
	if (argc == 3) {
		cb = nl_cb_alloc(NL_CB_DEFAULT);
		sleepd_cfg.action = 0;
		register_handler(print_sleeppd_response, (void *)false);
		nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, valid_handler, NULL);
	} else {
		sleepd_cfg.action = 1;
		sscanf(argv[3], "%hu", &sleepd_cfg.sleeppd);
	}
	NLA_PUT(msg, NL80211_ATTR_VENDOR_DATA, sizeof(sleepd_cfg), &sleepd_cfg);
	send_msg(msg);
	if (sleepd_cfg.action == 0) {
		nl_recvmsgs(nlstate.nl_sock, cb);
		nl_cb_put(cb);
	}
	return 0;
nla_put_failure:
	return 1;
}

static int process_hsoffload(int argc, char *argv[])
{
    struct nl_msg *msg = NULL;
    struct nl_cb *cb = NULL;
    struct nlattr *data;
    signed long long devidx = 0;
    int auto_arp = 0, auto_ping = 0, wake_on_mdns = 0;
    __u8 flags = 0;
    int ret = 1;

    if ((argc > 6) || (argc < 3)) {
        fprintf(stderr, "wrong argument numbers.\n");
        return 1;
    }

    msg = nlmsg_alloc();
    if (!msg) {
        fprintf(stderr, "failed to allocate netlink message\n");
        return 1;
    }

    if (!genlmsg_put(msg, 0, 0, nlstate.nl80211_id, 0, 0,
                     NL80211_CMD_VENDOR, 0)) {
        fprintf(stderr, "genlmsg_put failed\n");
        goto nla_put_failure;
    }

    devidx = if_nametoindex(argv[1]);
    if (devidx == 0) {
        fprintf(stderr, "%s: %s\n", strerror(errno), argv[1]);
        goto nla_put_failure;
    }

    NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, devidx);
    NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_ID, NXP_OUI);
    NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_SUBCMD,
                NXPWIFI_VENDOR_CMD_HSOFFLOAD);

    data = nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA);
    if (!data)
        goto out;

    /* ===================== */
    /* GET (query) operation */
    /* ===================== */
    if (argc == 3) {
        cb = nl_cb_alloc(NL_CB_DEFAULT);
        if (!cb) {
            fprintf(stderr, "nl_cb_alloc failed\n");
            goto out;
        }

        register_handler(print_hsoffload_response, (void *)false);
        nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, valid_handler, NULL);

		NLA_PUT_U8(msg, NXPWIFI_HS_OFFLOAD_ACTION, HOST_ACT_GEN_GET);
    } else {

        /* ===================== */
        /* SET operation         */
        /* ===================== */

        while (argc >= 4) {
            if (parse_argument(argv[argc - 1],
                               "autoarp=", &auto_arp)) {
                if (auto_arp)
                    flags |= HS_OFFLOAD_ARP;
				printf("autoarp set: %d\n", auto_arp);
            }

            if (parse_argument(argv[argc - 1],
                               "autoping=", &auto_ping)) {
                if (auto_ping)
                    flags |= HS_OFFLOAD_PING;
            }

            if (parse_argument(argv[argc - 1],
                               "wakeonmdns=", &wake_on_mdns)) {
                if (wake_on_mdns)
                    flags |= HS_WAKEON_MDNS;
            }

            argc--;
        }

        NLA_PUT_U8(msg, NXPWIFI_HS_OFFLOAD_ACTION, HOST_ACT_GEN_SET);
        NLA_PUT_U8(msg, NXPWIFI_HS_OFFLOAD_FLAGS, flags);
	}

    nla_nest_end(msg, data);

    /* send message */
    send_msg(msg);

    /* receive response */
    if (argc == 3 && cb) {
        nl_recvmsgs(nlstate.nl_sock, cb);
        nl_cb_put(cb);
    }

    ret = 0;
    goto out;

nla_put_failure:
    fprintf(stderr, "NLA put failed\n");

out:
    if (msg)
        nlmsg_free(msg);
    return ret;
}

/**
 * @brief Process the configuration for channel switch.
 * @param argc Number of arguments
 * @param argv A pointer to arguments array
 * @return 0--success, otherwise--fail
 */
static int process_channel_switch(int argc, char *argv[])
{
	__u8 *buffer = NULL;
	struct nl_msg *msg = NULL;
	struct nlattr *nested = NULL;
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
	if (NULL ==
	    genlmsg_put(msg, 0, 0, nlstate.nl80211_id, 0, 0, NL80211_CMD_VENDOR,
			0))
		goto nla_put_failure;
	devidx = if_nametoindex(argv[1]);
	if (devidx == 0) {
		if (errno == ENODEV)
			fprintf(stderr, "%s: %s\n", strerror(errno), argv[1]);
		goto nla_put_failure;
	}
	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, devidx);
	NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_ID, NXP_OUI);
	NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_SUBCMD,
		    NXPWIFI_VENDOR_CMD_CHANNELSWITCH);
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
	nested = nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA);
	if (!nested)
		goto nla_put_failure;
	NLA_PUT(msg, NXPWIFI_ATTR_CHSWITCH, sizeof(chsw_cfg), &chsw_cfg);
	nla_nest_end(msg, nested);
	count = send_msg(msg);
	if (count < 0) {
		fprintf(stderr, "failed to sent MSG: %s\n", strerror(count));
		goto nla_put_failure;
	}
	nlmsg_free(msg);
	return 0;
nla_put_failure:
	nlmsg_free(msg);
	return 1;
}
/**
 * @brief Process the configuration for channel switch.
 * @param argc Number of arguments
 * @param argv A pointer to arguments array
 * @return 0--success, otherwise--fail
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
	if (NULL ==
	    genlmsg_put(msg, 0, 0, nlstate.nl80211_id, 0, 0, NL80211_CMD_VENDOR,
			0))
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
		NLA_PUT_U16(nested, NXPWIFI_ANTENNA_MODE, (uint16_t)ant_mode);
		if (argc > 4) {
			count = sscanf(argv[4], "%u", &eval_time);
			NLA_PUT_U16(nested, NXPWIFI_SAD_EVAL_TIME,
				    (uint16_t)eval_time);
		}
		nla_put_nested(msg, NL80211_ATTR_VENDOR_DATA, nested);
	} else {
		cb = nl_cb_alloc(NL_CB_DEFAULT);
		register_handler(print_antcfg_response, (void *)false);
		nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, valid_handler, NULL);
	}
	count = send_msg(msg);
	if (count < 0) {
		fprintf(stderr, "failed to sent MSG: %s\n", strerror(count));
		goto nla_put_failure;
	}
	if (argc == 3) {
		nl_recvmsgs(nlstate.nl_sock, cb);
		nl_cb_put(cb);
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
 * @brief Process the configuration for EDMAC.
 * @param argc Number of arguments
 * @param argv A pointer to arguments array
 * @return 0--success, otherwise--fail
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
	} else if ((argc != 8) && (argc != 3)) {
		fprintf(stderr, "wrong argument numbers.\n");
		return 1;
	}
	msg = nlmsg_alloc();
	if (!msg) {
		fprintf(stderr, "failed to allocate netlink message\n");
		return 1;
	}
	if (NULL ==
	    genlmsg_put(msg, 0, 0, nlstate.nl80211_id, 0, 0, NL80211_CMD_VENDOR,
			0))
		goto nla_put_failure;
	devidx = if_nametoindex(argv[1]);
	if (devidx == 0) {
		if (errno == ENODEV)
			fprintf(stderr, "%s: %s\n", strerror(errno), argv[1]);
		goto nla_put_failure;
	}
	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, devidx);
	NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_ID, NXP_OUI);
	NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_SUBCMD,
		    NXPWIFI_VENDOR_CMD_EDMAC_CFG);
	if (argc == 8) {
		nested = nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA);
		count = sscanf(argv[3], "0x%x", &ed_ctrl_2g);
		NLA_PUT_U16(msg, NXPWIFI_EDMAC_CTRL_2G, (uint16_t)ed_ctrl_2g);
		count = sscanf(argv[4], "0x%x", &ed_offset_2g);
		NLA_PUT_S16(msg, NXPWIFI_EDMAC_OFFSET_2G,
			    (int16_t)ed_offset_2g);
		count = sscanf(argv[5], "0x%x", &ed_ctrl_5g);
		NLA_PUT_U16(msg, NXPWIFI_EDMAC_CTRL_5G, (uint16_t)ed_ctrl_5g);
		count = sscanf(argv[6], "0x%x", &ed_offset_5g);
		NLA_PUT_S16(msg, NXPWIFI_EDMAC_OFFSET_5G,
			    (int16_t)ed_offset_5g);
		count = sscanf(argv[7], "0x%x", &ed_bitmap_txq_lock);
		NLA_PUT_U32(msg, NXPWIFI_EDMAC_TXQ_LOCK,
			    (uint32_t)ed_bitmap_txq_lock);
		nla_nest_end(msg, nested);
	} else {
		cb = nl_cb_alloc(NL_CB_DEFAULT);
		register_handler(print_edmac_cfg_response, (void *)false);
		nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, valid_handler, NULL);
	}
	count = send_msg(msg);
	if (count < 0) {
		fprintf(stderr, "failed to sent MSG: %s\n", strerror(count));
		goto nla_put_failure;
	}
	if (argc == 3) {
		nl_recvmsgs(nlstate.nl_sock, cb);
		nl_cb_put(cb);
	}
	nlmsg_free(msg);
	return 0;
nla_put_failure:
	nlmsg_free(msg);
	return 1;
}
/**
 * @brief Convert char to hex integer
 *
 * @param chr Char
 * @return Hex integer
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
#define BUFFER_LENGTH (4 * 1024)
/**
 * @brief get hostcmd data
 *
 * @param ln A pointer to line number
 * @param buf A pointer to hostcmd data
 * @param size A pointer to the return size of hostcmd buffer
 * @return MLAN_STATUS_SUCCESS
 */
static int nxpwifi_get_hostcmd_data(FILE *fp, int *ln, unsigned char *buf,
				    unsigned short *size)
{
	int errors = 0, i;
	char line[512], *pos, *pos1, *pos2, *pos3;
	unsigned short len;
	while ((pos = nxpwifi_config_get_line(fp, line, sizeof(line), ln))) {
		(*ln)++;
		if (strcmp(pos, "}") == 0) {
			break;
		}
		pos1 = strchr(pos, ':');
		if (pos1 == NULL) {
			printf("Line %d: Invalid hostcmd line '%s'\n", *ln,
			       pos);
			errors++;
			continue;
		}
		*pos1++ = '\0';
		pos2 = strchr(pos1, '=');
		if (pos2 == NULL) {
			printf("Line %d: Invalid hostcmd line '%s'\n", *ln,
			       pos);
			errors++;
			continue;
		}
		*pos2++ = '\0';
		len = a2hex_or_atoi(pos1);
		if (len < 1 || len > BUFFER_LENGTH) {
			printf("Line %d: Invalid hostcmd line '%s'\n", *ln,
			       pos);
			errors++;
			continue;
		}
		*size += len;
		if (*pos2 == '\"') {
			pos2++;
			pos3 = strchr(pos2, '\"');
			if (pos3 == NULL) {
				printf("Line %d: invalid quotation '%s'\n", *ln,
				       pos);
				errors++;
				continue;
			}
			*pos3 = '\0';
			memset(buf, 0, len);
			len = strlen(pos2) < len ? strlen(pos2) : len;
			memmove(buf, &pos2, len);
			buf += len;
		} else if (*pos2 == '\'') {
			pos2++;
			pos3 = strchr(pos2, '\'');
			if (pos3 == NULL) {
				printf("Line %d: invalid quotation '%s'\n", *ln,
				       pos);
				errors++;
				continue;
			}
			*pos3 = ',';
			for (i = 0; i < len; i++) {
				pos3 = strchr(pos2, ',');
				if (pos3 != NULL) {
					*pos3 = '\0';
					*buf++ =
					    (unsigned char)a2hex_or_atoi(pos2);
					pos2 = pos3 + 1;
				} else
					*buf++ = 0;
			}
		} else {
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
 * @brief Get one line from the File
 *
 * @param fp File handler
 * @param str Storage location for data.
 * @param size Maximum number of characters to read.
 * @param lineno A pointer to return current line number
 * @return returns string or NULL
 */
char *nxpwifi_config_get_line(FILE *fp, char *str, int size, int *lineno)
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
			case ' ': /* White space */
			case '\t': /* Tab */
				start++;
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
					start++;
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
			case ' ': /* White space */
			case '\t': /* Tab */
			case '\n':
			case '\r':
				*end = '\0';
				end--;
				break;
			default:
				out = 0;
				break;
			}
		}
		if (*start == '\0')
			continue;
		return start;
	} while (1);
	return NULL;
}
/**
 * @brief Prepare host-command buffer
 * @param fp File handler
 * @param cmd_name Command name
 * @param buf A pointer to comand buffer
 * @return MLAN_STATUS_SUCCESS--success, otherwise--fail
 */
static int prepare_host_cmd_buffer(FILE *fp, char *cmd_name, unsigned char *buf,
				   uint16_t *len, unsigned short *hostcmd)
{
	char line[256], cmdname[256], *pos, cmdcode[10];
	int ln = 0, count = 0;
	int cmdname_found = 0, cmdcode_found = 0;
	unsigned short cmd;
	snprintf(cmdname, sizeof(cmdname), "%.253s={", cmd_name);
	cmdname_found = 0;
	while ((pos = nxpwifi_config_get_line(fp, line, sizeof(line), &ln))) {
		if (strcmp(pos, cmdname) == 0) {
			cmdname_found = 1;
			snprintf(cmdcode, sizeof(cmdcode), "CmdCode=");
			cmdcode_found = 0;
			while ((pos = nxpwifi_config_get_line(
				    fp, line, sizeof(line), &ln))) {
				if (strncmp(pos, cmdcode, strlen(cmdcode)) ==
				    0) {
					cmdcode_found = 1;
					*hostcmd = a2hex_or_atoi(
					    pos + strlen(cmdcode));
					nxpwifi_get_hostcmd_data(fp, &ln, buf,
								 len);
					break;
				}
			}
			if (!cmdcode_found) {
				fprintf(stderr,
					"mlanutl: CmdCode not found in conf "
					"file\n");
				return 1;
			}
			break;
		}
	}
	if (!cmdname_found) {
		fprintf(stderr,
			"mlanutl: cmdname '%s' is not found in conf file\n",
			cmd_name);
		return 1;
	}
	return 0;
}
static int process_chtrpc_cfg(signed long long devidx, unsigned char *buffer,
			      uint16_t cmd_len)
{
	struct nl_msg *msg;
	struct nl_cb *cb;
	msg = nlmsg_alloc();
	if (!msg) {
		fprintf(stderr, "failed to allocate netlink message\n");
		return 1;
	}
	if (NULL ==
	    genlmsg_put(msg, 0, 0, nlstate.nl80211_id, 0, 0, NL80211_CMD_VENDOR,
			0))
		goto nla_put_failure;
	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, devidx);
	NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_ID, NXP_OUI);
	NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_SUBCMD,
		    NXPWIFI_VENDOR_CMD_TXPOWER_LIMIT);
	NLA_PUT(msg, NL80211_ATTR_VENDOR_DATA, cmd_len, buffer);
	if (cmd_len == 4) {
		cb = nl_cb_alloc(NL_CB_DEFAULT);
		register_handler(print_txpwrlimit_response, (void *)false);
		nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, valid_handler, NULL);
	}
	send_msg(msg);
	if (cmd_len == 4) {
		nl_recvmsgs(nlstate.nl_sock, cb);
		nl_cb_put(cb);
	}
	return 0;
nla_put_failure:
	nlmsg_free(msg);
	return 1;
}
/**
 * @brief Process hostcmd command
 * @param argc Number of arguments
 * @param argv A pointer to arguments array
 * @return MLAN_STATUS_SUCCESS--success, otherwise--fail
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
	char ed_2g_enable[NXPWIFI_MAX_CMD_NAME_SIZE],
	    ed_2g_offset[NXPWIFI_MAX_CMD_NAME_SIZE],
	    ed_5g_enable[NXPWIFI_MAX_CMD_NAME_SIZE],
	    ed_5g_offset[NXPWIFI_MAX_CMD_NAME_SIZE],
	    ed_txq_lock[NXPWIFI_MAX_CMD_NAME_SIZE];
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
		printf("Syntax: ./nxpwifiutl mlanX hostcmd <hostcmd.conf> "
		       "<cmdname>\n");
		return 1;
	}
	snprintf(cmdname, sizeof(cmdname), "%s", argv[4]);
	if (!strcmp(cmdname, "generate_raw")) {
		call_ioctl = false;
	}
	if (!call_ioctl && argc != 6) {
		printf("Error: invalid no of arguments\n");
		printf("Syntax: ./nxpwifiutl mlanX hostcmd <hostcmd.conf> %s "
		       "<raw_data_file>\n",
		       cmdname);
		return 1;
	}
	fp = fopen(argv[3], "r");
	if (fp == NULL) {
		fprintf(stderr, "Cannot open file %s\n", argv[3]);
		return 1;
	}
	/* Initialize buffer */
	buffer = (unsigned char *)malloc(BUFFER_LENGTH);
	if (!buffer) {
		printf("ERR:Cannot allocate buffer for command!\n");
		fclose(fp);
		return 1;
	}
	memset(buffer, 0, BUFFER_LENGTH);
	if (call_ioctl) {
		if (0 !=
		    prepare_host_cmd_buffer(fp, cmdname, buffer, &cmd_len,
					    &hostcmd)) {
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
		if (devidx == 0) {
			if (errno == ENODEV)
				fprintf(stderr, "%s: %s\n", strerror(errno),
					argv[1]);
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
	} else if (argc > 9) {
		fprintf(stderr, "Too many arguments\n");
		return 1;
	}
	msg = nlmsg_alloc();
	if (!msg) {
		fprintf(stderr, "failed to allocate netlink message\n");
		return 1;
	}
	if (NULL ==
	    genlmsg_put(msg, 0, 0, nlstate.nl80211_id, 0, 0, NL80211_CMD_VENDOR,
			0))
		goto nla_put_failure;
	devidx = if_nametoindex(argv[1]);
	if (devidx == 0) {
		if (errno == ENODEV)
			fprintf(stderr, "%s: %s\n", strerror(errno), argv[1]);
		goto nla_put_failure;
	}
	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, devidx);
	NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_ID, NXP_OUI);
	NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_SUBCMD,
		    NXPWIFI_VENDOR_CMD_VHT_CFG);
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
		register_handler(print_vhtcfg_response, (void *)false);
		nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, valid_handler, NULL);
	}
	nla_nest_end(msg, nested);
	count = send_msg(msg);
	if (count < 0) {
		fprintf(stderr, "failed to sent MSG: %s\n", strerror(count));
		goto nla_put_failure;
	}
	if (argc == 5) {
		nl_recvmsgs(nlstate.nl_sock, cb);
		nl_cb_put(cb);
	}
	nlmsg_free(msg);
	return 0;
nla_put_failure:
	nlmsg_free(msg);
	return 1;
}
static int hexval(__s32 chr)
{
	if (chr >= '0' && chr <= '9')
		return chr - '0';
	if (chr >= 'A' && chr <= 'F')
		return chr - 'A' + 10;
	if (chr >= 'a' && chr <= 'f')
		return chr - 'a' + 10;
	return 0;
}
static __s8 *readCurCmd(__s8 *ptr, __s8 *curCmd)
{
	__s32 i = 0;
#define MAX_CMD_SIZE 64 /**< Max command size */
	while (*ptr != ']' && i < (MAX_CMD_SIZE - 1))
		curCmd[i++] = *(++ptr);
	if (*ptr != ']')
		return NULL;
	curCmd[i - 1] = '\0';
	return ++ptr;
}
static char *convert2hex(char *ptr, __u8 *chr)
{
	__u8 val;
	for (val = 0; *ptr && isxdigit((unsigned char)*ptr); ptr++) {
		val = (val * 16) + hexval(*ptr);
	}
	*chr = val;
	return ptr;
}
static int fparse_for_cmd_and_hex(FILE *fp, __u8 *dst, __u8 *cmd)
{
	__s8 *ptr;
	__u8 *dptr;
	__s8 buf[256], curCmd[64] = {0};
	__s32 isCurCmd = 0;
	dptr = dst;
	while (fgets((char *)buf, sizeof(buf), fp)) {
		ptr = buf;
		while (*ptr) {
			/* skip leading spaces */
			while (*ptr && isspace((unsigned char)*ptr))
				ptr++;
			/* skip blank lines and lines beginning with '#' */
			if (*ptr == '\0' || *ptr == '#')
				break;
			if (*ptr == '[' && *(ptr + 1) != '/') {
				ptr = readCurCmd(ptr, curCmd);
				if (!ptr)
					return 1;
				if (strcasecmp((char *)curCmd,
					       (char *)cmd)) /* Not equal */
					isCurCmd = 0;
				else
					isCurCmd = 1;
			}
			/* Ignore the rest if it is not correct cmd */
			if (!isCurCmd)
				break;
			if (*ptr == '[' && *(ptr + 1) == '/')
				return dptr - dst;
			if (isxdigit((unsigned char)*ptr)) {
				ptr = (__s8 *)convert2hex((char *)ptr, dptr++);
			} else {
				/* Invalid character on data line */
				ptr++;
			}
		}
	}
	return 1;
}
static int parse_id(FILE *fp, const char *name, __u8 *buf, int expected_len)
{
	int len = fparse_for_cmd_and_hex(fp, buf, (__u8 *)name);
	if (len != expected_len) {
		fprintf(stderr, "Expected %s size is %d bytes\n", name,
			expected_len);
		return -1;
	}

	if (g_dump_nlmsg) {
		printf("%s: ", name);
		for (int i = 0; i < len; i++) {
			printf("%02x ", buf[i]);
		}
		printf("\n");
	}
	return 0;
}

/* Pretty CSI usage (invoked on --help or wrong args) */
static void print_csi_usage(const char *prog)
{
	fprintf(
	    stderr,
	    "Usage:\n" 
	     "  %s <ifname> csi <0|1>\n"
		"    -> 1: enable CSI with default/last config; 0: disable "
		"CSI\n"
		"  %s <ifname> csi <config_file>\n"
		"    -> Load CSI config from file\n"
		"\n"
		"CSI config file format (ASCII, sections with hex bytes):\n"
		"  [headID]           # 4 bytes, e.g. 11 22 33 44\n"
		"  [tailID]           # 4 bytes\n"
		"  [chipID]           # 1 byte\n"
		"  [csifilter0] .. [csifilter15]  # up to 16 filters, 9 bytes "
		"each:\n"
		"     mac[6] pkt_type[1] subtype[1] flags[1]\n"
		"\n"
		"Examples:\n"
		"  %s mlan0 csi 1\n"
		"  %s mlan0 csi csi.conf --dump\n"
		"\n"
		"Notes:\n"
		"  - You can append --dump | dump=1 to print outgoing nl80211 "
		"vendor message.\n",
	    	prog, prog, prog, prog);
}

static int process_csi_cfg(int argc, char *argv[])
{
	/* Accept:
         *   nxpwifiutl <ifname> csi <0|1>
         *   nxpwifiutl <ifname> csi <config_file>
         * Also allow: nxpwifiutl <ifname> csi --help
         */
	if (argc < 4)
	{
		print_csi_usage(argv[0]);
		return 1;
	}

	if (!strcmp(argv[3], "--help") || !strcmp(argv[3], "-h"))
	{
		print_csi_usage(argv[0]);
		return 0;
	}
	struct nl_msg *msg = nlmsg_alloc();
	if (!msg) {
		fprintf(stderr, "Failed to allocate netlink message\n");
		return 1;
	}
	int ifindex = if_nametoindex(argv[1]);
	if (ifindex == 0) {
		fprintf(stderr, "%s: %s\n", strerror(errno), argv[1]);
		nlmsg_free(msg);
		return 1;
	}
	genlmsg_put(msg, 0, 0, nlstate.nl80211_id, 0, 0, NL80211_CMD_VENDOR, 0);
	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, ifindex);
	NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_ID, NXP_OUI);
	NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_SUBCMD,
		    NXPWIFI_VENDOR_CMD_CSI_CFG);
	struct nxpwifiutl_csi_cfg csi_cfg = {0};
	int parsed_count = sscanf(argv[3], "%hu", &csi_cfg.csi_enable);
	if (parsed_count == 0) {
		csi_cfg.csi_enable = 1;
		char filename[32] = {0};
		strncpy(filename, argv[3], sizeof(filename) - 1);
		FILE *fp = fopen(filename, "r");
		if (!fp) {
			perror("fopen");
			fprintf(stderr, "Cannot open CSI config file %s\n",
				filename);
			nlmsg_free(msg);
			return 1;
		}
		if (parse_id(fp, "headID", csi_cfg.head_id, 4) < 0

		    || parse_id(fp, "tailID", csi_cfg.tail_id, 4) < 0

		    || parse_id(fp, "chipID", &csi_cfg.chip_id, 1) < 0) {
			fclose(fp);
			nlmsg_free(msg);
			return 1;
		}
		for (__u8 i = 0; i < CSI_FILTER_MAX; i++) {
			char filter_name[20];
			snprintf(filter_name, sizeof(filter_name),
				 "csifilter%d", i);
			int len = fparse_for_cmd_and_hex(
			    fp, (__u8 *)&csi_cfg.csi_filter[i],
			    (__u8 *)filter_name);
			if (len != CSI_FILTER_SIZE)
				break;
			csi_cfg.csi_filter_cnt++;
		}
		fclose(fp);
	}
	struct nlattr *nested = nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA);
	if (!nested) {
		fprintf(stderr, "Failed to start nested attribute\n");
		nlmsg_free(msg);
		return 1;
	}
	NLA_PUT(msg, NXPWIFI_ATTR_CSI_CONFIG,
		sizeof(csi_cfg) -
		    (CSI_FILTER_MAX - csi_cfg.csi_filter_cnt) *
			sizeof(struct nxpwifiutl_csi_filter),
		&csi_cfg);
	nla_nest_end(msg, nested);
	int sent = send_msg(msg);
	if (sent < 0) {
		fprintf(stderr, "Failed to send MSG: %s\n", strerror(sent));
		nlmsg_free(msg);
		return 1;
	}
	int ack = nl_wait_for_ack(nlstate.nl_sock);
	if (ack < 0) {
		fprintf(stderr, "ACK error: %s\n", nl_geterror(ack));
		nlmsg_free(msg);
		return 1;
	}
	nlmsg_free(msg);
	return 0;
nla_put_failure:
	nlmsg_free(msg);
	return 1;
}

static int process_clocksync(int argc, char *argv[])
{
	__u8 *buffer = NULL;
	struct nl_msg *msg = NULL, *nested = NULL;
	signed long long devidx = 0;
	unsigned char action;
	struct nl_cb *cb;
	int mode, role, pin, level, width, count = 0;
	struct nxpwifiutl_gpio_tsf_latch clksync_cfg;
	struct nlattr *opts = NULL, *currattr;
	int rem;
	if ((argc != 8) && (argc != 3)) {
		fprintf(stderr, "Wrong argument number\n");
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
	if (NULL ==
	    genlmsg_put(msg, 0, 0, nlstate.nl80211_id, 0, 0, NL80211_CMD_VENDOR,
			0))
		goto nla_put_failure;
	devidx = if_nametoindex(argv[1]);
	if (devidx == 0) {
		if (errno == ENODEV)
			fprintf(stderr, "%s: %s\n", strerror(errno), argv[1]);
		goto nla_put_failure;
	}
	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, devidx);
	NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_ID, NXP_OUI);
	NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_SUBCMD,
		    NXPWIFI_VENDOR_CMD_CLOCKSYNC);
	count = sscanf(argv[3], "%u", &mode);
	clksync_cfg.mode = (uint8_t)mode;
	count = sscanf(argv[4], "%u", &role);
	clksync_cfg.role = (uint8_t)role;
	count = sscanf(argv[5], "%u", &pin);
	clksync_cfg.pin = (uint8_t)pin;
	count = sscanf(argv[6], "%u", &level);
	clksync_cfg.level = (uint8_t)level;
	count = sscanf(argv[7], "%u", &width);
	clksync_cfg.width = (uint16_t)width;
	NLA_PUT(nested, NL80211_ATTR_VENDOR_DATA, sizeof(clksync_cfg),
		&clksync_cfg);
	count = send_msg(msg);
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
static int process_irst(int argc, char *argv[])
{
	__u8 *buffer = NULL;
	struct nl_msg *msg = NULL, *nested = NULL;
	signed long long devidx = 0;
	unsigned char action;
	struct nl_cb *cb;
	int mode, pin, count = 0;
	struct nxpwifiutl_ireset_cfg irst_cfg;
	struct nlattr *opts = NULL, *currattr;
	int rem;
	if ((argc > 5) && (argc < 3)) {
		fprintf(stderr, "Wrong argument number\n");
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
	if (NULL ==
	    genlmsg_put(msg, 0, 0, nlstate.nl80211_id, 0, 0, NL80211_CMD_VENDOR,
			0))
		goto nla_put_failure;
	devidx = if_nametoindex(argv[1]);
	if (devidx == 0) {
		if (errno == ENODEV)
			fprintf(stderr, "%s: %s\n", strerror(errno), argv[1]);
		goto nla_put_failure;
	}
	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, devidx);
	NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_ID, NXP_OUI);
	NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_SUBCMD, NXPWIFI_VENDOR_CMD_INDRST);
	count = sscanf(argv[3], "%u", &mode);
	irst_cfg.ir_mode = (uint8_t)mode;
	count = sscanf(argv[5], "%u", &pin);
	irst_cfg.gpio_pin = (uint8_t)pin;
	NLA_PUT(nested, NL80211_ATTR_VENDOR_DATA, sizeof(irst_cfg), &irst_cfg);
	count = send_msg(msg);
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

static int parse_twt_section(const char *filename, const char *section,
			     struct nxpwifiutl_twt_setup *s,
			     struct nxpwifiutl_twt_teardown *td,
			     struct nxpwifiutl_twt_information *inf)
{
	FILE *fp = fopen(filename, "r");
	char line[256];
	int in = 0; /* 0: none, 1: in desired section */

	if (!fp)
	{
		perror("fopen");
		return -1;
	}

	/* Section header string, e.g., "twt_setup={" matches the conf format */
	char header[64];
	snprintf(header, sizeof(header), "%s={", section);

	while (fgets(line, sizeof(line), fp))
	{
		if (!in)
		{
			if (strstr(line, header))
			{
				in = 1;
				continue;
			}
			continue;
		}

		if (strchr(line, '}'))
		{
			in = 0;
			break;
		}

		char *hash = strchr(line, '#');

		if (hash)
			*hash = '\0';
		char key[64];
		unsigned int val;

		if (sscanf(line, " %63[^=]=%u", key, &val) == 2)
		{
			if (!strcasecmp(section, "twt_setup"))
			{
				if (!s)
					continue;

				if (!strcasecmp(key, "Implicit"))
					s->implicit = val;
				else if (!strcasecmp(key, "Announced"))
					s->announced = val;
				else if (!strcasecmp(key, "TriggerEnabled"))
					s->trigger_enabled = val;
				else if (!strcasecmp(key, "TWTInformationDisabled"))
				     s->twt_info_disabled = val;
				else if (!strcasecmp(key, "NegotiationType"))
				     s->negotiation_type = val;
				else if (!strcasecmp(key, "TWTWakeupDuration"))
				     s->twt_wakeup_duration = val;
				else if (!strcasecmp(key, "FlowIdentifier"))
				     s->flow_identifier = val;
				else if (!strcasecmp(key, "HardConstraint"))
				     s->hard_constraint = val;
				else if (!strcasecmp(key, "TWTExponent"))
				     s->twt_exponent = val;
				else if (!strcasecmp(key, "TWTMantissa"))
				     s->twt_mantissa = val;
				else if (!strcasecmp(key, "TWTRequestType"))
				     s->twt_request = val;
				/* If BCN_MISS / bcn_miss_threshold is not
				 * present in the conf, keep it as 0 */
			}
			else if (!strcasecmp(section, "twt_teardown"))
			{
				if (!td)
					continue;
				if (!strcasecmp(key, "FlowIdentifier"))
					td->flow_identifier = val;
				else if (!strcasecmp(key, "NegotiationType"))
					td->negotiation_type = val;
				else if (!strcasecmp(key, "TearDownAllTWT"))
					td->teardown_all_twt = val;
			}
			else if (!strcasecmp(section, "twt_information"))
			{
				if (!inf)
					continue;
				if (!strcasecmp(key, "FlowIdentifier"))
					inf->flow_identifier = val;
				else if (!strcasecmp(key, "SuspendDuration"))
					inf->suspend_duration = val;
			}
		}
	}

	fclose(fp);
	return 0;
}

static int send_btwt_ap_config_get_msg(const char *ifname, const void *req)
{
	struct nl_msg *msg = nlmsg_alloc();
	struct nl_cb *cb = NULL;
	int ifindex, sent, ack;

	if (!msg)
	{
		fprintf(stderr, "alloc netlink msg failed\n");
		return 1;
	}
	genlmsg_put(msg, 0, 0, nlstate.nl80211_id, 0, 0, NL80211_CMD_VENDOR,
		     0);
	ifindex = if_nametoindex(ifname);
	if (ifindex == 0)
	{
		fprintf(stderr, "%s: %s\n", strerror(errno), ifname);
		nlmsg_free(msg);
		return 1;
	}
	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, ifindex);
	NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_ID, NXP_OUI);
	NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_SUBCMD,
		     NXPWIFI_VENDOR_CMD_TWT_CFG);
	/* Put request as vendor binary attr (no nested) */
	NLA_PUT(msg, NXPWIFI_TWT_BTWT_AP_CFG_GET,
		sizeof(struct nxpwifiutl_btwt_ap_cfg_req), req);
	/* Send and wait for reply to print */
	cb = nl_cb_alloc(NL_CB_DEFAULT);
	if (!cb)
	{
		nlmsg_free(msg);
		return 1;
	}
	register_handler(print_btwt_ap_config_response, (void *)false);
	nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, valid_handler, NULL);
	sent = send_msg(msg);
	if (sent < 0)
	{
		fprintf(stderr, "send btwt ap cfg get failed: %s\n",
			strerror(sent));
		goto nla_put_failure;
	}
	nl_recvmsgs(nlstate.nl_sock, cb);
	nl_cb_put(cb);
	nlmsg_free(msg);
	return 0;
nla_put_failure :
	if (cb)
		nl_cb_put(cb);
	nlmsg_free(msg);
	return 1;
}

static int process_twt_cfg(int argc, char *argv[])
{
	struct nl_msg *msg = NULL;
	struct nlattr *nested = NULL;
	signed long long devidx = 0;
	struct nxpwifiutl_twt_setup setup = {0};
	int count;

	/* New mode: nxpwifiutl <ifname> twt <conf_file> <section> */
	if (argc == 5)
	{
		const char *conf = argv[3];
		const char *sec = argv[4];
		struct nxpwifiutl_twt_setup s = {0};
		struct nxpwifiutl_twt_teardown td = {0};
		struct nxpwifiutl_twt_information inf = {0};

		if (!strcasecmp(sec, "twt_setup"))
		{
			if (parse_twt_section(conf, sec, &s, NULL, NULL) < 0)
				return 1;
			return send_twt_setup_msg(argv[1], &s);
		}
		else if (!strcasecmp(sec, "twt_teardown"))
		{
			if (parse_twt_section(conf, sec, NULL, &td, NULL) < 0)
				return 1;
			return send_twt_teardown_msg(argv[1], &td);
		}
		else if (!strcasecmp(sec, "twt_information"))
		{
			if (parse_twt_section(conf, sec, NULL, NULL, &inf) < 0)
				return 1;
			return send_twt_information_msg(argv[1], &inf);
		} else if (!strcasecmp(sec, "btwt_AP_config_get"))
		{
			/* Parse request, then GET and print */
			struct nxpwifiutl_btwt_ap_cfg_req rq = {0};
			/* Reuse the section parser to fetch 4 request keys */
			FILE *fp = fopen(conf, "r");
			char line[256];
			int in = 0;
			if (!fp) {
				perror("fopen");
				return 1;
			}
			while (fgets(line, sizeof(line), fp)) {
				if (!in) {
					if (strstr(line, "btwt_AP_config_get={"))
					{
						in = 1;
						continue;
					}
					continue;
				}
				if (strchr(line, '}')) {
					in = 0;
					break;
				}
				char *hash = strchr(line, '#');
				if (hash)
					*hash = '\0';
				char key[64];
				unsigned int val;
				if (sscanf(line, " %63[^=]=%u", key, &val) ==
				    2) {
					if (!strcasecmp(
						key, "ap_bcast_bet_sta_wait"))
						rq.ap_bcast_bet_sta_wait =
						    (uint8_t)val;
					else if (!strcasecmp(key,
							     "Ap_Bcast_Offset"))
						rq.ap_bcast_offset =
						    htole16((uint16_t)val);
					else if (!strcasecmp(key, "bcastTWTLI"))
						rq.bcast_twtli = (uint8_t)val;
					else if (!strcasecmp(key, "count"))
						rq.count = (uint8_t)val;
				}
			}
			fclose(fp);
			/* Clamp count to [1..BTWT_AGREEMENT_MAX] if provided */
			if (rq.count == 0)
				rq.count = BTWT_AGREEMENT_MAX;
			if (rq.count > BTWT_AGREEMENT_MAX)
				rq.count = BTWT_AGREEMENT_MAX;
			return send_btwt_ap_config_get_msg(argv[1], &rq);
		} else if (!strcasecmp(sec, "btwt_AP_config_set")) {
			/* Parse SET section and send */
			struct nxpwifiutl_btwt_ap_cfg_set hdr = {0};
			struct nxpwifiutl_btwt_set sets[BTWT_AGREEMENT_MAX] = {0};
			uint8_t valid = 0;

			FILE *fp = fopen(conf, "r");
			char line[256];
			int in = 0;
			if (!fp)
			{
				perror("fopen");
				return 1;
			}
			while (fgets(line, sizeof(line), fp))
			{
				if (!in)
				{
					if (strstr(line,
						   "btwt_AP_config_set={"))
					{
						in = 1;
						continue;
					}
					continue;
				}
				if (strchr(line, '}'))
				{
					in = 0;
					break;
				}
				char *hash = strchr(line, '#');
				if (hash)
					*hash = '\0';
				char key[64];
				unsigned int val;
				if (sscanf(line, " %63[^=]=%u", key, &val) ==
				    2)
				{
					if (!strcasecmp(
							key, "ap_bcast_bet_sta_wait"))
						hdr.ap_bcast_bet_sta_wait = (uint8_t)val;
					else if (!strcasecmp(key, "Ap_Bcast_Offset"))
						hdr.ap_bcast_offset =
						    htole16((uint16_t)val);
					else if (!strcasecmp(key,
							      "bcastTWTLI"))
						hdr.bcast_twtli = (uint8_t)val;
					else if (!strcasecmp(key, "count"))
						hdr.count = (uint8_t)val;
					else
					{
						/* Per-set keys: btwtIdN /
						    Ap_Bcast_MantissaN /
						    Ap_Bcast_ExponentN /
						    nominalwakeN */
						    int idx = -1;
						if (!strncmp(key, "btwtId", 6))
						    idx = atoi(key + 6);
						else if (!strncmp(key, "Ap_Bcast_Mantissa", 16))
							idx = atoi(key + 17);
						else if (!strncmp(key, "Ap_Bcast_Exponent", 16))
							idx = atoi(key + 17);
						else if (!strncmp(key, "nominalwake", 11))
							idx = atoi(key + 11);
						printf("idx %d\n", idx);
						if (idx >= 0 &&
						    idx < BTWT_AGREEMENT_MAX) {
							if (!strncmp(key, "btwtId", 6))
								sets[idx].btwt_id = (uint8_t)val;
							else if (!strncmp(key, "Ap_Bcast_Mantissa", 16))
								sets[idx].ap_bcast_mantissa =
								    htole16((uint16_t)val);
							else if (!strncmp(key, "Ap_Bcast_Exponent", 16))
								sets[idx].ap_bcast_exponent =
								    (uint8_t)val;
							else if (!strncmp(key, "nominalwake", 11))
								sets[idx].nominalwake =
								    (uint8_t)val;
						}
					}
				}
			}
			fclose(fp);

			/* 計算有效組數（exponent 或 mantissa 有填就視為有效）
			 */
			for (int i = 0; i < BTWT_AGREEMENT_MAX; i++) {
				if (sets[i].ap_bcast_exponent ||
				    sets[i].ap_bcast_mantissa) {
					/* （可選）做範圍 clamp：exponent
					 * 10~26，nominalwake 64~255 */
					if (sets[i].ap_bcast_exponent < 10)
						sets[i].ap_bcast_exponent = 10;
					if (sets[i].ap_bcast_exponent > 26)
						sets[i].ap_bcast_exponent = 26;
					if (sets[i].nominalwake < 64)
						sets[i].nominalwake = 64;
					valid++;
				}
			}

			/* Clamp count and send */
			if (hdr.count == 0 || hdr.count > valid)
				hdr.count = valid;

			if (hdr.count < 2)
			{
				fprintf(stderr,
					"Invalid btwt_AP_config_set: need at "
					"least 2 sets (count=%u, valid=%u)\n",
					hdr.count, valid);
				return 1;
			}

			/* 動態組合：Header + count 個 set */
			size_t payload_len = sizeof(hdr) + hdr.count *
				sizeof(struct nxpwifiutl_btwt_set);
			uint8_t *payload = calloc(1, payload_len);
			if (!payload)
			{
				perror("calloc");
				return 1;
			}
			memcpy(payload, &hdr, sizeof(hdr));
			memcpy(payload + sizeof(hdr), sets,
				hdr.count * sizeof(sets[0]));
			int rc = send_btwt_ap_config_set_msg(argv[1], payload,
							      payload_len);
			free(payload);
			return rc;
		} else {
			fprintf(stderr,
				"Unknown section '%s'. "
				"Expect one of: "
				"twt_setup | twt_teardown "
				"| twt_information | "
				"btwt_AP_config_get | btwt_AP_config_set\n",
				sec);
			return 1;
		}
	}

	/* Old mode: 12 parameters (setup only) */
	if (argc != 15)
	{
		fprintf(stderr,
			"Usage:\n"
			     "  %s <ifname> twt <implicit> <announced> "
			     "<trigger_enabled> <twt_info_disabled> "
			     "<negotiation_type> <twt_wakeup_duration> "
			     "<flow_identifier> "
			     "<hard_constraint> <twt_exponent> <twt_mantissa> "
			     "<twt_request> <bcn_miss_threshold>\n"
			     "or\n"
			     "  %s <ifname> twt <conf_file> "
			     "<twt_setup|twt_teardown|twt_information>\n",
			argv[0], argv[0]);
		return 1;
	}

	msg = nlmsg_alloc();
	if (!msg)
	{
		fprintf(stderr, "failed to allocate netlink message\n");
		return 1;
	}
	if (NULL == genlmsg_put(msg, 0, 0, nlstate.nl80211_id, 0, 0,
				NL80211_CMD_VENDOR, 0))
	    goto nla_put_failure;
	devidx = if_nametoindex(argv[1]);
	if (devidx == 0)
	{
		if (errno == ENODEV)
		    fprintf(stderr, "%s: %s\n", strerror(errno), argv[1]);
		goto nla_put_failure;
	}
	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, devidx);
	NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_ID, NXP_OUI);
	NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_SUBCMD,
		    NXPWIFI_VENDOR_CMD_TWT_CFG);

	setup.implicit = (uint8_t)atoi(argv[3]);
	setup.announced = (uint8_t)atoi(argv[4]);
	setup.trigger_enabled = (uint8_t)atoi(argv[5]);
	setup.twt_info_disabled = (uint8_t)atoi(argv[6]);
	setup.negotiation_type = (uint8_t)atoi(argv[7]);
	setup.twt_wakeup_duration = (uint8_t)atoi(argv[8]);
	setup.flow_identifier = (uint8_t)atoi(argv[9]);
	setup.hard_constraint = (uint8_t)atoi(argv[10]);
	setup.twt_exponent = (uint8_t)atoi(argv[11]);
	setup.twt_mantissa = (uint16_t)atoi(argv[12]);
	setup.twt_request = (uint8_t)atoi(argv[13]);
	setup.bcn_miss_threshold = (uint16_t)atoi(argv[14]);
	nested = nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA);

	if (!nested)
		goto nla_put_failure;
	NLA_PUT(msg, NXPWIFI_TWT_SETUP, sizeof(setup), &setup);
	nla_nest_end(msg, nested);

	if (send_msg(msg) < 0) {
		fprintf(stderr, "Failed to send TWT setup\n");
		goto nla_put_failure;
	}

	if (nl_wait_for_ack(nlstate.nl_sock) < 0) {
		fprintf(stderr, "TWT setup ack error\n");
		goto nla_put_failure;
	}
	nlmsg_free(msg);
	return 0;

nla_put_failure :
	nlmsg_free(msg);
	return 1;
}

static int parse_twt_conf(const char *filename,
			  struct nxpwifiutl_twt_setup *setup,
			  struct nxpwifiutl_twt_teardown *teardown)
{
	FILE *fp = fopen(filename, "r");
	if (!fp) {
		perror("fopen");
		return -1;
	}
	char line[256];
	int in_setup = 0, in_teardown = 0;
	while (fgets(line, sizeof(line), fp)) {
		if (strstr(line, "twt_setup={")) {
			in_setup = 1;
			continue;
		}
		if (strstr(line, "twt_teardown={")) {
			in_teardown = 1;
			continue;
		}
		if (strchr(line, '}')) {
			in_setup = 0;
			in_teardown = 0;
			continue;
		}

		char key[64];
		unsigned int val;
		if (sscanf(line, "%63[^=]=%u", key, &val) == 2) {
			if (in_setup) {
				if (!strcasecmp(key, "Implicit"))
					setup->implicit = val;
				else if (!strcasecmp(key, "Announced"))
					setup->announced = val;
				else if (!strcasecmp(key, "TriggerEnabled"))
					setup->trigger_enabled = val;
				else if (!strcasecmp(key,
						     "TWTInformationDisabled"))
					setup->twt_info_disabled = val;
				else if (!strcasecmp(key, "NegotiationType"))
					setup->negotiation_type = val;
				else if (!strcasecmp(key, "TWTWakeupDuration"))
					setup->twt_wakeup_duration = val;
				else if (!strcasecmp(key, "FlowIdentifier"))
					setup->flow_identifier = val;
				else if (!strcasecmp(key, "HardConstraint"))
					setup->hard_constraint = val;
				else if (!strcasecmp(key, "TWTExponent"))
					setup->twt_exponent = val;
				else if (!strcasecmp(key, "TWTMantissa"))
					setup->twt_mantissa = val;
				else if (!strcasecmp(key, "TWTRequestType"))
					setup->twt_request = val;
			} else if (in_teardown) {
				if (!strcasecmp(key, "FlowIdentifier"))
					teardown->flow_identifier = val;
				else if (!strcasecmp(key, "NegotiationType"))
					teardown->negotiation_type = val;
				else if (!strcasecmp(key, "TearDownAllTWT"))
					teardown->teardown_all_twt = val;
			}
		}
	}
	fclose(fp);
	return 0;
}

/* ===== CLI: twt_information (2 args) =====
 + * nxpwifiutl <ifname> twt_information <flow_id> <suspend_ms>
 + */
static int process_twt_information(int argc, char *argv[])
{
	if (argc != 6 && argc != 5)
	{
		fprintf(stderr,
			"Usage:\n  %s <ifname> twt_information <flow_id> "
			  "<suspend_ms>\n",
			argv[0]);
		return 1;
	}
	struct nxpwifiutl_twt_information info = {0};
	info.flow_identifier = (uint8_t)atoi(argv[3]);
	info.suspend_duration = (uint32_t)atoi(argv[4]);
	return send_twt_information_msg(argv[1], &info);
}

static int process_twt_teardown(int argc, char *argv[])
{
	struct nl_msg *msg = NULL;
	struct nlattr *nested = NULL;
	signed long long devidx = 0;
	struct nxpwifiutl_twt_teardown td = {0};
	/* nxpwifiutl <ifname> twt_teardown <negotiation_type> <flow_id>
	   <teardown_all> */

	if (argc != 6)
	{
		fprintf(stderr,
			"Usage:\n"
			"  %s <ifname> twt_teardown <negotiation_type> "
			"<flow_id> <teardown_all>\n"
			"    negotiation_type: 0..3 (per spec / FW def)\n"
			"    flow_id: 0..7; ignored when teardown_all=1\n"
			"    teardown_all: 0|1\n",
			argv[0]);
		return 1;
	}

	msg = nlmsg_alloc();

	if (!msg)
	{
		fprintf(stderr, "failed to allocate netlink message\n");
		return 1;
	}

	if (NULL == genlmsg_put(msg, 0, 0, nlstate.nl80211_id, 0, 0,
				NL80211_CMD_VENDOR, 0))
		goto nla_put_failure;

	devidx = if_nametoindex(argv[1]);

	if (devidx == 0)
	{
		if (errno == ENODEV)
			fprintf(stderr, "%s: %s\n", strerror(errno), argv[1]);

		goto nla_put_failure;
	}

	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, devidx);
	NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_ID, NXP_OUI);
	NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_SUBCMD,
		    NXPWIFI_VENDOR_CMD_TWT_CFG);
	td.negotiation_type = (uint8_t)atoi(argv[3]);
	td.flow_identifier = (uint8_t)atoi(argv[4]);
	td.teardown_all_twt = (uint8_t)atoi(argv[5]);
	nested = nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA);

	if (!nested)
		goto nla_put_failure;

	NLA_PUT(msg, NXPWIFI_TWT_TEARDOWN, sizeof(td), &td);
	nla_nest_end(msg, nested);

	if (send_msg(msg) < 0)
	{
		fprintf(stderr, "Failed to send TWT teardown\n");
		goto nla_put_failure;
	}

	if (nl_wait_for_ack(nlstate.nl_sock) < 0)
	{
		fprintf(stderr, "TWT teardown ack error\n");
		goto nla_put_failure;
	}

	nlmsg_free(msg);
	return 0;

nla_put_failure :
	nlmsg_free(msg);
	return 1;
}

/* ===== Helpers to send vendor messages for TWT ===== */
static int send_twt_setup_msg(const char *ifname, const void *setup)
{
	struct nl_msg *msg = nlmsg_alloc();
	struct nlattr *nested;
	int ifindex, sent, ack;

	if (!msg)
	{
		fprintf(stderr, "alloc netlink msg failed\n");
		return 1;
	}

	genlmsg_put(msg, 0, 0, nlstate.nl80211_id, 0, 0, NL80211_CMD_VENDOR,
		     0);
	ifindex = if_nametoindex(ifname);

	if (ifindex == 0)
	{
		fprintf(stderr, "%s: %s\n", strerror(errno), ifname);
		nlmsg_free(msg);
		return 1;
	}
	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, ifindex);
	NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_ID, NXP_OUI);
	NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_SUBCMD,
		     NXPWIFI_VENDOR_CMD_TWT_CFG);
	nested = nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA);

	if (!nested)
		goto nla_put_failure;

	NLA_PUT(msg, NXPWIFI_TWT_SETUP, sizeof(struct nxpwifiutl_twt_setup),
		 setup);
	nla_nest_end(msg, nested);
	sent = send_msg(msg);

	if (sent < 0)
	{
		fprintf(stderr, "send twt setup failed: %s\n", strerror(sent));
		goto nla_put_failure;
	}

	ack = nl_wait_for_ack(nlstate.nl_sock);

	if (ack < 0)
	{
		fprintf(stderr, "twt setup ack error: %s\n", nl_geterror(ack));
		goto nla_put_failure;
	}

	nlmsg_free(msg);
	return 0;

nla_put_failure:
	nlmsg_free(msg);
	return 1;
}

static int send_twt_teardown_msg(const char *ifname, const void *teardown)
{
	struct nl_msg *msg = nlmsg_alloc();
	struct nlattr *nested;
	int ifindex, sent, ack;
	if (!msg)
	{
		fprintf(stderr, "alloc netlink msg failed\n");
		return 1;
	}
	genlmsg_put(msg, 0, 0, nlstate.nl80211_id, 0, 0, NL80211_CMD_VENDOR,
		     0);
	ifindex = if_nametoindex(ifname);
	if (ifindex == 0)
	{
		fprintf(stderr, "%s: %s\n", strerror(errno), ifname);
		nlmsg_free(msg);
		return 1;
	}
	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, ifindex);
	NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_ID, NXP_OUI);
	NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_SUBCMD,
		     NXPWIFI_VENDOR_CMD_TWT_CFG);
	nested = nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA);

	if (!nested)
		goto nla_put_failure;
	NLA_PUT(msg, NXPWIFI_TWT_TEARDOWN,
		 sizeof(struct nxpwifiutl_twt_teardown), teardown);
	nla_nest_end(msg, nested);
	sent = send_msg(msg);
	if (sent < 0)
	{
		fprintf(stderr, "send twt teardown failed: %s\n",
			strerror(sent));
		goto nla_put_failure;
	}
	ack = nl_wait_for_ack(nlstate.nl_sock);
	if (ack < 0)
	{
		fprintf(stderr, "twt teardown ack error: %s\n",
			nl_geterror(ack));
		goto nla_put_failure;
	}
	nlmsg_free(msg);
	return 0;

nla_put_failure: 
	nlmsg_free(msg);
	return 1;
}

static int
send_btwt_ap_config_set_msg(const char *ifname, const void *req, size_t len)
{
	struct nl_msg *msg = nlmsg_alloc();
	struct nlattr *nested = NULL;
	int ifindex, sent, ack;

	if (!msg)
	{
		fprintf(stderr, "alloc netlink msg failed\n");
		return 1;
	}
	genlmsg_put(msg, 0, 0, nlstate.nl80211_id, 0, 0, NL80211_CMD_VENDOR,
		    0);
	ifindex = if_nametoindex(ifname);
	if (ifindex == 0)
	{
		fprintf(stderr, "%s: %s\n", strerror(errno), ifname);
		nlmsg_free(msg);
		return 1;
	}
	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, ifindex);
	NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_ID, NXP_OUI);
	NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_SUBCMD,
		    NXPWIFI_VENDOR_CMD_TWT_CFG);

	/*Put request under NL80211_ATTR_VENDOR_DATA(nested) */
	nested = nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA);

	if (!nested)
		goto nla_put_failure;

	NLA_PUT(msg, NXPWIFI_TWT_BTWT_AP_CFG_SET, len, req);
	nla_nest_end(msg, nested);
	sent = send_msg(msg);
	if (sent < 0)
	{
		fprintf(stderr, "send btwt ap cfg set failed: %s\n",
			strerror(sent));
		goto nla_put_failure;
	}
	ack = nl_wait_for_ack(nlstate.nl_sock);
	if (ack < 0)
	{
		fprintf(stderr, "btwt ap cfg set ack error: %s\n",
			nl_geterror(ack));
		goto nla_put_failure;
	}
	nlmsg_free(msg);
	return 0;
nla_put_failure:
	nlmsg_free(msg);
	return 1;
}

static int process_twt_conf(int argc, char *argv[])
{
	if (argc != 4) {
		fprintf(stderr, "Usage: %s <ifname> twt_conf <conf_file>\n",
			argv[0]);
		return 1;
	}
	struct nxpwifiutl_twt_setup setup = {0};
	struct nxpwifiutl_twt_teardown teardown = {0};
	if (parse_twt_conf(argv[3], &setup, &teardown) < 0)
		return 1;

	if (setup.twt_mantissa) {
		return send_twt_setup_msg(argv[1], &setup);
	}

	if (teardown.teardown_all_twt || teardown.flow_identifier) {
		return send_twt_teardown_msg(argv[1], &teardown);
	}
	return 0;
}


static int process_dfstesting(int argc, char *argv[])
{
    /* Expected forms:
     *   nxpwifiutl <ifname> dfstesting
     *   nxpwifiutl <ifname> dfstesting <user_cac_pd> <user_nop_pd> <no_chan_change> <fixed_chan_num> <cac_restart>
     *
     * Where:
     *   user_cac_pd   : 0 (use default 60s) or 1..1800
     *   user_nop_pd   : 0 (use default 1800s) or 1..65535
     *   no_chan_change: 0 or 1
     *   fixed_chan_num: 0 (disable) or 1..255 (only effective if no_chan_change=0)
     *   cac_restart   : 0 or 1
     */

    struct nl_msg *msg = NULL;
    struct nlattr *nested = NULL;
    signed long long devidx = 0;

    /* argc must be 3 (GET) or 8 (SET) */
    if (!(argc == 3 || argc == 8)) {
        fprintf(stderr,
            "Usage:\n"
            "  %s <ifname> dfstesting [<user_cac_pd> <user_nop_pd> <no_chan_change> <fixed_chan_num> <cac_restart>]\n"
            "Where:\n"
            "  <user_cac_pd>   : 0 (use default 60s) or 1..1800\n"
            "  <user_nop_pd>   : 0 (use default 1800s) or 1..65535\n"
            "  <no_chan_change>: 0/1\n"
            "  <fixed_chan_num>: 0 (disable) or 1..255 (effective only if no_chan_change=0)\n"
            "  <cac_restart>   : 0/1 (auto restart CAC after success)\n"
            "Examples:\n"
            "  %s mlan0 dfstesting\n"
            "  %s mlan0 dfstesting 60 0 0 0 1\n"
            "  %s mlan0 dfstesting 0 120 0 64 0\n"
            "  %s mlan0 dfstesting 0 0 1 0 0\n",
            argv[0], argv[0], argv[0], argv[0], argv[0]);
        return 1;
    }

    /* Build a nl80211 vendor command */
    msg = nlmsg_alloc();
    if (!msg) {
        fprintf(stderr, "failed to allocate netlink message\n");
        return 1;
    }

    if (NULL == genlmsg_put(msg, 0, 0, nlstate.nl80211_id, 0, 0,
                            NL80211_CMD_VENDOR, 0))
        goto nla_put_failure;

    /* Resolve interface index */
    devidx = if_nametoindex(argv[1]);
    if (devidx == 0) {
        if (errno == ENODEV)
            fprintf(stderr, "%s: %s\n", strerror(errno), argv[1]);
        goto nla_put_failure;
    }

    /* Common vendor headers */
    NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, devidx);
    NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_ID, NXP_OUI);
    NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_SUBCMD, NXPWIFI_VENDOR_CMD_DFS_TESTING);


	/* GET case: argc == 3 -> send vendor command without NL80211_ATTR_VENDOR_DATA,
	 * then receive and print the parsed result.
	 */
	if (argc == 3) {
		struct nl_cb *cb = NULL;
		struct dfstesting_resp resp = {0};

		if (send_msg(msg) < 0) {
			fprintf(stderr, "Failed to send dfstesting GET\n");
			goto nla_put_failure;
		}

		/* Prepare a callback set that parses the vendor reply */
		cb = nl_cb_alloc(NL_CB_DEFAULT);
		if (!cb) {
			fprintf(stderr, "failed to allocate nl_cb\n");
			goto nla_put_failure;
		}
		nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, dfstesting_reply_cb, &resp);

		/* Receive and parse one or more replies */
		if (nl_recvmsgs(nlstate.nl_sock, cb) < 0) {
			fprintf(stderr, "dfstesting GET recv error\n");
			nl_cb_put(cb);
			goto nla_put_failure;
		}
		nl_cb_put(cb);

		/* Print a human-readable summary. If an attribute was not present, print N/A. */
		printf("dfstesting (current): "
				"user_cac_pd=%s, user_nop_pd=%s, no_chan_change=%s, fixed_chan_num=%s, cac_restart=%s\n",
				resp.have_cac_pd    ? ({ static char b1[16]; snprintf(b1, sizeof(b1), "%u", resp.user_cac_pd); b1; }) : "N/A",
				resp.have_nop_pd    ? ({ static char b2[16]; snprintf(b2, sizeof(b2), "%u", resp.user_nop_pd); b2; }) : "N/A",
				resp.have_no_change ? (resp.no_chan_change ? "1" : "0") : "N/A",
				resp.have_fixed_chan? ({ static char b3[16]; snprintf(b3, sizeof(b3), "%u", resp.fixed_chan_num); b3; }) : "N/A",
				resp.have_cac_restart ? (resp.cac_restart ? "1" : "0") : "N/A");

		nlmsg_free(msg);
		return 0;
	}

    /* SET case: argc == 8 -> parse and validate five parameters */
    {
        /* argv[3]..argv[7] */
        long user_cac_pd   = strtol(argv[3], NULL, 0);
        long user_nop_pd   = strtol(argv[4], NULL, 0);
        long no_chan_change= strtol(argv[5], NULL, 0);
        long fixed_chan_num= strtol(argv[6], NULL, 0);
        long cac_restart   = strtol(argv[7], NULL, 0);

        /* Validate ranges per spec */
        if (!((user_cac_pd == 0) || (user_cac_pd >= 1 && user_cac_pd <= 1800))) {
            fprintf(stderr, "user_cac_pd invalid: must be 0 or 1..1800\n");
            goto nla_put_failure;
        }
        if (!((user_nop_pd == 0) || (user_nop_pd >= 1 && user_nop_pd <= 65535))) {
            fprintf(stderr, "user_nop_pd invalid: must be 0 or 1..65535\n");
            goto nla_put_failure;
        }
        if (!(no_chan_change == 0 || no_chan_change == 1)) {
            fprintf(stderr, "no_chan_change invalid: must be 0 or 1\n");
            goto nla_put_failure;
        }
        if (!((fixed_chan_num == 0) || (fixed_chan_num >= 1 && fixed_chan_num <= 255))) {
            fprintf(stderr, "fixed_chan_num invalid: must be 0 or 1..255\n");
            goto nla_put_failure;
        }
        if (!(cac_restart == 0 || cac_restart == 1)) {
            fprintf(stderr, "cac_restart invalid: must be 0 or 1\n");
            goto nla_put_failure;
        }

        /* Build nested vendor data */
        nested = nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA);
        if (!nested)
            goto nla_put_failure;

        /* Always include all five attrs (zeros are meaningful settings) */
        NLA_PUT_U32(msg, NXPWIFI_DFS_TEST_ATTR_USER_CAC_PD,   (uint32_t)user_cac_pd);
        NLA_PUT_U32(msg, NXPWIFI_DFS_TEST_ATTR_USER_NOP_PD,   (uint32_t)user_nop_pd);
        NLA_PUT_U8 (msg, NXPWIFI_DFS_TEST_ATTR_NO_CHAN_CHANGE,(uint8_t) no_chan_change);
        NLA_PUT_U32(msg, NXPWIFI_DFS_TEST_ATTR_FIXED_CHAN_NUM,(uint32_t)fixed_chan_num);
        NLA_PUT_U8 (msg, NXPWIFI_DFS_TEST_ATTR_CAC_RESTART,   (uint8_t) cac_restart);

        nla_nest_end(msg, nested);

        /* Send and wait for ack */
        if (send_msg(msg) < 0) {
            fprintf(stderr, "Failed to send dfstesting SET\n");
            goto nla_put_failure;
        }
        if (nl_wait_for_ack(nlstate.nl_sock) < 0) {
            fprintf(stderr, "dfstesting SET ack error\n");
            goto nla_put_failure;
        }

        nlmsg_free(msg);
        return 0;
    }

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
static void register_handler(int (*handler)(struct nl_msg *, void *),
			     void *data)
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
 * @brief Display usage
 *
 * @return NA
 */
static void display_usage(void)
{
	__u32 i;
	for (i = 0; i < NELEMENTS(usage); i++)
		fprintf(stderr, "%s\n", usage[i]);
}
/**
 * @brief Find and execute command
 *
 * @param argc Number of arguments
 * @param argv A pointer to arguments array
 * @return MLAN_STATUS_SUCCESS for success, otherwise failure
 */
static int process_command(int argc, char *argv[])
{
	int i = 0, ret = 0;
	struct command_node *node = NULL;
	/* Handle common dump flag for all commands */
	parse_dump_arg(&argc, argv);
	for (i = 0; i < (int)NELEMENTS(command_list); i++) {
		node = &command_list[i];
		if (!strcasecmp(node->name, argv[2])) {
			ret = node->handler(argc, argv);
			break;
		}
	}
	return ret;
}
/*******************************************************
	    Global Functions
*******************************************************/
/**
 * @brief Entry function for nxpwifiutl
 * @param argc Number of arguments
 * @param argv A pointer to arguments array
 * @return MLAN_STATUS_SUCCESS--success, otherwise--fail
 */
int main(int argc, char *argv[])
{
	int err, ret;
	if ((argc == 2) && (strcmp(argv[1], "-v") == 0)) {
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
		if (ret)
			err = 1;
	}
	nl80211_cleanup(&nlstate);
	return err;
}
