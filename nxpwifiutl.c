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

#define NXPWIFIUTL_VER "0.1"
/** Find number of elements */
#define NELEMENTS(x) (sizeof(x)/sizeof(x[0]))

#define NXP_OUI	0x006037

#define HS_OFFLOAD_ARP 0x1
#define HS_OFFLOAD_PING 0x2
#define HS_WAKEON_MDNS 0x4

enum nxpwifi_vendor_commands {
	NXPWIFI_VENDOR_CMD_HSCFG,
	NXPWIFI_VENDOR_CMD_SLEEPPD,
	NXPWIFI_VENDOR_CMD_CLOCKSYNC,
	NXPWIFI_VENDOR_CMD_HSOFFLOAD,
	NXPWIFI_VENDOR_CMD_CHANNELSWITCH = 6
};

enum nxpwifiutl_attrs {
	NXPWIFI_HSCFG,
	NXPWIFI_SLEEPPD,
	NXPWIFI_CLKSYNC_CFG,
	NXPWIFI_HS_OFFLOAD
};

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

struct nxpwifiutl_hs_offload hsoffload = {0};

static int process_hscfg(int argc, char *argv[]);
static int process_sleeppd(int argc, char *argv[]);
static int process_hsoffload(int argc, char *argv[]);
static int process_channel_switch(int argc, char *argv[]);

struct command_node command_list[] = {
    {"hscfg",           process_hscfg},
    {"sleeppd",         process_sleeppd},
	{"hsoffload",		process_hsoffload},
	{"channel_switch",	process_channel_switch}
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
 *  @brief Process the configuration for auto_arp and auto_ping.
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
