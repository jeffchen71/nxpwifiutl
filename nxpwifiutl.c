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

#define NXPWIFI_UTL_BYTE2UINT(x) (((uint32_t)*(x + 7) << 24)  + ((uint32_t)*(x + 6) << 16)  + ((uint32_t)*(x + 5) << 8) + (uint32_t)*x);
enum nxpwifi_vendor_commands {
	NXPWIFI_VENDOR_CMD_HSCFG,
	NXPWIFI_VENDOR_CMD_SLEEPPD
};

enum nxpwifiutl_attrs {
	NXPWIFI_HSCFG,
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

static int process_hscfg(int argc, char *argv[]);
static int process_sleeppd(int argc, char *argv[]);

struct command_node command_list[] = {
    {"hscfg",           process_hscfg},
    {"sleeppd",         process_sleeppd},	
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

	if (argc == 4)
		sscanf(argv[3], "%d", &sleepd_cfg.sleeppd);

	if (argc == 3) {
		cb = nl_cb_alloc(NL_CB_DEFAULT);
		sleepd_cfg.action = 0;
		register_handler(print_sleeppd_response, (void *) false);
		nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, valid_handler, NULL);
	} else
		sleepd_cfg.action = 1;

	NLA_PUT(msg, NL80211_ATTR_VENDOR_DATA, sizeof(sleepd_cfg), &sleepd_cfg);
	
	nl_send_auto(nlstate.nl_sock, msg);

	if (sleepd_cfg.action == 0)
		nl_recvmsgs(nlstate.nl_sock, cb);

    return 0;
nla_put_failure:

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
            fprintf(stderr, "Invalid command specified!\n");
            display_usage();
            err = 1;
        }
    }

	nl80211_cleanup(&nlstate);
    return err;
}
