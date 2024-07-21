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

#define NXPWIFIUTL_VER "0.1"
/** Find number of elements */
#define NELEMENTS(x) (sizeof(x)/sizeof(x[0]))

#define NXP_OUI	0x006037

enum nxpwifi_vendor_commands {
	NXPWIFI_VENDOR_CMD_SET_EDMAC_DATA,
	NXPWIFI_VENDOR_CMD_HSCFG	
};

struct nl80211_state {
	struct nl_sock *nl_sock;
	int nl80211_id;
};


struct command_node {
    char *name;
    int (*handler) (int, char **);
};

struct priv_hs_cfg {
    /** MTRUE to invoke the HostCmd, MFALSE otherwise */
    __u32  is_invoke_hostcmd;
    /** Host sleep config condition */
    /** Bit0: broadcast data
     *  Bit1: unicast data
     *  Bit2: mac event
     *  Bit3: multicast data
     */
    __u32  conditions;
    /** GPIO pin or 0xff for interface */
    __u32  gpio;
    /** Gap in milliseconds or or 0xff for special setting (host acknowledge required) */
    __u32  gap;
    /** Host sleep wake interval */
    __u32  hs_wake_interval;
	/** Parameter type*/
    __u32 param_type_ind;
    /** Indication GPIO pin number */
    __u32  ind_gpio;
    /** Level on ind_GPIO pin for normal wakeup source */
    __u32  level;
    /** Parameter type*/
    __u32 param_type_ext;
    /** Force ignore events*/
    __u32  event_force_ignore;
    /** Events use ext gap to wake up host*/
    __u32  event_use_ext_gap;
    /** Ext gap*/
    __u8   ext_gap;
    /** GPIO wave level*/
    __u8 gpio_wave;
};

static int process_version(int argc, char *argv[]);
static int process_hscfg(int argc, char *argv[]);

struct command_node command_list[] = {
    {"version",         process_version},
#if 0	
    {"verext",          process_verext},
#ifdef HS_SUPPORT
    {"hssetpara",       process_hssetpara},
#endif
#endif
    {"hscfg",           process_hscfg},
#if 0
#ifdef HS_SUPPORT
    {"wakeupreason",    process_wakeupresaon},
    {"mgmtfilter",      process_mgmtfilter},
#endif
#endif
};

static char    *usage[] = {
    "Usage: ",
    "   mlanutl -v  (version)",
    "   mlanutl <ifname> <cmd> [...]",
    "   where",
    "   ifname : wireless network interface name, such as mlanX or uapX",
    "   cmd :",
    "         version",
    "         verext",
#ifdef HS_SUPPORT
    "         hssetpara",
#endif
    "         hscfg",
};

static 	struct nl80211_state nlstate;

/**
 *  @brief Process hscfg configuration
 *  @param argc   Number of arguments
 *  @param argv   A pointer to arguments array
 *  @return     MLAN_STATUS_SUCCESS--success, otherwise--fail
 */
static int process_hscfg(int argc, char *argv[])
{
    __u8 *buffer = NULL;
    char hscfg[3] = {0};
	struct nl_msg *msg;
	signed long long devidx = 0;

    fprintf(stdout, "enter %s\n", __FUNCTION__);

	msg = nlmsg_alloc();
	if (!msg) {
		fprintf(stderr, "failed to allocate netlink message\n");
		return 2;
	}

    genlmsg_put(msg, 0, 0, nlstate.nl80211_id, 0,
	            0, NL80211_CMD_VENDOR, 0);
	devidx = if_nametoindex(argv[1]);

	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, devidx);

	NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_ID, NXP_OUI);
	NLA_PUT_U32(msg, NL80211_ATTR_VENDOR_SUBCMD, NXPWIFI_VENDOR_CMD_HSCFG);
    //nest_ptr = nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA);

	sscanf(argv[3], "0x%x", hscfg);
	sscanf(argv[4], "0x%x", hscfg + 1);
	sscanf(argv[5], "0x%x", hscfg + 2);

    fprintf(stdout, "hscfg %x %d %d\n", *hscfg, *(hscfg + 1), *(hscfg + 2));

	NLA_PUT(msg, NL80211_ATTR_VENDOR_DATA, 3, hscfg);

	//nl_recvmsgs(nlstate.nl_sock, NULL);
	nl_send_auto(nlstate.nl_sock, msg);

nla_put_failure:
    return 0;
}

/**
 *  @brief Process version
 *  @param argc   Number of arguments
 *  @param argv   A pointer to arguments array
 *  @return     MLAN_STATUS_SUCCESS--success, otherwise--fail
 */
static int process_version(int argc, char *argv[])
{
    __u8 *buffer = NULL;
#if 0
    /* Initialize buffer */
    buffer = (t_u8 *) malloc(BUFFER_LENGTH);
    if (!buffer) {
        printf("ERR:Cannot allocate buffer for command!\n");
        return MLAN_STATUS_FAILURE;
    }

    prepare_buffer(buffer, argv[2], 0, NULL);

    cmd = (struct eth_priv_cmd *) malloc(sizeof(struct eth_priv_cmd));
    if (!cmd) {
        printf("ERR:Cannot allocate buffer for command!\n");
        free(buffer);
        return MLAN_STATUS_FAILURE;
    }

    /* Fill up buffer */
#ifdef USERSPACE_32BIT_OVER_KERNEL_64BIT
    memset(cmd, 0, sizeof(struct eth_priv_cmd));
    memcpy(&cmd->buf, &buffer, sizeof(buffer));
#else
    cmd->buf = buffer;
#endif
    cmd->used_len = 0;
    cmd->total_len = BUFFER_LENGTH;

    /* Perform IOCTL */
    memset(&ifr, 0, sizeof(struct ifreq));
    strncpy(ifr.ifr_ifrn.ifrn_name, dev_name, strlen(dev_name));
    ifr.ifr_ifru.ifru_data = (void *) cmd;

    if (ioctl(sockfd, MLAN_ETH_PRIV, &ifr)) {
        perror("mlanutl");
        fprintf(stderr, "mlanutl: version fail\n");
        if (cmd)
            free(cmd);
        if (buffer)
            free(buffer);
        return MLAN_STATUS_FAILURE;
    }

    /* Process result */
    printf("Version string received: %s\n", buffer);

    if (buffer)
        free(buffer);
    if (cmd)
        free(cmd);
#endif
    return 0;
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

void register_handler(int (*handler)(struct nl_msg *, void *), void *data)
{
	registered_handler = handler;
	registered_handler_data = data;
}

int valid_handler(struct nl_msg *msg, void *arg)
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
