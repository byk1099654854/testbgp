/*
 * Interface function.
 * Copyright (C) 1997, 1999 Kunihiro Ishiguro
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNU Zebra; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#include <zebra.h>
#include "if.h"
#include "vty.h"
#include "sockunion.h"
#include "prefix.h"
#include "command.h"
#include "memory.h"
#include "ioctl.h"
#include "connected.h"
#include "log.h"
#include "zclient.h"

#include "zebra/interface.h"
#include "zebra/rtadv.h"
#include "zebra/rib.h"
#include "zebra/zserv.h"
#include "zebra/redistribute.h"
#include "zebra/debug.h"
#include "zebra/irdp.h"
/*sangmeng add for filter show*/
#include "lib/filter.h"

//add by zhangzhibo for arp_cmd
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <string.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/socket.h>
#include <sys/param.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <netdb.h>
#include <net/if.h>
#include <netinet/if_ether.h>

#define KEEP_CONFIG_SIZE 50
#define NETLINK_TEST 17
#define MAX_PAYLOAD 1024  /* maximum payload size*/
extern struct list *iflist;
static int
ipv6_address_uninstall (struct vty *vty, struct interface *ifp,
                        const char *addr_str, const char *peer_str,
                        const char *label, int secondry);


static int
ip_address_uninstall (struct vty *vty, struct interface *ifp,
                      const char *addr_str, const char *peer_str,
                      const char *label);


int interface_AddressIsConfigured(struct vty *vty, struct interface *ifp, struct prefix *p);
struct nd_config
{
    char ip[50];
    char mac[19];
    char arp_dev[21];
} nd_keep_config[KEEP_CONFIG_SIZE];
int zj=0;

#ifdef RTADV
/* Order is intentional.  Matches RFC4191.  This array is also used for
   command matching, so only modify with care. */
const char *rtadv_pref_strs[] = { "medium", "high", "INVALID", "low", 0 };
#endif /* RTADV */

DEFUN (ipv6_nd_neighbor,
       ipv6_nd_neighbor_cmd,
       "ipv6 nd neighbor X:X:X:X::X HH:HH:HH:HH:HH:HH",
       "Interface IPv6 config commands\n"
       "IPv6 interface Neighbor Discovery subcommands\n"
       "Neighbor\n"
       "IPv6 address(e.g.1000::1)\n"
       "MAC address (e.g.10:50:56:f4:89:8f)\n"
      )
{
    struct interface* fp3=vty->index;
    struct zebra_if *if_data;
    if_data=fp3->info;
    if_data->nd= ND_INTERFACE;
    int i=0,flag=1;
    //printf("the ipv6 vty->index is %s",vty->index);
    char s[100];
    memset(s,0,sizeof(s));
    strcpy(s,"ip -6 neigh add ");
    strcat(s,argv[0]);
    //strcpy(nd_keep_config[zj].ip,argv[0]);
    strcat(s," lladdr ");
    strcat(s,argv[1]);
    //strcpy(nd_keep_config[zj].mac,argv[1]);
    strcat(s," dev ");
    strcat(s,fp3->name);
    for(i=0; i<KEEP_CONFIG_SIZE; i++)
    {
        if(strcmp(nd_keep_config[i].ip,argv[0])==0)
        {
            flag=0;
            break;
        }
    }
    if(system(s)!=0)
    {
        vty_out(vty,"Invalid input\n");

    }
    else if(flag==1)
    {
        strcpy(nd_keep_config[zj].ip,argv[0]);
        strcpy(nd_keep_config[zj].mac,argv[1]);
        strcpy(nd_keep_config[zj].arp_dev,fp3->name);
    }
    //execute_command ("ip -6 neigh add", 1, argv[0], NULL);
    zj=(zj+1)%KEEP_CONFIG_SIZE;

    return CMD_SUCCESS;
}


DEFUN (no_ipv6_nd_neighbor,
       no_ipv6_nd_neighbor_cmd,
       "no ipv6 nd neighbor X:X:X:X::X",
       "Negate a command or set its defaults\n"
       "Interface IPv6 config commands\n"
       "IPv6 interface Neighbor Discovery subcommands\n"
       "Neighbor\n"
       "IPv6 address(e.g.1000::1)\n"
      )
{
    struct interface* fp3=vty->index;
    struct zebra_if*if_data;
    if_data=fp3->info;
    if_data->nd=NO_NDINTERFACE;
    //printf("the ipv6 vty->index is %s",vty->index);
    char s[100];
    memset(s,0,sizeof(s));
    strcpy(s,"ip -6 neigh del ");
    strcat(s,argv[0]);
    strcat(s," dev ");
    strcat(s,fp3->name);
    //execute_command ("ip -6 neigh del", 1, argv[0], NULL);
    system(s);
    int j=0;
    for(j=0; j<KEEP_CONFIG_SIZE; j++)
        if(strcmp(nd_keep_config[j].ip,argv[0])==0)
            memset(&nd_keep_config[j],0,sizeof(struct nd_config));

    return CMD_SUCCESS;
}


/*sangmeng add for speed&duplex*/
#if 1

#ifndef SIOCETHTOOL
#define SIOCETHTOOL     0x8946
#endif

#define ETHTOOL_GSET		0x00000001	/* Get settings. */
#define ETHTOOL_SSET		0x00000002	/* Set settings. */

/* Enable or disable autonegotiation.  If this is set to enable,
 *  * the forced link modes above are completely ignored.
 *   */
#define AUTONEG_DISABLE		0x00
#define AUTONEG_ENABLE		0x01

/* The forced speed, 10Mb, 100Mb, gigabit, 2.5Gb, 10GbE. */
#define SPEED_10		10
#define SPEED_100		100
#define SPEED_1000		1000
#define SPEED_2500		2500
#define SPEED_10000		10000

/* Duplex, half or full. */
#define DUPLEX_HALF		0x00
#define DUPLEX_FULL		0x01

/* Duplex, half or full. */
#define DUPLEX_UN		1<<1
#define DUPLEX_HA		1<<2
#define DUPLEX_FU		1<<3

#define SPEED_UN        1<<4
#define SPEED_TEN   	1<<5
#define SPEED_HUN  	1<<6
#define SPEED_THOUS 	1<<7

/* Indicates what features are supported by the interface. */
#define SUPPORTED_10baseT_Half		(1 << 0)
#define SUPPORTED_10baseT_Full		(1 << 1)
#define SUPPORTED_100baseT_Half		(1 << 2)
#define SUPPORTED_100baseT_Full		(1 << 3)
#define SUPPORTED_1000baseT_Half	(1 << 4)
#define SUPPORTED_1000baseT_Full	(1 << 5)
#define SUPPORTED_Autoneg		(1 << 6)
#define SUPPORTED_TP			(1 << 7)
#define SUPPORTED_AUI			(1 << 8)
#define SUPPORTED_MII			(1 << 9)
#define SUPPORTED_FIBRE			(1 << 10)
#define SUPPORTED_BNC			(1 << 11)
#define SUPPORTED_10000baseT_Full	(1 << 12)
#define SUPPORTED_Pause			(1 << 13)
#define SUPPORTED_Asym_Pause		(1 << 14)
#define SUPPORTED_2500baseX_Full	(1 << 15)
#define SUPPORTED_Backplane		(1 << 16)
#define SUPPORTED_1000baseKX_Full	(1 << 17)
#define SUPPORTED_10000baseKX4_Full	(1 << 18)
#define SUPPORTED_10000baseKR_Full	(1 << 19)
#define SUPPORTED_10000baseR_FEC	(1 << 20)

/* Indicates what features are advertised by the interface. */
#define ADVERTISED_10baseT_Half		(1 << 0)
#define ADVERTISED_10baseT_Full		(1 << 1)
#define ADVERTISED_100baseT_Half	(1 << 2)
#define ADVERTISED_100baseT_Full	(1 << 3)
#define ADVERTISED_1000baseT_Half	(1 << 4)
#define ADVERTISED_1000baseT_Full	(1 << 5)
#define ADVERTISED_Autoneg		(1 << 6)
#define ADVERTISED_TP			(1 << 7)
#define ADVERTISED_AUI			(1 << 8)
#define ADVERTISED_MII			(1 << 9)
#define ADVERTISED_FIBRE		(1 << 10)
#define ADVERTISED_BNC			(1 << 11)
#define ADVERTISED_10000baseT_Full	(1 << 12)
#define ADVERTISED_Pause		(1 << 13)
#define ADVERTISED_Asym_Pause		(1 << 14)
#define ADVERTISED_2500baseX_Full	(1 << 15)
#define ADVERTISED_Backplane		(1 << 16)
#define ADVERTISED_1000baseKX_Full	(1 << 17)
#define ADVERTISED_10000baseKX4_Full	(1 << 18)
#define ADVERTISED_10000baseKR_Full	(1 << 19)
#define ADVERTISED_10000baseR_FEC	(1 << 20)

typedef unsigned long long u64;
typedef __uint32_t u32;
typedef __uint16_t u16;
typedef __uint8_t u8;
typedef __int32_t s32;
/* This should work for both 32 and 64 bit userland. */
struct ethtool_cmd
{
    __u32 cmd;
    __u32 supported;			/* Features this interface supports */
    __u32 advertising;			/* Features this interface advertises */
    __u16 speed;				/* The forced speed, 10Mb, 100Mb, gigabit */
    __u8 duplex;				/* Duplex, half or full */
    __u8 port;					/*  connector port */
    __u8 phy_address;
    __u8 transceiver;			/* Whic transceiver to use */
    __u8 autoneg;				/* Enable or disable autonegotiation */
    __u8 mdio_support;
    __u32 maxtxpkt;				/* Tx pkts before generating tx int */
    __u32 maxrxpkt;				/* Rx pkts before generating rx int */
    __u16 speed_hi;
    __u8 eth_tp_mdix;
    __u8 reserved2;
    __u32 lp_advertising;		/* Features the link partner advertises */
    __u32 reserved[2];
};
static int send_ioctl (int fd, struct ifreq *ifr)
{
    return ioctl (fd, SIOCETHTOOL, ifr);
}

static __inline__ __u32 ethtool_cmd_speed (struct ethtool_cmd *ep)
{
    return (ep->speed_hi << 16) | ep->speed;
}
static __inline__ void ethtool_cmd_speed_set(struct ethtool_cmd *ep,
        __u32 speed)
{

    ep->speed = (__u16)speed;
    ep->speed_hi = (__u16)(speed >> 16);
}
static int dump_ecmd (struct ethtool_cmd *ep)
{
    u32 speed;
    int speed_duplex;
#ifdef DEBUG
    fprintf (stdout, "%s", "	Speed: ");
#endif

    speed = ethtool_cmd_speed (ep);

    if (speed == 0 || speed == (u16) (-1) || speed == (u32) (-1))
    {
#ifdef DEBUG
        fprintf (stdout, "%s", "Unknown!\n");
#endif
        speed_duplex = SPEED_UN;
    }
    else
    {
#ifdef DEBUG
        fprintf (stdout, "%uMb/s\n", speed);
#endif
    }

    if (speed == 10)
        speed_duplex = SPEED_TEN;
    else if (speed == 100)
        speed_duplex = SPEED_HUN;
    else if (speed == 1000)
        speed_duplex = SPEED_THOUS;

#ifdef DEBUG
    fprintf (stdout, "%s", "	Duplex: ");
#endif
    switch (ep->duplex)
    {
    case DUPLEX_HALF:
#ifdef DEBUG
        fprintf (stdout, "%s", "Half\n");
#endif
        speed_duplex |= DUPLEX_HA;
        break;
    case DUPLEX_FULL:
#ifdef DEBUG
        fprintf (stdout, "%s", "Full\n");
#endif
        speed_duplex |= DUPLEX_FU;
        break;
    default:
#ifdef DEBUG
        fprintf (stdout, "Unknown! (%i)\n", ep->duplex);
#endif
        speed_duplex |= DUPLEX_UN;
        break;
    };
#ifdef DEBUG
    printf ("speed duplex:%0x\n", speed_duplex);
#endif
    return speed_duplex;

}

static int do_gset (int fd, struct ifreq *ifr)
{
    int err;
    int speed_duplex;
    struct ethtool_cmd ecmd;
    /*sangmeng mark here */

    ecmd.cmd = ETHTOOL_GSET;
    ifr->ifr_data = (caddr_t) & ecmd;
    err = send_ioctl (fd, ifr);
    if (err == 0)
    {
        speed_duplex = dump_ecmd (&ecmd);	/*sangmeng mark here */
        return speed_duplex;
    }
    else if (errno != EOPNOTSUPP)
    {
        perror ("Cannot get device settings");
    }
    return -1;

}

static int get_net_device_speed_duplex (int fd, struct ifreq *ifr)
{
    int speed_duplex;
    speed_duplex = do_gset (fd, ifr);
    return speed_duplex;
}

static int do_sset (int fd, struct ifreq *ifr, int speed_mode)
{
    int err;
    struct ethtool_cmd ecmd;

    ecmd.cmd = ETHTOOL_GSET;
    ifr->ifr_data = (caddr_t)&ecmd;
    err = send_ioctl(fd, ifr);
    if (err < 0)
    {
        printf("err 1\n");
        perror("Cannot get current device settings");
    }
    else
    {
        ethtool_cmd_speed_set(&ecmd, speed_mode);
        ecmd.duplex = DUPLEX_FULL;
        if (speed_mode == 10)
            ecmd.autoneg = AUTONEG_DISABLE;
        else if (speed_mode == 1000)
            ecmd.autoneg = AUTONEG_ENABLE;

        /* Try to perform the update. */
        ecmd.cmd = ETHTOOL_SSET;
        ifr->ifr_data = (caddr_t)&ecmd;
        err = send_ioctl(fd, ifr);
        if (err < 0)
        {
            printf("err 2\n");
            perror("Cannot set new settings");
        }
        else
            printf("set speed:%d &duplex full success\n", speed_mode);
    }

    return 0;
}

static int set_net_device_speed_duplex (int fd, struct ifreq *ifr, int speed_mode)
{
    do_sset (fd, ifr, speed_mode);
    return 0;
}
int doit(char *ifname, int flag, int speed_mode)
{
    int fd;
    struct ifreq ifr;
    int speed_duplex = 0;
    /* Setup our control structures. */
    memset (&ifr, 0, sizeof (ifr));
    strcpy (ifr.ifr_name, ifname);

    /* Open control socket. */
    fd = socket (AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
    {
        perror ("Cannot get control socket");
        return 0;
    }
    if (flag == 0)
    {
        speed_duplex =get_net_device_speed_duplex (fd, &ifr);
    }
    else if (flag == 1)
    {
        printf("set speed duplex\n");
        set_net_device_speed_duplex(fd, &ifr, speed_mode);
    }

    close (fd);

    return speed_duplex;
}

#endif





/* Called when new interface is added. */
static int
if_zebra_new_hook (struct interface *ifp)
{
    struct zebra_if *zebra_if;

    zebra_if = XCALLOC (MTYPE_TMP, sizeof (struct zebra_if));

    zebra_if->multicast = IF_ZEBRA_MULTICAST_UNSPEC;
    zebra_if->shutdown = IF_ZEBRA_SHUTDOWN_UNSPEC;

    //added for nat 20130508
    zebra_if->nat = NO_NAT;

#ifdef RTADV
    {
        /* Set default router advertise values. */
        struct rtadvconf *rtadv;

        rtadv = &zebra_if->rtadv;

        rtadv->AdvSendAdvertisements = 0;
        rtadv->MaxRtrAdvInterval = RTADV_MAX_RTR_ADV_INTERVAL;
        rtadv->MinRtrAdvInterval = RTADV_MIN_RTR_ADV_INTERVAL;
        rtadv->AdvIntervalTimer = 0;
        rtadv->AdvManagedFlag = 0;
        rtadv->AdvOtherConfigFlag = 0;
        rtadv->AdvHomeAgentFlag = 0;
        rtadv->AdvLinkMTU = 0;
        rtadv->AdvReachableTime = 0;
        rtadv->AdvRetransTimer = 0;
        rtadv->AdvCurHopLimit = 0;
        rtadv->AdvDefaultLifetime = -1; /* derive from MaxRtrAdvInterval */
        rtadv->HomeAgentPreference = 0;
        rtadv->HomeAgentLifetime = -1; /* derive from AdvDefaultLifetime */
        rtadv->AdvIntervalOption = 0;
        rtadv->DefaultPreference = RTADV_PREF_MEDIUM;

        rtadv->AdvPrefixList = list_new ();
    }
#endif /* RTADV */

    /* Initialize installed address chains tree. */
    zebra_if->ipv4_subnets = route_table_init ();

    ifp->info = zebra_if;
    return 0;
}

/* Called when interface is deleted. */
static int
if_zebra_delete_hook (struct interface *ifp)
{
    struct zebra_if *zebra_if;

    if (ifp->info)
    {
        zebra_if = ifp->info;

        /* Free installed address chains tree. */
        if (zebra_if->ipv4_subnets)
            route_table_finish (zebra_if->ipv4_subnets);

        XFREE (MTYPE_TMP, zebra_if);
    }

    return 0;
}

#if 1
/* Tie an interface address to its derived subnet list of addresses. */
int
if_subnet_add_new (struct interface *ifp, struct connected *ifc)
{
    struct route_node *rn;
    struct zebra_if *zebra_if;
    struct prefix cp;
    struct list *addr_list;

    assert (ifp && ifp->info && ifc);
    zebra_if = ifp->info;

    /* Get address derived subnet node and associated address list, while marking
       address secondary attribute appropriately. */
    cp = *ifc->address;
    apply_mask (&cp);
    rn = route_node_get (zebra_if->ipv4_subnets, &cp);

    if ((addr_list = rn->info))
    {
        return 0;
        SET_FLAG (ifc->flags, ZEBRA_IFA_SECONDARY);
    }
    else
    {
        UNSET_FLAG (ifc->flags, ZEBRA_IFA_SECONDARY);
        rn->info = addr_list = list_new ();
        route_lock_node (rn);
    }

    /* Tie address at the tail of address list. */
    listnode_add (addr_list, ifc);

    /* Return list element count. */
    return (addr_list->count);
}
#endif




/* Tie an interface address to its derived subnet list of addresses. */
int
if_subnet_add (struct interface *ifp, struct connected *ifc)
{
    struct route_node *rn;
    struct zebra_if *zebra_if;
    struct prefix cp;
    struct list *addr_list;

    assert (ifp && ifp->info && ifc);
    zebra_if = ifp->info;

    /* Get address derived subnet node and associated address list, while marking
       address secondary attribute appropriately. */
    cp = *ifc->address;
    apply_mask (&cp);
    rn = route_node_get (zebra_if->ipv4_subnets, &cp);

    if ((addr_list = rn->info))
        SET_FLAG (ifc->flags, ZEBRA_IFA_SECONDARY);
    else
    {
        UNSET_FLAG (ifc->flags, ZEBRA_IFA_SECONDARY);
        rn->info = addr_list = list_new ();
        route_lock_node (rn);
    }

    /* Tie address at the tail of address list. */
    listnode_add (addr_list, ifc);

    /* Return list element count. */
    return (addr_list->count);
}

/* Untie an interface address from its derived subnet list of addresses. */
int
if_subnet_delete (struct interface *ifp, struct connected *ifc)
{
    struct route_node *rn;
    struct zebra_if *zebra_if;
    struct list *addr_list;

    assert (ifp && ifp->info && ifc);
    zebra_if = ifp->info;

    /* Get address derived subnet node. */
    rn = route_node_lookup (zebra_if->ipv4_subnets, ifc->address);
    if (! (rn && rn->info))
        return -1;
    route_unlock_node (rn);

    /* Untie address from subnet's address list. */
    addr_list = rn->info;
    listnode_delete (addr_list, ifc);
    route_unlock_node (rn);

    /* Return list element count, if not empty. */
    if (addr_list->count)
    {
        /* If deleted address is primary, mark subsequent one as such and distribute. */
        if (! CHECK_FLAG (ifc->flags, ZEBRA_IFA_SECONDARY))
        {
            ifc = listgetdata (listhead (addr_list));
            zebra_interface_address_delete_update (ifp, ifc);
            UNSET_FLAG (ifc->flags, ZEBRA_IFA_SECONDARY);
            zebra_interface_address_add_update (ifp, ifc);
        }

        return addr_list->count;
    }

    /* Otherwise, free list and route node. */
    list_free (addr_list);
    rn->info = NULL;
    route_unlock_node (rn);

    return 0;
}

/* if_flags_mangle: A place for hacks that require mangling
 * or tweaking the interface flags.
 *
 * ******************** Solaris flags hacks **************************
 *
 * Solaris IFF_UP flag reflects only the primary interface as the
 * routing socket only sends IFINFO for the primary interface.  Hence
 * ~IFF_UP does not per se imply all the logical interfaces are also
 * down - which we only know of as addresses. Instead we must determine
 * whether the interface really is up or not according to how many
 * addresses are still attached. (Solaris always sends RTM_DELADDR if
 * an interface, logical or not, goes ~IFF_UP).
 *
 * Ie, we mangle IFF_UP to *additionally* reflect whether or not there
 * are addresses left in struct connected, not just the actual underlying
 * IFF_UP flag.
 *
 * We must hence remember the real state of IFF_UP, which we do in
 * struct zebra_if.primary_state.
 *
 * Setting IFF_UP within zebra to administratively shutdown the
 * interface will affect only the primary interface/address on Solaris.
 ************************End Solaris flags hacks ***********************
 */
static void
if_flags_mangle (struct interface *ifp, uint64_t *newflags)
{
#ifdef SUNOS_5
    struct zebra_if *zif = ifp->info;

    zif->primary_state = *newflags & (IFF_UP & 0xff);

    if (CHECK_FLAG (zif->primary_state, IFF_UP)
            || listcount(ifp->connected) > 0)
        SET_FLAG (*newflags, IFF_UP);
    else
        UNSET_FLAG (*newflags, IFF_UP);
#endif /* SUNOS_5 */
}

/* Update the flags field of the ifp with the new flag set provided.
 * Take whatever actions are required for any changes in flags we care
 * about.
 *
 * newflags should be the raw value, as obtained from the OS.
 */
void
if_flags_update (struct interface *ifp, uint64_t newflags)
{
    if_flags_mangle (ifp, &newflags);

    if (if_is_operative (ifp))
    {
        /* operative -> inoperative? */
        ifp->flags = newflags;
        if (!if_is_operative (ifp))
            if_down (ifp);
    }
    else
    {
        /* inoperative -> operative? */
        ifp->flags = newflags;
        if (if_is_operative (ifp))
            if_up (ifp);
    }
}

/* Wake up configured address if it is not in current kernel
   address. */
static void
if_addr_wakeup (struct interface *ifp)
{
    struct listnode *node, *nnode;
    struct connected *ifc;
    struct prefix *p;
    int ret;

    for (ALL_LIST_ELEMENTS (ifp->connected, node, nnode, ifc))
    {
        p = ifc->address;

        if (CHECK_FLAG (ifc->conf, ZEBRA_IFC_CONFIGURED)
                && ! CHECK_FLAG (ifc->conf, ZEBRA_IFC_REAL))
        {
            /* Address check. */
            if (p->family == AF_INET)
            {
                if (! if_is_up (ifp))
                {
                    /* XXX: WTF is it trying to set flags here?
                     * caller has just gotten a new interface, has been
                             * handed the flags already. This code has no business
                             * trying to override administrative status of the interface.
                             * The only call path to here which doesn't originate from
                             * kernel event is irdp - what on earth is it trying to do?
                             *
                             * further RUNNING is not a settable flag on any system
                             * I (paulj) am aware of.
                             */
                    if_set_flags (ifp, IFF_UP | IFF_RUNNING);
                    if_refresh (ifp);
                }

                ret = if_set_prefix (ifp, ifc);
                if (ret < 0)
                {
                    zlog_warn ("Can't set interface's address: %s",
                               safe_strerror(errno));
                    continue;
                }

                /* Add to subnet chain list. */
                if_subnet_add (ifp, ifc);

                SET_FLAG (ifc->conf, ZEBRA_IFC_REAL);

                zebra_interface_address_add_update (ifp, ifc);

                if (if_is_operative(ifp))
                    connected_up_ipv4 (ifp, ifc);
            }
#ifdef HAVE_IPV6
            if (p->family == AF_INET6)
            {
                if (! if_is_up (ifp))
                {
                    /* XXX: See long comment above */
                    if_set_flags (ifp, IFF_UP | IFF_RUNNING);
                    if_refresh (ifp);
                }

                ret = if_prefix_add_ipv6 (ifp, ifc);
                if (ret < 0)
                {
                    zlog_warn ("Can't set interface's address: %s",
                               safe_strerror(errno));
                    continue;
                }
                SET_FLAG (ifc->conf, ZEBRA_IFC_REAL);

                zebra_interface_address_add_update (ifp, ifc);

                if (if_is_operative(ifp))
                    connected_up_ipv6 (ifp, ifc);
            }
#endif /* HAVE_IPV6 */
        }
    }
}

/* Handle interface addition */
void
if_add_update (struct interface *ifp)
{
    struct zebra_if *if_data;

    if_data = ifp->info;
    if (if_data->multicast == IF_ZEBRA_MULTICAST_ON)
        if_set_flags (ifp, IFF_MULTICAST);
    else if (if_data->multicast == IF_ZEBRA_MULTICAST_OFF)
        if_unset_flags (ifp, IFF_MULTICAST);

    zebra_interface_add_update (ifp);

    if (! CHECK_FLAG (ifp->status, ZEBRA_INTERFACE_ACTIVE))
    {
        SET_FLAG (ifp->status, ZEBRA_INTERFACE_ACTIVE);

        if_addr_wakeup (ifp);

        if (IS_ZEBRA_DEBUG_KERNEL)
            zlog_debug ("interface %s index %d becomes active.",
                        ifp->name, ifp->ifindex);
    }
    else
    {
        if (IS_ZEBRA_DEBUG_KERNEL)
            zlog_debug ("interface %s index %d is added.", ifp->name, ifp->ifindex);
    }
}

/* Handle an interface delete event */
void
if_delete_update (struct interface *ifp)
{
    struct connected *ifc;
    struct prefix *p;
    struct route_node *rn;
    struct zebra_if *zebra_if;

    zebra_if = ifp->info;

    if (if_is_up(ifp))
    {
        printf("interface %s index %d is still up while being deleted.",
               ifp->name, ifp->ifindex);


        zlog_err ("interface %s index %d is still up while being deleted.",
                  ifp->name, ifp->ifindex);
        return;
    }

    /* Mark interface as inactive */
    UNSET_FLAG (ifp->status, ZEBRA_INTERFACE_ACTIVE);

    if (IS_ZEBRA_DEBUG_KERNEL)
        zlog_debug ("interface %s index %d is now inactive.",
                    ifp->name, ifp->ifindex);

    /* Delete connected routes from the kernel. */
    if (ifp->connected)
    {
        struct listnode *node;
        struct listnode *last = NULL;

        while ((node = (last ? last->next : listhead (ifp->connected))))
        {
            ifc = listgetdata (node);
            p = ifc->address;

            if (p->family == AF_INET
                    && (rn = route_node_lookup (zebra_if->ipv4_subnets, p)))
            {
                struct listnode *anode;
                struct listnode *next;
                struct listnode *first;
                struct list *addr_list;

                route_unlock_node (rn);
                addr_list = (struct list *) rn->info;

                /* Remove addresses, secondaries first. */
                first = listhead (addr_list);
                for (anode = first->next; anode || first; anode = next)
                {
                    if (!anode)
                    {
                        anode = first;
                        first = NULL;
                    }
                    next = anode->next;

                    ifc = listgetdata (anode);
                    p = ifc->address;

                    connected_down_ipv4 (ifp, ifc);

                    zebra_interface_address_delete_update (ifp, ifc);

                    UNSET_FLAG (ifc->conf, ZEBRA_IFC_REAL);

                    /* Remove from subnet chain. */
                    list_delete_node (addr_list, anode);
                    route_unlock_node (rn);

                    /* Remove from interface address list (unconditionally). */
                    if (!CHECK_FLAG (ifc->conf, ZEBRA_IFC_CONFIGURED))
                    {
                        listnode_delete (ifp->connected, ifc);
                        connected_free (ifc);
                    }
                    else
                        last = node;
                }

                /* Free chain list and respective route node. */
                list_delete (addr_list);
                rn->info = NULL;
                route_unlock_node (rn);
            }
#ifdef HAVE_IPV6
            else if (p->family == AF_INET6)
            {
                connected_down_ipv6 (ifp, ifc);

                zebra_interface_address_delete_update (ifp, ifc);

                UNSET_FLAG (ifc->conf, ZEBRA_IFC_REAL);

                if (CHECK_FLAG (ifc->conf, ZEBRA_IFC_CONFIGURED))
                    last = node;
                else
                {
                    listnode_delete (ifp->connected, ifc);
                    connected_free (ifc);
                }
            }
#endif /* HAVE_IPV6 */
            else
            {
                last = node;
            }
        }
    }
    zebra_interface_delete_update (ifp);

    /* Update ifindex after distributing the delete message.  This is in
       case any client needs to have the old value of ifindex available
       while processing the deletion.  Each client daemon is responsible
       for setting ifindex to IFINDEX_INTERNAL after processing the
       interface deletion message. */


    //wjh del 20190110
    //ifp->ifindex = IFINDEX_INTERNAL;
}

/* Interface is up. */
void
if_up (struct interface *ifp)
{
    struct listnode *node;
    struct listnode *next;
    struct connected *ifc;
    struct prefix *p;

    /* Notify the protocol daemons. */
    zebra_interface_up_update (ifp);

    /* Install connected routes to the kernel. */
    if (ifp->connected)
    {
        for (ALL_LIST_ELEMENTS (ifp->connected, node, next, ifc))
        {
            p = ifc->address;

            if (p->family == AF_INET)
                connected_up_ipv4 (ifp, ifc);
#ifdef HAVE_IPV6
            else if (p->family == AF_INET6)
                connected_up_ipv6 (ifp, ifc);
#endif /* HAVE_IPV6 */
        }
    }

    /* Examine all static routes. */
    rib_update ();
}

/* Interface goes down.  We have to manage different behavior of based
   OS. */
void
if_down (struct interface *ifp)
{
    struct listnode *node;
    struct listnode *next;
    struct connected *ifc;
    struct prefix *p;

    /* Notify to the protocol daemons. */
    zebra_interface_down_update (ifp);

    /* Delete connected routes from the kernel. */
    if (ifp->connected)
    {
        for (ALL_LIST_ELEMENTS (ifp->connected, node, next, ifc))
        {
            p = ifc->address;

            if (p->family == AF_INET)
                connected_down_ipv4 (ifp, ifc);
#ifdef HAVE_IPV6
            else if (p->family == AF_INET6)
                connected_down_ipv6 (ifp, ifc);
#endif /* HAVE_IPV6 */
        }
    }

    /* Examine all static routes which direct to the interface. */
    rib_update ();
}

void
if_refresh (struct interface *ifp)
{
    //printf("-----in func:%s  ifp->flags & IFF_RUNNING = %d \n",__func__,ifp->flags & IFF_RUNNING);
    if_get_flags (ifp);
}

/* Output prefix string to vty. */
static int
prefix_vty_out (struct vty *vty, struct prefix *p)
{
    char str[INET6_ADDRSTRLEN];

    inet_ntop (p->family, &p->u.prefix, str, sizeof (str));
    vty_out (vty, "%s", str);
    return strlen (str);
}

/* Dump if address information to vty. */
static void
connected_dump_vty (struct vty *vty, struct connected *connected)
{
    struct prefix *p;

    /* Print interface address. */
    p = connected->address;
    vty_out (vty, "  %s ", prefix_family_str (p));
    prefix_vty_out (vty, p);
    vty_out (vty, "/%d", p->prefixlen);

    /* If there is destination address, print it. */
    if (connected->destination)
    {
        vty_out (vty, (CONNECTED_PEER(connected) ? " peer " : " broadcast "));
        prefix_vty_out (vty, connected->destination);
    }

    if (CHECK_FLAG (connected->flags, ZEBRA_IFA_SECONDARY))
        vty_out (vty, " secondary");

    if (connected->label)
        vty_out (vty, " %s", connected->label);

    vty_out (vty, "%s", VTY_NEWLINE);
}

#ifdef RTADV
/* Dump interface ND information to vty. */
static void
nd_dump_vty (struct vty *vty, struct interface *ifp)
{
    struct zebra_if *zif;
    struct rtadvconf *rtadv;
    int interval;

    zif = (struct zebra_if *) ifp->info;
    rtadv = &zif->rtadv;

    if (rtadv->AdvSendAdvertisements)
    {
        vty_out (vty, "  ND advertised reachable time is %d milliseconds%s",
                 rtadv->AdvReachableTime, VTY_NEWLINE);
        vty_out (vty, "  ND advertised retransmit interval is %d milliseconds%s",
                 rtadv->AdvRetransTimer, VTY_NEWLINE);
        interval = rtadv->MaxRtrAdvInterval;
        if (interval % 1000)
            vty_out (vty, "  ND router advertisements are sent every "
                     "%d milliseconds%s", interval,
                     VTY_NEWLINE);
        else
            vty_out (vty, "  ND router advertisements are sent every "
                     "%d seconds%s", interval / 1000,
                     VTY_NEWLINE);
        if (rtadv->AdvDefaultLifetime != -1)
            vty_out (vty, "  ND router advertisements live for %d seconds%s",
                     rtadv->AdvDefaultLifetime, VTY_NEWLINE);
        else
            vty_out (vty, "  ND router advertisements lifetime tracks ra-interval%s",
                     VTY_NEWLINE);
        vty_out (vty, "  ND router advertisement default router preference is "
                 "%s%s", rtadv_pref_strs[rtadv->DefaultPreference],
                 VTY_NEWLINE);
        if (rtadv->AdvManagedFlag)
            vty_out (vty, "  Hosts use DHCP to obtain routable addresses.%s",
                     VTY_NEWLINE);
        else
            vty_out (vty, "  Hosts use stateless autoconfig for addresses.%s",
                     VTY_NEWLINE);
        if (rtadv->AdvHomeAgentFlag)
        {
            vty_out (vty, "  ND router advertisements with "
                     "Home Agent flag bit set.%s",
                     VTY_NEWLINE);
            if (rtadv->HomeAgentLifetime != -1)
                vty_out (vty, "  Home Agent lifetime is %u seconds%s",
                         rtadv->HomeAgentLifetime, VTY_NEWLINE);
            else
                vty_out (vty, "  Home Agent lifetime tracks ra-lifetime%s",
                         VTY_NEWLINE);
            vty_out (vty, "  Home Agent preference is %u%s",
                     rtadv->HomeAgentPreference, VTY_NEWLINE);
        }
        if (rtadv->AdvIntervalOption)
            vty_out (vty, "  ND router advertisements with Adv. Interval option.%s",
                     VTY_NEWLINE);
    }
}
#endif /* RTADV */

/* Interface's information print out to vty interface. */
static void
if_dump_vty (struct vty *vty, struct interface *ifp)
{
#ifdef HAVE_STRUCT_SOCKADDR_DL
    struct sockaddr_dl *sdl;
#endif /* HAVE_STRUCT_SOCKADDR_DL */
    struct connected *connected;
    struct listnode *node;
    struct route_node *rn;
    struct zebra_if *zebra_if;

    zebra_if = ifp->info;

#if 0
    vty_out (vty, "Interface %s is ", ifp->name);
    if (if_is_up(ifp))
    {
        vty_out (vty, "up, line protocol ");

        if (CHECK_FLAG(ifp->status, ZEBRA_INTERFACE_LINKDETECTION))
        {
            if (if_is_running(ifp))
                vty_out (vty, "is up%s", VTY_NEWLINE);
            else
                vty_out (vty, "is down%s", VTY_NEWLINE);
        }
        else
        {
            vty_out (vty, "detection is disabled%s", VTY_NEWLINE);
        }
    }
    else
    {
        vty_out (vty, "down%s", VTY_NEWLINE);
    }
#endif
    if (CHECK_FLAG(ifp->status, ZEBRA_INTERFACE_LINKDETECTION))
    {
        vty_out (vty, "Interface %s is ", ifp->name);
        //if (if_is_up(ifp)) {
        //  vty_out (vty, "up, line protocol ");

        /* vty_out (vty, "is up%s", VTY_NEWLINE);*/


        if (CHECK_FLAG(ifp->status, ZEBRA_INTERFACE_LINKDETECTION))
        {
            if (if_is_running(ifp))
            {
                vty_out (vty, "up, line protocol ");
                vty_out (vty, "is up%s", VTY_NEWLINE);
            }
            else
            {
                vty_out (vty, "down, line protocol ");
                vty_out (vty, "is down%s", VTY_NEWLINE);
            }
        }
        else
        {
            vty_out (vty, "unknow state, line protocol ");
            vty_out (vty, "detection is disabled%s", VTY_NEWLINE);
        }

    }
    else
    {
        vty_out (vty, "Interface %s is ", ifp->name);
        if (if_is_up(ifp))
        {
            vty_out (vty, "up, line protocol ");

            /* vty_out (vty, "is up%s", VTY_NEWLINE);*/


            if (CHECK_FLAG(ifp->status, ZEBRA_INTERFACE_LINKDETECTION))
            {
                if (if_is_running(ifp))
                    vty_out (vty, "is up%s", VTY_NEWLINE);
                else
                    vty_out (vty, "is down%s", VTY_NEWLINE);
            }
            else
            {
                vty_out (vty, "detection is disabled%s", VTY_NEWLINE);
            }
        }
        else
        {
            vty_out (vty, "down%s", VTY_NEWLINE);
        }

    }
    if (ifp->desc)
        vty_out (vty, "  Description: %s%s", ifp->desc,
                 VTY_NEWLINE);
    if (ifp->ifindex == IFINDEX_INTERNAL)
    {
        vty_out(vty, "  pseudo interface%s", VTY_NEWLINE);
        return;
    }
    else if (! CHECK_FLAG (ifp->status, ZEBRA_INTERFACE_ACTIVE))
    {
        vty_out(vty, "  index %d inactive interface%s",
                ifp->ifindex,
                VTY_NEWLINE);
        return;
    }

    vty_out (vty, "  index %d metric %d mtu %d ",
             ifp->ifindex, ifp->metric, ifp->mtu);
#ifdef HAVE_IPV6
    if (ifp->mtu6 != ifp->mtu)
        vty_out (vty, "mtu6 %d ", ifp->mtu6);
#endif
    vty_out (vty, "%s  flags: %s%s", VTY_NEWLINE,
             if_flag_dump (ifp->flags), VTY_NEWLINE);

    /* Hardware address. */
#ifdef HAVE_STRUCT_SOCKADDR_DL
    sdl = &ifp->sdl;
    if (sdl != NULL && sdl->sdl_alen != 0)
    {
        int i;
        u_char *ptr;

        vty_out (vty, "  HWaddr: ");
        for (i = 0, ptr = (u_char *)LLADDR (sdl); i < sdl->sdl_alen; i++, ptr++)
            vty_out (vty, "%s%02x", i == 0 ? "" : ":", *ptr);
        vty_out (vty, "%s", VTY_NEWLINE);
    }
#else
    if (ifp->hw_addr_len != 0)
    {
        int i;

        vty_out (vty, "  HWaddr: ");
        for (i = 0; i < ifp->hw_addr_len; i++)
            vty_out (vty, "%s%02x", i == 0 ? "" : ":", ifp->hw_addr[i]);
        vty_out (vty, "%s", VTY_NEWLINE);
    }
#endif /* HAVE_STRUCT_SOCKADDR_DL */

    /* Bandwidth in kbps */
    if (ifp->bandwidth != 0)
    {
        vty_out(vty, "  bandwidth %u kbps", ifp->bandwidth);
        vty_out(vty, "%s", VTY_NEWLINE);
    }

    for (rn = route_top (zebra_if->ipv4_subnets); rn; rn = route_next (rn))
    {
        if (! rn->info)
            continue;

        for (ALL_LIST_ELEMENTS_RO ((struct list *)rn->info, node, connected))
            connected_dump_vty (vty, connected);
    }

    for (ALL_LIST_ELEMENTS_RO (ifp->connected, node, connected))
    {
        if (CHECK_FLAG (connected->conf, ZEBRA_IFC_REAL) &&
                (connected->address->family == AF_INET6))
            connected_dump_vty (vty, connected);
    }

#ifdef RTADV
    nd_dump_vty (vty, ifp);
#endif /* RTADV */

#ifdef HAVE_PROC_NET_DEV
    /* Statistics print out using proc file system. */
    vty_out (vty, "    %lu input packets (%lu multicast), %lu bytes, "
             "%lu dropped%s",
             ifp->stats.rx_packets, ifp->stats.rx_multicast,
             ifp->stats.rx_bytes, ifp->stats.rx_dropped, VTY_NEWLINE);

    vty_out (vty, "    %lu input errors, %lu length, %lu overrun,"
             " %lu CRC, %lu frame%s",
             ifp->stats.rx_errors, ifp->stats.rx_length_errors,
             ifp->stats.rx_over_errors, ifp->stats.rx_crc_errors,
             ifp->stats.rx_frame_errors, VTY_NEWLINE);

    vty_out (vty, "    %lu fifo, %lu missed%s", ifp->stats.rx_fifo_errors,
             ifp->stats.rx_missed_errors, VTY_NEWLINE);

    vty_out (vty, "    %lu output packets, %lu bytes, %lu dropped%s",
             ifp->stats.tx_packets, ifp->stats.tx_bytes,
             ifp->stats.tx_dropped, VTY_NEWLINE);

    vty_out (vty, "    %lu output errors, %lu aborted, %lu carrier,"
             " %lu fifo, %lu heartbeat%s",
             ifp->stats.tx_errors, ifp->stats.tx_aborted_errors,
             ifp->stats.tx_carrier_errors, ifp->stats.tx_fifo_errors,
             ifp->stats.tx_heartbeat_errors, VTY_NEWLINE);

    vty_out (vty, "    %lu window, %lu collisions%s",
             ifp->stats.tx_window_errors, ifp->stats.collisions, VTY_NEWLINE);
#endif /* HAVE_PROC_NET_DEV */

#ifdef HAVE_NET_RT_IFLIST
#if defined (__bsdi__) || defined (__NetBSD__)
    /* Statistics print out using sysctl (). */
    vty_out (vty, "    input packets %qu, bytes %qu, dropped %qu,"
             " multicast packets %qu%s",
             ifp->stats.ifi_ipackets, ifp->stats.ifi_ibytes,
             ifp->stats.ifi_iqdrops, ifp->stats.ifi_imcasts,
             VTY_NEWLINE);

    vty_out (vty, "    input errors %qu%s",
             ifp->stats.ifi_ierrors, VTY_NEWLINE);

    vty_out (vty, "    output packets %qu, bytes %qu, multicast packets %qu%s",
             ifp->stats.ifi_opackets, ifp->stats.ifi_obytes,
             ifp->stats.ifi_omcasts, VTY_NEWLINE);

    vty_out (vty, "    output errors %qu%s",
             ifp->stats.ifi_oerrors, VTY_NEWLINE);

    vty_out (vty, "    collisions %qu%s",
             ifp->stats.ifi_collisions, VTY_NEWLINE);
#else
    /* Statistics print out using sysctl (). */
    vty_out (vty, "    input packets %lu, bytes %lu, dropped %lu,"
             " multicast packets %lu%s",
             ifp->stats.ifi_ipackets, ifp->stats.ifi_ibytes,
             ifp->stats.ifi_iqdrops, ifp->stats.ifi_imcasts,
             VTY_NEWLINE);

    vty_out (vty, "    input errors %lu%s",
             ifp->stats.ifi_ierrors, VTY_NEWLINE);

    vty_out (vty, "    output packets %lu, bytes %lu, multicast packets %lu%s",
             ifp->stats.ifi_opackets, ifp->stats.ifi_obytes,
             ifp->stats.ifi_omcasts, VTY_NEWLINE);

    vty_out (vty, "    output errors %lu%s",
             ifp->stats.ifi_oerrors, VTY_NEWLINE);

    vty_out (vty, "    collisions %lu%s",
             ifp->stats.ifi_collisions, VTY_NEWLINE);
#endif /* __bsdi__ || __NetBSD__ */
#endif /* HAVE_NET_RT_IFLIST */
}

/* Wrapper hook point for zebra daemon so that ifindex can be set
 * DEFUN macro not used as extract.pl HAS to ignore this
 * See also interface_cmd in lib/if.c
 */
DEFUN_NOSH (zebra_interface,
            zebra_interface_cmd,
            "interface IFNAME",
            "Select an interface to configure\n"
            "Interface's name\n")
{
    int ret;
    struct interface * ifp;

    /* Call lib interface() */
    if ((ret = interface_cmd.func (self, vty, argc, argv)) != CMD_SUCCESS)
        return ret;

    ifp = vty->index;

    if (ifp->ifindex == IFINDEX_INTERNAL)
        /* Is this really necessary?  Shouldn't status be initialized to 0
           in that case? */
        UNSET_FLAG (ifp->status, ZEBRA_INTERFACE_ACTIVE);

    return ret;
}

DEFUN_NOSH (zebra_interfacegigabitethernet,
            zebra_interfacegigabitethernet_cmd,
            "interface gigabitethernet WORD",
            "Select an interface to configure\n"
            "Interface's name\n")
{
    int ret;
    struct interface * ifp;
    char name[20];
    int i,j;
    int if_status=0;
    memset(name,0,20);
    sscanf(argv[0],"vEth%d_%d",&i,&j);
    sprintf(name,"vEth%d_%d",i,j);


    if(i>4||i<=0)
    {
        vty_out (vty, "%% phynum must is [1,4]%s", name, VTY_NEWLINE);
        return CMD_WARNING;

    }

    if(j>=4||j<0)
    {
        vty_out (vty, "%% virnum must is [0,3]%s", name, VTY_NEWLINE);
        return CMD_WARNING;

    }

    memcpy(argv[0],name,20);

    if(!strcmp(name,"vEth1_0"))
    {
        vty_out (vty, "%% vEth1_0 is a control interface and cannot be configured %s", VTY_NEWLINE);
        return CMD_WARNING;
    }


    ifp = if_lookup_by_name (name);
    if(ifp == NULL)
    {
        vty_out (vty, "%% interface %s no exist!", name, VTY_NEWLINE);
        return CMD_WARNING;
    }
    // printf("ifp->isenable = %d\n",ifp->isenable);
    if(ifp->isenable == 0)
    {
        if_status = 1;
    }

    /*
        vty_out (vty, "  in zebra/interface.c  name : %s %s",argv[0], VTY_NEWLINE);
    	char name[20]= "GE3";
    	memcpy(argv[0],name,20);
        vty_out (vty, "  in zebra/interface.c  name : %s %s",argv[0], VTY_NEWLINE);

    */
    /* Call lib interface() */
    if ((ret = interfacegigabitethernet_cmd.func (self, vty, argc, argv)) != CMD_SUCCESS)
    {
        vty_out(vty,"in ret != CMD_SUCCESS 1 return\n");
        return ret;
    }

    ifp = vty->index;

    if (ifp->ifindex == IFINDEX_INTERNAL)
    {
        vty_out(vty,"in ifindex internal\n");
        /* Is this really necessary?  Shouldn't status be initialized to 0
           in that case? */
        UNSET_FLAG (ifp->status, ZEBRA_INTERFACE_ACTIVE);

    }

#if 1 //add wjh
    int speed_duplex = 0;
    char port_ifname[20];
    memset(port_ifname,0,20);
    int port_i ,port_j ;
    sscanf(ifp->name,"vEth%d_%d",&port_i,&port_j);
    sprintf(port_ifname,"vEth%d_0",port_i);
    //speed_duplex = doit (ifp->name, 0, 0);
    speed_duplex = doit (port_ifname, 0, 0);
//	printf(" %s --  speed_duplex = %d\n",port_ifname,speed_duplex);
#if _5U_DEVICE
    if(speed_duplex & SPEED_1000)
    {
        //	printf("1000M\n");
        SET_FLAG (ifp->flags, IFF_RUNNING);
    }
    else
    {

        //	printf("0M\n");
        UNSET_FLAG (ifp->flags, IFF_RUNNING);
    }
#else
    if(speed_duplex & SPEED_UN)
    {
        UNSET_FLAG (ifp->flags, IFF_RUNNING);
    }
    else
    {

        SET_FLAG (ifp->flags, IFF_RUNNING);
    }

#endif

#endif

//printf("if_status = %d\n",if_status);

    if(if_status == 1)
    {
#if 1
        if (! if_is_up (ifp))
        {
            if_set_flags (ifp, IFF_UP);
//	printf("-----in  func:%s lind:%d ifp->flags & IFF_RUNNING = %d \n",__func__,__LINE__,ifp->flags & IFF_RUNNING);
            if_refresh (ifp);
//	printf("-----in  func:%s ifp->flags & IFF_RUNNING = %d \n",__func__,ifp->flags & IFF_RUNNING);
        }
#endif
        //printf("******************************send dpdk*******************\n");
        send_interface_up_down_to_dpdk(vty,name,1);
    }


    write_file_for_dpdk_conf(vty);
    return ret;
}



DEFUN_NOSH (zebra_no_interfacegigabitethernet,
            zebra_no_interfacegigabitethernet_cmd,
            "no interface gigabitethernet WORD",
            "Select an interface to configure\n"
            "Interface's name\n")
{
    int ret;
    struct interface * ifp;
    char name[20];
    int i,j;
    struct listnode *addrnode;
    struct connected *ifc;
    struct zebra_if *if_data;
    struct prefix *p;




    memset(name,0,20);
    sscanf(argv[0],"vEth%d_%d",&i,&j);
    sprintf(name,"vEth%d_%d",i,j);


    if(i>4||i<=0)
    {
        vty_out (vty, "%% phynum must is [1,4]%s", name, VTY_NEWLINE);
        return CMD_WARNING;

    }

    if(j>=4||j<0)
    {
        vty_out (vty, "%% virnum must is [0,3]%s", name, VTY_NEWLINE);
        return CMD_WARNING;

    }

    memcpy(argv[0],name,20);
    //ifp = vty->index;
    ifp = NULL;

    if(ifp == NULL)
    {
        ifp = if_lookup_by_name (name);

        if (ifp == NULL)
        {
            vty_out (vty, "%% Interface %s does not exist%s", name, VTY_NEWLINE);
            return CMD_WARNING;
        }

    }

    //vty_out (vty, "%% ifp = %p ifp->isenable = %d %s", ifp,ifp->isenable, VTY_NEWLINE);
    if(0 == ifp->isenable)
    {
        vty_out (vty, "%% interface %s not exist %s", name, VTY_NEWLINE);
        return CMD_WARNING;

    }


    ifp->isenable = 0;
    ifp->vlan_id = 0;

    //if (ifp->ifindex == IFINDEX_INTERNAL)
    /* Is this really necessary?  Shouldn't status be initialized to 0
       in that case? */
    //  UNSET_FLAG (ifp->status, ZEBRA_INTERFACE_ACTIVE);

    //for (ALL_LIST_ELEMENTS_RO_2(ifp->connected, addrnode, ifc))
    //for (addrnode = listhead(ifp->connected),ifc = NULL;addrnode != NULL && (ifc = listgetdata(addrnode) ,1); )

    addrnode = listhead(ifp->connected);
    while(1)
    {

        ifc=NULL;
        if(addrnode == NULL)
            break;
        ifc = listgetdata(addrnode);
        if(ifc == NULL)
            break;

        if (CHECK_FLAG (ifc->conf, ZEBRA_IFC_CONFIGURED))
        {
            char buf[INET6_ADDRSTRLEN];
            p = ifc->address;

            char address[30];
            memset(address,0,30);
            inet_ntop (p->family, &p->u.prefix, buf, sizeof(buf));
            sprintf(address,"%s/%d",buf,p->prefixlen);
            //vty_out(vty,"address:%s%s",address,VTY_NEWLINE);
            if(p->family == AF_INET)
            {
                ret = ip_address_uninstall (vty, ifp,(const char *)address , NULL, NULL);

            }
            else if(p->family == AF_INET6)
            {
                ret = ipv6_address_uninstall (vty, ifp,(const char *)address , NULL, NULL, 0);
            }

            addrnode = listhead(ifp->connected);

        }
        else
        {
            addrnode = listnextnode(addrnode);
            //break;
        }
    }

    send_interface_up_down_to_dpdk(vty,name,0);
    write_file_for_dpdk_conf(vty);

    // return ret;
    return CMD_SUCCESS;
}

struct cmd_node interface_node =
{
    INTERFACE_NODE,
    "%s(config-if)# ",
    1
};

/* Interface name and statistics get function using proc file system
 * Copyright (C) 1999 Kunihiro Ishiguro
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNU Zebra; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#include <zebra.h>

#include "if.h"
#include "prefix.h"
#include "log.h"

#include "zebra/ioctl.h"
#include "zebra/connected.h"
#include "zebra/interface.h"

/* Proc filesystem one line buffer. */
#define PROCBUFSIZ                  1024

/* Path to device proc file system. */
#ifndef _PATH_PROC_NET_DEV
#define _PATH_PROC_NET_DEV        "/proc/net/dev"
#endif /* _PATH_PROC_NET_DEV */

/* Return statistics data pointer. */
static char *
interface_name_cut (char *buf, char **name)
{
    char *stat;

    /* Skip white space.  Line will include header spaces. */
    while (*buf == ' ')
        buf++;
    *name = buf;

    /* Cut interface name. */
    stat = strrchr (buf, ':');
    *stat++ = '\0';

    return stat;
}

/* Fetch each statistics field. */
static int
ifstat_dev_fields (int version, char *buf, struct interface *ifp)
{
    switch (version)
    {
    case 3:
        sscanf(buf,
               "%ld %ld %ld %ld %ld %ld %ld %ld %ld %ld %ld %ld %ld %ld %ld %ld",
               &ifp->stats.rx_bytes,
               &ifp->stats.rx_packets,
               &ifp->stats.rx_errors,
               &ifp->stats.rx_dropped,
               &ifp->stats.rx_fifo_errors,
               &ifp->stats.rx_frame_errors,
               &ifp->stats.rx_compressed,
               &ifp->stats.rx_multicast,

               &ifp->stats.tx_bytes,
               &ifp->stats.tx_packets,
               &ifp->stats.tx_errors,
               &ifp->stats.tx_dropped,
               &ifp->stats.tx_fifo_errors,
               &ifp->stats.collisions,
               &ifp->stats.tx_carrier_errors,
               &ifp->stats.tx_compressed);
        break;
    case 2:
        sscanf(buf, "%ld %ld %ld %ld %ld %ld %ld %ld %ld %ld %ld %ld %ld",
               &ifp->stats.rx_bytes,
               &ifp->stats.rx_packets,
               &ifp->stats.rx_errors,
               &ifp->stats.rx_dropped,
               &ifp->stats.rx_fifo_errors,
               &ifp->stats.rx_frame_errors,

               &ifp->stats.tx_bytes,
               &ifp->stats.tx_packets,
               &ifp->stats.tx_errors,
               &ifp->stats.tx_dropped,
               &ifp->stats.tx_fifo_errors,
               &ifp->stats.collisions,
               &ifp->stats.tx_carrier_errors);
        ifp->stats.rx_multicast = 0;
        break;
    case 1:
        sscanf(buf, "%ld %ld %ld %ld %ld %ld %ld %ld %ld %ld %ld",
               &ifp->stats.rx_packets,
               &ifp->stats.rx_errors,
               &ifp->stats.rx_dropped,
               &ifp->stats.rx_fifo_errors,
               &ifp->stats.rx_frame_errors,

               &ifp->stats.tx_packets,
               &ifp->stats.tx_errors,
               &ifp->stats.tx_dropped,
               &ifp->stats.tx_fifo_errors,
               &ifp->stats.collisions,
               &ifp->stats.tx_carrier_errors);
        ifp->stats.rx_bytes = 0;
        ifp->stats.tx_bytes = 0;
        ifp->stats.rx_multicast = 0;
        break;
    }
    return 0;
}

/* Update interface's statistics. */
void
ifstat_update_proc1 (void)
{
    FILE *fp;
    char buf[PROCBUFSIZ];
    int version;
    struct interface *ifp;
    char *stat;
    char *name;

    /* Open /proc/net/dev. */
    fp = fopen (_PATH_PROC_NET_DEV, "r");
    if (fp == NULL)
    {
        zlog_warn ("Can't open proc file %s: %s",
                   _PATH_PROC_NET_DEV, safe_strerror (errno));
        return;
    }

    /* Drop header lines. */
    fgets (buf, PROCBUFSIZ, fp);
    fgets (buf, PROCBUFSIZ, fp);

    /* To detect proc format veresion, parse second line. */
    if (strstr (buf, "compressed"))
        version = 3;
    else if (strstr (buf, "bytes"))
        version = 2;
    else
        version = 1;

    /* Update each interface's statistics. */
    while (fgets (buf, PROCBUFSIZ, fp) != NULL)
    {
        stat = interface_name_cut (buf, &name);
        ifp = if_get_by_name (name);
        ifstat_dev_fields (version, stat, ifp);
    }
    fclose(fp);
    return;
}

/* Interface structure allocation by proc filesystem. */
int
interface_list_proc ()
{
    FILE *fp;
    char buf[PROCBUFSIZ];
    struct interface *ifp;
    char *name;

    /* Open /proc/net/dev. */
    fp = fopen (_PATH_PROC_NET_DEV, "r");
    if (fp == NULL)
    {
        zlog_warn ("Can't open proc file %s: %s",
                   _PATH_PROC_NET_DEV, safe_strerror (errno));
        return -1;
    }

    /* Drop header lines. */
    fgets (buf, PROCBUFSIZ, fp);
    fgets (buf, PROCBUFSIZ, fp);

    /* Only allocate interface structure.  Other jobs will be done in
       if_ioctl.c. */
    while (fgets (buf, PROCBUFSIZ, fp) != NULL)
    {
        interface_name_cut (buf, &name);
        ifp = if_get_by_name (name);
        if_add_update (ifp);
    }
    fclose(fp);
    return 0;
}

#if defined(HAVE_IPV6) && defined(HAVE_PROC_NET_IF_INET6)

#ifndef _PATH_PROC_NET_IF_INET6
#define _PATH_PROC_NET_IF_INET6          "/proc/net/if_inet6"
#endif /* _PATH_PROC_NET_IF_INET6 */

int
ifaddr_proc_ipv6 ()
{
    FILE *fp;
    char buf[PROCBUFSIZ];
    int n;
    char addr[33];
    char ifname[21];
    int ifindex, plen, scope, status;
    struct interface *ifp;
    struct prefix_ipv6 p;

    /* Open proc file system. */
    fp = fopen (_PATH_PROC_NET_IF_INET6, "r");
    if (fp == NULL)
    {
        zlog_warn ("Can't open proc file %s: %s",
                   _PATH_PROC_NET_IF_INET6, safe_strerror (errno));
        return -1;
    }

    /* Get interface's IPv6 address. */
    while (fgets (buf, PROCBUFSIZ, fp) != NULL)
    {
        n = sscanf (buf, "%32s %02x %02x %02x %02x %20s",
                    addr, &ifindex, &plen, &scope, &status, ifname);
        if (n != 6)
            continue;

        ifp = if_get_by_name (ifname);

        /* Fetch interface's IPv6 address. */
        str2in6_addr (addr, &p.prefix);
        p.prefixlen = plen;

        connected_add_ipv6 (ifp, 0, &p.prefix, p.prefixlen, NULL, ifname);
    }
    fclose (fp);
    return 0;
}
#endif /* HAVE_IPV6 && HAVE_PROC_NET_IF_INET6 */



/* Show all or specified interface to vty. */
DEFUN (show_interface, show_interface_cmd,
       "show interface [IFNAME]",
       SHOW_STR
       "Interface status and configuration\n"
       "Inteface name\n")
{
    struct listnode *node;
    struct interface *ifp;

#ifdef HAVE_PROC_NET_DEV
    /* If system has interface statistics via proc file system, update
       statistics. */
    ifstat_update_proc1 ();
#endif /* HAVE_PROC_NET_DEV */
#ifdef HAVE_NET_RT_IFLIST
    ifstat_update_sysctl ();
#endif /* HAVE_NET_RT_IFLIST */

    /* Specified interface print. */
    if (argc != 0)
    {
        ifp = if_lookup_by_name (argv[0]);
        if (ifp == NULL || 0 == ifp->isenable)
        {
            vty_out (vty, "%% Can't find interface %s%s", argv[0],
                     VTY_NEWLINE);
            return CMD_WARNING;
        }
        if_dump_vty (vty, ifp);
        return CMD_SUCCESS;
    }

    /* All interface print. */
    for (ALL_LIST_ELEMENTS_RO (iflist, node, ifp))
    {
        if(0 == ifp->isenable)
            continue;
        if_dump_vty (vty, ifp);
    }
    return CMD_SUCCESS;
}

DEFUN (show_interface_desc,
       show_interface_desc_cmd,
       "show interface description",
       SHOW_STR
       "Interface status and configuration\n"
       "Interface description\n")
{
    struct listnode *node;
    struct interface *ifp;

    vty_out (vty, "Interface       Status  Protocol  Description%s", VTY_NEWLINE);
    for (ALL_LIST_ELEMENTS_RO (iflist, node, ifp))
    {
        int len;

        len = vty_out (vty, "%s", ifp->name);
        vty_out (vty, "%*s", (16 - len), " ");

        if (if_is_up(ifp))
        {
            vty_out (vty, "up      ");
            if (CHECK_FLAG(ifp->status, ZEBRA_INTERFACE_LINKDETECTION))
            {
                if (if_is_running(ifp))
                    vty_out (vty, "up        ");
                else
                    vty_out (vty, "down      ");
            }
            else
            {
                vty_out (vty, "unknown   ");
            }
        }
        else
        {
            vty_out (vty, "down    down      ");
        }

        if (ifp->desc)
            vty_out (vty, "%s", ifp->desc);
        vty_out (vty, "%s", VTY_NEWLINE);
    }
    return CMD_SUCCESS;
}

DEFUN (multicast,
       multicast_cmd,
       "multicast",
       "Set multicast flag to interface\n")
{
    int ret;
    struct interface *ifp;
    struct zebra_if *if_data;

    ifp = (struct interface *) vty->index;
    if (CHECK_FLAG (ifp->status, ZEBRA_INTERFACE_ACTIVE))
    {
        ret = if_set_flags (ifp, IFF_MULTICAST);
        if (ret < 0)
        {
            vty_out (vty, "Can't set multicast flag%s", VTY_NEWLINE);
            return CMD_WARNING;
        }
        if_refresh (ifp);
    }
    if_data = ifp->info;
    if_data->multicast = IF_ZEBRA_MULTICAST_ON;

    return CMD_SUCCESS;
}

DEFUN (no_multicast,
       no_multicast_cmd,
       "no multicast",
       NO_STR
       "Unset multicast flag to interface\n")
{
    int ret;
    struct interface *ifp;
    struct zebra_if *if_data;

    ifp = (struct interface *) vty->index;
    if (CHECK_FLAG (ifp->status, ZEBRA_INTERFACE_ACTIVE))
    {
        ret = if_unset_flags (ifp, IFF_MULTICAST);
        if (ret < 0)
        {
            vty_out (vty, "Can't unset multicast flag%s", VTY_NEWLINE);
            return CMD_WARNING;
        }
        if_refresh (ifp);
    }
    if_data = ifp->info;
    if_data->multicast = IF_ZEBRA_MULTICAST_OFF;

    return CMD_SUCCESS;
}

DEFUN (linkdetect,
       linkdetect_cmd,
       "link-detect",
       "Enable link detection on interface\n")
{
    struct interface *ifp;
    int if_was_operative;

    ifp = (struct interface *) vty->index;
    if_was_operative = if_is_operative(ifp);
    SET_FLAG(ifp->status, ZEBRA_INTERFACE_LINKDETECTION);


#if 1 // wjh add
    int speed_duplex = 0;
    char port_ifname[20];
    memset(port_ifname,0,20);
    int port_i ,port_j ;
    sscanf(ifp->name,"vEth%d_%d",&port_i,&port_j);
    sprintf(port_ifname,"vEth%d_0",port_i);
    //speed_duplex = doit (ifp->name, 0, 0);
    speed_duplex = doit (port_ifname, 0, 0);
    printf(" %s --  speed_duplex = %d\n",port_ifname,speed_duplex);
#if _5U_DEVICE
    if(speed_duplex & SPEED_1000)
    {
        printf("1000M\n");
        SET_FLAG (ifp->flags, IFF_RUNNING);
    }
    else
    {

        printf("0M\n");
        UNSET_FLAG (ifp->flags, IFF_RUNNING);
    }
#else
    if(speed_duplex & SPEED_UN)
    {
        UNSET_FLAG (ifp->flags, IFF_RUNNING);
    }
    else
    {

        SET_FLAG (ifp->flags, IFF_RUNNING);
    }

#endif

#endif


    /* When linkdetection is enabled, if might come down */
    if (!if_is_operative(ifp) && if_was_operative)
    {
        UNSET_FLAG (ifp->flags, IFF_RUNNING);
        if_delete_update (ifp);
        ip_address_delete_from_kernel (ifp);


        //if_down(ifp);

    }



    /* FIXME: Will defer status change forwarding if interface
       does not come down! */

    write_file_for_dpdk_conf(vty);
    return CMD_SUCCESS;
}


DEFUN (no_linkdetect,
       no_linkdetect_cmd,
       "no link-detect",
       NO_STR
       "Disable link detection on interface\n")
{
    struct interface *ifp;
    int if_was_operative;

    ifp = (struct interface *) vty->index;
    /* Interface may come up after disabling link detection */

    /* When linkdetection is enabled, if might come down */

#if 1 // wjh add
    int speed_duplex = 0;
    char port_ifname[20];
    memset(port_ifname,0,20);
    int port_i ,port_j ;
    sscanf(ifp->name,"vEth%d_%d",&port_i,&port_j);
    sprintf(port_ifname,"vEth%d_0",port_i);
    //speed_duplex = doit (ifp->name, 0, 0);
    speed_duplex = doit (port_ifname, 0, 0);
    printf(" %s --  speed_duplex = %d\n",port_ifname,speed_duplex);
#if _5U_DEVICE
    if(speed_duplex & SPEED_1000)
    {
        printf("1000M\n");
        SET_FLAG (ifp->flags, IFF_RUNNING);
    }
    else
    {

        printf("0M\n");
        UNSET_FLAG (ifp->flags, IFF_RUNNING);
    }
#else
    if(speed_duplex & SPEED_UN)
    {
        UNSET_FLAG (ifp->flags, IFF_RUNNING);
    }
    else
    {

        SET_FLAG (ifp->flags, IFF_RUNNING);
    }

#endif


#endif
    if_was_operative = if_is_operative(ifp);
    UNSET_FLAG(ifp->status, ZEBRA_INTERFACE_LINKDETECTION);


#if 1
    printf("if_is_operative(ifp) = %d\n",if_is_operative(ifp));
    printf("!if_was_operative = %d\n",!if_was_operative);
    printf("ifp->flags & IFF_UP = %d\n",ifp->flags & IFF_UP);
    printf("ifp->flags & IFF_RUNNING = %d\n",ifp->flags & IFF_RUNNING);
    printf("!CHECK_FLAG(ifp->status, ZEBRA_INTERFACE_LINKDETECTION) = %d\n",!CHECK_FLAG(ifp->status, ZEBRA_INTERFACE_LINKDETECTION));

#endif
    if (if_is_operative(ifp) && !if_was_operative)
    {
        ip_address_delete_from_kernel (ifp);
        if_refresh (ifp);
        interface_config_recovery (ifp);

        zebra_interface_up_update (ifp);

        //if_up(ifp);
    }


    /* FIXME: see linkdetect_cmd */

    write_file_for_dpdk_conf(vty);
    return CMD_SUCCESS;
}






struct vlan_info
{
    uint8_t type;//0:add 1:del
    uint8_t ifindex;
    uint16_t vlan_id;
};
void send_interface_vlan_msg_dpdk(struct vty *vty,uint8_t ifindex ,int type,uint16_t vlan_id)
{
    int sockfd;
    int ret;
    struct comm_head *comm;
    int len = sizeof(struct vlan_info);

    comm = (struct comm_head *) malloc (sizeof (struct comm_head) + len);
    if (comm == NULL)
    {
        fprintf (stderr, "%s\n", "flow engine info head malloc failed");
        return -1;
    }
    memset (comm, 0, sizeof (struct comm_head) + len);

    comm->type =0x37;
    comm->len = htonl(sizeof (struct comm_head) + len);

    struct vlan_info *vlan = (struct vlan_info *)comm->data;
    vlan->type = type;
    vlan->ifindex = ifindex;
    vlan->vlan_id = vlan_id;

    //vty_out(vty,"--%d--%d--%d--\n",vlan->type,vlan->ifindex,vlan->vlan_id);

    sockfd = connect_dpdk(vty);
    ret = send (sockfd, (char *) comm, sizeof (struct comm_head) + len, 0);
    if (ret < 0)
    {
        fprintf (stderr, "%s\n", "send comm failed");
        close (sockfd);
        free (comm);
        return -1;
    }
    close (sockfd);
    free (comm);
    return 0;


}



int if_vlan_id_exist(struct vty *vty,int vlan_id)
{
    struct listnode *node;
    struct interface *ifp;
    int iRetVal = 0;

    for (ALL_LIST_ELEMENTS_RO (iflist, node, ifp))
    {
        struct zebra_if *if_data;
        struct listnode *addrnode;
        struct connected *ifc;
        struct prefix *p;

        if_data = ifp->info;

        //added for 4over6 20130314
        iRetVal = memcmp(ifp->name, "4o6_tnl", 7);
        if(iRetVal == 0)
        {
            continue;
        }
        if(ifp->isenable == 0)
        {
            continue;
        }

        //vty_out (vty, "in for %s %d -- %d\n", ifp->name,ifp->vlan_id,vlan_id);
        if(ifp->vlan_id == vlan_id)
        {
            return 1;
        }
    }

    return 0;

}





DEFUN (vlan_if,
       vlan_if_cmd,
       "vlan <1-4094>",
       "configure vlan the selected interface\n")
{
    int ret;
    struct interface *ifp;
    uint8_t ifindex = 0;


    ret = if_vlan_id_exist(vty,atoi(argv[0]));
    if(ret != 0)
    {
        vty_out (vty, "this vlan_id already exist%s", VTY_NEWLINE);
        return;
    }



    ifp = (struct interface *) vty->index;

    ifindex = get_ifindex_by_ifname(ifp->name);
    ifp->vlan_id = atoi(argv[0]);




    vty_out (vty, "vlan %s %d %s",ifp->name,atoi(argv[0]), VTY_NEWLINE);


    send_interface_vlan_msg_dpdk(vty,ifindex ,0,atoi(argv[0]));
    write_file_for_dpdk_conf(vty);
    return CMD_SUCCESS;
}

DEFUN (no_vlan_if,
       no_vlan_if_cmd,
       "no vlan",
       "configure vlan the selected interface\n")
{
    int ret;
    struct interface *ifp;
    struct zebra_if *if_data;
    uint8_t ifindex=0;

    ifp = (struct interface *) vty->index;
    ifindex = get_ifindex_by_ifname(ifp->name);

    ifp->vlan_id = 0x0;

    vty_out (vty, "no vlan %s %d %s",ifp->name,atoi(argv[0]), VTY_NEWLINE);
    send_interface_vlan_msg_dpdk(vty,ifindex ,1,0);
    write_file_for_dpdk_conf(vty);
    return CMD_SUCCESS;
}



DEFUN (shutdown_if,
       shutdown_if_cmd,
       "shutdown",
       "Shutdown the selected interface\n")
{
    int ret = 0;
    struct interface *ifp;
    struct zebra_if *if_data;
    struct connected *ifc;
    struct listnode *addrnode;
    struct prefix *p;

    ifp = (struct interface *) vty->index;
    //del by wjh 20190131 for 5U
    ret = if_unset_flags (ifp, IFF_UP);
    if (ret < 0)
    {
        vty_out (vty, "Can't shutdown interface%s", VTY_NEWLINE);
        return CMD_WARNING;
    }
    if_refresh (ifp);
    if_data = ifp->info;
    if_data->shutdown = IF_ZEBRA_SHUTDOWN_ON;

#if 1 //del ipv4 route
    addrnode = listhead(ifp->connected);
    while(1)
    {

        ifc=NULL;
        if(addrnode == NULL)
            break;
        ifc = listgetdata(addrnode);
        if(ifc == NULL)
            break;

        if (CHECK_FLAG (ifc->conf, ZEBRA_IFC_CONFIGURED))
        {
            char buf[INET6_ADDRSTRLEN];
            p = ifc->address;

            char address[30];
            memset(address,0,30);
            inet_ntop (p->family, &p->u.prefix, buf, sizeof(buf));
            sprintf(address,"%s/%d",buf,p->prefixlen);
            //vty_out(vty,"address:%s%s",address,VTY_NEWLINE);
            if(p->family == AF_INET)
            {
                //ret = ip_address_uninstall (vty, ifp,(const char *)address , NULL, NULL);
                char cmd_buf[128];
                memset(cmd_buf,0,sizeof(cmd_buf));
                sprintf(cmd_buf,"ip addr del %s dev %s",(const char *)address,ifp->name);
                //printf("cmd_buf:%s\n",cmd_buf);
                system(cmd_buf);
                break;
            }
            addrnode = listnextnode(addrnode);
            //addrnode = listhead(ifp->connected);
        }
        else
        {
            addrnode = listnextnode(addrnode);
        }
    }

#endif

    send_interface_up_down_to_dpdk(vty,ifp->name,0);
    write_file_for_dpdk_conf(vty);
    return CMD_SUCCESS;
}

/* Qinhz add for recovery the interface's config */
int interface_configRecovery(struct vty *vty, struct interface *ifp)
{
    struct connected *ifc;
    struct listnode *node2;
    int ret;

    for (ALL_LIST_ELEMENTS_RO (ifp->connected, node2, ifc))
    {
        if(ifc->address->family == AF_INET6)
        {
            printf("Recovery v6 address\n");
#if 1
            if (! CHECK_FLAG (ifc->conf, ZEBRA_IFC_CONFIGURED))
                SET_FLAG (ifc->conf, ZEBRA_IFC_CONFIGURED);

            /* In case of this route need to install kernel. */
            if (! CHECK_FLAG (ifc->conf, ZEBRA_IFC_REAL)
                    && CHECK_FLAG (ifp->status, ZEBRA_INTERFACE_ACTIVE))
            {
                /* Some system need to up the interface to set IP address. */
                if (! if_is_up (ifp))
                {
                    if_set_flags (ifp, IFF_UP | IFF_RUNNING);
                    if_refresh (ifp);
                }
#endif
                ret = if_prefix_add_ipv6 (ifp, ifc);

                if (ret < 0)
                {
                    if(ret != EEXIST)
                        vty_out (vty, "%% Can't set interface IP address: %s.%s",
                                 safe_strerror(errno), VTY_NEWLINE);
                    return CMD_WARNING;
                }

                /* IP address propery set. */
                SET_FLAG (ifc->conf, ZEBRA_IFC_REAL);

                /* Update interface address information to protocol daemon. */
                zebra_interface_address_add_update (ifp, ifc);

                /* If interface is up register connected route. */
                if (if_is_operative(ifp))
                    connected_up_ipv6 (ifp, ifc);
            }
        }
        else
        {
            printf("Recovery v4 address\n");
#if 1
            /* This address is configured from zebra. */
            if (! CHECK_FLAG (ifc->conf, ZEBRA_IFC_CONFIGURED))
                SET_FLAG (ifc->conf, ZEBRA_IFC_CONFIGURED);

            /* In case of this route need to install kernel. */
            if (! CHECK_FLAG (ifc->conf, ZEBRA_IFC_REAL)
                    && CHECK_FLAG (ifp->status, ZEBRA_INTERFACE_ACTIVE))
            {
                /* Some system need to up the interface to set IP address. */
                if (! if_is_up (ifp))
                {
                    if_set_flags (ifp, IFF_UP | IFF_RUNNING);
                    if_refresh (ifp);
                }
#endif

                ret = if_set_prefix (ifp, ifc);
                if (ret < 0)
                {
                    vty_out (vty, "%% Can't set interface IP address: %s.%s",
                             safe_strerror(errno), VTY_NEWLINE);
                    return CMD_WARNING;
                }

                /* Add to subnet chain list (while marking secondary attribute). */
                if_subnet_add (ifp, ifc);

                /* IP address propery set. */
                SET_FLAG (ifc->conf, ZEBRA_IFC_REAL);

                /* Update interface address information to protocol daemon. */
                zebra_interface_address_add_update (ifp, ifc);

                /* If interface is up register connected route. */
                if (if_is_operative(ifp))
                    connected_up_ipv4 (ifp, ifc);
            }
        }
    }
    return CMD_SUCCESS;
}

int interface_config_recovery( struct interface *ifp)
{
    struct connected *ifc;
    struct listnode *node2;
    int ret;

    for (ALL_LIST_ELEMENTS_RO (ifp->connected, node2, ifc))
    {
        if(ifc->address->family == AF_INET6)
        {
            printf("Recovery v6 address\n");
            /*sangmeng add*/
            struct prefix_ipv6 *p;
            p = (struct prefix_ipv6 *) ifc->address;

#if 0
            if (p->family == AF_INET6)
            {
                char string[128];

                memset(string, 0, sizeof(string));
                inet_ntop(AF_INET6, p->prefix.s6_addr, string, sizeof(string));
                printf ("[%d]%s()interface ipv6 address:%s\n", __LINE__, __func__, string);
            }
#endif
            if (p->prefix.s6_addr16[0] == htons(0xfe80))
            {
                printf("this is fe80 address, continue\n");
                continue;
            }
#if 1
            if (! CHECK_FLAG (ifc->conf, ZEBRA_IFC_CONFIGURED))
                SET_FLAG (ifc->conf, ZEBRA_IFC_CONFIGURED);

#if 0
            /* In case of this route need to install kernel. */
            if (! CHECK_FLAG (ifc->conf, ZEBRA_IFC_REAL)
                    && CHECK_FLAG (ifp->status, ZEBRA_INTERFACE_ACTIVE))
#endif
            {
                /* Some system need to up the interface to set IP address. */
                if (! if_is_up (ifp))
                {
                    if_set_flags (ifp, IFF_UP | IFF_RUNNING);
                    if_refresh (ifp);
                }
#endif
                ret = if_prefix_add_ipv6 (ifp, ifc);

                if (ret < 0)
                {
                    if(ret != EEXIST)
                        printf ("Can't set interface IPv6 address: %s.\n",
                                safe_strerror(errno));
                    return CMD_WARNING;
                }

                /* IP address propery set. */
                SET_FLAG (ifc->conf, ZEBRA_IFC_REAL);

                /* Update interface address information to protocol daemon. */
                zebra_interface_address_add_update (ifp, ifc);

                /* If interface is up register connected route. */
                if (if_is_operative(ifp))
                    connected_up_ipv6 (ifp, ifc);
            }
        }
        else
        {
            printf("Recovery v4 address\n");
#if 1
            /* This address is configured from zebra. */
            if (! CHECK_FLAG (ifc->conf, ZEBRA_IFC_CONFIGURED))
                SET_FLAG (ifc->conf, ZEBRA_IFC_CONFIGURED);

#if 0
            /* In case of this route need to install kernel. */
            if (! CHECK_FLAG (ifc->conf, ZEBRA_IFC_REAL)
                    && CHECK_FLAG (ifp->status, ZEBRA_INTERFACE_ACTIVE))
#endif
            {
                /* Some system need to up the interface to set IP address. */
                if (! if_is_up (ifp))
                {
                    if_set_flags (ifp, IFF_UP | IFF_RUNNING);
                    if_refresh (ifp);
                }
#endif

                ret = if_set_prefix (ifp, ifc);
                if (ret < 0)
                {
                    printf ("Can't set interface IP address: %s.\n",
                            safe_strerror(errno));
                    return CMD_WARNING;
                }

                /* Add to subnet chain list (while marking secondary attribute). */
                if_subnet_add_new (ifp, ifc);

                /* IP address propery set. */
                SET_FLAG (ifc->conf, ZEBRA_IFC_REAL);

                /* Update interface address information to protocol daemon. */
                zebra_interface_address_add_update (ifp, ifc);

                /* If interface is up register connected route. */
                if (if_is_operative(ifp))
                    connected_up_ipv4 (ifp, ifc);
            }
        }
    }
    return 0;
}




DEFUN (no_shutdown_if,
       no_shutdown_if_cmd,
       "no shutdown",
       NO_STR
       "Shutdown the selected interface\n")
{
    int ret;
    struct interface *ifp;
    struct zebra_if *if_data;

    ifp = (struct interface *) vty->index;

    //del by wjh 20190131 for 5U
    ret = if_set_flags (ifp, IFF_UP | IFF_RUNNING);
    if (ret < 0)
    {
        vty_out (vty, "Can't up interface%s", VTY_NEWLINE);
        return CMD_WARNING;
    }
    if(if_is_operative (ifp))
    {
        if_refresh (ifp);
    }
#if 1 //add wjh
    int speed_duplex = 0;
    if(CHECK_FLAG(ifp->status, ZEBRA_INTERFACE_LINKDETECTION))
    {
        char port_ifname[20];
        memset(port_ifname,0,20);
        int port_i ,port_j ;
        sscanf(ifp->name,"vEth%d_%d",&port_i,&port_j);
        sprintf(port_ifname,"vEth%d_0",port_i);
        //speed_duplex = doit (ifp->name, 0, 0);
        speed_duplex = doit (port_ifname, 0, 0);
        printf(" %s --  speed_duplex = %d\n",port_ifname,speed_duplex);
#if _5U_DEVICE
        if(speed_duplex & SPEED_1000)
        {
            printf("1000M\n");
            SET_FLAG (ifp->flags, IFF_RUNNING);
        }
        else
        {

            printf("0M\n");
            UNSET_FLAG (ifp->flags, IFF_RUNNING);
        }
#else
        if(speed_duplex & SPEED_UN)
        {
            UNSET_FLAG (ifp->flags, IFF_RUNNING);
        }
        else
        {

            SET_FLAG (ifp->flags, IFF_RUNNING);
        }

#endif


    }

#endif


    if_data = ifp->info;
    if_data->shutdown = IF_ZEBRA_SHUTDOWN_OFF;
    /* Qinhz add for recovery pre address configure */

    SET_FLAG(ifp->flags, IFF_UP);
#if 1
    printf("if_is_operative(ifp) = %d\n",if_is_operative(ifp));
    printf("ifp->flags & IFF_UP = %d\n",ifp->flags & IFF_UP);
    printf("ifp->flags & IFF_RUNNING = %d\n",ifp->flags & IFF_RUNNING);
    printf("!CHECK_FLAG(ifp->status, ZEBRA_INTERFACE_LINKDETECTION) = %d\n",!CHECK_FLAG(ifp->status, ZEBRA_INTERFACE_LINKDETECTION));

#endif


    if(if_is_operative (ifp))
    {
        interface_configRecovery(vty, ifp);
    }
    send_interface_up_down_to_dpdk(vty,ifp->name,1);
    write_file_for_dpdk_conf(vty);
    return CMD_SUCCESS;

}

DEFUN (bandwidth_if,
       bandwidth_if_cmd,
       "bandwidth <1-10000000>",
       "Set bandwidth informational parameter\n"
       "Bandwidth in kilobits\n")
{
    struct interface *ifp;
    unsigned int bandwidth;

    ifp = (struct interface *) vty->index;
    bandwidth = strtol(argv[0], NULL, 10);

    /* bandwidth range is <1-10000000> */
    if (bandwidth < 1 || bandwidth > 10000000)
    {
        vty_out (vty, "Bandwidth is invalid%s", VTY_NEWLINE);
        return CMD_WARNING;
    }

    ifp->bandwidth = bandwidth;

    /* force protocols to recalculate routes due to cost change */
    if (if_is_operative (ifp))
        zebra_interface_up_update (ifp);

    return CMD_SUCCESS;
}

DEFUN (no_bandwidth_if,
       no_bandwidth_if_cmd,
       "no bandwidth",
       NO_STR
       "Set bandwidth informational parameter\n")
{
    struct interface *ifp;

    ifp = (struct interface *) vty->index;

    ifp->bandwidth = 0;

    /* force protocols to recalculate routes due to cost change */
    if (if_is_operative (ifp))
        zebra_interface_up_update (ifp);

    return CMD_SUCCESS;
}
int interface_AddressIsConfigured(struct vty *vty, struct interface *ifp, struct prefix *p)
{
    struct listnode *node, *nnode;
    struct interface *tmp;
    struct connected *tmp2;
    struct listnode *node2;

    for (ALL_LIST_ELEMENTS (iflist, node, nnode, tmp))
    {
        if(tmp == ifp)
            continue;

        for (ALL_LIST_ELEMENTS_RO (tmp->connected, node2, tmp2))
        {
            if (prefix_same (tmp2->address, p))
            {
                return 1;
            }

        }
    }
    return 0;

}
int check_address_legal(struct in_addr addr,struct vty *vty)
{
    struct listnode *node;
    struct interface *ifp;

    for (ALL_LIST_ELEMENTS_RO (iflist, node, ifp))
    {

        struct listnode *cnode;
        struct connected *connected;
        for (ALL_LIST_ELEMENTS_RO (ifp->connected, cnode, connected))
        {
            struct prefix_ipv4 *p;

            p = (struct prefix_ipv4 *) connected->address;

            if (p->family != AF_INET)
                continue;
            if (IPV4_ADDR_CMP (&p->prefix, &addr) == 0)
                return 1;
        }
    }
    return 0;
}
ALIAS (no_bandwidth_if,
       no_bandwidth_if_val_cmd,
       "no bandwidth <1-10000000>",
       NO_STR
       "Set bandwidth informational parameter\n"
       "Bandwidth in kilobits\n")
static int
ip_address_install (struct vty *vty, struct interface *ifp,
                    const char *addr_str, const char *peer_str,
                    const char *label)
{

    struct prefix_ipv4 cp;
    struct connected *ifc;
    struct prefix_ipv4 *p;
    int ret;

    if(strncmp(ifp->name,"4o6",3)==0||strncmp(ifp->name,"ivi",3)==0||strncmp(ifp->name,"nat",3)==0||strncmp(ifp->name,"6o4",3)==0||strncmp(ifp->name,"ip",2)==0)
    {
        vty_out (vty, "%% Can't set interface IP address"
                );
        return CMD_ERR_NOTHING_TODO;
    }

    if(ifp->ipv4_Address_Configed!=0)
    {
        vty_out (vty, "%% Interface has configed v4 address%s", VTY_NEWLINE);
        return CMD_WARNING;
    }
    ret = str2prefix_ipv4 (addr_str, &cp);
    if (ret <= 0)
    {
        vty_out (vty, "%% Malformed address %s", VTY_NEWLINE);
        return CMD_WARNING;
    }
    /* Qinhz add for can not configure the address which other interface has configured */

    if(0 != interface_AddressIsConfigured(vty, ifp, (struct prefix *) &cp))
    {
        vty_out (vty, "%% Other interface has configured the address!%s", VTY_NEWLINE);
        return CMD_WARNING;//add by ccc
    }

    ifc = connected_check (ifp, (struct prefix *) &cp);
    if (! ifc)
    {
        ifc = connected_new ();
        ifc->ifp = ifp;

        /* Address. */
        p = prefix_ipv4_new ();
        *p = cp;
        ifc->address = (struct prefix *) p;

        /* Broadcast. */
        if (p->prefixlen <= IPV4_MAX_PREFIXLEN-2)
        {
            p = prefix_ipv4_new ();
            *p = cp;
            p->prefix.s_addr = ipv4_broadcast_addr(p->prefix.s_addr,p->prefixlen);
            ifc->destination = (struct prefix *) p;
        }

        /* Label. */
        if (label)
            ifc->label = XSTRDUP (MTYPE_CONNECTED_LABEL, label);

        /* Add to linked list. */
        listnode_add (ifp->connected, ifc);
    }

    /* This address is configured from zebra. */
    if (! CHECK_FLAG (ifc->conf, ZEBRA_IFC_CONFIGURED))
        SET_FLAG (ifc->conf, ZEBRA_IFC_CONFIGURED);

    /* In case of this route need to install kernel. */
    if (! CHECK_FLAG (ifc->conf, ZEBRA_IFC_REAL)
            && CHECK_FLAG (ifp->status, ZEBRA_INTERFACE_ACTIVE))
    {
        /* Some system need to up the interface to set IP address. */
        if (! if_is_up (ifp))
        {
            if_set_flags (ifp, IFF_UP | IFF_RUNNING);
            if_refresh (ifp);
        }

        ret = if_set_prefix (ifp, ifc);
        if (ret < 0)
        {
            vty_out (vty, "%% Can't set interface IP address: %s.%s",
                     safe_strerror(errno), VTY_NEWLINE);
            return CMD_WARNING;
        }
        ifp->ipv4_Address_Configed = 1;
        /* Add to subnet chain list (while marking secondary attribute). */
        if_subnet_add (ifp, ifc);

        /* IP address propery set. */
        SET_FLAG (ifc->conf, ZEBRA_IFC_REAL);

        /* Update interface address information to protocol daemon. */
        zebra_interface_address_add_update (ifp, ifc);

        /* If interface is up register connected route. */
        if (if_is_operative(ifp))
            connected_up_ipv4 (ifp, ifc);
    }

    return CMD_SUCCESS;
}

//sangmeng add
int ip_address_delete_from_kernel(struct interface *ifp)
{
    printf("in %s :%s\n",__func__,ifp->name);
    int ret;
    struct connected *connected;
    struct listnode *node;
    struct route_node *rn;
    struct zebra_if *zebra_if;

    zebra_if = ifp->info;
    for (rn = route_top (zebra_if->ipv4_subnets); rn; rn = route_next (rn))
    {
        if (! rn->info)
            continue;

        for (ALL_LIST_ELEMENTS_RO ((struct list *)rn->info, node, connected))
        {
            ret = if_unset_prefix (ifp, connected);
            if (ret < 0)
            {
                printf (" Can't unset interface IP address: %s\n",
                        safe_strerror(errno));
            }
        }

    }

    for (ALL_LIST_ELEMENTS_RO (ifp->connected, node, connected))
    {

        printf("CHECK_FLAG (connected->conf, ZEBRA_IFC_REAL) = %d\n",CHECK_FLAG (connected->conf, ZEBRA_IFC_REAL));
#if 0
        if (CHECK_FLAG (connected->conf, ZEBRA_IFC_REAL) &&
                (connected->address->family == AF_INET6))
#endif
            if(connected->address->family == AF_INET6)
                ret = if_prefix_delete_ipv6(ifp, connected);
        if (ret < 0)
        {
            printf ("Can't unset interface IPv6 address: %s\n",
                    safe_strerror(errno));
        }
        else
        {
            printf("unset interface IPv6 address success\n");
        }
    }


    return 0;

}
#if 1
int ip_address_lookup_in_list(struct interface *ifp)
{
    int ret;
    struct connected *connected;
    struct listnode *node;
    struct route_node *rn;
    struct zebra_if *zebra_if;

    zebra_if = ifp->info;
    for (rn = route_top (zebra_if->ipv4_subnets); rn; rn = route_next (rn))
    {
        if (! rn->info)
            continue;

        for (ALL_LIST_ELEMENTS_RO ((struct list *)rn->info, node, connected))
        {
            printf("[%d]%s()connected->conf:%d \n", __LINE__, __func__, connected->conf);
        }

    }
    return 0;

}
#endif



static int
ip_address_uninstall (struct vty *vty, struct interface *ifp,
                      const char *addr_str, const char *peer_str,
                      const char *label)
{
    struct prefix_ipv4 cp;
    struct connected *ifc;
    int ret;

    /* Convert to prefix structure. */
    ret = str2prefix_ipv4 (addr_str, &cp);
    if (ret <= 0)
    {
        vty_out (vty, "%% Malformed address %s", VTY_NEWLINE);
        return CMD_WARNING;
    }

    /* Check current interface address. */
    ifc = connected_check (ifp, (struct prefix *) &cp);
    if (! ifc)
    {
        vty_out (vty, "%% Can't find address%s", VTY_NEWLINE);
        return CMD_WARNING;
    }

    /* This is not configured address. */
    if (! CHECK_FLAG (ifc->conf, ZEBRA_IFC_CONFIGURED))
        return CMD_WARNING;

    UNSET_FLAG (ifc->conf, ZEBRA_IFC_CONFIGURED);

    /* This is not real address or interface is not active. */
    if (! CHECK_FLAG (ifc->conf, ZEBRA_IFC_REAL)
            || ! CHECK_FLAG (ifp->status, ZEBRA_INTERFACE_ACTIVE))
    {
        listnode_delete (ifp->connected, ifc);
        connected_free (ifc);
        return CMD_WARNING;
    }

    /* This is real route. */
    ret = if_unset_prefix (ifp, ifc);
    if (ret < 0)
    {
        vty_out (vty, "%% Can't unset interface IP address: %s.%s",
                 safe_strerror(errno), VTY_NEWLINE);
        return CMD_WARNING;
    }

#if 1
    /* Redistribute this information. */
    zebra_interface_address_delete_update (ifp, ifc);

    /* Remove connected route. */
    connected_down_ipv4 (ifp, ifc);

    /* Free address information. */
    listnode_delete (ifp->connected, ifc);
    if_subnet_delete(ifp,ifc);
// connected_free (ifc);
#endif
    ifp->ipv4_Address_Configed=0;

    return CMD_SUCCESS;
}

DEFUN (ip_address,
       ip_address_cmd,
       "ip address A.B.C.D/M",
       "Interface Internet Protocol config commands\n"
       "Set the IP address of an interface\n"
       "IP address (e.g. 10.0.0.1/8)\n")
{
    int ret = ip_address_install (vty, vty->index, argv[0], NULL, NULL);
    if(ret == CMD_SUCCESS)
    {
#if _5U_DEVICE
        char cmd_buf[256] = "\0";
        memset(cmd_buf,0,sizeof(cmd_buf));
        //printf("argv[0]:%s\n",argv[0]);
        sprintf(cmd_buf,"/bitway/run/send_ua.sh %s %s 4", argv[0], ((struct interface *)(vty->index))->name);
        //printf("cmd_buf:%s\n",cmd_buf);
        if(system(cmd_buf) == -1)
            printf("[system] perform %s cmd fail\n",cmd_buf);
#endif
    }
    write_file_for_dpdk_conf(vty);
    return ret;
}

DEFUN (no_ip_address,
       no_ip_address_cmd,
       "no ip address A.B.C.D/M",
       NO_STR
       "Interface Internet Protocol config commands\n"
       "Set the IP address of an interface\n"
       "IP Address (e.g. 10.0.0.1/8)")
{
    int ret = ip_address_uninstall (vty, vty->index, argv[0], NULL, NULL);
    write_file_for_dpdk_conf(vty);
    return ret;
}

#ifdef HAVE_NETLINK
DEFUN (ip_address_label,
       ip_address_label_cmd,
       "ip address A.B.C.D/M label LINE",
       "Interface Internet Protocol config commands\n"
       "Set the IP address of an interface\n"
       "IP address (e.g. 10.0.0.1/8)\n"
       "Label of this address\n"
       "Label\n")
{
    return ip_address_install (vty, vty->index, argv[0], NULL, argv[1]);
}

DEFUN (no_ip_address_label,
       no_ip_address_label_cmd,
       "no ip address A.B.C.D/M label LINE",
       NO_STR
       "Interface Internet Protocol config commands\n"
       "Set the IP address of an interface\n"
       "IP address (e.g. 10.0.0.1/8)\n"
       "Label of this address\n"
       "Label\n")
{
    return ip_address_uninstall (vty, vty->index, argv[0], NULL, argv[1]);
}
#endif /* HAVE_NETLINK */

#ifdef HAVE_IPV6
static int
ipv6_address_install (struct vty *vty, struct interface *ifp,
                      const char *addr_str, const char *peer_str,
                      const char *label, int secondary)
{
    struct prefix_ipv6 cp;
    struct connected *ifc;
    struct prefix_ipv6 *p;
    int ret;

    if(strncmp(ifp->name,"4o6",3)==0||strncmp(ifp->name,"ivi",3)==0||strncmp(ifp->name,"nat",3)==0||strncmp(ifp->name,"6o4",3)==0)
    {
        vty_out (vty, "%% Can't set interface IP address: %s.%s",
                 safe_strerror(errno), VTY_NEWLINE);
        return CMD_WARNING;
    }
    ret = str2prefix_ipv6 (addr_str, &cp);
// add by huwei
#if 1
    struct in6_addr s;
    int host_bit;
    inet_pton(AF_INET6,strtok(addr_str,"/"),(void *)&s);
    host_bit=atoi(strtok(NULL,"/"));
    int a=1;
    for(int k=0; k<(128-host_bit)%8; k++)
        a*=2;
    a--;
    int b=16-(128-host_bit)/8;
    int c=0;
    //vty_out(vty,"a=%d  b=%d",a,b);
    for (int j=15; j>=b; j--)
    {
        c+=(s.s6_addr[j]&255);
        //vty_out(vty,"[%d]=%d",j,s.s6_addr[j]&255);
    }
//	vty_out(vty,"c=%d\n",c);
    if(c==0)
    {
        //	vty_out(vty,"s.s6_addr[15-b]&a=%d",s.s6_addr[15-b]&a);
        if((s.s6_addr[15-b]&a)==0)
        {
            //vty_out(vty,"\nin s6_addr & a");
            ret=0;
        }

    }
    else if(c==255*b)
    {
        if(s.s6_addr[15-b]==a)
            ret=0;
    }
#endif
//end add
    if (ret <= 0)
    {
        vty_out (vty, "%% Malformed address %s", VTY_NEWLINE);
        return CMD_WARNING;
    }
    /* Qinhz add for can not configure the address which other interface has configured */

    if(0 != interface_AddressIsConfigured(vty, ifp, (struct prefix *) &cp))
    {
        vty_out (vty, "%% Other interface has configured the address!%s", VTY_NEWLINE);
        return CMD_WARNING;//add by ccc
    }

    ifc = connected_check (ifp, (struct prefix *) &cp);
    if (! ifc)
    {
        ifc = connected_new ();
        ifc->ifp = ifp;

        /* Address. */
        p = prefix_ipv6_new ();
        *p = cp;
        ifc->address = (struct prefix *) p;

        /* Secondary. */
        if (secondary)
            SET_FLAG (ifc->flags, ZEBRA_IFA_SECONDARY);

        /* Label. */
        if (label)
            ifc->label = XSTRDUP (MTYPE_CONNECTED_LABEL, label);

        /* Add to linked list. */
        listnode_add (ifp->connected, ifc);
    }

    /* This address is configured from zebra. */
    if (! CHECK_FLAG (ifc->conf, ZEBRA_IFC_CONFIGURED))
        SET_FLAG (ifc->conf, ZEBRA_IFC_CONFIGURED);



#if 1 //add wjh
    int speed_duplex = 0;
    if(CHECK_FLAG(ifp->status, ZEBRA_INTERFACE_LINKDETECTION))
    {
        char port_ifname[20];
        memset(port_ifname,0,20);
        int port_i ,port_j ;
        sscanf(ifp->name,"vEth%d_%d",&port_i,&port_j);
        sprintf(port_ifname,"vEth%d_0",port_i);
        //speed_duplex = doit (ifp->name, 0, 0);
        speed_duplex = doit (port_ifname, 0, 0);
        printf(" %s --  speed_duplex = %d\n",port_ifname,speed_duplex);
#if _5U_DEVICE
        if(speed_duplex & SPEED_1000)
        {
            printf("1000M\n");
            SET_FLAG (ifp->flags, IFF_RUNNING);
        }
        else
        {

            printf("0M\n");
            UNSET_FLAG (ifp->flags, IFF_RUNNING);
            return CMD_WARNING;
        }
#else
        if(speed_duplex & SPEED_UN)
        {
            UNSET_FLAG (ifp->flags, IFF_RUNNING);
            return CMD_WARNING;
        }
        else
        {

            SET_FLAG (ifp->flags, IFF_RUNNING);
        }

#endif

    }

#endif




    /* In case of this route need to install kernel. */
    if (! CHECK_FLAG (ifc->conf, ZEBRA_IFC_REAL)
            && CHECK_FLAG (ifp->status, ZEBRA_INTERFACE_ACTIVE))
    {
        /* Some system need to up the interface to set IP address. */
        if (! if_is_up (ifp))
        {
            if_set_flags (ifp, IFF_UP | IFF_RUNNING);
            if_refresh (ifp);
        }

        ret = if_prefix_add_ipv6 (ifp, ifc);

        if (ret < 0)
        {
            vty_out (vty, "%% Can't set interface IP address: %s.%s",
                     safe_strerror(errno), VTY_NEWLINE);
            return CMD_WARNING;
        }

        /* IP address propery set. */
        SET_FLAG (ifc->conf, ZEBRA_IFC_REAL);

        /* Update interface address information to protocol daemon. */
        zebra_interface_address_add_update (ifp, ifc);

        /* If interface is up register connected route. */
        if (if_is_operative(ifp))
            connected_up_ipv6 (ifp, ifc);
    }

    return CMD_SUCCESS;
}

static int
ipv6_address_uninstall (struct vty *vty, struct interface *ifp,
                        const char *addr_str, const char *peer_str,
                        const char *label, int secondry)
{
    struct prefix_ipv6 cp;
    struct connected *ifc;
    int ret;

    /* Convert to prefix structure. */
    ret = str2prefix_ipv6 (addr_str, &cp);
    if (ret <= 0)
    {
        vty_out (vty, "%% Malformed address %s", VTY_NEWLINE);
        return CMD_WARNING;
    }

    /* Check current interface address. */
    ifc = connected_check (ifp, (struct prefix *) &cp);
    if (! ifc)
    {
        vty_out (vty, "%% Can't find address%s", VTY_NEWLINE);
        return CMD_WARNING;
    }

    /* This is not configured address. */
    if (! CHECK_FLAG (ifc->conf, ZEBRA_IFC_CONFIGURED))
        return CMD_WARNING;

    /* This is not real address or interface is not active. */
    if (! CHECK_FLAG (ifc->conf, ZEBRA_IFC_REAL)
            || ! CHECK_FLAG (ifp->status, ZEBRA_INTERFACE_ACTIVE))
    {
        listnode_delete (ifp->connected, ifc);
        connected_free (ifc);
        return CMD_WARNING;
    }

    /* This is real route. */
    ret = if_prefix_delete_ipv6 (ifp, ifc);
    if (ret < 0)
    {
        vty_out (vty, "%% Can't unset interface IP address: %s.%s",
                 safe_strerror(errno), VTY_NEWLINE);
        return CMD_WARNING;
    }

    /* Redistribute this information. */
    zebra_interface_address_delete_update (ifp, ifc);

    /* Remove connected route. */
    connected_down_ipv6 (ifp, ifc);

    /* Free address information. */
    listnode_delete (ifp->connected, ifc);
    connected_free (ifc);

    return CMD_SUCCESS;
}

DEFUN (ipv6_address,
       ipv6_address_cmd,
       "ipv6 address X:X::X:X/M",
       "Interface IPv6 config commands\n"
       "Set the IP address of an interface\n"
       "IPv6 address (e.g. 3ffe:506::1/48)\n")
{
    // printf("argv[0]1:%s\n",argv[0]);
    int ret = ipv6_address_install (vty, vty->index, argv[0], NULL, NULL, 0);
    if(ret == CMD_SUCCESS)
    {
#if _5U_DEVICE
        char cmd_buf[256] = "\0";
        memset(cmd_buf,0,sizeof(cmd_buf));
        //printf("argv[0]:%s\n",argv[0]);
        sprintf(cmd_buf,"/bitway/run/send_ua.sh %s %s 6", argv[0], ((struct interface *)(vty->index))->name);
        //printf("cmd_buf:%s\n",cmd_buf);
        if(system(cmd_buf) == -1)
            printf("[system] perform %s cmd fail\n",cmd_buf);
#endif
    }
    write_file_for_dpdk_conf(vty);
    return ret;
}

DEFUN (no_ipv6_address,
       no_ipv6_address_cmd,
       "no ipv6 address X:X::X:X/M",
       NO_STR
       "Interface IPv6 config commands\n"
       "Set the IP address of an interface\n"
       "IPv6 address (e.g. 3ffe:506::1/48)\n")
{
    int ret = ipv6_address_uninstall (vty, vty->index, argv[0], NULL, NULL, 0);
    write_file_for_dpdk_conf(vty);
    return ret;
}


#endif /* HAVE_IPV6 */

static int
if_config_write (struct vty *vty)
{
    struct listnode *node;
    struct interface *ifp;
    int iRetVal = 0;

    for (ALL_LIST_ELEMENTS_RO (iflist, node, ifp))
    {
        struct zebra_if *if_data;
        struct listnode *addrnode;
        struct connected *ifc;
        struct prefix *p;

        if_data = ifp->info;

        //added for 4over6 20130314
        iRetVal = memcmp(ifp->name, "4o6_tnl", 7);
        if(iRetVal == 0)
            continue;

        //vty_out (vty, "%% ifp = %p ifp->isenable = %d %s", ifp,ifp->isenable, VTY_NEWLINE);
        if(ifp->isenable == 0)
            continue;

        vty_out (vty, "interface gigabitethernet %s %s", ifp->name,
                 VTY_NEWLINE);
        if (ifp->vlan_id)
            vty_out (vty, " vlan %d%s", ifp->vlan_id,
                     VTY_NEWLINE);


        if (ifp->desc)
            vty_out (vty, " description %s%s", ifp->desc,
                     VTY_NEWLINE);

        /* Assign bandwidth here to avoid unnecessary interface flap
        while processing config script */
        if (ifp->bandwidth != 0)
            vty_out(vty, " bandwidth %u%s", ifp->bandwidth, VTY_NEWLINE);

        if (CHECK_FLAG(ifp->status, ZEBRA_INTERFACE_LINKDETECTION))
            vty_out(vty, " link-detect%s", VTY_NEWLINE);

        for (ALL_LIST_ELEMENTS_RO (ifp->connected, addrnode, ifc))
        {
            if (CHECK_FLAG (ifc->conf, ZEBRA_IFC_CONFIGURED))
            {
                char buf[INET6_ADDRSTRLEN];
                p = ifc->address;
                vty_out (vty, " ip%s address %s/%d",
                         p->family == AF_INET ? "" : "v6",
                         inet_ntop (p->family, &p->u.prefix, buf, sizeof(buf)),
                         p->prefixlen);

                if (ifc->label)
                    vty_out (vty, " label %s", ifc->label);

                vty_out (vty, "%s", VTY_NEWLINE);
            }
        }

        if (if_data)
        {
#if 1
            if(if_data->nd==ND_INTERFACE)
            {
                //add for ipv6 nd neigh
                int k=0;
                for(k=0; k<KEEP_CONFIG_SIZE; k++)
                {
                    //if(strcmp(nd_keep_config[k].ip,"\0")!=0) vty_out(vty,"the dev name is %s\n",nd_keep_config[k].arp_dev);
                    if(strcmp(nd_keep_config[k].arp_dev,ifp->name)==0)
                    {
                        if(strcmp(nd_keep_config[k].ip,"\0")!=0)
                        {
                            vty_out(vty," ipv6 nd neighbor %s %s",nd_keep_config[k].ip,nd_keep_config[k].mac);
                            vty_out(vty,"%s",VTY_NEWLINE);
                        }
                    }
                }
                //add end

            }
#endif
            //added for nat 20130508
            if(if_data->nat == NAT_INSIDE)
                vty_out (vty, " ip nat inside%s", VTY_NEWLINE);
            if(if_data->nat == NAT_OUTSIDE)
                vty_out (vty, " ip nat outside%s", VTY_NEWLINE);

            if (if_data->shutdown == IF_ZEBRA_SHUTDOWN_ON)
                vty_out (vty, " shutdown%s", VTY_NEWLINE);

            if (if_data->multicast != IF_ZEBRA_MULTICAST_UNSPEC)
                vty_out (vty, " %smulticast%s",
                         if_data->multicast == IF_ZEBRA_MULTICAST_ON ? "" : "no ",
                         VTY_NEWLINE);
            /*sangmeng add for filter show*/
#if 1
            struct iptables_interface_list *list;

            for (list = ilist.head; list; list = list->next)
            {

                if (strcmp(list->ifp_name, ifp->name) == 0)
                {
                    if (strlen(list->rname_ipv4.name_in) != 0)
                        vty_out(vty, " ip access-group %s in%s", list->rname_ipv4.name_in, VTY_NEWLINE);
                    if (strlen(list->rname_ipv4.name_out) != 0)
                        vty_out(vty, " ip access-group %s out%s", list->rname_ipv4.name_out, VTY_NEWLINE);
#if 0 //wjh 20190214
                    if (strlen(list->rname_ipv6.name_in) != 0)
                        vty_out(vty, " ipv6 access-group %s in%s", list->rname_ipv6.name_in, VTY_NEWLINE);
                    if (strlen(list->rname_ipv6.name_out) != 0)
                        vty_out(vty, " ipv6 access-group %s out%s", list->rname_ipv6.name_out, VTY_NEWLINE);
#else
                    if (strlen(list->rname_ipv6.name_in) != 0)
                        vty_out(vty, " ipv6 access-group %s %s", list->rname_ipv6.name_in, VTY_NEWLINE);

#endif
                }
            }
#endif

        }
#ifdef RTADV
        rtadv_config_write (vty, ifp);
#endif /* RTADV */

#ifdef HAVE_IRDP
        irdp_config_write (vty, ifp);
#endif /* IRDP */

        vty_out (vty, "!%s", VTY_NEWLINE);
    }
    return 0;
}

/* Allocate and initialize interface vector. */
void
zebra_if_init (void)
{
    memset(nd_keep_config,0,sizeof(nd_keep_config));
    /* Initialize interface and new hook. */
    if_init ();
    if_add_hook (IF_NEW_HOOK, if_zebra_new_hook);
    if_add_hook (IF_DELETE_HOOK, if_zebra_delete_hook);

    /* Install configuration write function. */
    install_node (&interface_node, if_config_write);

    install_element (VIEW_NODE, &show_interface_cmd);
    install_element (ENABLE_NODE, &show_interface_cmd);
    install_element (ENABLE_NODE, &show_interface_desc_cmd);
    //install_element (CONFIG_NODE, &zebra_interface_cmd);
    install_element (CONFIG_NODE, &zebra_interfacegigabitethernet_cmd);
    install_element (CONFIG_NODE, &zebra_no_interfacegigabitethernet_cmd);
    install_element (CONFIG_NODE, &no_interface_cmd);
    //  install_element (CONFIG_NODE, &no_interfacegigabitethernet_cmd);
    install_default (INTERFACE_NODE);
    install_element (INTERFACE_NODE, &interface_desc_cmd);
    install_element (INTERFACE_NODE, &no_interface_desc_cmd);
    install_element (INTERFACE_NODE, &multicast_cmd);
    install_element (INTERFACE_NODE, &no_multicast_cmd);
    install_element (INTERFACE_NODE, &linkdetect_cmd);
    install_element (INTERFACE_NODE, &no_linkdetect_cmd);
    install_element (INTERFACE_NODE, &shutdown_if_cmd);
    install_element (INTERFACE_NODE, &no_shutdown_if_cmd);

    install_element (INTERFACE_NODE, &vlan_if_cmd);
    install_element (INTERFACE_NODE, &no_vlan_if_cmd);

    install_element (INTERFACE_NODE, &bandwidth_if_cmd);
    install_element (INTERFACE_NODE, &no_bandwidth_if_cmd);
    install_element (INTERFACE_NODE, &no_bandwidth_if_val_cmd);
    install_element (INTERFACE_NODE, &ip_address_cmd);
    install_element (INTERFACE_NODE, &no_ip_address_cmd);
#ifdef HAVE_IPV6
    install_element (INTERFACE_NODE, &ipv6_address_cmd);
    install_element (INTERFACE_NODE, &no_ipv6_address_cmd);
    //add for ipv6 nd neighbor cmd
    install_element (INTERFACE_NODE, &ipv6_nd_neighbor_cmd);
    install_element (INTERFACE_NODE, &no_ipv6_nd_neighbor_cmd);
#endif /* HAVE_IPV6 */
#ifdef HAVE_NETLINK
    //install_element (INTERFACE_NODE, &ip_address_label_cmd);
    //install_element (INTERFACE_NODE, &no_ip_address_label_cmd);
#endif /* HAVE_NETLINK */
}
