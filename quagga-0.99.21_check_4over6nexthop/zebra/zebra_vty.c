/* Zebra VTY functions
 * Copyright (C) 2002 Kunihiro Ishiguro
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
 * along with GNU Zebra; see the file COPYING.  If not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#include <zebra.h>
#include <sys/socket.h>
#include <stdlib.h>
#include  <string.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
//#include <net/if.h>        /*struct ifreq*/
#include <linux/ip6_tunnel.h>	/* struct ip6_tnl_parm */
#include <linux/if_tunnel.h>	/*tunnel cmd */
#include <errno.h>
#include "memory.h"
#include "if.h"
#include "prefix.h"
#include "command.h"
#include "table.h"
#include "rib.h"
#include "flowengine.h"
#include "zebra/interface.h"
#include "bgpd/bgp_zebra.h"


#include "zebra/zserv.h"
#include "lib/filter.h"
//add for arp_cmd
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

#define HAVE_NETWIRE
#define HAVE_DNS64
#define HAVE_DHCPV4
//#define HAVE_4OVER6_TCPMSS
#define HAVE_IPNAT
//#define HAVE_SNMP
#define BYTE unsigned char

#ifdef HAVE_DNS64
char dnsprefix[100] = { 0 };
char dnsv4[50] = { 0 };
char dns64_ubit[10] = { 0 };
#endif
/* add by s 130806*/


int ipv6_server_forwarding_status = 0 ;//0: no forwarding  1:forwarding

extern struct zebra_4over6_tunnel_entry zebra4over6TunnelEntry;
int g_U8_t_DataMemcmp(u8_t  * pbySrc, u8_t  * pbyDest, u8_t byLen);
//extern struct interface *if_lookup_by_ipv6 (struct in6_addr *);

char ifname[20];
static char *dpdk_ifindex2ifname(int ifindex)
{
    memset(ifname,0,20);
    ifindex += 5;
    //char ifname[20];
    sprintf(ifname,"vEth%d_%d",ifindex/5 ,ifindex%5);
    return ifname;
}

struct interface *
if_lookup_by_ipv6 (struct in6_addr *addr)
{
    struct listnode *ifnode;
    struct listnode *cnode;
    struct interface *ifp;
    struct connected *connected;
    struct prefix_ipv6 p;
    struct prefix *cp;

    p.family = AF_INET6;
    p.prefix = *addr;
    p.prefixlen = IPV6_MAX_BITLEN;

    for (ALL_LIST_ELEMENTS_RO (iflist, ifnode, ifp))
    {
        for (ALL_LIST_ELEMENTS_RO (ifp->connected, cnode, connected))
        {
            cp = connected->address;

            if (cp->family == AF_INET6)
                if (prefix_match (cp, (struct prefix *)&p))
                    return ifp;
        }
    }
    return NULL;
}




struct save_mss
{
    int mss_value;
    int mss_flag;
} save_mss;

struct save_mss save_tunnel4o6_tcpmss;

struct route_table_info
{
    char table_name[32];
    int table_len;
};

#define CLENT_ID_UNM 5
unsigned char client_id[CLENT_ID_UNM]= {0};
/* end add*/

//added by wangyl for dhcp
typedef struct DHCP_CFG_TABLE
{
    char OneCmdLine[128];
} DHCP_CFG_TABLE;

typedef struct DHCP_CFG_HEAD
{
    int count;
} DHCP_CFG_HEAD;
//added end

/*ivi46  or nat64*/
struct ion_prefix
{
    struct in6_addr prefix;
    int len;
    int ubit;
};
struct tnl_parm
{
    char name[IFNAMSIZ];		/* name of tunnel device */
    int link;					/* ifindex of underlying L2 interface */
    __u8 proto;					/* tunnel protocol */
    __u8 encap_limit;			/* encapsulation limit for tunnel */
    __u8 hop_limit;				/* hop limit for tunnel */
    __be32 flowinfo;			/* traffic class and flowlabel for tunnel */
    __u32 flags;				/* tunnel flags */
    struct in6_addr laddr;		/* local tunnel end-point address */
    struct in6_addr raddr;		/* remote tunnel end-point address */
    struct ion_prefix prefix;
};
#if 1
struct ivi64_tnl_parm
{
    char name[IFNAMSIZ];		/* name of tunnel device */
    int link;					/* ifindex of underlying L2 interface */
    __u8 proto;					/* tunnel protocol */
    __u8 encap_limit;			/* encapsulation limit for tunnel */
    __u8 hop_limit;				/* hop limit for tunnel */
    __be32 flowinfo;			/* traffic class and flowlabel for tunnel */
    __u32 flags;				/* tunnel flags */
    struct in6_addr laddr;		/* local tunnel end-point address */
    struct in6_addr raddr;		/* remote tunnel end-point address */
    struct ion_prefix prefix;
};
#endif
#if 0
struct ivi64_tnl_parm
{
    char name[IFNAMSIZ];		/* name of tunnel device */
    int link;					/* ifindex of underlying L2 interface */
    __be16 i_flags;
    __be16 o_flags;
    __be32 i_key;
    __be32 o_key;
    struct iphdr iph;
    struct ion_prefix prefix;
};
#endif
unsigned int v4Dns;
struct prefix v6prefix;
#define KEEP_CONFIG_SIZE 50
struct arp_config
{
    int flag;
    char ip[16];
    char mac[19];
    char arp_dev[21];
} arp_keep_config[KEEP_CONFIG_SIZE];
int arp_count = 0;
//added for nat 20130507
struct nat_pool_entry natPoolEntry;
struct nat_source_list natSourceList;
struct nat_source_list_pool_entry natSourceListPoolEntry;

/* General fucntion for static route. */
static int zebra_static_ipv4 (struct vty *vty, int add_cmd, const char *dest_str, const char *mask_str, const char *gate_str, const char *flag_str, const char *distance_str)
{
    int ret;
    u_char distance;
    struct prefix p;
    struct in_addr gate;
    struct in_addr mask;
    const char *ifname;
    u_char flag = 0;

    ret = str2prefix (dest_str, &p);
    if (ret <= 0)
    {
        vty_out (vty, "%% Malformed address%s", VTY_NEWLINE);
        return CMD_WARNING;
    }

    /* Cisco like mask notation. */
    if (mask_str)
    {
        ret = inet_aton (mask_str, &mask);
        if (ret == 0)
        {
            vty_out (vty, "%% Malformed address%s", VTY_NEWLINE);
            return CMD_WARNING;
        }
        p.prefixlen = ip_masklen (mask);
    }

    /* Apply mask for given prefix. */
    apply_mask (&p);

    /* Administrative distance. */
    if (distance_str)
        distance = atoi (distance_str);
    else
        distance = ZEBRA_STATIC_DISTANCE_DEFAULT;

    /* Null0 static route.  */
    if ((gate_str != NULL) && (strncasecmp (gate_str, "Null0", strlen (gate_str)) == 0))
    {
        if (flag_str)
        {
            vty_out (vty, "%% can not have flag %s with Null0%s", flag_str, VTY_NEWLINE);
            return CMD_WARNING;
        }
        if (add_cmd)
            static_add_ipv4 (&p, NULL, NULL, ZEBRA_FLAG_BLACKHOLE, distance, 0);
        else
            static_delete_ipv4 (&p, NULL, NULL, distance, 0);
        return CMD_SUCCESS;
    }

    /* Route flags */
    if (flag_str)
    {
        switch (flag_str[0])
        {
        case 'r':
        case 'R':				/* XXX */
            SET_FLAG (flag, ZEBRA_FLAG_REJECT);
            break;
        case 'b':
        case 'B':				/* XXX */
            SET_FLAG (flag, ZEBRA_FLAG_BLACKHOLE);
            break;
        default:
            vty_out (vty, "%% Malformed flag %s %s", flag_str, VTY_NEWLINE);
            return CMD_WARNING;
        }
    }

    if (gate_str == NULL)
    {
        if (add_cmd)
            static_add_ipv4 (&p, NULL, NULL, flag, distance, 0);
        else
            static_delete_ipv4 (&p, NULL, NULL, distance, 0);

        return CMD_SUCCESS;
    }

    /* When gateway is A.B.C.D format, gate is treated as nexthop
       address other case gate is treated as interface name. */
    ret = inet_aton (gate_str, &gate);
    if (ret)
        ifname = NULL;
    else
        ifname = gate_str;

    if (add_cmd)
        static_add_ipv4 (&p, ifname ? NULL : &gate, ifname, flag, distance, 0);
    else
        static_delete_ipv4 (&p, ifname ? NULL : &gate, ifname, distance, 0);

    return CMD_SUCCESS;
}
/*sangmeng add for customize route 20180705*/
/* General fucntion for static customize route. */
static int zebra_ipv4_customize (int add_cmd, char *routetablename, const char *dest_str, const char *mask_str, const char *gate_str, char *ifname, const char *distance_str)
{
    int ret;
    u_char distance;
    struct prefix p;
    struct in_addr gate;
    struct in_addr mask;
    u_char flag = 0;

    ret = str2prefix (dest_str, &p);
    if (ret <= 0)
    {
        return CMD_WARNING;
    }

    /* Cisco like mask notation. */
    if (mask_str)
    {
        ret = inet_aton (mask_str, &mask);
        if (ret == 0)
        {
            return CMD_WARNING;
        }
        p.prefixlen = ip_masklen (mask);
    }

    /* Apply mask for given prefix. */
    apply_mask (&p);

    /* Administrative distance. */
    if (distance_str)
        distance = atoi (distance_str);
    else
        distance = ZEBRA_STATIC_DISTANCE_DEFAULT;

    /* When gateway is A.B.C.D format, gate is treated as nexthop
       address other case gate is treated as interface name. */
    ret = inet_aton (gate_str, &gate);
    if (!ret)
    {
        printf("gate is error,\n");
        return CMD_WARNING;
    }

    if (add_cmd)
        zebra_rib_add_ipv4_customize (routetablename, &p, &gate, ifname, distance, 0);
    else
        zebra_rib_delete_ipv4_customize (routetablename, &p, &gate, ifname, 0);

    return CMD_SUCCESS;
}
/* General fucntion for static customize route. */
static int zebra_static_ipv4_customize (/*struct vty *vty,*/ int add_cmd, const char *dest_str, const char *mask_str, const char *gate_str, const char *flag_str, const char *distance_str)
{
    int ret;
    u_char distance;
    struct prefix p;
    struct in_addr gate;
    struct in_addr mask;
    const char *ifname;
    u_char flag = 0;

    ret = str2prefix (dest_str, &p);
    if (ret <= 0)
    {
        //vty_out (vty, "%% Malformed address%s", VTY_NEWLINE);
        return CMD_WARNING;
    }

    /* Cisco like mask notation. */
    if (mask_str)
    {
        ret = inet_aton (mask_str, &mask);
        if (ret == 0)
        {
            //vty_out (vty, "%% Malformed address%s", VTY_NEWLINE);
            return CMD_WARNING;
        }
        p.prefixlen = ip_masklen (mask);
    }

    /* Apply mask for given prefix. */
    apply_mask (&p);

    /* Administrative distance. */
    if (distance_str)
        distance = atoi (distance_str);
    else
        distance = ZEBRA_STATIC_DISTANCE_DEFAULT;

    /* Null0 static route.  */
    if ((gate_str != NULL) && (strncasecmp (gate_str, "Null0", strlen (gate_str)) == 0))
    {
        if (flag_str)
        {
            //vty_out (vty, "%% can not have flag %s with Null0%s", flag_str, VTY_NEWLINE);
            return CMD_WARNING;
        }
        printf("%d add ipv4 customize route here.\n", __LINE__);
        if (add_cmd)
            static_add_ipv4_customize (&p, NULL, NULL, ZEBRA_FLAG_BLACKHOLE, distance, 0);
        else
            static_delete_ipv4_customize (&p, NULL, NULL, distance, 0);
        return CMD_SUCCESS;
    }

    /* Route flags */
    if (flag_str)
    {
        switch (flag_str[0])
        {
        case 'r':
        case 'R':				/* XXX */
            SET_FLAG (flag, ZEBRA_FLAG_REJECT);
            break;
        case 'b':
        case 'B':				/* XXX */
            SET_FLAG (flag, ZEBRA_FLAG_BLACKHOLE);
            break;
        default:
            //vty_out (vty, "%% Malformed flag %s %s", flag_str, VTY_NEWLINE);
            return CMD_WARNING;
        }
    }

    if (gate_str == NULL)
    {
        printf("%d add ipv4 customize route here.\n", __LINE__);
        if (add_cmd)
            static_add_ipv4_customize (&p, NULL, NULL, flag, distance, 0);
        else
            static_delete_ipv4_customize (&p, NULL, NULL, distance, 0);

        return CMD_SUCCESS;
    }

    /* When gateway is A.B.C.D format, gate is treated as nexthop
       address other case gate is treated as interface name. */
    ret = inet_aton (gate_str, &gate);
    if (ret)
        ifname = NULL;
    else
        ifname = gate_str;

    printf("%d add ipv4 customize route here, add_cmd:%d.\n", __LINE__, add_cmd);
    if (add_cmd)
        static_add_ipv4_customize (&p, ifname ? NULL : &gate, ifname, flag, distance, 0);
    else
        static_delete_ipv4_customize (&p, ifname ? NULL : &gate, ifname, distance, 0);

    return CMD_SUCCESS;
}

//added for 4over6 20130205
static int zebra_static_ipv4_4over6 (struct vty *vty, int add_cmd, const char *dest_str, const char *mask_str, const char *gate_str)
{
    int ret;
    u_char distance;
    struct prefix p;
    struct in6_addr gate;
    struct in_addr mask;
    const char *ifname;
    char tunnel_name[IFNAMSIZ] = { 0 };
    u_char type = 0;
    u_char flag = 0;

    ret = str2prefix (dest_str, &p);
    if (ret <= 0)
    {
        vty_out (vty, "%% Malformed address%s", VTY_NEWLINE);
        return CMD_WARNING;
    }

    /* Cisco like mask notation. */
    if (mask_str)
    {
        ret = inet_aton (mask_str, &mask);
        if (ret == 0)
        {
            vty_out (vty, "%% Malformed address%s", VTY_NEWLINE);
            return CMD_WARNING;
        }
        p.prefixlen = ip_masklen (mask);
    }

    /* Apply mask for given prefix. */
    apply_mask (&p);

    distance = ZEBRA_STATIC_DISTANCE_DEFAULT;

    TEST_DEBUG("gate_str:%s.\n", gate_str);
    /* When gateway is valid IPv6 addrees, then gate is treated as
       nexthop address other case gate is treated as interface name. */
    ret = inet_pton (AF_INET6, gate_str, &gate);
    if (ret == 1)
    {
        type = STATIC_IPV6_GATEWAY;
        ifname = NULL;
    }
    else
    {
        type = STATIC_IPV6_IFNAME;
        ifname = gate_str;
    }

    if (add_cmd)
    {
        zebra_4over6_nexthop_add_check (gate, (struct prefix_ipv4 *)&p);
        ret = zebra_4over6_nexthop_lookup (&gate, tunnel_name);
        if (ret == 0)
        {
            ifname = tunnel_name;
            type = STATIC_IPV6_GATEWAY_IFNAME;
        }
#if 1//for no 4over6 route in kernel
        static_add_ipv4_4over6 (&p, type, &gate, ifname, flag, distance, 0);
#endif
    }
    else
    {
        ret = zebra_4over6_nexthop_lookup (&gate, tunnel_name);
        if (ret == 0)
        {
            ifname = tunnel_name;
            type = STATIC_IPV6_GATEWAY_IFNAME;
        }
#if 1//for no 4over6 route in kernel
        static_delete_ipv4_4over6 (&p, type, &gate, ifname, distance, 0);
#endif
        zebra_4over6_nexthop_del_check (gate);
    }

    return CMD_SUCCESS;
}

/* Static route configuration.  */
DEFUN (ip_route,
       ip_route_cmd,
       "ip route A.B.C.D/M (A.B.C.D|INTERFACE|null0)",
       IP_STR
       "Establish static routes\n"
       "IP destination prefix (e.g. 10.0.0.0/8)\n"
       "IP gateway address\n"
       "IP gateway interface name\n"
       "Null interface\n")
{
    return zebra_static_ipv4 (vty, 1, argv[0], NULL, argv[1], NULL, NULL);
}

DEFUN (ip_route_flags,
       ip_route_flags_cmd,
       "ip route A.B.C.D/M (A.B.C.D|INTERFACE) (reject|blackhole)",
       IP_STR
       "Establish static routes\n"
       "IP destination prefix (e.g. 10.0.0.0/8)\n" "IP gateway address\n" "IP gateway interface name\n" "Emit an ICMP unreachable when matched\n" "Silently discard pkts when matched\n")
{
    return zebra_static_ipv4 (vty, 1, argv[0], NULL, argv[1], argv[2], NULL);
}

DEFUN (ip_route_flags2,
       ip_route_flags2_cmd,
       "ip route A.B.C.D/M (reject|blackhole)",
       IP_STR "Establish static routes\n" "IP destination prefix (e.g. 10.0.0.0/8)\n" "Emit an ICMP unreachable when matched\n" "Silently discard pkts when matched\n")
{
    return zebra_static_ipv4 (vty, 1, argv[0], NULL, NULL, argv[1], NULL);
}

/* Mask as A.B.C.D format.  */
DEFUN (ip_route_mask,
       ip_route_mask_cmd,
       "ip route A.B.C.D A.B.C.D (A.B.C.D|INTERFACE|null0)",
       IP_STR
       "Establish static routes\n"
       "IP destination prefix\n"
       "IP destination prefix mask\n"
       "IP gateway address\n"
       "IP gateway interface name\n"
       "Null interface\n")
{
    return zebra_static_ipv4 (vty, 1, argv[0], argv[1], argv[2], NULL, NULL);
}

//added for 4over6 20130205
DEFUN (ip_4over6_route,
       ip_4over6_route_cmd,
       "ip 4over6 route A.B.C.D/M X:X::X:X",
       IP_STR
       "Establish 4over6 routes\n"
       "Establish static routes\n"
       "IP destination prefix (e.g. 10.0.0.0/8)\n"
       "IPv6 destination address\n")
{
    return zebra_static_ipv4_4over6 (vty, 1, argv[0], NULL, argv[1]);
}

DEFUN (no_ip_4over6_route,
       no_ip_4over6_route_cmd,
       "no ip 4over6 route A.B.C.D/M X:X::X:X",
       NO_STR IP_STR
       "Establish 4over6 routes\n"
       "Establish static routes\n"
       "IP destination prefix (e.g. 10.0.0.0/8)\n"
       "IPv6 gateway address\n")
{
    return zebra_static_ipv4_4over6 (vty, 0, argv[0], NULL, argv[1]);
}

DEFUN (ip_4over6_route_mask,
       ip_4over6_route_mask_cmd,
       "ip 4over6 route A.B.C.D A.B.C.D X:X::X:X",
       IP_STR
       "Establish 4over6 routes\n"
       "Establish static routes\n"
       "IP destination prefix\n"
       "IP destination prefix mask\n"
       "IPv6 gateway address\n")
{
    return zebra_static_ipv4_4over6 (vty, 1, argv[0], argv[1], argv[2]);
}

DEFUN (no_ip_4over6_route_mask,
       no_ip_4over6_route_mask_cmd,
       "no ip 4over6 route A.B.C.D A.B.C.D X:X::X:X",
       NO_STR IP_STR
       "Establish 4over6 routes\n"
       "Establish static routes\n"
       "IP destination prefix\n"
       "IP destination prefix mask\n"
       "IPv6 gateway address\n")
{
    return zebra_static_ipv4_4over6 (vty, 0, argv[0], argv[1], argv[2]);
}

#ifdef HAVE_IPNAT
//added for nat 20130505
static int ip_nat_state_change_by_add_pool (const char *pool_name)
{
    struct nat_source_list_pool_entry *pLast;
    struct nat_source_list_pool_entry *pNext;
    int ret_pool = 0;
    char poolname[NATSIZE];
    char addcmd[CMDSTR];

    memset (addcmd, 0, CMDSTR);
    memset (poolname, 0, NATSIZE);
    sprintf (poolname, pool_name);

    pLast = &natSourceListPoolEntry;
    pNext = natSourceListPoolEntry.next;
    while (pNext != NULL)
    {
        ret_pool = memcmp (poolname, pNext->pool.name, NATSIZE);
        if (ret_pool == 0)
        {
            pNext->pool_state = NAT_ENABLE;
            if (pNext->list_state == NAT_ENABLE)
            {
                sprintf (addcmd, "/sbin/iptables -t nat -A POSTROUTING -s %s -j SNAT --to %s", pNext->source.snet, pNext->pool.poolcmdstr);
                system (addcmd);
            }
        }

        pLast = pNext;
        pNext = pNext->next;
    }

    return CMD_SUCCESS;
}

static int ip_nat_pool_add (struct vty *vty, const char *pool_name, const char *start_addr, const char *end_addr)
{
    struct nat_pool_entry *pLast;
    struct nat_pool_entry *pNext;
    struct nat_pool_entry *pNew;
    int iRetVal = 0;
    int ret = 1;
    int ret_cmp = 0;
    char poolname[NATSIZE];
    char startaddr[NATSIZE];
    char endaddr[NATSIZE];
    struct in_addr start;
    struct in_addr end;

    memset (poolname, 0, NATSIZE);
    memset (startaddr, 0, NATSIZE);
    memset (startaddr, 0, NATSIZE);
    memset (&start, 0, sizeof (struct in_addr));
    memset (&end, 0, sizeof (struct in_addr));
    sprintf (poolname, pool_name);
    sprintf (startaddr, start_addr);
    sprintf (endaddr, end_addr);

    ret = inet_aton (start_addr, &start);
    if (ret == 0)
    {
        vty_out (vty, "%% Start address translation error%s", VTY_NEWLINE);
        return CMD_WARNING;
    }
    ret = inet_aton (end_addr, &end);
    if (ret == 0)
    {
        vty_out (vty, "%% End address translation error%s", VTY_NEWLINE);
        return CMD_WARNING;
    }
    if (IPV4_ADDR_CMP (&start, &end) > 0)
    {
        vty_out (vty, "%% Start address is greater than end address%s", VTY_NEWLINE);
        return CMD_WARNING;
    }

    pLast = &natPoolEntry;
    pNext = natPoolEntry.next;
    while (pNext != NULL)
    {
        iRetVal = memcmp (poolname, pNext->name, NATSIZE);
        if (iRetVal == 0)
            break;

        pLast = pNext;
        pNext = pNext->next;
    }
    if (pNext != NULL)
    {
        vty_out (vty, "%% The pool name is repeat%s", VTY_NEWLINE);
        return CMD_WARNING;
    }
    else
    {
        pNew = XCALLOC (MTYPE_NAT, sizeof (struct nat_pool_entry));
        if (pNew == NULL)
        {
            vty_out (vty, "%% Memory could not be applied%s", VTY_NEWLINE);
            return CMD_WARNING;
        }

        memset (pNew, 0, sizeof (struct nat_pool_entry));
        strlcpy (pNew->name, poolname, NATSIZE);
        sprintf (pNew->startaddr, start_addr);
        sprintf (pNew->endaddr, end_addr);
        IPV4_ADDR_COPY (&pNew->start_addr, &start);
        IPV4_ADDR_COPY (&pNew->end_addr, &end);
        pNew->next = NULL;

        ret_cmp = memcmp (startaddr, endaddr, NATSIZE);
        if (ret_cmp == 0)
            sprintf (pNew->poolcmdstr, start_addr);
        else
            sprintf (pNew->poolcmdstr, "%s-%s", start_addr, endaddr);

        ip_nat_state_change_by_add_pool (poolname);

        pLast->next = pNew;
    }

    return CMD_SUCCESS;
}

static int ip_nat_state_change_by_del_pool (const char *pool_name)
{
    struct nat_source_list_pool_entry *pLast;
    struct nat_source_list_pool_entry *pNext;
    int ret_pool = 0;
    char poolname[NATSIZE];
    char delcmd[CMDSTR];

    memset (delcmd, 0, CMDSTR);
    memset (poolname, 0, NATSIZE);
    sprintf (poolname, pool_name);

    pLast = &natSourceListPoolEntry;
    pNext = natSourceListPoolEntry.next;
    while (pNext != NULL)
    {
        ret_pool = memcmp (poolname, pNext->pool.name, NATSIZE);
        if (ret_pool == 0)
        {
            pNext->pool_state = NAT_DISABLE;
            if (pNext->list_state == NAT_ENABLE)
            {
                sprintf (delcmd, "/sbin/iptables -t nat -D POSTROUTING -s %s -j SNAT --to %s", pNext->source.snet, pNext->pool.poolcmdstr);
                system (delcmd);
            }
        }

        pLast = pNext;
        pNext = pNext->next;
    }

    return CMD_SUCCESS;
}

static int ip_nat_pool_del (struct vty *vty, const char *pool_name)
{
    struct nat_pool_entry *pLast;
    struct nat_pool_entry *pNext;
    int iRetVal = 0;
    char poolname[NATSIZE];

    memset (poolname, 0, NATSIZE);
    sprintf (poolname, pool_name);

    pLast = &natPoolEntry;
    pNext = natPoolEntry.next;
    while (pNext != NULL)
    {
        iRetVal = memcmp (poolname, pNext->name, NATSIZE);
        if (iRetVal == 0)
            break;

        pLast = pNext;
        pNext = pNext->next;
    }
    if (pNext != NULL)
    {
        ip_nat_state_change_by_del_pool (pNext->name);
        pLast->next = pNext->next;
        XFREE (MTYPE_NAT, pNext);
    }

    return CMD_SUCCESS;
}

DEFUN (ip_nat_pool, ip_nat_pool_cmd, "ip nat pool WORD A.B.C.D A.B.C.D", IP_STR "NAT configuration commands\n" "Define pool of addresses\n" "Pool name\n" "Start IP address\n" "End IP address\n")
{
    return ip_nat_pool_add (vty, argv[0], argv[1], argv[2]);
}

DEFUN (no_ip_nat_pool, no_ip_nat_pool_cmd, "no ip nat pool WORD", NO_STR IP_STR "NAT configuration commands\n" "Define pool of addresses\n" "Pool name\n")
{
    return ip_nat_pool_del (vty, argv[0]);
}

static int ip_nat_state_change_by_add_source_list (const char *list_name)
{
    struct nat_source_list_pool_entry *pLast;
    struct nat_source_list_pool_entry *pNext;
    int ret_list = 0;
    char listname[NATSIZE];
    char addcmd[CMDSTR];

    memset (addcmd, 0, CMDSTR);
    memset (listname, 0, NATSIZE);
    sprintf (listname, list_name);

    pLast = &natSourceListPoolEntry;
    pNext = natSourceListPoolEntry.next;
    while (pNext != NULL)
    {
        ret_list = memcmp (listname, pNext->source.name, NATSIZE);
        if (ret_list == 0)
        {
            pNext->list_state = NAT_ENABLE;
            if (pNext->pool_state == NAT_ENABLE)
            {
                sprintf (addcmd, "/sbin/iptables -t nat -A POSTROUTING -s %s -j SNAT --to %s", pNext->source.snet, pNext->pool.poolcmdstr);
                system (addcmd);
            }
        }

        pLast = pNext;
        pNext = pNext->next;
    }

    return CMD_SUCCESS;
}

static int ip_nat_source_list_add (struct vty *vty, const char *list_name, const char *net_str)
{
    struct nat_source_list *pLast;
    struct nat_source_list *pNext;
    struct nat_source_list *pNew;
    int iRetVal = 0;
    int ret = 0;
    char listname[NATSIZE];
    struct prefix_ipv4 p;

    memset (listname, 0, NATSIZE);
    sprintf (listname, list_name);

    ret = str2prefix_ipv4 (net_str, &p);
    if (ret == 0)
    {
        vty_out (vty, "%% The Prefix is error%s", VTY_NEWLINE);
        return CMD_WARNING;
    }

    pLast = &natSourceList;
    pNext = natSourceList.next;
    while (pNext != NULL)
    {
        iRetVal = memcmp (listname, pNext->name, NATSIZE);
        if (iRetVal == 0)
            break;

        pLast = pNext;
        pNext = pNext->next;
    }
    if (pNext != NULL)
    {
        vty_out (vty, "%% The source list name is repeat%s", VTY_NEWLINE);
        return CMD_WARNING;
    }
    else
    {
        pNew = XCALLOC (MTYPE_NAT, sizeof (struct nat_source_list));
        if (pNew == NULL)
        {
            vty_out (vty, "%% Memory could not be applied%s", VTY_NEWLINE);
            return CMD_WARNING;
        }

        memset (pNew, 0, sizeof (struct nat_source_list));
        strlcpy (pNew->name, listname, NATSIZE);
        sprintf (pNew->snet, net_str);
        IPV4_ADDR_COPY (&pNew->source_addr, &p.prefix);
        pNew->masklen = p.prefixlen;
        pNew->next = NULL;

        ip_nat_state_change_by_add_source_list (listname);

        pLast->next = pNew;
    }

    return CMD_SUCCESS;
}

static int ip_nat_state_change_by_del_source_list (const char *list_name)
{
    struct nat_source_list_pool_entry *pLast;
    struct nat_source_list_pool_entry *pNext;
    int ret_list = 0;
    char listname[NATSIZE];
    char delcmd[CMDSTR];

    memset (delcmd, 0, CMDSTR);
    memset (listname, 0, NATSIZE);
    sprintf (listname, list_name);

    pLast = &natSourceListPoolEntry;
    pNext = natSourceListPoolEntry.next;
    while (pNext != NULL)
    {
        ret_list = memcmp (listname, pNext->source.name, NATSIZE);
        if (ret_list == 0)
        {
            pNext->list_state = NAT_DISABLE;
            if (pNext->pool_state = NAT_ENABLE)
            {
                sprintf (delcmd, "/sbin/iptables -t nat -D POSTROUTING -s %s -j SNAT --to %s", pNext->source.snet, pNext->pool.poolcmdstr);
                system (delcmd);
            }
        }

        pLast = pNext;
        pNext = pNext->next;
    }

    return CMD_SUCCESS;
}

static int ip_nat_source_list_del (struct vty *vty, const char *list_name)
{
    struct nat_source_list *pLast;
    struct nat_source_list *pNext;
    int iRetVal = 0;
    char listname[NATSIZE];

    memset (listname, 0, NATSIZE);
    sprintf (listname, list_name);

    pLast = &natSourceList;
    pNext = natSourceList.next;
    while (pNext != NULL)
    {
        iRetVal = memcmp (listname, pNext->name, NATSIZE);
        if (iRetVal == 0)
            break;

        pLast = pNext;
        pNext = pNext->next;
    }
    if (pNext != NULL)
    {
        ip_nat_state_change_by_del_source_list (pNext->name);
        pLast->next = pNext->next;
        XFREE (MTYPE_NAT, pNext);
    }

    return CMD_SUCCESS;
}

DEFUN (ip_nat_source_list,
       ip_nat_source_list_cmd,
       "ip nat source list WORD A.B.C.D/M",
       IP_STR "NAT configuration commands\n" "Source address translation\n" "Specify access list describing local addresses\n" "IP nat source-list name\n" "Prefix to match. e.g. 10.0.0.0/8\n")
{
    return ip_nat_source_list_add (vty, argv[0], argv[1]);
}

DEFUN (no_ip_nat_source_list,
       no_ip_nat_source_list_cmd,
       "no ip nat source list WORD", NO_STR IP_STR "NAT configuration commands\n" "Source address translation\n" "Specify access list describing local addresses\n" "IP nat source list name\n")
{
    return ip_nat_source_list_del (vty, argv[0]);
}

int ip_nat_pool_lookup (char *pool_name, struct nat_pool_entry *pool)
{
    struct nat_pool_entry *pLast;
    struct nat_pool_entry *pNext;
    int iRetVal = 0;

    pLast = &natPoolEntry;
    pNext = natPoolEntry.next;
    while (pNext != NULL)
    {
        iRetVal = memcmp (pNext->name, pool_name, NATSIZE);
        if (iRetVal == 0)
            break;

        pLast = pNext;
        pNext = pNext->next;
    }
    if (pNext != NULL)
    {
        memcpy (pool, pNext, sizeof (struct nat_pool_entry));
        return 0;
    }
    else
        return -1;
}

int ip_nat_source_list_lookup (char *list_name, struct nat_source_list *source)
{
    struct nat_source_list *pLast;
    struct nat_source_list *pNext;
    int iRetVal = 0;

    pLast = &natSourceList;
    pNext = natSourceList.next;
    while (pNext != NULL)
    {
        iRetVal = memcmp (pNext->name, list_name, NATSIZE);
        if (iRetVal == 0)
            break;

        pLast = pNext;
        pNext = pNext->next;
    }
    if (pNext != NULL)
    {
        memcpy (source, pNext, sizeof (struct nat_source_list));
        return 0;
    }
    else
        return -1;
}

static int ip_nat_source_list_pool_add (struct vty *vty, const char *list_name, const char *pool_name)
{
    struct nat_source_list_pool_entry *pLast;
    struct nat_source_list_pool_entry *pNext;
    struct nat_source_list_pool_entry *pNew;
    struct nat_source_list sourcelist;
    struct nat_pool_entry pool;
    int ret_pool = 0;
    int ret_list = 0;
    int ret = 0;
    char listname[NATSIZE];
    char poolname[NATSIZE];
    char addcmd[CMDSTR];

    memset (addcmd, 0, CMDSTR);
    memset (poolname, 0, NATSIZE);
    memset (listname, 0, NATSIZE);
    sprintf (poolname, pool_name);
    sprintf (listname, list_name);

    ret = ip_nat_source_list_lookup (listname, &sourcelist);
    if (ret != 0)
    {
        vty_out (vty, "%% The source list does not exist%s", VTY_NEWLINE);
        return CMD_WARNING;
    }

    ret = ip_nat_pool_lookup (poolname, &pool);
    if (ret != 0)
    {
        vty_out (vty, "%% The pool does not exist%s", VTY_NEWLINE);
        return CMD_WARNING;
    }

    pLast = &natSourceListPoolEntry;
    pNext = natSourceListPoolEntry.next;
    while (pNext != NULL)
    {
        ret_list = memcmp (listname, pNext->source.name, NATSIZE);
        ret_pool = memcmp (poolname, pNext->pool.name, NATSIZE);
        if (ret_pool == 0 && ret_list == 0)
            break;

        pLast = pNext;
        pNext = pNext->next;
    }
    if (pNext != NULL)
    {
        vty_out (vty, "%% The source list pool is repeat%s", VTY_NEWLINE);
        return CMD_WARNING;
    }
    else
    {
        pNew = XCALLOC (MTYPE_NAT, sizeof (struct nat_source_list_pool_entry));
        if (pNew == NULL)
        {
            vty_out (vty, "%% Memory could not be applied%s", VTY_NEWLINE);
            return CMD_WARNING;
        }

        memset (pNew, 0, sizeof (struct nat_source_list_pool_entry));
        pNew->pool_state = NAT_ENABLE;
        pNew->list_state = NAT_ENABLE;
        memcpy (&pNew->source, &sourcelist, sizeof (struct nat_source_list));
        memcpy (&pNew->pool, &pool, sizeof (struct nat_pool_entry));
        pNew->next = NULL;

        sprintf (addcmd, "/sbin/iptables -t nat -A POSTROUTING -s %s -j SNAT --to %s", pNew->source.snet, pNew->pool.poolcmdstr);
        system (addcmd);

        pLast->next = pNew;
    }

    return CMD_SUCCESS;
}

static int ip_nat_source_list_pool_del (struct vty *vty, const char *list_name, const char *pool_name)
{
    struct nat_source_list_pool_entry *pLast;
    struct nat_source_list_pool_entry *pNext;
    struct nat_source_list_pool_entry *pNew;
    struct nat_source_list *sourcelist;
    struct nat_pool_entry *pool;
    int ret_pool = 0;
    int ret_list = 0;
    int ret = 0;
    char listname[NATSIZE];
    char poolname[NATSIZE];
    char delcmd[CMDSTR];

    memset (delcmd, 0, CMDSTR);
    memset (poolname, 0, NATSIZE);
    memset (listname, 0, NATSIZE);
    sprintf (poolname, pool_name);
    sprintf (listname, list_name);

    pLast = &natSourceListPoolEntry;
    pNext = natSourceListPoolEntry.next;
    while (pNext != NULL)
    {
        ret_list = memcmp (listname, pNext->source.name, NATSIZE);
        ret_pool = memcmp (poolname, pNext->pool.name, NATSIZE);
        if (ret_pool == 0 && ret_list == 0)
            break;

        pLast = pNext;
        pNext = pNext->next;
    }
    if (pNext != NULL)
    {
        sprintf (delcmd, "/sbin/iptables -t nat -D POSTROUTING -s %s -j SNAT --to %s", pNext->source.snet, pNext->pool.poolcmdstr);
        system (delcmd);

        pLast->next = pNext->next;
        XFREE (MTYPE_NAT, pNext);
    }

    return CMD_SUCCESS;
}

DEFUN (ip_nat_inside_source_list_pool,
       ip_nat_inside_source_list_pool_cmd,
       "ip nat inside source list WORD pool WORD",
       IP_STR
       "NAT configuration commands\n"
       "Inside address translation\n"
       "Source address translation\n" "Specify access list describing local addresses\n" "Source list name for local addresses\n" "Name pool of global addresses\n" "Pool name for global addresses\n")
{
    return ip_nat_source_list_pool_add (vty, argv[0], argv[1]);
}

DEFUN (no_ip_nat_inside_source_list_pool,
       no_ip_nat_inside_source_list_pool_cmd,
       "no ip nat inside source list WORD pool WORD",
       NO_STR
       IP_STR
       "NAT configuration commands\n"
       "Inside address translation\n"
       "Source address translation\n" "Specify access list describing local addresses\n" "Source list name for local addresses\n" "Name pool of global addresses\n" "Pool name for global addresses\n")
{
    return ip_nat_source_list_pool_del (vty, argv[0], argv[1]);
}

DEFUN (ip_nat_inside, ip_nat_inside_cmd, "ip nat inside", IP_STR "NAT configuration commands\n" "Inside interface for address translation\n")
{
    struct interface *ifp;
    struct zebra_if *if_data;

    ifp = (struct interface *) vty->index;
    if_data = ifp->info;
    if_data->nat = NAT_INSIDE;

    return CMD_SUCCESS;
}

DEFUN (no_ip_nat_inside, no_ip_nat_inside_cmd, "no ip nat inside", NO_STR IP_STR "NAT configuration commands\n" "Inside interface for address translation\n")
{
    struct interface *ifp;
    struct zebra_if *if_data;

    ifp = (struct interface *) vty->index;
    if_data = ifp->info;
    if_data->nat = NO_NAT;

    return CMD_SUCCESS;
}

DEFUN (ip_nat_outside, ip_nat_outside_cmd, "ip nat outside", IP_STR "NAT configuration commands\n" "Outside interface for address translation\n")
{
    struct interface *ifp;
    struct zebra_if *if_data;

    ifp = (struct interface *) vty->index;
    if_data = ifp->info;
    if_data->nat = NAT_OUTSIDE;

    return CMD_SUCCESS;
}

DEFUN (no_ip_nat_outside, no_ip_nat_outside_cmd, "no ip nat outside", NO_STR IP_STR "NAT configuration commands\n" "Outside interface for address translation\n")
{
    struct interface *ifp;
    struct zebra_if *if_data;

    ifp = (struct interface *) vty->index;
    if_data = ifp->info;
    if_data->nat = NO_NAT;

    return CMD_SUCCESS;
}
#endif

DEFUN (ip_route_mask_flags,
       ip_route_mask_flags_cmd,
       "ip route A.B.C.D A.B.C.D (A.B.C.D|INTERFACE) (reject|blackhole)",
       IP_STR
       "Establish static routes\n"
       "IP destination prefix\n" "IP destination prefix mask\n" "IP gateway address\n" "IP gateway interface name\n" "Emit an ICMP unreachable when matched\n" "Silently discard pkts when matched\n")
{
    return zebra_static_ipv4 (vty, 1, argv[0], argv[1], argv[2], argv[3], NULL);
}

DEFUN (ip_route_mask_flags2,
       ip_route_mask_flags2_cmd,
       "ip route A.B.C.D A.B.C.D (reject|blackhole)",
       IP_STR "Establish static routes\n" "IP destination prefix\n" "IP destination prefix mask\n" "Emit an ICMP unreachable when matched\n" "Silently discard pkts when matched\n")
{
    return zebra_static_ipv4 (vty, 1, argv[0], argv[1], NULL, argv[2], NULL);
}

/* Distance option value.  */
DEFUN (ip_route_distance,
       ip_route_distance_cmd,
       "ip route A.B.C.D/M (A.B.C.D|INTERFACE|null0) <1-255>",
       IP_STR "Establish static routes\n" "IP destination prefix (e.g. 10.0.0.0/8)\n" "IP gateway address\n" "IP gateway interface name\n" "Null interface\n" "Distance value for this route\n")
{
    return zebra_static_ipv4 (vty, 1, argv[0], NULL, argv[1], NULL, argv[2]);
}

DEFUN (ip_route_flags_distance,
       ip_route_flags_distance_cmd,
       "ip route A.B.C.D/M (A.B.C.D|INTERFACE) (reject|blackhole) <1-255>",
       IP_STR
       "Establish static routes\n"
       "IP destination prefix (e.g. 10.0.0.0/8)\n"
       "IP gateway address\n" "IP gateway interface name\n" "Emit an ICMP unreachable when matched\n" "Silently discard pkts when matched\n" "Distance value for this route\n")
{
    return zebra_static_ipv4 (vty, 1, argv[0], NULL, argv[1], argv[2], argv[3]);
}

DEFUN (ip_route_flags_distance2,
       ip_route_flags_distance2_cmd,
       "ip route A.B.C.D/M (reject|blackhole) <1-255>",
       IP_STR
       "Establish static routes\n" "IP destination prefix (e.g. 10.0.0.0/8)\n" "Emit an ICMP unreachable when matched\n" "Silently discard pkts when matched\n" "Distance value for this route\n")
{
    return zebra_static_ipv4 (vty, 1, argv[0], NULL, NULL, argv[1], argv[2]);
}

DEFUN (ip_route_mask_distance,
       ip_route_mask_distance_cmd,
       "ip route A.B.C.D A.B.C.D (A.B.C.D|INTERFACE|null0) <1-255>",
       IP_STR
       "Establish static routes\n" "IP destination prefix\n" "IP destination prefix mask\n" "IP gateway address\n" "IP gateway interface name\n" "Null interface\n" "Distance value for this route\n")
{
    return zebra_static_ipv4 (vty, 1, argv[0], argv[1], argv[2], NULL, argv[3]);
}

DEFUN (ip_route_mask_flags_distance,
       ip_route_mask_flags_distance_cmd,
       "ip route A.B.C.D A.B.C.D (A.B.C.D|INTERFACE) (reject|blackhole) <1-255>",
       IP_STR
       "Establish static routes\n"
       "IP destination prefix\n"
       "IP destination prefix mask\n"
       "IP gateway address\n" "IP gateway interface name\n" "Distance value for this route\n" "Emit an ICMP unreachable when matched\n" "Silently discard pkts when matched\n")
{
    return zebra_static_ipv4 (vty, 1, argv[0], argv[1], argv[2], argv[3], argv[4]);
}

DEFUN (ip_route_mask_flags_distance2,
       ip_route_mask_flags_distance2_cmd,
       "ip route A.B.C.D A.B.C.D (reject|blackhole) <1-255>",
       IP_STR
       "Establish static routes\n"
       "IP destination prefix\n" "IP destination prefix mask\n" "Distance value for this route\n" "Emit an ICMP unreachable when matched\n" "Silently discard pkts when matched\n")
{
    return zebra_static_ipv4 (vty, 1, argv[0], argv[1], NULL, argv[2], argv[3]);
}

DEFUN (no_ip_route,
       no_ip_route_cmd,
       "no ip route A.B.C.D/M (A.B.C.D|INTERFACE|null0)",
       NO_STR IP_STR "Establish static routes\n" "IP destination prefix (e.g. 10.0.0.0/8)\n" "IP gateway address\n" "IP gateway interface name\n" "Null interface\n")
{
    return zebra_static_ipv4 (vty, 0, argv[0], NULL, argv[1], NULL, NULL);
}

ALIAS (no_ip_route,
       no_ip_route_flags_cmd,
       "no ip route A.B.C.D/M (A.B.C.D|INTERFACE) (reject|blackhole)",
       NO_STR
       IP_STR
       "Establish static routes\n"
       "IP destination prefix (e.g. 10.0.0.0/8)\n"
       "IP gateway address\n"
       "IP gateway interface name\n"
       "Emit an ICMP unreachable when matched\n"
       "Silently discard pkts when matched\n")
DEFUN (no_ip_route_flags2,
       no_ip_route_flags2_cmd,
       "no ip route A.B.C.D/M (reject|blackhole)",
       NO_STR IP_STR "Establish static routes\n" "IP destination prefix (e.g. 10.0.0.0/8)\n" "Emit an ICMP unreachable when matched\n" "Silently discard pkts when matched\n")
{
    return zebra_static_ipv4 (vty, 0, argv[0], NULL, NULL, NULL, NULL);
}

DEFUN (no_ip_route_mask,
       no_ip_route_mask_cmd,
       "no ip route A.B.C.D A.B.C.D (A.B.C.D|INTERFACE|null0)",
       NO_STR IP_STR "Establish static routes\n" "IP destination prefix\n" "IP destination prefix mask\n" "IP gateway address\n" "IP gateway interface name\n" "Null interface\n")
{
    return zebra_static_ipv4 (vty, 0, argv[0], argv[1], argv[2], NULL, NULL);
}

ALIAS (no_ip_route_mask,
       no_ip_route_mask_flags_cmd,
       "no ip route A.B.C.D A.B.C.D (A.B.C.D|INTERFACE) (reject|blackhole)",
       NO_STR
       IP_STR
       "Establish static routes\n"
       "IP destination prefix\n"
       "IP destination prefix mask\n"
       "IP gateway address\n"
       "IP gateway interface name\n"
       "Emit an ICMP unreachable when matched\n"
       "Silently discard pkts when matched\n")
DEFUN (no_ip_route_mask_flags2,
       no_ip_route_mask_flags2_cmd,
       "no ip route A.B.C.D A.B.C.D (reject|blackhole)",
       NO_STR IP_STR "Establish static routes\n" "IP destination prefix\n" "IP destination prefix mask\n" "Emit an ICMP unreachable when matched\n" "Silently discard pkts when matched\n")
{
    return zebra_static_ipv4 (vty, 0, argv[0], argv[1], NULL, NULL, NULL);
}

DEFUN (no_ip_route_distance,
       no_ip_route_distance_cmd,
       "no ip route A.B.C.D/M (A.B.C.D|INTERFACE|null0) <1-255>",
       NO_STR IP_STR "Establish static routes\n" "IP destination prefix (e.g. 10.0.0.0/8)\n" "IP gateway address\n" "IP gateway interface name\n" "Null interface\n" "Distance value for this route\n")
{
    return zebra_static_ipv4 (vty, 0, argv[0], NULL, argv[1], NULL, argv[2]);
}

DEFUN (no_ip_route_flags_distance,
       no_ip_route_flags_distance_cmd,
       "no ip route A.B.C.D/M (A.B.C.D|INTERFACE) (reject|blackhole) <1-255>",
       NO_STR
       IP_STR
       "Establish static routes\n"
       "IP destination prefix (e.g. 10.0.0.0/8)\n"
       "IP gateway address\n" "IP gateway interface name\n" "Emit an ICMP unreachable when matched\n" "Silently discard pkts when matched\n" "Distance value for this route\n")
{
    return zebra_static_ipv4 (vty, 0, argv[0], NULL, argv[1], argv[2], argv[3]);
}

DEFUN (no_ip_route_flags_distance2,
       no_ip_route_flags_distance2_cmd,
       "no ip route A.B.C.D/M (reject|blackhole) <1-255>",
       NO_STR
       IP_STR
       "Establish static routes\n" "IP destination prefix (e.g. 10.0.0.0/8)\n" "Emit an ICMP unreachable when matched\n" "Silently discard pkts when matched\n" "Distance value for this route\n")
{
    return zebra_static_ipv4 (vty, 0, argv[0], NULL, NULL, argv[1], argv[2]);
}

DEFUN (no_ip_route_mask_distance,
       no_ip_route_mask_distance_cmd,
       "no ip route A.B.C.D A.B.C.D (A.B.C.D|INTERFACE|null0) <1-255>",
       NO_STR
       IP_STR
       "Establish static routes\n" "IP destination prefix\n" "IP destination prefix mask\n" "IP gateway address\n" "IP gateway interface name\n" "Null interface\n" "Distance value for this route\n")
{
    return zebra_static_ipv4 (vty, 0, argv[0], argv[1], argv[2], NULL, argv[3]);
}

DEFUN (no_ip_route_mask_flags_distance,
       no_ip_route_mask_flags_distance_cmd,
       "no ip route A.B.C.D A.B.C.D (A.B.C.D|INTERFACE) (reject|blackhole) <1-255>",
       NO_STR
       IP_STR
       "Establish static routes\n"
       "IP destination prefix\n"
       "IP destination prefix mask\n"
       "IP gateway address\n" "IP gateway interface name\n" "Emit an ICMP unreachable when matched\n" "Silently discard pkts when matched\n" "Distance value for this route\n")
{
    return zebra_static_ipv4 (vty, 0, argv[0], argv[1], argv[2], argv[3], argv[4]);
}

DEFUN (no_ip_route_mask_flags_distance2,
       no_ip_route_mask_flags_distance2_cmd,
       "no ip route A.B.C.D A.B.C.D (reject|blackhole) <1-255>",
       NO_STR
       IP_STR
       "Establish static routes\n"
       "IP destination prefix\n" "IP destination prefix mask\n" "Emit an ICMP unreachable when matched\n" "Silently discard pkts when matched\n" "Distance value for this route\n")
{
    return zebra_static_ipv4 (vty, 0, argv[0], argv[1], NULL, argv[2], argv[3]);
}

char *proto_rm[AFI_MAX][ZEBRA_ROUTE_MAX + 1];	/* "any" == ZEBRA_ROUTE_MAX */

DEFUN (ip_protocol, ip_protocol_cmd, "ip protocol PROTO route-map ROUTE-MAP", NO_STR "Apply route map to PROTO\n" "Protocol name\n" "Route map name\n")
{
    int i;

    if (strcasecmp (argv[0], "any") == 0)
        i = ZEBRA_ROUTE_MAX;
    else
        i = proto_name2num (argv[0]);
    if (i < 0)
    {
        vty_out (vty, "invalid protocol name \"%s\"%s", argv[0] ? argv[0] : "", VTY_NEWLINE);
        return CMD_WARNING;
    }
    if (proto_rm[AFI_IP][i])
        XFREE (MTYPE_ROUTE_MAP_NAME, proto_rm[AFI_IP][i]);
    proto_rm[AFI_IP][i] = XSTRDUP (MTYPE_ROUTE_MAP_NAME, argv[1]);
    return CMD_SUCCESS;
}

DEFUN (no_ip_protocol, no_ip_protocol_cmd, "no ip protocol PROTO", NO_STR "Remove route map from PROTO\n" "Protocol name\n")
{
    int i;

    if (strcasecmp (argv[0], "any") == 0)
        i = ZEBRA_ROUTE_MAX;
    else
        i = proto_name2num (argv[0]);
    if (i < 0)
    {
        vty_out (vty, "invalid protocol name \"%s\"%s", argv[0] ? argv[0] : "", VTY_NEWLINE);
        return CMD_WARNING;
    }
    if (proto_rm[AFI_IP][i])
        XFREE (MTYPE_ROUTE_MAP_NAME, proto_rm[AFI_IP][i]);
    proto_rm[AFI_IP][i] = NULL;
    return CMD_SUCCESS;
}

/* New RIB.  Detailed information for IPv4 route. */
static void vty_show_ip_route_detail (struct vty *vty, struct route_node *rn)
{
    struct rib *rib;
    struct nexthop *nexthop;

    for (rib = rn->info; rib; rib = rib->next)
    {
        vty_out (vty, "Routing entry for %s/%d%s", inet_ntoa (rn->p.u.prefix4), rn->p.prefixlen, VTY_NEWLINE);
        vty_out (vty, "  Known via \"%s\"", zebra_route_string (rib->type));
        vty_out (vty, ", distance %d, metric %d", rib->distance, rib->metric);
        if (CHECK_FLAG (rib->flags, ZEBRA_FLAG_SELECTED))
            vty_out (vty, ", best");
        if (rib->refcnt)
            vty_out (vty, ", refcnt %ld", rib->refcnt);
        if (CHECK_FLAG (rib->flags, ZEBRA_FLAG_BLACKHOLE))
            vty_out (vty, ", blackhole");
        if (CHECK_FLAG (rib->flags, ZEBRA_FLAG_REJECT))
            vty_out (vty, ", reject");
        vty_out (vty, "%s", VTY_NEWLINE);

#define ONE_DAY_SECOND 60*60*24
#define ONE_WEEK_SECOND 60*60*24*7
        if (rib->type == ZEBRA_ROUTE_RIP || rib->type == ZEBRA_ROUTE_OSPF || rib->type == ZEBRA_ROUTE_BABEL || rib->type == ZEBRA_ROUTE_ISIS || rib->type == ZEBRA_ROUTE_BGP)
        {
            time_t uptime;
            struct tm *tm;

            uptime = time (NULL);
            uptime -= rib->uptime;
            tm = gmtime (&uptime);

            vty_out (vty, "  Last update ");

            if (uptime < ONE_DAY_SECOND)
                vty_out (vty, "%02d:%02d:%02d", tm->tm_hour, tm->tm_min, tm->tm_sec);
            else if (uptime < ONE_WEEK_SECOND)
                vty_out (vty, "%dd%02dh%02dm", tm->tm_yday, tm->tm_hour, tm->tm_min);
            else
                vty_out (vty, "%02dw%dd%02dh", tm->tm_yday / 7, tm->tm_yday - ((tm->tm_yday / 7) * 7), tm->tm_hour);
            vty_out (vty, " ago%s", VTY_NEWLINE);
        }

        for (nexthop = rib->nexthop; nexthop; nexthop = nexthop->next)
        {
            char addrstr[32];

            vty_out (vty, "  %c", CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB) ? '*' : ' ');

            switch (nexthop->type)
            {
            case NEXTHOP_TYPE_IPV4:
            case NEXTHOP_TYPE_IPV4_IFINDEX:
                vty_out (vty, " %s", inet_ntoa (nexthop->gate.ipv4));
                if (nexthop->ifindex)
                    vty_out (vty, ", via %s", ifindex2ifname (nexthop->ifindex));
                break;
            case NEXTHOP_TYPE_IFINDEX:
                vty_out (vty, " directly connected, %s", ifindex2ifname (nexthop->ifindex));
                break;
            case NEXTHOP_TYPE_IFNAME:
                vty_out (vty, " directly connected, %s", nexthop->ifname);
                break;
            case NEXTHOP_TYPE_BLACKHOLE:
                vty_out (vty, " directly connected, Null0");
                break;
            default:
                break;
            }
            if (!CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE))
                vty_out (vty, " inactive");

            if (CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_RECURSIVE))
            {
                vty_out (vty, " (recursive");

                switch (nexthop->rtype)
                {
                case NEXTHOP_TYPE_IPV4:
                case NEXTHOP_TYPE_IPV4_IFINDEX:
                    vty_out (vty, " via %s)", inet_ntoa (nexthop->rgate.ipv4));
                    break;
                case NEXTHOP_TYPE_IFINDEX:
                case NEXTHOP_TYPE_IFNAME:
                    vty_out (vty, " is directly connected, %s)", ifindex2ifname (nexthop->rifindex));
                    break;
                default:
                    break;
                }
            }
            switch (nexthop->type)
            {
            case NEXTHOP_TYPE_IPV4:
            case NEXTHOP_TYPE_IPV4_IFINDEX:
            case NEXTHOP_TYPE_IPV4_IFNAME:
                if (nexthop->src.ipv4.s_addr)
                {
                    if (inet_ntop (AF_INET, &nexthop->src.ipv4, addrstr, sizeof addrstr))
                        vty_out (vty, ", src %s", addrstr);
                }
                break;
#ifdef HAVE_IPV6
            case NEXTHOP_TYPE_IPV6:
            case NEXTHOP_TYPE_IPV6_IFINDEX:
            case NEXTHOP_TYPE_IPV6_IFNAME:
                if (!IPV6_ADDR_SAME (&nexthop->src.ipv6, &in6addr_any))
                {
                    if (inet_ntop (AF_INET6, &nexthop->src.ipv6, addrstr, sizeof addrstr))
                        vty_out (vty, ", src %s", addrstr);
                }
                break;
#endif /* HAVE_IPV6 */
            default:
                break;
            }
            vty_out (vty, "%s", VTY_NEWLINE);
        }
        vty_out (vty, "%s", VTY_NEWLINE);
    }
}

//added for 4over6 20130304
static void vty_show_ip_4over6_route (struct vty *vty, struct route_node *rn, struct rib *rib)
{
    struct nexthop *nexthop;
    int len = 0;
    char buf[BUFSIZ];

    /* Nexthop information. */
    for (nexthop = rib->nexthop; nexthop; nexthop = nexthop->next)
    {
        if (nexthop == rib->nexthop)
        {
            /* Prefix information. */
            len = vty_out (vty, "%c%c%c %s/%d",
                           zebra_route_char (rib->type),
                           CHECK_FLAG (rib->flags, ZEBRA_FLAG_SELECTED) ? '>' : ' ',
                           CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB) ? '*' : ' ', inet_ntop (AF_INET, &rn->p.u.prefix, buf, BUFSIZ), rn->p.prefixlen);

            /* Distance and metric display. */
            if (rib->type != ZEBRA_ROUTE_CONNECT && rib->type != ZEBRA_ROUTE_KERNEL)
                len += vty_out (vty, " [%d/%d]", rib->distance, rib->metric);
        }
        else
            vty_out (vty, "  %c%*c", CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB) ? '*' : ' ', len - 3, ' ');

        switch (nexthop->type)
        {
        case NEXTHOP_TYPE_IPV6:
        case NEXTHOP_TYPE_IPV6_IFINDEX:
        case NEXTHOP_TYPE_IPV6_IFNAME:
            vty_out (vty, " via %s", inet_ntop (AF_INET6, &nexthop->gate.ipv6, buf, BUFSIZ));
            if (nexthop->type == NEXTHOP_TYPE_IPV6_IFNAME)
                vty_out (vty, ", %s", nexthop->ifname);
            else if (nexthop->ifindex)
                vty_out (vty, ", %s", ifindex2ifname (nexthop->ifindex));
            break;
        case NEXTHOP_TYPE_IFINDEX:
            vty_out (vty, " is directly connected, %s", ifindex2ifname (nexthop->ifindex));
            break;
        case NEXTHOP_TYPE_IFNAME:
            vty_out (vty, " is directly connected, %s", nexthop->ifname);
            break;
        default:
            break;
        }

        if (!CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE))
            vty_out (vty, " inactive");

        if (CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_RECURSIVE))
        {
            vty_out (vty, " (recursive");

            switch (nexthop->rtype)
            {
            case NEXTHOP_TYPE_IPV6:
            case NEXTHOP_TYPE_IPV6_IFINDEX:
            case NEXTHOP_TYPE_IPV6_IFNAME:
                vty_out (vty, " via %s)", inet_ntop (AF_INET6, &nexthop->rgate.ipv6, buf, BUFSIZ));
                if (nexthop->rifindex)
                    vty_out (vty, ", %s", ifindex2ifname (nexthop->rifindex));
                break;
            case NEXTHOP_TYPE_IFINDEX:
            case NEXTHOP_TYPE_IFNAME:
                vty_out (vty, " is directly connected, %s)", ifindex2ifname (nexthop->rifindex));
                break;
            default:
                break;
            }
        }

        if (CHECK_FLAG (rib->flags, ZEBRA_FLAG_BLACKHOLE))
            vty_out (vty, ", bh");
        if (CHECK_FLAG (rib->flags, ZEBRA_FLAG_REJECT))
            vty_out (vty, ", rej");

        if (rib->type == ZEBRA_ROUTE_RIP || rib->type == ZEBRA_ROUTE_OSPF || rib->type == ZEBRA_ROUTE_BABEL || rib->type == ZEBRA_ROUTE_ISIS || rib->type == ZEBRA_ROUTE_BGP)
        {
            time_t uptime;
            struct tm *tm;

            uptime = time (NULL);
            uptime -= rib->uptime;
            tm = gmtime (&uptime);

#define ONE_DAY_SECOND 60*60*24
#define ONE_WEEK_SECOND 60*60*24*7

            if (uptime < ONE_DAY_SECOND)
                vty_out (vty, ", %02d:%02d:%02d", tm->tm_hour, tm->tm_min, tm->tm_sec);
            else if (uptime < ONE_WEEK_SECOND)
                vty_out (vty, ", %dd%02dh%02dm", tm->tm_yday, tm->tm_hour, tm->tm_min);
            else
                vty_out (vty, ", %02dw%dd%02dh", tm->tm_yday / 7, tm->tm_yday - ((tm->tm_yday / 7) * 7), tm->tm_hour);
        }
        vty_out (vty, "%s", VTY_NEWLINE);
    }
}

static void vty_show_ip_route (struct vty *vty, struct route_node *rn, struct rib *rib)
{
    struct nexthop *nexthop;
    int len = 0;
    char buf[BUFSIZ];

    /* Nexthop information. */
    for (nexthop = rib->nexthop; nexthop; nexthop = nexthop->next)
    {
        if (nexthop == rib->nexthop)
        {
            if (strcmp ("127.0.0.0", inet_ntop (AF_INET, &rn->p.u.prefix, buf, BUFSIZ)) != 0)
            {
                /* Prefix information. */
                len = vty_out (vty, "%c%c%c %s/%d",
                               zebra_route_char (rib->type),
                               CHECK_FLAG (rib->flags, ZEBRA_FLAG_SELECTED)
                               ? '>' : ' ', CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB) ? '*' : ' ', inet_ntop (AF_INET, &rn->p.u.prefix, buf, BUFSIZ), rn->p.prefixlen);

                /* Distance and metric display. */
                if (rib->type != ZEBRA_ROUTE_CONNECT && rib->type != ZEBRA_ROUTE_KERNEL)
                    len += vty_out (vty, " [%d/%d]", rib->distance, rib->metric);
            }
        }
        else if (strcmp ("127.0.0.0", inet_ntop (AF_INET, &rn->p.u.prefix, buf, BUFSIZ)) != 0)
        {
            vty_out (vty, "  %c%*c", CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB) ? '*' : ' ', len - 3, ' ');
        }
        if (strcmp ("127.0.0.0", inet_ntop (AF_INET, &rn->p.u.prefix, buf, BUFSIZ)) != 0)
        {
            switch (nexthop->type)
            {
            case NEXTHOP_TYPE_IPV4:
            case NEXTHOP_TYPE_IPV4_IFINDEX:
                vty_out (vty, " via %s", inet_ntoa (nexthop->gate.ipv4));
                if (nexthop->ifindex)
                    vty_out (vty, ", %s", ifindex2ifname (nexthop->ifindex));
                break;
            case NEXTHOP_TYPE_IFINDEX:
                vty_out (vty, " is directly connected, %s", ifindex2ifname (nexthop->ifindex));
                break;
            case NEXTHOP_TYPE_IFNAME:
                vty_out (vty, " is directly connected, %s", nexthop->ifname);
                break;
            case NEXTHOP_TYPE_BLACKHOLE:
                vty_out (vty, " is directly connected, Null0");
                break;
            default:
                break;
            }
            if (!CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE))
                vty_out (vty, " inactive");

            if (CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_RECURSIVE))
            {
                vty_out (vty, " (recursive");

                switch (nexthop->rtype)
                {
                case NEXTHOP_TYPE_IPV4:
                case NEXTHOP_TYPE_IPV4_IFINDEX:
                    vty_out (vty, " via %s)", inet_ntoa (nexthop->rgate.ipv4));
                    break;
                case NEXTHOP_TYPE_IFINDEX:
                case NEXTHOP_TYPE_IFNAME:
                    vty_out (vty, " is directly connected, %s)", ifindex2ifname (nexthop->rifindex));
                    break;
                default:
                    break;
                }
            }
            switch (nexthop->type)
            {
            case NEXTHOP_TYPE_IPV4:
            case NEXTHOP_TYPE_IPV4_IFINDEX:
            case NEXTHOP_TYPE_IPV4_IFNAME:
                if (nexthop->src.ipv4.s_addr)
                {
                    if (inet_ntop (AF_INET, &nexthop->src.ipv4, buf, sizeof buf))
                        vty_out (vty, ", src %s", buf);
                }
                break;
#ifdef HAVE_IPV6
            case NEXTHOP_TYPE_IPV6:
            case NEXTHOP_TYPE_IPV6_IFINDEX:
            case NEXTHOP_TYPE_IPV6_IFNAME:
                if (!IPV6_ADDR_SAME (&nexthop->src.ipv6, &in6addr_any))
                {
                    if (inet_ntop (AF_INET6, &nexthop->src.ipv6, buf, sizeof buf))
                        vty_out (vty, ", src %s", buf);
                }
                break;
#endif /* HAVE_IPV6 */
            default:
                break;
            }

            if (CHECK_FLAG (rib->flags, ZEBRA_FLAG_BLACKHOLE))
                vty_out (vty, ", bh");
            if (CHECK_FLAG (rib->flags, ZEBRA_FLAG_REJECT))
                vty_out (vty, ", rej");

            if (rib->type == ZEBRA_ROUTE_RIP || rib->type == ZEBRA_ROUTE_OSPF || rib->type == ZEBRA_ROUTE_BABEL || rib->type == ZEBRA_ROUTE_ISIS || rib->type == ZEBRA_ROUTE_BGP)
            {
                time_t uptime;
                struct tm *tm;

                uptime = time (NULL);
                uptime -= rib->uptime;
                tm = gmtime (&uptime);

#define ONE_DAY_SECOND 60*60*24
#define ONE_WEEK_SECOND 60*60*24*7

                if (uptime < ONE_DAY_SECOND)
                    vty_out (vty, ", %02d:%02d:%02d", tm->tm_hour, tm->tm_min, tm->tm_sec);
                else if (uptime < ONE_WEEK_SECOND)
                    vty_out (vty, ", %dd%02dh%02dm", tm->tm_yday, tm->tm_hour, tm->tm_min);
                else
                    vty_out (vty, ", %02dw%dd%02dh", tm->tm_yday / 7, tm->tm_yday - ((tm->tm_yday / 7) * 7), tm->tm_hour);
            }
            vty_out (vty, "%s", VTY_NEWLINE);
        }
    }
}

int vtysh_show_dpdk_4over6_route (struct vty *vty)
{
    int i;
    int sockfd;
    ssize_t n;
    char buf[4096];
    char ipv6_address_string[128];
    struct in_addr ipv4_addr;
    struct _ipv4overipv6_address_pool ipv4overipv6_address;

    sockfd = connect_dpdk (vty);

    char bgp_4over6_route_msg[8];

    memset (bgp_4over6_route_msg, 0, 8);
    *(int *) &bgp_4over6_route_msg[0] = REQUEST_BGP_4OVER6_ROUTE;
    *(int *) &bgp_4over6_route_msg[4] = htonl (8);

    n = send (sockfd, bgp_4over6_route_msg, 8, 0);
    if (n < 0)
    {
        vty_out (vty, "send request bgp 4over6 route msg failed %s", VTY_NEWLINE);
        return -1;
    }
    memset (buf, 0, sizeof (buf));
    n = recv (sockfd, buf, sizeof(buf), 0);
    if (n < 0)
    {
        vty_out (vty, "recv response bgp 4over6 route msg failed %s", VTY_NEWLINE);
        return -1;
    }
#if 1
    for (i = 0; i < n; i += ntohl (*(int *) &buf[i + 4]))
    {
        if (*(int *) &buf[i] == RESPONSE_BGP_4OVER6_ROUTE)
        {
            memset (&ipv4overipv6_address, 0, sizeof (ipv4overipv6_address));
            memcpy (&ipv4overipv6_address, (char *) &buf[i] + 8, ntohl (*(int *) &buf[i + 4]) - 8);
            vty_out (vty, "%s", "DPDK-46>* ");

            memset (&ipv4_addr, 0, sizeof (ipv4_addr));
            ipv4_addr.s_addr = ipv4overipv6_address.ipv4overipv6_address_prefix;
            vty_out (vty, "%s/%d ", inet_ntoa (ipv4_addr), ipv4overipv6_address.ipv4overipv6_address_len);

            memset (ipv6_address_string, 0, sizeof (ipv6_address_string));
            inet_ntop (AF_INET6, ipv4overipv6_address.ipv4overipv6_tunnel_src_addr, ipv6_address_string, sizeof (ipv6_address_string));
            vty_out (vty, "tnl src:%s ", ipv6_address_string);

            memset (ipv6_address_string, 0, sizeof (ipv6_address_string));
            inet_ntop (AF_INET6, ipv4overipv6_address.ipv4overipv6_tunnel_dst_addr, ipv6_address_string, sizeof (ipv6_address_string));
            vty_out (vty, "tnl dst:%s %s", ipv6_address_string, VTY_NEWLINE);
        }
    }
#endif
    return 0;
}

DEFUN (show_ip_route,
       show_ip_route_cmd,
       "show ip route",
       SHOW_STR IP_STR
       "IP routing table\n")
{
    struct route_table *table;
    struct route_table *table_4over6;
    struct route_table *table_customize;
    struct route_node *rn;
    struct rib *rib;
    int first = 1;

    table = vrf_table (AFI_IP, SAFI_UNICAST, 0);
    if (!table)
        return CMD_SUCCESS;

    /* Show all IPv4 routes. */
    for (rn = route_top (table); rn; rn = route_next (rn))
        for (rib = rn->info; rib; rib = rib->next)
        {
            if (first)
            {
                vty_out (vty, SHOW_ROUTE_V4_HEADER);
                first = 0;
            }
            vty_show_ip_route (vty, rn, rib);
        }

    //added for 4over6 20130304
    table_4over6 = vrf_table (AFI_IP, SAFI_4OVER6, 0);
    if (!table_4over6)
        return CMD_SUCCESS;
    for (rn = route_top (table_4over6); rn; rn = route_next (rn))
    {
        for (rib = rn->info; rib; rib = rib->next)
        {
            vty_show_ip_4over6_route (vty, rn, rib);
        }
    }

#if 1
    vtysh_show_dpdk_4over6_route (vty);
#endif

    //sangmeng add for show customize route 20180705
    table_customize = vrf_table (AFI_IP, SAFI_CUSTOMIZE_ONE, 0);
    if (!table_customize)
        return CMD_SUCCESS;

    for (rn = route_top (table_customize); rn; rn = route_next (rn))
    {
        for (rib = rn->info; rib; rib = rib->next)
        {
            vty_show_ip_route (vty, rn, rib);
        }
    }


    return CMD_SUCCESS;
}

DEFUN (show_ip_route_prefix_longer,
       show_ip_route_prefix_longer_cmd,
       "show ip route A.B.C.D/M longer-prefixes",
       SHOW_STR IP_STR
       "IP routing table\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Show route matching the specified Network/Mask pair only\n")
{
    struct route_table *table;
    struct route_node *rn;
    struct rib *rib;
    struct prefix p;
    int ret;
    int first = 1;

    ret = str2prefix (argv[0], &p);
    if (!ret)
    {
        vty_out (vty, "%% Malformed Prefix%s", VTY_NEWLINE);
        return CMD_WARNING;
    }

    table = vrf_table (AFI_IP, SAFI_UNICAST, 0);
    if (!table)
        return CMD_SUCCESS;

    /* Show matched type IPv4 routes. */
    for (rn = route_top (table); rn; rn = route_next (rn))
        for (rib = rn->info; rib; rib = rib->next)
            if (prefix_match (&p, &rn->p))
            {
                if (first)
                {
                    vty_out (vty, SHOW_ROUTE_V4_HEADER);
                    first = 0;
                }
                vty_show_ip_route (vty, rn, rib);
            }
    return CMD_SUCCESS;
}

DEFUN (show_ip_route_supernets,
       show_ip_route_supernets_cmd,
       "show ip route supernets-only",
       SHOW_STR IP_STR
       "IP routing table\n"
       "Show supernet entries only\n")
{
    struct route_table *table;
    struct route_node *rn;
    struct rib *rib;
    u_int32_t addr;
    int first = 1;

    table = vrf_table (AFI_IP, SAFI_UNICAST, 0);
    if (!table)
        return CMD_SUCCESS;

    /* Show matched type IPv4 routes. */
    for (rn = route_top (table); rn; rn = route_next (rn))
        for (rib = rn->info; rib; rib = rib->next)
        {
            addr = ntohl (rn->p.u.prefix4.s_addr);

            if ((IN_CLASSC (addr) && rn->p.prefixlen < 24) || (IN_CLASSB (addr) && rn->p.prefixlen < 16) || (IN_CLASSA (addr) && rn->p.prefixlen < 8))
            {
                if (first)
                {
                    vty_out (vty, SHOW_ROUTE_V4_HEADER);
                    first = 0;
                }
                vty_show_ip_route (vty, rn, rib);
            }
        }
    return CMD_SUCCESS;
}

DEFUN (show_ip_route_protocol, show_ip_route_protocol_cmd, "show ip route " QUAGGA_IP_REDIST_STR_ZEBRA, SHOW_STR IP_STR "IP routing table\n" QUAGGA_IP_REDIST_HELP_STR_ZEBRA)
{
    int type;
    struct route_table *table;
    struct route_node *rn;
    struct rib *rib;
    int first = 1;

    type = proto_redistnum (AFI_IP, argv[0]);
    if (type < 0)
    {
        vty_out (vty, "Unknown route type%s", VTY_NEWLINE);
        return CMD_WARNING;
    }

    table = vrf_table (AFI_IP, SAFI_UNICAST, 0);
    if (!table)
        return CMD_SUCCESS;

    /* Show matched type IPv4 routes. */
    for (rn = route_top (table); rn; rn = route_next (rn))
        for (rib = rn->info; rib; rib = rib->next)
            if (rib->type == type)
            {
                if (first)
                {
                    vty_out (vty, SHOW_ROUTE_V4_HEADER);
                    first = 0;
                }
                vty_show_ip_route (vty, rn, rib);
            }
    return CMD_SUCCESS;
}
struct lpm_route_info
{
    int af;
    uint8_t next_hop;
    union
    {
        struct in_addr gateway;
        struct in6_addr gateway6;
    } u;
    uint8_t forward;
};


#define BAD_PORT    ((uint8_t)-1)
int zebra_connect_dpdk_send_route_lookup (struct vty *vty, struct zebra_config_message *msg_to_dpdk, int size)
{
    int ret = 0;
    int sockfd;
    struct comm_head  *head_lpm_route;
    char str[64];
    sockfd = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);

    if (sockfd <= 0)
    {
        return -1;
    }
    struct sockaddr_in socketaddress;
    socketaddress.sin_family = AF_INET;
    socketaddress.sin_port = htons (DPDK_SERVER_PORT);
    socketaddress.sin_addr.s_addr = inet_addr (DPDK_SERVER_ADDRESS);
    memset (&(socketaddress.sin_zero), 0, 8);
    /*start connect */
    ret = connect (sockfd, &socketaddress, sizeof (struct sockaddr));
    if (ret < 0)
    {
        close (sockfd);
        return -1;
    }
    /*send ivi message */
    char buf[512];
    memset(buf, 0, sizeof(buf));
    memcpy (buf, msg_to_dpdk, sizeof (struct zebra_config_message));
    memcpy (buf + sizeof (struct zebra_config_message), msg_to_dpdk->data, size);
    ret = send (sockfd, buf, msg_to_dpdk->len, 0);

    memset (buf, 0, sizeof(buf));
    ret = recv (sockfd, buf, sizeof(buf), 0);
    head_lpm_route = (struct comm_head *)buf;
    struct lpm_route_info *route_info;
    route_info = (struct lpm_route_info *)head_lpm_route->data;
    if (route_info->af == AF_INET)
    {
        if (route_info->next_hop == BAD_PORT)
        {
            vty_out(vty, "don't find route in lpm%s", VTY_NEWLINE);
            close (sockfd);
            return -1;
        }

        inet_ntop(AF_INET, &route_info->u.gateway, str, sizeof(str));
        vty_out(vty, "%s oif:%s gateway:%s forward:%d%s", msg_to_dpdk->data, dpdk_ifindex2ifname(route_info->next_hop), str, route_info->forward, VTY_NEWLINE);
    }
    else if (route_info->af == AF_INET6)
    {
        if (route_info->next_hop == BAD_PORT)
        {
            vty_out(vty, "don't find route in lpm%s", VTY_NEWLINE);
            close (sockfd);
            return -1;
        }

        inet_ntop(AF_INET6, &route_info->u.gateway6, str, sizeof(str));

        vty_out(vty, "%s oif:%s gateway:%s type:%s%s", msg_to_dpdk->data, dpdk_ifindex2ifname(route_info->next_hop),
                str, (route_info->forward == 0) ? "input": ((route_info->forward == 1) ? "forward" : ((route_info->forward == 2) ? "4over6 encap" :"drop")), VTY_NEWLINE);
    }
    else
        printf("msg error.\n");

    close (sockfd);
    printf("send %d bytes to dpdk, socket:%d.\n",ret, sockfd);
    return 0;
}

DEFUN (show_ip_frt_route_addr,
       show_ip_frt_route_addr_cmd,
       "show ip frt route A.B.C.D",
       SHOW_STR
       IP_STR
       "forwart route table\n"
       "IP routing table\n"
       "Network in the IP routing table to display\n")
{
    int ret;
    struct prefix_ipv4 p;

    ret = str2prefix_ipv4 (argv[0], &p);
    if (ret <= 0)
    {
        vty_out (vty, "%% Malformed IPv4 address%s", VTY_NEWLINE);
        return CMD_WARNING;
    }

    struct zebra_config_message msg_to_dpdk;
    bzero (&msg_to_dpdk, sizeof (struct zebra_config_message));
    msg_to_dpdk.type = SHOW_ROUTE_FROM_LPM;
    msg_to_dpdk.len = sizeof (struct zebra_config_message) + strlen(argv[0])+1;
    msg_to_dpdk.data = argv[0];
    zebra_connect_dpdk_send_route_lookup(vty, &msg_to_dpdk, msg_to_dpdk.len - sizeof (struct zebra_config_message));


    return CMD_SUCCESS;
}


DEFUN (show_ip_route_addr,
       show_ip_route_addr_cmd,
       "show ip route A.B.C.D",
       SHOW_STR
       IP_STR
       "IP routing table\n"
       "Network in the IP routing table to display\n")
{
    int ret;
    struct prefix_ipv4 p;
    struct route_table *table;
    struct route_node *rn;

    ret = str2prefix_ipv4 (argv[0], &p);
    if (ret <= 0)
    {
        vty_out (vty, "%% Malformed IPv4 address%s", VTY_NEWLINE);
        return CMD_WARNING;
    }

    table = vrf_table (AFI_IP, SAFI_UNICAST, 0);
    if (!table)
        return CMD_SUCCESS;

    rn = route_node_match (table, (struct prefix *) &p);
    if (!rn)
    {
        vty_out (vty, "%% Network not in table%s", VTY_NEWLINE);
        return CMD_WARNING;
    }

    vty_show_ip_route_detail (vty, rn);

    route_unlock_node (rn);

    return CMD_SUCCESS;
}

DEFUN (show_ip_route_prefix, show_ip_route_prefix_cmd, "show ip route A.B.C.D/M", SHOW_STR IP_STR "IP routing table\n" "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n")
{
    int ret;
    struct prefix_ipv4 p;
    struct route_table *table;
    struct route_node *rn;

    ret = str2prefix_ipv4 (argv[0], &p);
    if (ret <= 0)
    {
        vty_out (vty, "%% Malformed IPv4 address%s", VTY_NEWLINE);
        return CMD_WARNING;
    }

    table = vrf_table (AFI_IP, SAFI_UNICAST, 0);
    if (!table)
        return CMD_SUCCESS;

    rn = route_node_match (table, (struct prefix *) &p);
    if (!rn || rn->p.prefixlen != p.prefixlen)
    {
        vty_out (vty, "%% Network not in table%s", VTY_NEWLINE);
        return CMD_WARNING;
    }

    vty_show_ip_route_detail (vty, rn);

    route_unlock_node (rn);

    return CMD_SUCCESS;
}

static void vty_show_ip_route_summary (struct vty *vty, struct route_table *table)
{
    struct route_node *rn;
    struct rib *rib;
    struct nexthop *nexthop;
#define ZEBRA_ROUTE_IBGP  ZEBRA_ROUTE_MAX
#define ZEBRA_ROUTE_TOTAL (ZEBRA_ROUTE_IBGP + 1)
    u_int32_t rib_cnt[ZEBRA_ROUTE_TOTAL + 1];
    u_int32_t fib_cnt[ZEBRA_ROUTE_TOTAL + 1];
    u_int32_t i;

    memset (&rib_cnt, 0, sizeof (rib_cnt));
    memset (&fib_cnt, 0, sizeof (fib_cnt));
    for (rn = route_top (table); rn; rn = route_next (rn))
        for (rib = rn->info; rib; rib = rib->next)
            for (nexthop = rib->nexthop; nexthop; nexthop = nexthop->next)
            {
                rib_cnt[ZEBRA_ROUTE_TOTAL]++;
                rib_cnt[rib->type]++;
                if (CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB))
                {
                    fib_cnt[ZEBRA_ROUTE_TOTAL]++;
                    fib_cnt[rib->type]++;
                }
                if (rib->type == ZEBRA_ROUTE_BGP && CHECK_FLAG (rib->flags, ZEBRA_FLAG_IBGP))
                {
                    rib_cnt[ZEBRA_ROUTE_IBGP]++;
                    if (CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB))
                        fib_cnt[ZEBRA_ROUTE_IBGP]++;
                }
            }

    vty_out (vty, "%-20s %-20s %-20s %s", "Route Source", "Routes", "FIB", VTY_NEWLINE);

    for (i = 0; i < ZEBRA_ROUTE_MAX; i++)
    {
        if (rib_cnt[i] > 0)
        {
            if (i == ZEBRA_ROUTE_BGP)
            {
                vty_out (vty, "%-20s %-20d %-20d %s", "ebgp", rib_cnt[ZEBRA_ROUTE_BGP] - rib_cnt[ZEBRA_ROUTE_IBGP], fib_cnt[ZEBRA_ROUTE_BGP] - fib_cnt[ZEBRA_ROUTE_IBGP], VTY_NEWLINE);
                vty_out (vty, "%-20s %-20d %-20d %s", "ibgp", rib_cnt[ZEBRA_ROUTE_IBGP], fib_cnt[ZEBRA_ROUTE_IBGP], VTY_NEWLINE);
            }
            else
                vty_out (vty, "%-20s %-20d %-20d %s", zebra_route_string (i), rib_cnt[i], fib_cnt[i], VTY_NEWLINE);
        }
    }

    vty_out (vty, "------%s", VTY_NEWLINE);
    vty_out (vty, "%-20s %-20d %-20d %s", "Totals", rib_cnt[ZEBRA_ROUTE_TOTAL], fib_cnt[ZEBRA_ROUTE_TOTAL], VTY_NEWLINE);
}

/* Show route summary.  */
DEFUN (show_ip_route_summary, show_ip_route_summary_cmd, "show ip route summary", SHOW_STR IP_STR "IP routing table\n" "Summary of all routes\n")
{
    struct route_table *table;

    table = vrf_table (AFI_IP, SAFI_UNICAST, 0);
    if (!table)
        return CMD_SUCCESS;

    vty_show_ip_route_summary (vty, table);

    return CMD_SUCCESS;
}
//sangmeng mark here 20190905
//added for 4over6 20130306
static int static_config_ipv4_4over6 (struct vty *vty)
{
    struct route_node *rn;
    struct static_ipv6 *si;
    int write;
    char buf[BUFSIZ];
    struct route_table *stable;

    write = 0;

    /* Lookup table.  */
    stable = vrf_static_table (AFI_IP, SAFI_4OVER6, 0);
    if (!stable)
        return -1;

    for (rn = route_top (stable); rn; rn = route_next (rn))
    {
        for (si = rn->info; si; si = si->next)
        {
            vty_out (vty, "ip 4over6 route %s/%d", inet_ntoa (rn->p.u.prefix4), rn->p.prefixlen);

            switch (si->type)
            {
            case STATIC_IPV6_GATEWAY:
            case STATIC_IPV6_GATEWAY_IFNAME:
                vty_out (vty, " %s", inet_ntop (AF_INET6, &si->ipv6, buf, BUFSIZ));
                break;
            case STATIC_IPV6_IFNAME:
                vty_out (vty, " %s", si->ifname);
                break;
            }

            if (CHECK_FLAG (si->flags, ZEBRA_FLAG_REJECT))
                vty_out (vty, " %s", "reject");

            if (CHECK_FLAG (si->flags, ZEBRA_FLAG_BLACKHOLE))
                vty_out (vty, " %s", "blackhole");

            if (si->distance != ZEBRA_STATIC_DISTANCE_DEFAULT)
                vty_out (vty, " %d", si->distance);

            vty_out (vty, "%s", VTY_NEWLINE);

            write = 1;
        }
    }
    return write;
}

/*manage ipv4 pool*/
////change by ccc
DEFUN (nat64_v4pool, nat64_v4pool_cmd, "nat64 v4pool X.X.X.X/M ", "Configure nat64 protocol\n" "Configure IPv4 pool\n" "IP prefix <network>/<length>, e.g., 35.0.0.0/29\n")
{
    if (nat_pool_head != NULL)
    {
        vty_out (vty, "this pool is alreay exist%s", VTY_NEWLINE);
        return CMD_WARNING;
    }
    struct zebra_config_message *p_zebra_msg = (struct zebra_config_message *) malloc (sizeof (struct zebra_config_message));
    memset (p_zebra_msg, 0, sizeof (struct zebra_config_message));
    struct nat_pool_message *p_nat_pool = (struct nat_pool_message *) malloc (sizeof (struct nat_pool_message));
    memset (p_nat_pool, 0, sizeof (struct nat_pool_message));
    p_zebra_msg->data = p_nat_pool;

    int ret = 0;
    /*start get info and fill ivi message */
    p_zebra_msg->type = ADD_NAT64_POOL;	//type
    //prefix
    ret = str2prefix_ipv4 (argv[0], &(p_nat_pool->prefix4));
    if (ret <= 0)
    {
        free (p_zebra_msg);
        free (p_nat_pool);
        vty_out (vty, "%% Malformed address%s", VTY_NEWLINE);
        return CMD_WARNING;
    }
    if (!(p_nat_pool->prefix4.prefixlen > 28))
    {
        free (p_zebra_msg);
        free (p_nat_pool);
        vty_out (vty, "%% prefixlen should be greater than 28%s", VTY_NEWLINE);
        return CMD_WARNING;
    }
    p_zebra_msg->len = sizeof (struct zebra_config_message) + sizeof (struct nat_pool_message);	//len
    if (-1 == zebra_connect_dpdk_send_message_two (p_zebra_msg, p_zebra_msg->len))
    {
        free (p_nat_pool);
        free (p_zebra_msg);
        vty_out (vty, "connot connect server%s", VTY_NEWLINE);
        return CMD_SUCCESS;
    }
    nat_pool_head = p_nat_pool;
    return CMD_SUCCESS;

    /*
    #define SIOCADDPOOL (SIOCCHGTUNNEL+10)
    #define NO_MATCH 37
    #define V4POOL_EXIST 38
    #define V4POOL_OVERFLOW 39
    struct address{
    struct in_addr start;
    struct in_addr end;
    };
    struct address addr;
    struct ifreq ifr;
    int socketfd;
    int ret=0;
    int cmd=0;
    struct prefix_ipv4 ipv4p;
    unsigned int usTemp;
    char cNAT64[]="nat64";

    ret = str2prefix_ipv4 (argv[0], &ipv4p);
    ipv4p.prefix.s_addr = htonl((unsigned int)ipv4p.prefix.s_addr);
    socketfd=socket(AF_INET,SOCK_DGRAM,0);
    if(socketfd<0)
    {
    vty_out(vty,"socket error\n");
    return -1;
    }
    cmd = SIOCADDPOOL;
    strcpy(ifr.ifr_name,cNAT64);
    addr.start = ipv4p.prefix;
    usTemp = ipv4p.prefixlen;
    memcpy(&addr.end,&usTemp,sizeof(unsigned int));
    //vty_out(vty,"prefix is %x len is %x\n",addr.start.s_addr,addr.end.s_addr);
    //addr.end = ipv4p.prefixlen;

    ifr.ifr_data = &addr;
    ret=ioctl(socketfd,cmd,&ifr);
    if(ret == -1)
    {
    //vty_out(vty,"ioctl error: %d\n",errno);
    if(errno == NO_MATCH)
    {
    vty_out(vty,"The start address and end address is error!\n");
    }
    else if(errno == V4POOL_EXIST)
    {
    vty_out(vty,"Nat64 v4pool existing!\n");
    }
    else if(errno == V4POOL_OVERFLOW)
    {
    vty_out(vty,"NAT64 configure fail! the  address numbers of nat64 pool  must less than 8\n");
    }
    close(socketfd);
    return -1;
    }
    close(socketfd);
    return CMD_SUCCESS;
     */
}

/*manage ipv4 pool*/

DEFUN (no_nat64_v4pool, no_nat64_v4pool_cmd, "no nat64 v4pool X.X.X.X/M ", NO_STR "Configure nat64 protocol\n" "Configure IPv4 pool\n" "IP prefix <network>/<length>, e.g., 35.0.0.0/29\n")
{
    if (nat_pool_head == NULL)
        return CMD_WARNING;
    struct zebra_config_message *p_zebra_msg = (struct zebra_config_message *) malloc (sizeof (struct zebra_config_message));
    memset (p_zebra_msg, 0, sizeof (struct zebra_config_message));
    struct nat_pool_message *p_nat_pool = (struct nat_pool_message *) malloc (sizeof (struct nat_pool_message));
    memset (p_nat_pool, 0, sizeof (struct nat_pool_message));
    p_zebra_msg->data = p_nat_pool;

    int ret = 0;
    /*start get info and fill ivi message */
    p_zebra_msg->type = DEL_NAT64_POOL;	//type
    //prefix
    ret = str2prefix_ipv4 (argv[0], &(p_nat_pool->prefix4));
    if (ret <= 0)
    {
        free (p_zebra_msg);
        free (p_nat_pool);
        vty_out (vty, "%% Malformed address%s", VTY_NEWLINE);
        return CMD_WARNING;
    }
    if (memcmp (&(nat_pool_head->prefix4), &(p_nat_pool->prefix4), sizeof (struct prefix_ipv4)))
    {
        free (p_zebra_msg);
        free (p_nat_pool);
        vty_out (vty, "%% not match address%s", VTY_NEWLINE);
        return CMD_WARNING;
    }
    p_zebra_msg->len = sizeof (struct zebra_config_message) + sizeof (struct nat_pool_message);	//len
    if (-1 == zebra_connect_dpdk_send_message_two (p_zebra_msg, p_zebra_msg->len))
    {
        free (p_nat_pool);
        free (p_zebra_msg);
        vty_out (vty, "ivi socket wrong%s", VTY_NEWLINE);
        return CMD_SUCCESS;
    }

    free (nat_pool_head);
    nat_pool_head = NULL;

    free (p_nat_pool);
    free (p_zebra_msg);
    return CMD_SUCCESS;
    /*
    #define SIOCDELPOOL (SIOCCHGTUNNEL+11)
    #define NO_MATCH 37
    struct address{
    struct in_addr start;
    struct in_addr end;
    };
    struct address addr;
    struct ifreq ifr;
    int socketfd;
    int ret=0;
    int cmd=0;
    struct prefix_ipv4 ipv4p;
    unsigned int usTemp;
    char cNAT64[]="nat64";

    ret = str2prefix_ipv4 (argv[0], &ipv4p);
    ipv4p.prefix.s_addr = htonl((unsigned int)ipv4p.prefix.s_addr);
    socketfd=socket(AF_INET,SOCK_DGRAM,0);
    if(socketfd<0)
    {
    vty_out(vty,"socket error\n");
    return -1;
    }

    cmd = SIOCDELPOOL;
    strcpy(ifr.ifr_name,cNAT64);
    addr.start = ipv4p.prefix;
    usTemp = ipv4p.prefixlen;
    memcpy(&addr.end,&usTemp,sizeof(unsigned int));
    //addr.end = ipv4p.prefixlen;

    ifr.ifr_data = &addr;
    ret=ioctl(socketfd,cmd,&ifr);
    if(ret == -1)
    {
    vty_out(vty,"ioctl error2: %d\n",errno);
    if(errno == NO_MATCH)
    {
    vty_out(vty,"The start address and end address is error!\n");
    }
    close(socketfd);
    return -1;
    }
    close(socketfd);
    return CMD_SUCCESS;
     */
}

/* Write IPv4 static route configuration. */
static int static_config_ipv4 (struct vty *vty)
{
    struct route_node *rn;
    struct static_ipv4 *si;
    struct route_table *stable;
    int write;

    write = 0;

    /* Lookup table.  */
    stable = vrf_static_table (AFI_IP, SAFI_UNICAST, 0);
    if (!stable)
        return -1;

    for (rn = route_top (stable); rn; rn = route_next (rn))
        for (si = rn->info; si; si = si->next)
        {
            vty_out (vty, "ip route %s/%d", inet_ntoa (rn->p.u.prefix4), rn->p.prefixlen);

            switch (si->type)
            {
            case STATIC_IPV4_GATEWAY:
                vty_out (vty, " %s", inet_ntoa (si->gate.ipv4));
                break;
            case STATIC_IPV4_IFNAME:
                vty_out (vty, " %s", si->gate.ifname);
                break;
            case STATIC_IPV4_BLACKHOLE:
                vty_out (vty, " Null0");
                break;
            }

            /* flags are incompatible with STATIC_IPV4_BLACKHOLE */
            if (si->type != STATIC_IPV4_BLACKHOLE)
            {
                if (CHECK_FLAG (si->flags, ZEBRA_FLAG_REJECT))
                    vty_out (vty, " %s", "reject");

                if (CHECK_FLAG (si->flags, ZEBRA_FLAG_BLACKHOLE))
                    vty_out (vty, " %s", "blackhole");
            }

            if (si->distance != ZEBRA_STATIC_DISTANCE_DEFAULT)
                vty_out (vty, " %d", si->distance);

            vty_out (vty, "%s", VTY_NEWLINE);

            write = 1;
        }
    return write;
}

DEFUN (show_ip_protocol, show_ip_protocol_cmd, "show ip protocol", SHOW_STR IP_STR "IP protocol filtering status\n")
{
    int i;

    vty_out (vty, "Protocol    : route-map %s", VTY_NEWLINE);
    vty_out (vty, "------------------------%s", VTY_NEWLINE);
    for (i = 0; i < ZEBRA_ROUTE_MAX; i++)
    {
        if (proto_rm[AFI_IP][i])
            vty_out (vty, "%-10s  : %-10s%s", zebra_route_string (i), proto_rm[AFI_IP][i], VTY_NEWLINE);
        else
            vty_out (vty, "%-10s  : none%s", zebra_route_string (i), VTY_NEWLINE);
    }
    if (proto_rm[AFI_IP][i])
        vty_out (vty, "%-10s  : %-10s%s", "any", proto_rm[AFI_IP][i], VTY_NEWLINE);
    else
        vty_out (vty, "%-10s  : none%s", "any", VTY_NEWLINE);

    return CMD_SUCCESS;
}

/*
 *add by huang jing in 2013 5 14
 *function:add dhcpv4 commands
 */
#ifdef HAVE_DHCPV4
int sendtoserver (struct vty *vty, char buffer[1024])
{
    struct sockaddr_in my_addr;
    bzero (&my_addr, sizeof (my_addr));
    my_addr.sin_family = AF_INET;
    my_addr.sin_port = htons (8889);
    my_addr.sin_addr.s_addr = inet_addr ("127.0.0.1");

    int fd;
    char buf[1024] = { 0 };

    strcpy (buf, buffer);
    //vty_out (vty,"++%s++\n",buf);

    fd = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd == -1)
    {
        vty_out (vty, "socket fault!\n");
        return -1;
    }

    if (connect (fd, (struct sockaddr *) &my_addr, sizeof (my_addr)) == -1)
    {
        //vty_out (vty,"dhcp server progress does not open!\n");
        return -1;
    }

    //  vty_out (vty,"--1---%s--%d-%d--\n",buf,sizeof(buf),strlen(buf));
    usleep (1000);
    if (send (fd, "1send", sizeof ("1send"), 0) == -1)
    {
        vty_out (vty, "send fault!\n");
        return -1;
    }

    //  vty_out (vty,"--2---%s-----\n",buf);
    usleep (1000);
    if (send (fd, buf, strlen (buf) + 1, 0) == -1)
    {
        vty_out (vty, "send fault!\n");
        return -1;
    }

    //  vty_out (vty,"11111111\n");
    memset (buf, 0, sizeof (buf));
    if (recv (fd, buf, sizeof (buf) - 1, 0) == -1)
    {
        vty_out (vty, "revc commands to respond fault!\n");
        return -1;
    }
    //  vty_out (vty,"22222222\n");
    if (strcmp (buf, "command success") == 0)
    {
        close (fd);
        return 0;
    }
    else if (strcmp (buf, "command fault") == 0)
    {
        close (fd);
        return -2;
    }

}

void change_ipv4address (char *buf)
{
    char str[50] = { 0 };
    char *start = NULL, *p = buf;
    int i, address1, address2, address3, address4;

    //去除点分十进制地址中的无效的0，eg: 010.01.001.1 -> 10.1.1.1
    i = 0;
    start = p;
    while (*p != '.')
    {
        p++;
        i++;
    }
    strncpy (str, start, i);
    str[i] = '\0';
    address1 = atoi (str);

    i = 0;
    p++;
    start = p;
    memset (str, 0, sizeof (str));
    while (*p != '.')
    {
        p++;
        i++;
    }
    strncpy (str, start, i);
    str[i] = '\0';
    address2 = atoi (str);

    i = 0;
    p++;
    start = p;
    memset (str, 0, sizeof (str));
    while (*p != '.')
    {
        p++;
        i++;
    }
    strncpy (str, start, i);
    str[i] = '\0';
    address3 = atoi (str);

    i = 0;
    p++;
    start = p;
    memset (str, 0, sizeof (str));
    while (*p != '\0')
    {
        p++;
        i++;
    }
    strncpy (str, start, i);
    str[i] = '\0';
    address4 = atoi (str);

    memset (str, 0, sizeof (str));
    sprintf (str, "%d.%d.%d.%d", address1, address2, address3, address4);
    strcpy (buf, str);

    return;
}

int compare_twoaddress (char buf[], char buf2[])	//low address should be < high address
{
    char str[50] = { 0 };
    char *start = NULL, *p = buf;
    int i, address1_1, address1_2, address1_3, address1_4;
    int address2_1, address2_2, address2_3, address2_4;

    i = 0;
    start = p;
    while (*p != '.')
    {
        p++;
        i++;
    }
    strncpy (str, start, i);
    str[i] = '\0';
    address1_1 = atoi (str);

    i = 0;
    p++;
    start = p;
    memset (str, 0, sizeof (str));
    while (*p != '.')
    {
        p++;
        i++;
    }
    strncpy (str, start, i);
    str[i] = '\0';
    address1_2 = atoi (str);

    i = 0;
    p++;
    start = p;
    memset (str, 0, sizeof (str));
    while (*p != '.')
    {
        p++;
        i++;
    }
    strncpy (str, start, i);
    str[i] = '\0';
    address1_3 = atoi (str);

    i = 0;
    p++;
    start = p;
    memset (str, 0, sizeof (str));
    while (*p != '\0')
    {
        p++;
        i++;
    }
    strncpy (str, start, i);
    str[i] = '\0';
    address1_4 = atoi (str);

    p = buf2;
    i = 0;
    start = p;
    while (*p != '.')
    {
        p++;
        i++;
    }
    strncpy (str, start, i);
    str[i] = '\0';
    address2_1 = atoi (str);

    i = 0;
    p++;
    start = p;
    memset (str, 0, sizeof (str));
    while (*p != '.')
    {
        p++;
        i++;
    }
    strncpy (str, start, i);
    str[i] = '\0';
    address2_2 = atoi (str);

    i = 0;
    p++;
    start = p;
    memset (str, 0, sizeof (str));
    while (*p != '.')
    {
        p++;
        i++;
    }
    strncpy (str, start, i);
    str[i] = '\0';
    address2_3 = atoi (str);

    i = 0;
    p++;
    start = p;
    memset (str, 0, sizeof (str));
    while (*p != '\0')
    {
        p++;
        i++;
    }
    strncpy (str, start, i);
    str[i] = '\0';
    address2_4 = atoi (str);

    if (address1_1 > address2_1)
        return -1;
    else if (address1_1 < address2_1)
        return 0;
    else
    {
        if (address1_2 > address2_2)
            return -1;
        else if (address1_2 < address2_2)
            return 0;
        else
        {
            if (address1_3 > address2_3)
                return -1;
            else if (address1_3 < address2_3)
                return 0;
            else
            {
                if (address1_4 >= address2_4)
                    return -1;
                else
                    return 0;
            }
        }
    }

    return 0;
}

DEFUN (ip_dhcp_excluded_address,
       ip_dhcp_excluded_address_cmd,
       "ip dhcp excluded-address A.B.C.D  A.B.C.D", IP_STR "Configure DHCP server and relay parameters\n" "Prevent DHCP from assigning certain addresses\n" "Low IP address\n" "High IP address\n")
{
    char buf[1024] = { 0 };
    char *p = NULL;
    int i;
    int ret;
    //dhcp_flag = 1;

    i = 0;
    p = argv[0];
    if (*p == '.')
    {
        vty_out (vty, "% [ZEBRA] Unknown command: %s\n", buf);
        return CMD_WARNING;
    }
    while (*p != '\0')
    {
        if (*p == '.')
            i++;
        p++;
    }
    p--;
    if ((i != 3) || (*p == '.'))
    {
        vty_out (vty, "% [ZEBRA] Unknown command: %s\n", buf);
        return CMD_WARNING;
    }

    i = 0;
    p = argv[1];
    if (*p == '.')
    {
        vty_out (vty, "% [ZEBRA] Unknown command: %s\n", buf);
        return CMD_WARNING;
    }
    while (*p != '\0')
    {
        if (*p == '.')
            i++;
        p++;
    }
    p--;
    if ((i != 3) || (*p == '.'))
    {
        vty_out (vty, "% [ZEBRA] Unknown command: %s\n", buf);
        return CMD_WARNING;
    }

    change_ipv4address (argv[0]);
    change_ipv4address (argv[1]);
    if (compare_twoaddress (argv[0], argv[1]) == -1)	//address argv[1] should >= argv[0]
    {
        vty_out (vty, "% [%s, %s] is an illegal address range.\n", argv[0], argv[1]);
        return CMD_WARNING;
    }

    if (*(argv[0]) == '0')
        strcpy (buf, "ip dhcp excluded-address 0.0.0.0");
    else
    {
        strcpy (buf, "ip dhcp excluded-address ");
        strcat (buf, argv[0]);
        strcat (buf, " ");
        strcat (buf, argv[1]);
    }

    //  vty_out (vty,"-----%s-----\n",buf);
    ret = sendtoserver (vty, buf);
    if (ret == -1)
        return CMD_WARNING;

    return CMD_SUCCESS;
}

DEFUN (no_ip_dhcp_excluded_address,
       no_ip_dhcp_excluded_address_cmd,
       "no ip dhcp excluded-address A.B.C.D  A.B.C.D",
       NO_STR IP_STR "Configure DHCP server and relay parameters\n" "Prevent DHCP from assigning certain addresses\n" "Low IP address\n" "High IP address\n")
{
    char buf[1024] = { 0 };
    int ret;
    char *p = NULL;
    int i;

    //dhcp_flag = 1;

    i = 0;
    p = argv[0];
    if (*p == '.')
    {
        vty_out (vty, "% [ZEBRA] Unknown command: %s\n", buf);
        return CMD_WARNING;
    }
    while (*p != '\0')
    {
        if (*p == '.')
            i++;
        p++;
    }
    p--;
    if ((i != 3) || (*p == '.'))
    {
        vty_out (vty, "% [ZEBRA] Unknown command: %s\n", buf);
        return CMD_WARNING;
    }

    i = 0;
    p = argv[1];
    if (*p == '.')
    {
        vty_out (vty, "% [ZEBRA] Unknown command: %s\n", buf);
        return CMD_WARNING;
    }
    while (*p != '\0')
    {
        if (*p == '.')
            i++;
        p++;
    }
    p--;
    if ((i != 3) || (*p == '.'))
    {
        vty_out (vty, "% [ZEBRA] Unknown command: %s\n", buf);
        return CMD_WARNING;
    }

    change_ipv4address (argv[0]);
    change_ipv4address (argv[1]);

    if (*(argv[0]) == '0')
        strcpy (buf, "no ip dhcp excluded-address 0.0.0.0");
    else
    {

        strcpy (buf, "no ip dhcp excluded-address ");
        strcat (buf, argv[0]);
        strcat (buf, " ");
        strcat (buf, argv[1]);
    }

    //  vty_out (vty,"-----%s-----\n",buf);
    ret = sendtoserver (vty, buf);
    if (ret == -1)
        return CMD_WARNING;
    else if (ret == -2)
    {
        vty_out (vty, "\% Range [ %s,  %s] is not in the database.\n", argv[0], argv[1]);
        return CMD_WARNING;
    }

    return CMD_SUCCESS;
}

DEFUN (ip_dhcp_excluded_address_distance1,
       ip_dhcp_excluded_address__distance1_cmd,
       "ip dhcp excluded-address A.B.C.D", IP_STR "Configure DHCP server and relay parameters\n" "Prevent DHCP from assigning certain addresses\n" "Low IP address\n")
{
    char buf[1024] = { 0 };
    //char str[100] = {0};
    int ret;
    char *p = NULL;
    int i;
    //dhcp_flag = 1;

    i = 0;
    p = argv[0];
    if (*p == '.')
    {
        vty_out (vty, "% [ZEBRA] Unknown command: %s\n", buf);
        return CMD_WARNING;
    }
    while (*p != '\0')
    {
        if (*p == '.')
            i++;
        p++;
    }
    p--;
    if ((i != 3) || (*p == '.'))
    {
        vty_out (vty, "% [ZEBRA] Unknown command: %s\n", buf);
        return CMD_WARNING;
    }

    change_ipv4address (argv[0]);

    if (*(argv[0]) == '0')
        strcpy (buf, "ip dhcp excluded-address 0.0.0.0");
    else
    {
        strcpy (buf, "ip dhcp excluded-address ");
        strcat (buf, argv[0]);
    }

    //  vty_out (vty,"-----%s-----\n",buf);
    ret = sendtoserver (vty, buf);
    if (ret != 0)
        return CMD_WARNING;

    return CMD_SUCCESS;
}

DEFUN (no_ip_dhcp_excluded_address_distance1,
       no_ip_dhcp_excluded_address__distance1_cmd,
       "no ip dhcp excluded-address A.B.C.D", NO_STR IP_STR "Configure DHCP server and relay parameters\n" "Prevent DHCP from assigning certain addresses\n" "Low IP address\n")
{
    char buf[1024] = { 0 };
    int ret;
    char *p = NULL;
    int i;
    //dhcp_flag = 1;

    i = 0;
    p = argv[0];
    if (*p == '.')
    {
        vty_out (vty, "% [ZEBRA] Unknown command: %s\n", buf);
        return CMD_WARNING;
    }
    while (*p != '\0')
    {
        if (*p == '.')
            i++;
        p++;
    }
    p--;
    if ((i != 3) || (*p == '.'))
    {
        vty_out (vty, "% [ZEBRA] Unknown command: %s\n", buf);
        return CMD_WARNING;
    }

    change_ipv4address (argv[0]);

    if (*(argv[0]) == '0')
        strcpy (buf, "no ip dhcp excluded-address 0.0.0.0");
    else
    {
        strcpy (buf, "no ip dhcp excluded-address ");
        strcat (buf, argv[0]);
    }

    //  vty_out (vty,"-----%s-----\n",buf);
    ret = sendtoserver (vty, buf);
    if (ret == -1)
        return CMD_WARNING;
    else if (ret == -2)
    {
        vty_out (vty, "\% Range [ %s,  %s] is not in the database.\n", argv[0], argv[0]);
        return CMD_WARNING;
    }

    return CMD_SUCCESS;
}

DEFUN (ip_dhcp_pool, ip_dhcp_pool_cmd, "ip dhcp pool WORD", IP_STR "Configure DHCP server and relay parameters\n" "Configure DHCP address pools\n" "  WORD  Pool name\n")
{
    char buf[1024] = { 0 };
    int ret;
    //dhcp_flag = 2;
    strcpy (buf, "ip dhcp pool ");
    strcat (buf, argv[0]);

    ret = sendtoserver (vty, buf);
    if (ret == -1)
        return CMD_WARNING;
    else if (ret == -2)
    {
        vty_out (vty, "name of pool %s is not in the database.\n", argv[0]);
        return CMD_WARNING;
    }

    vty->node = DHCP_NODE;
    return CMD_SUCCESS;
}

DEFUN (no_ip_dhcp_pool, no_ip_dhcp_pool_cmd, "no ip dhcp pool WORD", NO_STR IP_STR "Configure DHCP server and relay parameters" "Configure DHCP address pools\n" "  WORD  Pool name\n")
{
    char buf[1024] = { 0 };
    int ret;
    //dhcp_flag = 2;

    strcpy (buf, "no ip dhcp pool ");
    strcat (buf, argv[0]);

    //  vty_out (vty,"-----%s-----\n",buf);
    ret = sendtoserver (vty, buf);
    if (ret == -1)
        return CMD_WARNING;
    else if (ret == -2)
    {
        vty_out (vty, "name of pool %s is not in the database.\n", argv[0]);
        return CMD_WARNING;
    }

    return CMD_SUCCESS;
}

DEFUN (ip_dhcp_pool_network, ip_dhcp_pool_network_cmd, "network A.B.C.D A.B.C.D", "Network number and mask\n" "Network number in dotted-decimal notation\n" "Network mask or prefix length\n")
{
    char buf[1024] = { 0 };
    int ret;
    int i;
    char *p = NULL;

    i = 0;
    p = argv[0];
    if (*p == '.')
    {
        vty_out (vty, "% [ZEBRA] Unknown command: %s\n", buf);
        return CMD_WARNING;
    }
    while (*p != '\0')
    {
        if (*p == '.')
            i++;
        p++;
    }
    p--;
    if ((i != 3) || (*p == '.'))
    {
        vty_out (vty, "% [ZEBRA] Unknown command: %s\n", buf);
        return CMD_WARNING;
    }

    i = 0;
    p = argv[1];
    if (*p == '.')
    {
        vty_out (vty, "% [ZEBRA] Unknown command: %s\n", buf);
        return CMD_WARNING;
    }
    while (*p != '\0')
    {
        if (*p == '.')
            i++;
        p++;
    }
    p--;
    if ((i != 3) || (*p == '.'))
    {
        vty_out (vty, "% [ZEBRA] Unknown command: %s\n", buf);
        return CMD_WARNING;
    }

    change_ipv4address (argv[0]);
    change_ipv4address (argv[1]);
    if ((*(argv[0]) == '0') || (*(argv[1]) == '0'))
    {
        vty_out (vty, "%s / %s is an invalid network.\n", argv[0], argv[1]);
        return CMD_WARNING;
    }

    strcpy (buf, "network ");
    strcat (buf, argv[0]);
    strcat (buf, " ");
    strcat (buf, argv[1]);

    //  vty_out (vty,"-----%s-----\n",buf);
    ret = sendtoserver (vty, buf);
    if (ret != 0)
        return CMD_WARNING;

    return CMD_SUCCESS;
}

DEFUN (no_ip_dhcp_pool_network,
       no_ip_dhcp_pool_network_cmd, "no network A.B.C.D A.B.C.D", NO_STR "Network number and mask\n" "Network number in dotted-decimal notation\n" "Network mask or prefix length\n")
{
    char buf[1024] = { 0 };
    int ret;
    int i;
    char *p = NULL;

    i = 0;
    p = argv[0];
    if (*p == '.')
    {
        vty_out (vty, "% [ZEBRA] Unknown command: %s\n", buf);
        return CMD_WARNING;
    }
    while (*p != '\0')
    {
        if (*p == '.')
            i++;
        p++;
    }
    p--;
    if ((i != 3) || (*p == '.'))
    {
        vty_out (vty, "% [ZEBRA] Unknown command: %s\n", buf);
        return CMD_WARNING;
    }

    i = 0;
    p = argv[1];
    if (*p == '.')
    {
        vty_out (vty, "% [ZEBRA] Unknown command: %s\n", buf);
        return CMD_WARNING;
    }
    while (*p != '\0')
    {
        if (*p == '.')
            i++;
        p++;
    }
    p--;
    if ((i != 3) || (*p == '.'))
    {
        vty_out (vty, "% [ZEBRA] Unknown command: %s\n", buf);
        return CMD_WARNING;
    }

    change_ipv4address (argv[0]);
    change_ipv4address (argv[1]);

    strcpy (buf, "no network ");
    strcat (buf, argv[0]);
    strcat (buf, " ");
    strcat (buf, argv[1]);

    //  vty_out (vty,"-----%s-----\n",buf);
    ret = sendtoserver (vty, buf);
    if (ret == -1)
        return CMD_WARNING;
    else if (ret == -2)
    {
        vty_out (vty, "\% Range [ %s,  %s] is not in the database.\n", argv[0], argv[1]);
        return CMD_WARNING;
    }

    return CMD_SUCCESS;
}

DEFUN (ip_dhcp_pool_dnsserver_dnstince1, ip_dhcp_pool_dnsserver_dnstince1_cmd, "dns-server A.B.C.D", "DNS servers\n" "Server's IP address\n")
{
    char buf[1024] = { 0 };
    int ret;
    int i;
    char *p = NULL;

    i = 0;
    p = argv[0];
    if (*p == '.')
    {
        vty_out (vty, "% [ZEBRA] Unknown command: %s\n", buf);
        return CMD_WARNING;
    }
    while (*p != '\0')
    {
        if (*p == '.')
            i++;
        p++;
    }
    p--;
    if ((i != 3) || (*p == '.'))
    {
        vty_out (vty, "% [ZEBRA] Unknown command: %s\n", buf);
        return CMD_WARNING;
    }

    change_ipv4address (argv[0]);
    if ((*(argv[0]) == '0'))
        strcpy (buf, "dns-server 0.0.0.0");
    else
    {
        strcpy (buf, "dns-server ");
        strcat (buf, argv[0]);
    }

    //  vty_out (vty,"-----%s-----\n",buf);
    ret = sendtoserver (vty, buf);
    if (ret != 0)
        return CMD_WARNING;

    return CMD_SUCCESS;
}

DEFUN (ip_dhcp_pool_dnsserver_dnstince2, ip_dhcp_pool_dnsserver_dnstince2_cmd, "dns-server A.B.C.D A.B.C.D", "DNS servers\n" "Server's IP address\n" "Server's IP address\n")
{
    char buf[1024] = { 0 };
    int ret;
    int i;
    char *p = NULL;

    i = 0;
    p = argv[0];
    if (*p == '.')
    {
        vty_out (vty, "% [ZEBRA] Unknown command: %s\n", buf);
        return CMD_WARNING;
    }
    while (*p != '\0')
    {
        if (*p == '.')
            i++;
        p++;
    }
    p--;
    if ((i != 3) || (*p == '.'))
    {
        vty_out (vty, "% [ZEBRA] Unknown command: %s\n", buf);
        return CMD_WARNING;
    }

    i = 0;
    p = argv[1];
    if (*p == '.')
    {
        vty_out (vty, "% [ZEBRA] Unknown command: %s\n", buf);
        return CMD_WARNING;
    }
    while (*p != '\0')
    {
        if (*p == '.')
            i++;
        p++;
    }
    p--;
    if ((i != 3) || (*p == '.'))
    {
        vty_out (vty, "% [ZEBRA] Unknown command: %s\n", buf);
        return CMD_WARNING;
    }

    change_ipv4address (argv[0]);
    change_ipv4address (argv[1]);

    strcpy (buf, "dns-server ");
    if ((*(argv[0]) == '0'))
        strcat (buf, "0.0.0.0");
    else
        strcat (buf, argv[0]);

    if ((*(argv[1]) == '0'))
    {
        strcat (buf, " ");
        strcat (buf, "0.0.0.0");
    }
    else
    {
        strcat (buf, " ");
        strcat (buf, argv[1]);
    }

    //  vty_out (vty,"-----%s-----\n",buf);
    ret = sendtoserver (vty, buf);
    if (ret != 0)
        return CMD_WARNING;

    return CMD_SUCCESS;
}

DEFUN (ip_dhcp_pool_dnsserver, ip_dhcp_pool_dnsserver_cmd, "dns-server A.B.C.D  A.B.C.D A.B.C.D", "DNS servers\n" "Server's IP address\n" "Server's IP address\n" "Server's IP address\n")
{
    char buf[1024] = { 0 };
    int ret;
    int i;
    char *p = NULL;

    i = 0;
    p = argv[0];
    if (*p == '.')
    {
        vty_out (vty, "% [ZEBRA] Unknown command: %s\n", buf);
        return CMD_WARNING;
    }
    while (*p != '\0')
    {
        if (*p == '.')
            i++;
        p++;
    }
    p--;
    if ((i != 3) || (*p == '.'))
    {
        vty_out (vty, "% [ZEBRA] Unknown command: %s\n", buf);
        return CMD_WARNING;
    }

    i = 0;
    p = argv[1];
    if (*p == '.')
    {
        vty_out (vty, "% [ZEBRA] Unknown command: %s\n", buf);
        return CMD_WARNING;
    }
    while (*p != '\0')
    {
        if (*p == '.')
            i++;
        p++;
    }
    p--;
    if ((i != 3) || (*p == '.'))
    {
        vty_out (vty, "% [ZEBRA] Unknown command: %s\n", buf);
        return CMD_WARNING;
    }

    i = 0;
    p = argv[2];
    if (*p == '.')
    {
        vty_out (vty, "% [ZEBRA] Unknown command: %s\n", buf);
        return CMD_WARNING;
    }
    while (*p != '\0')
    {
        if (*p == '.')
            i++;
        p++;
    }
    p--;
    if ((i != 3) || (*p == '.'))
    {
        vty_out (vty, "% [ZEBRA] Unknown command: %s\n", buf);
        return CMD_WARNING;
    }

    change_ipv4address (argv[0]);
    change_ipv4address (argv[1]);
    change_ipv4address (argv[2]);

    strcpy (buf, "dns-server ");
    if ((*(argv[0]) == '0'))
        strcat (buf, "0.0.0.0");
    else
        strcat (buf, argv[0]);

    if ((*(argv[1]) == '0'))
    {
        strcat (buf, " ");
        strcat (buf, "0.0.0.0");
    }
    else
    {
        strcat (buf, " ");
        strcat (buf, argv[1]);
    }

    if ((*(argv[2]) == '0'))
    {
        strcat (buf, " ");
        strcat (buf, "0.0.0.0");
    }
    else
    {
        strcat (buf, " ");
        strcat (buf, argv[2]);
    }
    /*
       strcpy(buf,"dns-server ");
       strcat(buf,argv[0]);
       strcat(buf," ");
       strcat(buf,argv[1]);
       strcat(buf," ");
       strcat(buf,argv[2]);
     */
    //  vty_out (vty,"-----%s-----\n",buf);
    ret = sendtoserver (vty, buf);
    if (ret != 0)
        return CMD_WARNING;

    return CMD_SUCCESS;
}

DEFUN (no_ip_dhcp_pool_dnsserver, no_ip_dhcp_pool_dnsserver_cmd, "no dns-server", NO_STR "DNS servers\n")
{
    char buf[1024] = { 0 };
    int ret;

    strcpy (buf, "no dns-server ");

    //  vty_out (vty,"-----%s-----\n",buf);
    ret = sendtoserver (vty, buf);
    if (ret != 0)
        return CMD_WARNING;

    return CMD_SUCCESS;
}

DEFUN (ip_dhcp_pool_defaultroute_dnstince1, ip_dhcp_pool_defaultroute_dnstince1_cmd, "default-router A.B.C.D", "Default routers\n" "Router's IP address\n")
{
    char buf[1024] = { 0 };
    int ret;
    int i;
    char *p = NULL;

    i = 0;
    p = argv[0];
    if (*p == '.')
    {
        vty_out (vty, "% [ZEBRA] Unknown command: %s\n", buf);
        return CMD_WARNING;
    }
    while (*p != '\0')
    {
        if (*p == '.')
            i++;
        p++;
    }
    p--;
    if ((i != 3) || (*p == '.'))
    {
        vty_out (vty, "% [ZEBRA] Unknown command: %s\n", buf);
        return CMD_WARNING;
    }

    change_ipv4address (argv[0]);
    if ((*(argv[0]) == '0'))
        strcpy (buf, "default-router 0.0.0.0");
    else
    {
        strcpy (buf, "default-router ");
        strcat (buf, argv[0]);
    }

    //strcpy(buf,"default-router ");
    //strcat(buf,argv[0]);

    //  vty_out (vty,"-----%s-----\n",buf);
    ret = sendtoserver (vty, buf);
    if (ret != 0)
        return CMD_WARNING;

    return CMD_SUCCESS;
}

/*
   DEFUN (no_ip_dhcp_pool_defaultroute_dnstince1,
   no_ip_dhcp_pool_defaultroute_dnstince1_cmd,
   "no default-router A.B.C.D",
   NO_STR
   "Default routers\n"
   "Router's IP address\n"
   )
   {
   return CMD_SUCCESS;
   }
 */
DEFUN (ip_dhcp_pool_defaultroute_dnstince2, ip_dhcp_pool_defaultroute_dnstince2_cmd, "default-router A.B.C.D A.B.C.D", "Default routers\n" "Router's IP address\n" "Router's IP address\n")
{
    char buf[1024] = { 0 };
    int ret;
    int i;
    char *p = NULL;

    i = 0;
    p = argv[0];
    if (*p == '.')
    {
        vty_out (vty, "% [ZEBRA] Unknown command: %s\n", buf);
        return CMD_WARNING;
    }
    while (*p != '\0')
    {
        if (*p == '.')
            i++;
        p++;
    }
    p--;
    if ((i != 3) || (*p == '.'))
    {
        vty_out (vty, "% [ZEBRA] Unknown command: %s\n", buf);
        return CMD_WARNING;
    }

    i = 0;
    p = argv[1];
    if (*p == '.')
    {
        vty_out (vty, "% [ZEBRA] Unknown command: %s\n", buf);
        return CMD_WARNING;
    }
    while (*p != '\0')
    {
        if (*p == '.')
            i++;
        p++;
    }
    p--;
    if ((i != 3) || (*p == '.'))
    {
        vty_out (vty, "% [ZEBRA] Unknown command: %s\n", buf);
        return CMD_WARNING;
    }

    change_ipv4address (argv[0]);
    change_ipv4address (argv[1]);

    strcpy (buf, "default-router ");
    if ((*(argv[0]) == '0'))
        strcat (buf, "0.0.0.0");
    else
        strcat (buf, argv[0]);

    if ((*(argv[1]) == '0'))
    {
        strcat (buf, " ");
        strcat (buf, "0.0.0.0");
    }
    else
    {
        strcat (buf, " ");
        strcat (buf, argv[1]);
    }
    /*
       strcpy(buf,"default-router ");
       strcat(buf,argv[0]);
       strcat(buf," ");
       strcat(buf,argv[1]);
     */
    //  vty_out (vty,"-----%s-----\n",buf);
    ret = sendtoserver (vty, buf);
    if (ret != 0)
        return CMD_WARNING;

    return CMD_SUCCESS;
}

DEFUN (ip_dhcp_pool_defaultroute, ip_dhcp_pool_defaultroute_cmd, "default-router A.B.C.D  A.B.C.D A.B.C.D", "Default routers\n" "Router's IP address\n" "Router's IP address\n" "Router's IP address\n")
{
    char buf[1024] = { 0 };
    int ret;
    int i;
    char *p = NULL;

    i = 0;
    p = argv[0];
    if (*p == '.')
    {
        vty_out (vty, "% [ZEBRA] Unknown command: %s\n", buf);
        return CMD_WARNING;
    }
    while (*p != '\0')
    {
        if (*p == '.')
            i++;
        p++;
    }
    p--;
    if ((i != 3) || (*p == '.'))
    {
        vty_out (vty, "% [ZEBRA] Unknown command: %s\n", buf);
        return CMD_WARNING;
    }

    i = 0;
    p = argv[1];
    if (*p == '.')
    {
        vty_out (vty, "% [ZEBRA] Unknown command: %s\n", buf);
        return CMD_WARNING;
    }
    while (*p != '\0')
    {
        if (*p == '.')
            i++;
        p++;
    }
    p--;
    if ((i != 3) || (*p == '.'))
    {
        vty_out (vty, "% [ZEBRA] Unknown command: %s\n", buf);
        return CMD_WARNING;
    }

    i = 0;
    p = argv[2];
    if (*p == '.')
    {
        vty_out (vty, "% [ZEBRA] Unknown command: %s\n", buf);
        return CMD_WARNING;
    }
    while (*p != '\0')
    {
        if (*p == '.')
            i++;
        p++;
    }
    p--;
    if ((i != 3) || (*p == '.'))
    {
        vty_out (vty, "% [ZEBRA] Unknown command: %s\n", buf);
        return CMD_WARNING;
    }

    change_ipv4address (argv[0]);
    change_ipv4address (argv[1]);
    change_ipv4address (argv[2]);

    strcpy (buf, "default-router ");
    if ((*(argv[0]) == '0'))
        strcat (buf, "0.0.0.0");
    else
        strcat (buf, argv[0]);

    if ((*(argv[1]) == '0'))
    {
        strcat (buf, " ");
        strcat (buf, "0.0.0.0");
    }
    else
    {
        strcat (buf, " ");
        strcat (buf, argv[1]);
    }

    if ((*(argv[2]) == '0'))
    {
        strcat (buf, " ");
        strcat (buf, "0.0.0.0");
    }
    else
    {
        strcat (buf, " ");
        strcat (buf, argv[2]);
    }
    /*
       strcpy(buf,"default-router ");
       strcat(buf,argv[0]);
       strcat(buf," ");
       strcat(buf,argv[1]);
       strcat(buf," ");
       strcat(buf,argv[2]);
     */
    //  vty_out (vty,"-----%s-----\n",buf);
    ret = sendtoserver (vty, buf);
    if (ret != 0)
        return CMD_WARNING;

    return CMD_SUCCESS;
}

DEFUN (no_ip_dhcp_pool_defaultroute, no_ip_dhcp_pool_defaultroute_cmd, "no default-router ", NO_STR "Default routers\n")
{
    char buf[1024] = { 0 };
    int ret;

    strcpy (buf, "no default-router ");

    //  vty_out (vty,"-----%s-----\n",buf);
    ret = sendtoserver (vty, buf);
    if (ret != 0)
        return CMD_WARNING;

    return CMD_SUCCESS;
}

DEFUN (ip_dhcp_pool_lease, ip_dhcp_pool_lease_cmd, "lease (<0-365>|infinite)", "Address lease time\n" "<0-365> Days\n" "Lease time is infinited\n")
{
    char buf[1024] = { 0 };
    int ret;

    strcpy (buf, "lease ");
    if (*(argv[0]) == 'i')
        strcpy (argv[0], "infinite");
    strcat (buf, argv[0]);

    //  vty_out (vty,"-----%s-----\n",buf);
    ret = sendtoserver (vty, buf);
    if (ret != 0)
        return CMD_WARNING;

    return CMD_SUCCESS;
}

DEFUN (ip_dhcp_pool_lease_hours, ip_dhcp_pool_lease_hours_cmd, "lease <0-365> <0-23>", "Address lease time\n" "<0-365> Days\n" "<0-23> Hours\n")
{
    char buf[1024] = { 0 };
    int ret;

    strcpy (buf, "lease ");
    strcat (buf, argv[0]);
    strcat (buf, " ");
    strcat (buf, argv[1]);

    //  vty_out (vty,"-----%s-----\n",buf);
    ret = sendtoserver (vty, buf);
    if (ret != 0)
        return CMD_WARNING;

    return CMD_SUCCESS;
}

DEFUN (ip_dhcp_pool_lease_minutes, ip_dhcp_pool_lease_minutes_cmd, "lease <0-365> <0-23> <0-59>", "Address lease time\n" "<0-365> Days\n" "<0-23> Hours\n" "<0-59>  Minutes\n")
{
    char buf[1024] = { 0 };
    int ret;

    strcpy (buf, "lease ");
    strcat (buf, argv[0]);
    strcat (buf, " ");
    strcat (buf, argv[1]);
    strcat (buf, " ");
    strcat (buf, argv[2]);

    //  vty_out (vty,"-----%s-----\n",buf);
    ret = sendtoserver (vty, buf);
    if (ret != 0)
        return CMD_WARNING;

    return CMD_SUCCESS;
}

DEFUN (no_ip_dhcp_pool_lease, no_ip_dhcp_pool_lease_cmd, "no lease", NO_STR "Address lease time\n")
{
    char buf[1024] = { 0 };
    int ret;

    strcpy (buf, "no lease");

    //  vty_out (vty,"-----%s-----\n",buf);
    ret = sendtoserver (vty, buf);
    if (ret != 0)
        return CMD_WARNING;

    return CMD_SUCCESS;
}
#endif
#ifdef HAVE_DHCPV4
int zebra_dhcp_write_config (struct vty *vty)
{
    struct sockaddr_in my_addr;
    DHCP_CFG_TABLE *pTempData;
    DHCP_CFG_HEAD *pstCfgHead;
    int fd, i, j;
    char cBuf[4096];
    char *tempBuf;
    char testBuf[32];
    int len;

    bzero (&my_addr, sizeof (my_addr));
    my_addr.sin_family = AF_INET;
    my_addr.sin_port = htons (8889);
    my_addr.sin_addr.s_addr = inet_addr ("127.0.0.1");

    fd = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd == -1)
    {
        vty_out (vty, "socket fault!\n");
        return CMD_SUCCESS;
    }

    if (connect (fd, (struct sockaddr *) &my_addr, sizeof (my_addr)) == -1)
    {
        //vty_out (vty,"dhcp server progress does not open!\n");
        return CMD_SUCCESS;
    }

    if (send (fd, "2recv", sizeof ("2recv"), 0) == -1)
    {
        vty_out (vty, "send fault!\n");
        return CMD_SUCCESS;
    }

    if ((len = recv (fd, cBuf, sizeof(cBuf), 0)) == -1)
    {
        vty_out (vty, "revc show running fault!\n");
        return CMD_SUCCESS;
    }

    pstCfgHead = (DHCP_CFG_HEAD *) cBuf;
    tempBuf = cBuf + 4;

    //vty_out(vty,"count is %d,len is %d",pstCfgHead->count,len);
    //vty_out (vty, "%s", VTY_NEWLINE);

    //vty_out(vty,"%s","!");
    for (i = 0; i < pstCfgHead->count; i++)
    {
        //vty_out(vty,"-----------11--------\n");
        pTempData = (DHCP_CFG_TABLE *) tempBuf;
        vty_out (vty, "%s", pTempData->OneCmdLine);
        vty_out (vty, "%s", VTY_NEWLINE);
        tempBuf += 128;
    }
    vty_out (vty, "%s", "!");
    vty_out (vty, "%s", VTY_NEWLINE);
    //vty_out(vty,"%s","!");
    //vty_out (vty, "%s", VTY_NEWLINE);

    close (fd);
    return CMD_SUCCESS;
}
#endif
/*add dhcp ,add by huang jing in 2013 5 14*/
#ifdef HAVE_IPV6
/* General fucntion for IPv6 static route. */
static int static_ipv6_func (struct vty *vty, int add_cmd, const char *dest_str, const char *gate_str, const char *ifname, const char *flag_str, const char *distance_str)
{
    int ret;
    u_char distance;
    struct prefix p;
    struct in6_addr *gate = NULL;
    struct in6_addr gate_addr;
    u_char type = 0;
    int table = 0;
    u_char flag = 0;

    ret = str2prefix (dest_str, &p);
    if (ret <= 0)
    {
        vty_out (vty, "%% Malformed address%s", VTY_NEWLINE);
        return CMD_WARNING;
    }

    /* Apply mask for given prefix. */
    apply_mask (&p);

    /* Route flags */
    if (flag_str)
    {
        switch (flag_str[0])
        {
        case 'r':
        case 'R':				/* XXX */
            SET_FLAG (flag, ZEBRA_FLAG_REJECT);
            break;
        case 'b':
        case 'B':				/* XXX */
            SET_FLAG (flag, ZEBRA_FLAG_BLACKHOLE);
            break;
        default:
            vty_out (vty, "%% Malformed flag %s %s", flag_str, VTY_NEWLINE);
            return CMD_WARNING;
        }
    }

    /* Administrative distance. */
    if (distance_str)
        distance = atoi (distance_str);
    else
        distance = ZEBRA_STATIC_DISTANCE_DEFAULT;

    /* When gateway is valid IPv6 addrees, then gate is treated as
       nexthop address other case gate is treated as interface name. */
    ret = inet_pton (AF_INET6, gate_str, &gate_addr);

    if (ifname)
    {
        /* When ifname is specified.  It must be come with gateway
           address. */
        if (ret != 1)
        {
            vty_out (vty, "%% Malformed address%s", VTY_NEWLINE);
            return CMD_WARNING;
        }
        type = STATIC_IPV6_GATEWAY_IFNAME;
        gate = &gate_addr;
    }
    else
    {
        if (ret == 1)
        {
            type = STATIC_IPV6_GATEWAY;
            gate = &gate_addr;
        }
        else
        {
            type = STATIC_IPV6_IFNAME;
            ifname = gate_str;
        }
    }

    if (add_cmd)
        static_add_ipv6 (&p, type, gate, ifname, flag, distance, table);
    else
        static_delete_ipv6 (&p, type, gate, ifname, distance, table);

    return CMD_SUCCESS;
}

static int addnodeforheadercompression(struct vty *vty,struct header_compression_table *newnode)
{



    struct header_compression_table *pos=NULL;
    if (header_compression_table_head == NULL)
    {
        header_compression_table_head  = newnode;
        header_compression_table_head ->next = NULL;
        header_compression_table_head ->prev = NULL;

        return 0;

    }
    else
    {

        for(pos = header_compression_table_head ; pos->next != NULL; pos = pos->next)
        {
            if(pos->node.prefix.prefixlen ==  newnode->node.prefix.prefixlen)
            {

                if(!g_U8_t_DataMemcmp(&pos->node.prefix.u.prefix6,&newnode->node.prefix.u.prefix6,newnode->node.prefix.prefixlen))
                {
                    return -1;
                }
            }

        }


        if(pos->node.prefix.prefixlen ==  newnode->node.prefix.prefixlen)
        {

            if(!g_U8_t_DataMemcmp(&pos->node.prefix.u.prefix6,&newnode->node.prefix.u.prefix6,newnode->node.prefix.prefixlen))
            {

                return -1;
            }
        }

        pos->next = newnode;
        newnode->next = NULL;
        newnode->prev = pos;
        return 0;

    }

}

static int delnodeforheadercompression(struct vty *vty,struct header_compression_table *newnode)
{
    struct header_compression_table *pos=NULL;
    if (header_compression_table_head == NULL)
    {
        return 1;

    }
    else
    {

        for(pos = header_compression_table_head; pos!= NULL; pos = pos->next)
        {
            if(pos->node.prefix.prefixlen ==  newnode->node.prefix.prefixlen)
            {
                //vty_out (vty, "%% prefixlen == prefixlen =%d %s", newnode->node.prefix.prefixlen,VTY_NEWLINE);

                if(!g_U8_t_DataMemcmp(&pos->node.prefix.u.prefix6,&newnode->node.prefix.u.prefix6,newnode->node.prefix.prefixlen))
                {

                    // vty_out (vty, "%% prefix == prefix %s", VTY_NEWLINE);

                    //vty_out (vty, "%% gate == gate %s", VTY_NEWLINE);
                    if(pos->prev != NULL)
                    {
                        pos->prev->next = pos->next;
                    }
                    if(pos->next != NULL)
                    {
                        pos->next->prev = pos->prev;
                    }
                    free(pos);
                    if(pos == header_compression_table_head)
                    {
                        header_compression_table_head = NULL;
                    }
                    return 0;
                }
            }

        }

        //vty_out (vty, "%% %s", VTY_NEWLINE);
        return 1;

    }

}

static int addnodeforpolicybasedroute(struct vty *vty,struct acl_route_table *newnode)
{
    struct in6_addr *g = (struct in6_addr *)malloc(sizeof(struct in6_addr));
    memset(g,0,sizeof(struct in6_addr));

    struct acl_route_table *pos=NULL;
    if (acl_route_table_head == NULL)
    {
        acl_route_table_head = newnode;
        acl_route_table_head->next = NULL;
        acl_route_table_head->prev = NULL;

        return 0;
    }
    else
    {
        for(pos = acl_route_table_head; pos->next != NULL; pos = pos->next)
        {
            if(pos->node.prefix.prefixlen ==  newnode->node.prefix.prefixlen)
            {
                //vty_out (vty, "%% prefixlen == prefixlen =%d %s", newnode->node.prefix.prefixlen,VTY_NEWLINE);
                if(!g_U8_t_DataMemcmp(&pos->node.prefix.u.prefix6,&newnode->node.prefix.u.prefix6,newnode->node.prefix.prefixlen))
                {
                    //vty_out (vty, "%% prefix == prefix %s", VTY_NEWLINE);
                    memcpy(g,&pos->node.gateway,sizeof(struct in6_addr));
                    memcpy(&pos->node.gateway,&newnode->node.gateway,sizeof(struct in6_addr));
                    memcpy(&newnode->node.gateway,g,sizeof(struct in6_addr));
                    return 1;
                }
            }
        }

        if(pos->node.prefix.prefixlen ==  newnode->node.prefix.prefixlen)
        {
            //vty_out (vty, "%% prefixlen == prefixlen =%d %s", newnode->node.prefix.prefixlen,VTY_NEWLINE);
            if(!g_U8_t_DataMemcmp(&pos->node.prefix.u.prefix6,&newnode->node.prefix.u.prefix6,newnode->node.prefix.prefixlen))
            {
                //vty_out (vty, "%% prefix == prefix %s", VTY_NEWLINE);
                memcpy(g,&pos->node.gateway,sizeof(struct in6_addr));
                memcpy(&pos->node.gateway,&newnode->node.gateway,sizeof(struct in6_addr));
                memcpy(&newnode->node.gateway,g,sizeof(struct in6_addr));
                return 1;
            }
        }
        pos->next = newnode;
        newnode->next = NULL;
        newnode->prev = pos;
        return 0;
    }
    return 0;
}

static int delnodeforpolicybasedroute(struct vty *vty,struct acl_route_table *newnode)
{
    struct acl_route_table *pos=NULL;
    if (acl_route_table_head == NULL)
    {
        return 1;

    }
    else
    {

        for(pos = acl_route_table_head; pos!= NULL; pos = pos->next)
        {
            if(pos->node.prefix.prefixlen ==  newnode->node.prefix.prefixlen)
            {
                //vty_out (vty, "%% prefixlen == prefixlen =%d %s", newnode->node.prefix.prefixlen,VTY_NEWLINE);

                if(!g_U8_t_DataMemcmp(&pos->node.prefix.u.prefix6,&newnode->node.prefix.u.prefix6,newnode->node.prefix.prefixlen))
                {

                    // vty_out (vty, "%% prefix == prefix %s", VTY_NEWLINE);

                    if(!g_U8_t_DataMemcmp(pos->node.gateway,newnode->node.gateway,128))
                    {
                        //vty_out (vty, "%% gate == gate %s", VTY_NEWLINE);
                        newnode->node.ifp = pos->node.ifp;
                        if(pos->prev != NULL)
                        {
                            pos->prev->next = pos->next;
                        }
                        if(pos->next != NULL)
                        {
                            pos->next->prev = pos->prev;
                        }
                        free(pos);
                        if(pos == acl_route_table_head)
                        {
                            acl_route_table_head = NULL;
                        }
                        return 0;
                    }
                }
            }

        }

        //vty_out (vty, "%% %s", VTY_NEWLINE);
        return 1;

    }

}


send_header_compression_to_dpdk(struct vty *vty,struct prefix *p,int type)
{
    int sockfd;
    int ret;
    struct comm_head *comm;
    int len = sizeof(struct header_compression_node);

    struct header_compression_node *buf = (struct header_compression_node *)malloc(sizeof(struct header_compression_node));
    memset(buf,0,sizeof(struct header_compression_node));
    memcpy(&buf->prefix,p,sizeof(struct prefix));

    comm = (struct comm_head *) malloc (sizeof (struct comm_head) + len);
    if (comm == NULL)
    {
        fprintf (stderr, "%s\n", "flow engine info head malloc failed");
        return -1;
    }
    memset (comm, 0, sizeof (struct comm_head) + len);

    if(type == 0)//add
    {
        comm->type =0x38;
    }
    else        //del
    {
        comm->type =0x39;
    }
    comm->len = htonl(sizeof (struct comm_head) + len);

    memcpy (comm->data,(char *)buf, len);

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
//sangmeng mark
struct policy_based_route_msg
{
    struct prefix s_prefix;
    struct prefix prefix;
    uint8_t gateway[16];
    char ifp[20];
};

int send_polict_based_route_to_dpdk(struct vty *vty, struct prefix *s, struct prefix *p, struct in6_addr *gate, struct interface *ifp,int type)
{
    int sockfd;
    int ret;
    struct comm_head *comm;
    int len = sizeof(struct policy_based_route_msg);

    struct policy_based_route_msg *buf = (struct policy_based_route_msg *)malloc(sizeof(struct policy_based_route_msg));
    memset(buf, 0, sizeof(struct policy_based_route_msg));

    if (s != NULL)
        memcpy(&buf->s_prefix, s, sizeof(struct prefix));

    memcpy(&buf->prefix, p, sizeof(struct prefix));
    memcpy(buf->gateway, gate, sizeof(struct in6_addr));
    memcpy(buf->ifp, ifp->name, 20);

    comm = (struct comm_head *) malloc (sizeof (struct comm_head) + len);
    if (comm == NULL)
    {
        fprintf (stderr, "%s\n", "flow engine info head malloc failed");
        return -1;
    }
    memset (comm, 0, sizeof (struct comm_head) + len);

    if(type == 0)//add
    {
        comm->type =0x30;
    }
    else        //del
    {
        comm->type =0x31;
    }
    comm->len = htonl(sizeof (struct comm_head) + len);

    memcpy (comm->data,(char *)buf, len);

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


static int add_header_compression(struct vty *vty,struct prefix *p)
{

    struct header_compression_table *newnode;
    int ret;
    newnode = (struct header_compression_table *)malloc(sizeof(struct header_compression_table));
    memset(newnode,0,sizeof(struct header_compression_table));



    memcpy(&newnode->node.prefix,p,sizeof(struct prefix));


    char buf[BUFSIZ];
    prefix2str(&newnode->node.prefix,buf,BUFSIZ);
    //vty_out (vty, " %s", buf);

    ret = addnodeforheadercompression(vty,newnode);
    if(ret ==0)
    {
        send_header_compression_to_dpdk(vty,p,0);

    }
    else if(ret == -1)
    {
        vty_out(vty,"this prefix already exist%");
        free(newnode);
    }


    return ret;

}


static int del_header_compression(struct vty *vty, struct prefix *p)
{

    struct header_compression_table *newnode;
    int ret;
    newnode = (struct header_compression_table *)malloc(sizeof(struct header_compression_table));
    memset(newnode,0,sizeof(struct header_compression_table));



    memcpy(&newnode->node.prefix,p,sizeof(struct prefix));


    //vty_out (vty, "%% static_del_policy_based_route %s", VTY_NEWLINE);
    char buf[BUFSIZ];
    prefix2str(&newnode->node.prefix,buf,BUFSIZ);
    //vty_out (vty, " %s", buf);

    ret = delnodeforheadercompression(vty,newnode);
    if(ret == 0)
    {
        send_header_compression_to_dpdk(vty,p,1);
    }
    else
    {

        vty_out(vty,"this prefix not exist%");
    }

    free(newnode);

    return ret;


}

static int static_add_policy_based_route(struct vty *vty, struct prefix *s, struct prefix *p, u_char type, struct in6_addr *gate, const char *ifname )
{
    struct acl_route_table *newnode;
    int ret;
    newnode = (struct acl_route_table *)malloc(sizeof(struct acl_route_table));
    memset(newnode,0,sizeof(struct acl_route_table));

    struct interface *ifp;
    ifp = if_lookup_by_ipv6(gate);
    if(ifp == NULL)
    {
        vty_out (vty, "%% This nexthop has no outing interface %s", VTY_NEWLINE);
        free(newnode);
        return -1;
    }
    else
    {
        //vty_out (vty, "%% name= %s  ifindex = %d %s", ifp->name,ifp->ifindex,VTY_NEWLINE);
        newnode->node.ifp = ifp;
        newnode->node.status = 1;
    }

    memcpy(&newnode->node.s_prefix, s, sizeof(struct prefix));
    memcpy(&newnode->node.prefix, p, sizeof(struct prefix));
    memcpy(&newnode->node.gateway, gate, sizeof(struct in6_addr));

    char buf[BUFSIZ];
    prefix2str(&newnode->node.prefix, buf, BUFSIZ);

    ret = addnodeforpolicybasedroute(vty, newnode);
    if(ret ==0)
    {
        send_polict_based_route_to_dpdk(vty, s, p, gate, ifp, 0);

    }
    else if(ret ==1)
    {
        send_polict_based_route_to_dpdk(vty, s, p, &newnode->node.gateway, ifp, 1);
        send_polict_based_route_to_dpdk(vty, s, p, gate, ifp, 0);
        free(newnode);
    }

    return ret;
}
static int static_del_policy_based_route(struct vty *vty, struct prefix *s, struct prefix *p, u_char type, struct in6_addr *gate, const char *ifname)
{

    struct acl_route_table *newnode;
    int ret;
    newnode = (struct acl_route_table *)malloc(sizeof(struct acl_route_table));
    memset(newnode, 0, sizeof(struct acl_route_table));

    memcpy(&newnode->node.prefix, s, sizeof(struct prefix));
    memcpy(&newnode->node.prefix, p, sizeof(struct prefix));
    memcpy(&newnode->node.gateway, gate, sizeof(struct in6_addr));

    struct interface *ifp;
#if 0
    ifp = if_lookup_by_ipv6(gate);
    if(ifp == NULL)
    {
        vty_out (vty, "%% This nexthop has no outing interface %s", VTY_NEWLINE);
        return -1;

    }
    else
    {
        newnode->node.ifp = ifp;
    }
#endif
    char buf[BUFSIZ];
    prefix2str(&newnode->node.prefix, buf, BUFSIZ);
    //vty_out (vty, " %s", buf);

    ret = delnodeforpolicybasedroute(vty, newnode);
    if(ret == 0)
    {
	printf("will send polict route to dpdk for del.\n");
        send_polict_based_route_to_dpdk(vty, s, p, gate, newnode->node.ifp, 1);
    }
    else
    {

    }

    free(newnode);
    return ret;
}


static int header_compression_func (struct vty *vty, int add_cmd, const char *dest_str)
{

    int ret;
    struct prefix p;
    struct in6_addr gate_addr;
    u_char type = 0;
    int table = 0;

    //ddvty_out (vty, "%% rohc:%s %s", dest_str,VTY_NEWLINE);
    ret = str2prefix (dest_str, &p);
    if (ret <= 0)
    {
        vty_out (vty, "%% Malformed address%s", VTY_NEWLINE);
        return CMD_WARNING;
    }

    /* Apply mask for given prefix. */
    apply_mask (&p);



    if (!add_cmd)
    {
        add_header_compression (vty,&p);
    }
    else
    {
        del_header_compression (vty,&p);
    }
    return CMD_SUCCESS;


}

static int static_policy_based_route_func (struct vty *vty, int add_cmd, const char *src_str, const char *dest_str, const char *gate_str, const char *ifname)
{
    int ret;
    struct prefix s;
    struct prefix p;
    struct in6_addr *gate = NULL;
    struct in6_addr gate_addr;
    u_char type = 0;
    int table = 0;

    memset(&s, 0x00, sizeof(struct prefix));
    memset(&p, 0x00, sizeof(struct prefix));
    if (src_str != NULL)
    {
        ret = str2prefix (src_str, &s);
        if (ret <= 0)
        {
            vty_out (vty, "%% Malformed address%s", VTY_NEWLINE);
            return CMD_WARNING;
        }
    }

    ret = str2prefix (dest_str, &p);
    if (ret <= 0)
    {
        vty_out (vty, "%% Malformed address%s", VTY_NEWLINE);
        return CMD_WARNING;
    }

    /* Apply mask for given prefix. */
    apply_mask (&p);

    ret = inet_pton (AF_INET6, gate_str, &gate_addr);

    if (ifname)
    {
        /* When ifname is specified.  It must be come with gateway
           address. */
        if (ret != 1)
        {
            vty_out (vty, "%% Malformed address%s", VTY_NEWLINE);
            return CMD_WARNING;
        }
        type = STATIC_IPV6_GATEWAY_IFNAME;
        gate = &gate_addr;
    }
    else
    {
        if (ret == 1)
        {
            type = STATIC_IPV6_GATEWAY;
            gate = &gate_addr;
        }
        else
        {
            type = STATIC_IPV6_IFNAME;
            ifname = gate_str;
        }
    }

    if (!add_cmd)
    {
        printf("add pilicy based route.\n");
        static_add_policy_based_route (vty, &s, &p, type, gate, ifname);
    }
    else
    {
        printf("del pilicy based route.\n");
        static_del_policy_based_route(vty, &s, &p, type, gate, ifname);
    }
    return CMD_SUCCESS;
}

static int static_ipv6_customize (/*struct vty *vty,*/ int add_cmd, const char *dest_str, const char *gate_str, const char *ifname, const char *flag_str, const char *distance_str)
{
    int ret;
    u_char distance;
    struct prefix p;
    struct in6_addr *gate = NULL;
    struct in6_addr gate_addr;
    u_char type = 0;
    int table = 0;
    u_char flag = 0;

    ret = str2prefix (dest_str, &p);
    if (ret <= 0)
    {
        //vty_out (vty, "%% Malformed address%s", VTY_NEWLINE);
        return CMD_WARNING;
    }

    /* Apply mask for given prefix. */
    apply_mask (&p);

    /* Route flags */
    if (flag_str)
    {
        switch (flag_str[0])
        {
        case 'r':
        case 'R':				/* XXX */
            SET_FLAG (flag, ZEBRA_FLAG_REJECT);
            break;
        case 'b':
        case 'B':				/* XXX */
            SET_FLAG (flag, ZEBRA_FLAG_BLACKHOLE);
            break;
        default:
            //vty_out (vty, "%% Malformed flag %s %s", flag_str, VTY_NEWLINE);
            return CMD_WARNING;
        }
    }

    /* Administrative distance. */
    if (distance_str)
        distance = atoi (distance_str);
    else
        distance = ZEBRA_STATIC_DISTANCE_DEFAULT;

    /* When gateway is valid IPv6 addrees, then gate is treated as
       nexthop address other case gate is treated as interface name. */
    ret = inet_pton (AF_INET6, gate_str, &gate_addr);

    if (ifname)
    {
        /* When ifname is specified.  It must be come with gateway
           address. */
        if (ret != 1)
        {
            //vty_out (vty, "%% Malformed address%s", VTY_NEWLINE);
            return CMD_WARNING;
        }
        type = STATIC_IPV6_GATEWAY_IFNAME;
        gate = &gate_addr;
    }
    else
    {
        if (ret == 1)
        {
            type = STATIC_IPV6_GATEWAY;
            gate = &gate_addr;
        }
        else
        {
            type = STATIC_IPV6_IFNAME;
            ifname = gate_str;
        }
    }

    printf("%s()%d ipv6 customize route, add_cmd:%d\n", __func__, __LINE__, add_cmd);
    if (add_cmd)
        static_add_ipv6_customize (&p, type, gate, ifname, flag, distance, table);
    else
        static_delete_ipv6_customize (&p, type, gate, ifname, distance, table);

    return CMD_SUCCESS;
}
//static int zebra_ipv6_customize (int add_cmd, char *routetablename, const char *dest_str, const char *gate_str, const char *ifname, const char *distance_str)
static int zebra_ipv6_customize (int add_cmd, char *routetablename, const char *dest_str, const char *gate_str, const char *ifname, const char *distance_str, const char *describe)

{
    int ret;
    u_char distance;
    struct prefix p;
    struct in6_addr gate;
    int table = 0;
    u_char flag = 0;

    ret = str2prefix (dest_str, &p);
    if (ret <= 0)
    {
        //vty_out (vty, "%% Malformed address%s", VTY_NEWLINE);
        return CMD_WARNING;
    }

    /* Apply mask for given prefix. */
    apply_mask (&p);

    /* Administrative distance. */
    if (distance_str)
        distance = atoi (distance_str);
    else
        distance = ZEBRA_STATIC_DISTANCE_DEFAULT;

    /* When gateway is valid IPv6 addrees, then gate is treated as
       nexthop address other case gate is treated as interface name. */
    ret = inet_pton (AF_INET6, gate_str, &gate);
    if (!ret)
    {
        printf("gateway is error.\n");
        return CMD_WARNING;
    }

    if (add_cmd)
    {
        //zebra_rib_add_ipv6_customize (routetablename, &p, &gate, ifname, distance, table);
        printf("add route msg\n");
        zebra_rib_add_ipv6_customize (routetablename, &p, &gate, ifname, distance, table, describe,1);
    }
    else
        zebra_rib_delete_ipv6_customize (routetablename, &p, &gate, ifname,  table);

    return CMD_SUCCESS;
}

/*struct nat64_prefix{
  struct in6_addr prefix;
  int len;
  int ubit;
  };
 */
static int str_to_prefix6 (const char *str, struct ion_prefix *prefix)
{
    char *s = NULL;
    char *p = NULL;
    int ret;
    s = strchr (str, '/');
    p = malloc (s - str + 1);
    prefix->len = atoi (++s);
    strncpy (p, str, s - str - 1);
    *(p + (s - str - 1)) = '\0';
    ret = inet_pton (AF_INET6, p, &(prefix->prefix));
    free (p);
    return ret;
}

/*NAT64 prefix*/
//change by ccc
DEFUN (nat64_prefix, nat64_prefix_cmd, "nat64 prefix X:X::X:X/M (ubit|no-ubit)", "Configure nat64 protocol\n" "Configure IPv6 prefix\n" "prefix/prefix_length\n" "with ubit\n" "without ubit\n")
{

    if (nat_prefix_head != NULL)
    {
        vty_out (vty, "this prefix is already exist%s", VTY_NEWLINE);
        return CMD_WARNING;
    }
    struct zebra_config_message *p_zebra_msg = (struct zebra_config_message *) malloc (sizeof (struct zebra_config_message));
    memset (p_zebra_msg, 0, sizeof (struct zebra_config_message));
    struct nat_prefix_message *p_nat_prefix = (struct nat_prefix_message *) malloc (sizeof (struct nat_prefix_message));
    memset (p_nat_prefix, 0, sizeof (struct nat_prefix_message));
    p_zebra_msg->data = p_nat_prefix;

    int ret = 0;
    /*start get info and fill ivi message */
    p_zebra_msg->type = ADD_NAT64_PREFIX;	//type
    //prefix
    ret = str2prefix_ipv6 (argv[0], &(p_nat_prefix->prefix6));
    if (ret <= 0)
    {
        free (p_zebra_msg);
        free (p_nat_prefix);
        vty_out (vty, "%% Malformed address%s", VTY_NEWLINE);
        return CMD_WARNING;
    }

    if (!strcmp (argv[1], "ubit"))
    {
        p_nat_prefix->flag = UBIT;	//flag
    }
    else if (!strcmp (argv[1], "no-ubit"))
    {
        p_nat_prefix->flag = NO_UBIT;
    }
    else
    {
        free (p_zebra_msg);
        free (p_nat_prefix);
        vty_out (vty, "%% Malformed bubit%s", VTY_NEWLINE);
        return CMD_WARNING;
    }

    p_zebra_msg->len = sizeof (struct zebra_config_message) + sizeof (struct nat_prefix_message);	//len

    if (-1 == zebra_connect_dpdk_send_message_two (p_zebra_msg, p_zebra_msg->len))
    {
        free (p_nat_prefix);
        free (p_zebra_msg);
        //vty_out(vty,"connect server fail%s",VTY_NEWLINE);
        return CMD_SUCCESS;
    }

    nat_prefix_head = p_nat_prefix;
    return CMD_SUCCESS;
    /*
    #define SIOCADDNAT64PREFIX SIOCCHGTUNNEL
    struct ifreq ifr;
    int socketfd;
    int ret=0;
    struct tnl_parm nat64;
    char cNAT64[]="nat64";
    socketfd=socket(AF_INET6,SOCK_DGRAM,0);
    if(socketfd<0)
    {
    vty_out(vty,"socket error\n");
    return -1;
    }
    strcpy(ifr.ifr_name,cNAT64);
    ret = str_to_prefix6(argv[0],&(nat64.prefix));
    if(ret == 0)
    {
    vty_out(vty,"input error prefix\n");
    close(socketfd);
    return -1;
    }
    if(argc == 2)
    {
    #if 0
    if(strcmp(argv[1],"ubit") != 0 && strcmp(argv[1],"no-ubit") != 0)
    {
    vty_out(vty,"input error UBIT\n");
    close(socketfd);
    return -1;
    }
    else if(strcmp(argv[1],"ubit") == 0)
    nat64.prefix.ubit = 1;
    else if(strcmp(argv[1],"no-ubit") == 0)
    nat64.prefix.ubit = 0;
    #endif
    if( *(argv[1])=='n' )
    {
    strcpy(argv[1],"no-ubit");
    nat64.prefix.ubit = 0;
    }
    else if( *(argv[1])=='u' )
    {
    strcpy(argv[1],"ubit");
    nat64.prefix.ubit = 1;
    }
    else
    {
    vty_out(vty,"input error UBIT\n");
    close(socketfd);
    return -1;
    }
    }
    else
    nat64.prefix.ubit = 1;
    nat64.proto = IPPROTO_IPIP;
    ifr.ifr_data=&nat64;

    ret=ioctl(socketfd, SIOCADDNAT64PREFIX,&ifr);
    if(ret == -1)
    {
    vty_out(vty,"ioctl error: %d\n",errno);
    close(socketfd);
    return -1;
    }
    //static_ipv6_func (vty, 1, argv[0],argv[1],NULL, NULL, NULL);
    close(socketfd);
    return CMD_SUCCESS;
     */
}

/*no nat64 prefix ---delete nat64 prefix*/
DEFUN (no_nat64_prefix, no_nat64_prefix_cmd, "no nat64 prefix X:X::X:X/M", NO_STR "Configure nat64 protocol\n" "Configure IPv6 prefix\n" "prefix/prefix_length\n")
{
    if (nat_prefix_head == NULL)
        return CMD_WARNING;
    struct zebra_config_message *p_zebra_msg = (struct zebra_config_message *) malloc (sizeof (struct zebra_config_message));
    memset (p_zebra_msg, 0, sizeof (struct zebra_config_message));
    struct nat_prefix_message *p_nat_prefix = (struct nat_prefix_message *) malloc (sizeof (struct nat_prefix_message));
    memset (p_nat_prefix, 0, sizeof (struct nat_prefix_message));
    p_zebra_msg->data = p_nat_prefix;

    int ret = 0;
    /*start get info and fill ivi message */
    p_zebra_msg->type = DEL_NAT64_PREFIX;	//type
    //prefix
    ret = str2prefix_ipv6 (argv[0], &(p_nat_prefix->prefix6));
    if (ret <= 0)
    {
        free (p_zebra_msg);
        free (p_nat_prefix);
        vty_out (vty, "%% Malformed address%s", VTY_NEWLINE);
        return CMD_WARNING;
    }

    p_nat_prefix->flag = 0;
    p_zebra_msg->len = sizeof (struct zebra_config_message) + sizeof (struct nat_prefix_message);	//len
    if (-1 == zebra_connect_dpdk_send_message_two (p_zebra_msg, p_zebra_msg->len))
    {
        free (p_nat_prefix);
        free (p_zebra_msg);
        vty_out (vty, "connect server fail%s", VTY_NEWLINE);
        return CMD_SUCCESS;
    }
    //delete
    if (!memcmp (&(nat_prefix_head->prefix6), &(p_nat_prefix->prefix6), sizeof (struct prefix_ipv6)))
    {
        free (nat_prefix_head);
        nat_prefix_head = NULL;
    }

    free (p_nat_prefix);
    free (p_zebra_msg);
    return CMD_SUCCESS;
    /*
    #define SIOCDELNAT64PREFIX  (SIOCCHGTUNNEL+9)
    struct ifreq ifr;
    int socketfd;
    int ret=0;
    struct tnl_parm nat64;
    char cNAT64[]="nat64";

    socketfd=socket(AF_INET6,SOCK_DGRAM,0);
    if(socketfd<0)
    {
    vty_out(vty,"socket error\n");
    return -1;
    }
    strcpy(ifr.ifr_name,cNAT64);
    ret = str_to_prefix6(argv[0],&(nat64.prefix));
    if(ret == 0)
    {
    vty_out(vty,"input error prefix\n");
    close(socketfd);
    return -1;
    }
    nat64.proto = IPPROTO_IPIP;
    ifr.ifr_data=&nat64;

    ret=ioctl(socketfd,SIOCDELNAT64PREFIX ,&ifr);
    if(ret == -1)
    {
    vty_out(vty,"ioctl error: %d\n",errno);
    if(errno == 36)
    {
    vty_out(vty,"input error prefix!\n");
    }
    close(socketfd);
    return -1;
    }
    close(socketfd);
    return CMD_SUCCESS;
     */
}

#if 0
/* show nat64 prefix */
DEFUN (show_nat64_prefix, show_nat64_prefix_cmd, "show nat64 prefix INTERFACE", SHOW_NAT64_PREFIX "INTERFACE : interface name\n")
{
#define SIOCGETPREFIX SIOCGETTUNNEL
    struct ifreq ifr;
    struct tnl_parm nat64;
    int socketfd;
    int ret = 0;
    char pre[40];
    socketfd = socket (AF_INET6, SOCK_DGRAM, 0);
    if (socketfd < 0)
    {
        vty_out (vty, "socket error\n");
        return -1;
    }
    memcpy (ifr.ifr_name, argv[0], strlen (argv[0]) + 1);
    ifr.ifr_data = &nat64;
    ret = ioctl (socketfd, SIOCGETPREFIX, &ifr);
    if (ret == -1)
    {
        vty_out (vty, "ioctl error: %d\n", errno);
        close (socketfd);
        return -1;
    }
    if (nat64.prefix.len == 0)
    {
        vty_out (vty, "prefix is 0\n");
    }
    else
    {
        inet_ntop (AF_INET6, &(nat64.prefix.prefix), pre, 40);
        vty_out (vty, "ivi prefix is  %s/", pre);
        vty_out (vty, "%d     ", nat64.prefix.len);
        if (nat64.prefix.ubit == 1)
        {
            vty_out (vty, "ubit\n");
        }
    }
    close (socketfd);
    return CMD_SUCCESS;
}
#endif
/*configure ivi prefix*/
int zebra_connect_dpdk_send_message_two (struct zebra_config_message *p_zebra_msg, int size)
{
    int ret = 0;
    int sockfd;
    sockfd = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);

    if (sockfd <= 0)
    {
        return -1;
    }
    struct sockaddr_in socketaddress;
    socketaddress.sin_family = AF_INET;
    socketaddress.sin_port = htons (DPDK_SERVER_PORT);
    socketaddress.sin_addr.s_addr = inet_addr (DPDK_SERVER_ADDRESS);
    memset (&(socketaddress.sin_zero), 0, 8);
    /*start connect */
    ret = connect (sockfd, &socketaddress, sizeof (struct sockaddr));
    if (ret < 0)
    {
        close (sockfd);
        return -1;
    }

    char buf[1024];
    memset(buf, 0x00, sizeof(buf));
    memcpy (buf, p_zebra_msg, sizeof (struct zebra_config_message));

    if ((p_zebra_msg->type == ADD_IVI_PREFIX) || (p_zebra_msg->type == DEL_IVI_PREFIX))
        memcpy (buf + sizeof (struct zebra_config_message), p_zebra_msg->data, sizeof (struct ivi_prefix_message));
    if ((p_zebra_msg->type == ADD_IVI_POOL) || (p_zebra_msg->type == DEL_IVI_POOL))
    {
        printf("send %s msg.\n", (p_zebra_msg->type == ADD_IVI_POOL)? "ADD_IVI_POOL":"DEL_IVI_POOL");
        memcpy (buf + sizeof (struct zebra_config_message), p_zebra_msg->data, sizeof (struct ivi_pool_message));
    }
    if ((p_zebra_msg->type == ADD_TUNNEL) || (p_zebra_msg->type == DEL_TUNNEL))
    {
        printf("send %s msg.\n", (p_zebra_msg->type == ADD_TUNNEL)? "ADD_TUNNEL":"DEL_TUNNEL");
        memcpy (buf + sizeof (struct zebra_config_message), p_zebra_msg->data, sizeof (struct tunnel_info));
    }
    if ((p_zebra_msg->type == ADD_NAT64_PREFIX) || (p_zebra_msg->type == DEL_NAT64_PREFIX))
        memcpy (buf + sizeof (struct zebra_config_message), p_zebra_msg->data, sizeof (struct nat_prefix_message));
    if ((p_zebra_msg->type == ADD_NAT64_POOL) || (p_zebra_msg->type == DEL_NAT64_POOL))
        memcpy (buf + sizeof (struct zebra_config_message), p_zebra_msg->data, sizeof (struct nat_pool_message));
    if ((p_zebra_msg->type == ADD_NAT64_TIMEOUT) || (p_zebra_msg->type == DEL_NAT64_TIMEOUT))
        memcpy (buf + sizeof (struct zebra_config_message), p_zebra_msg->data, sizeof (struct nat_timeout_message));
    ret = send (sockfd, buf, size, 0);
    close (sockfd);
#if 1
    int i;
    for (i = 0; i < size; i++)
        printf("%02x ", buf[i]);
    printf("\n");
#endif

    printf("send %d bytes to dpdk, socket:%d.\n",ret, sockfd);
    return 0;
}

static int g_dpdk_fd = -1;
int connect_dpdk_send_message (struct zebra_config_message *p_zebra_msg, int size)
{
    //sangmeng 20190329
    /*start connect server */
#if 0
    struct tcp_info info;
    int len=sizeof(info);
    getsockopt(g_dpdk_fd, IPPROTO_TCP, TCP_INFO, &info, (socklen_t *)&len);
    if((info.tcpi_state==TCP_CLOSE))
    {
        g_dpdk_fd = -1;
    }
#endif

    int ret = 0;
    int sockfd;
#if 0
    printf(">>> g_dpdk_fd = %d, type:%d\n",g_dpdk_fd,  p_zebra_msg->type);
    if(g_dpdk_fd <= 0)
    {
#endif
        sockfd = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);

        if (sockfd <= 0)
        {
            return -1;
        }
        struct sockaddr_in socketaddress;
        socketaddress.sin_family = AF_INET;
        socketaddress.sin_port = htons (DPDK_SERVER_PORT);
        socketaddress.sin_addr.s_addr = inet_addr (DPDK_SERVER_ADDRESS);
        memset (&(socketaddress.sin_zero), 0, 8);
        /*start connect */
        ret = connect (sockfd, &socketaddress, sizeof (struct sockaddr));
        if (ret < 0)
        {
            close (sockfd);
            return -1;
        }
#if 0
        g_dpdk_fd = sockfd;
    }
    //printf("2 g_dpdk_fd = %d\n",g_dpdk_fd);
    sockfd = g_dpdk_fd;
#endif

    /*send ivi message */
    char buf[1024];
    memset(buf, 0x00, sizeof(buf));
    memcpy (buf, p_zebra_msg, sizeof (struct zebra_config_message));

    if ((p_zebra_msg->type == ADD_IVI_PREFIX) || (p_zebra_msg->type == DEL_IVI_PREFIX))
        memcpy (buf + sizeof (struct zebra_config_message), p_zebra_msg->data, sizeof (struct ivi_prefix_message));
    if ((p_zebra_msg->type == ADD_IVI_POOL) || (p_zebra_msg->type == DEL_IVI_POOL))
    {
        printf("send %s msg.\n", (p_zebra_msg->type == ADD_IVI_POOL)? "ADD_IVI_POOL":"DEL_IVI_POOL");
        memcpy (buf + sizeof (struct zebra_config_message), p_zebra_msg->data, sizeof (struct ivi_pool_message));
    }
    if ((p_zebra_msg->type == ADD_TUNNEL) || (p_zebra_msg->type == DEL_TUNNEL))
    {
        printf("send %s msg.\n", (p_zebra_msg->type == ADD_TUNNEL)? "ADD_TUNNEL":"DEL_TUNNEL");
        memcpy (buf + sizeof (struct zebra_config_message), p_zebra_msg->data, sizeof (struct tunnel_info));
    }
    if ((p_zebra_msg->type == ADD_NAT64_PREFIX) || (p_zebra_msg->type == DEL_NAT64_PREFIX))
        memcpy (buf + sizeof (struct zebra_config_message), p_zebra_msg->data, sizeof (struct nat_prefix_message));
    if ((p_zebra_msg->type == ADD_NAT64_POOL) || (p_zebra_msg->type == DEL_NAT64_POOL))
        memcpy (buf + sizeof (struct zebra_config_message), p_zebra_msg->data, sizeof (struct nat_pool_message));
    if ((p_zebra_msg->type == ADD_NAT64_TIMEOUT) || (p_zebra_msg->type == DEL_NAT64_TIMEOUT))
        memcpy (buf + sizeof (struct zebra_config_message), p_zebra_msg->data, sizeof (struct nat_timeout_message));
    ret = send (sockfd, buf, size, 0);
    //close (sockfd);
#if 1
    int i;
    for (i = 0; i < size; i++)
        printf("%02x ", buf[i]);
    printf("\n");
#endif

    printf("send %d bytes to dpdk, socket:%d.\n",ret, sockfd);
    close(sockfd);
    return 0;
}

DEFUN (ivi_prefix, ivi_prefix_cmd, "ivi prefix X:X::X:X/M (ubit|no-ubit)", "configure ivi prefix\n" "ivi ipv6 prefix\n" "prefix/prefix_length\n" "with ubit\n" "without ubit\n")
{
    if (ivi_prefix_head != NULL)
    {
        vty_out (vty, "IVI prefix is already exist%s", VTY_NEWLINE);
        return CMD_WARNING;
    }
    struct zebra_config_message *p_zebra_msg = (struct zebra_config_message *) malloc (sizeof (struct zebra_config_message));
    memset (p_zebra_msg, 0, sizeof (struct zebra_config_message));
    struct ivi_prefix_message *p_zebra_msg_prefix = (struct ivi_prefix_message *) malloc (sizeof (struct ivi_prefix_message));
    memset (p_zebra_msg_prefix, 0, sizeof (struct ivi_prefix_message));
    p_zebra_msg->data = p_zebra_msg_prefix;

    int ret = 0;
    /*start get info and fill ivi message */
    p_zebra_msg->type = ADD_IVI_PREFIX;	//type
    //prefix
    ret = str2prefix_ipv6 (argv[0], &(p_zebra_msg_prefix->prefix6));
    if (ret <= 0)
    {
        free (p_zebra_msg);
        free (p_zebra_msg_prefix);
        vty_out (vty, "%% Malformed address%s", VTY_NEWLINE);
        return CMD_WARNING;
    }

    if (!strcmp (argv[1], "ubit"))
    {
        p_zebra_msg_prefix->flag = UBIT;	//flag
    }
    else if (!strcmp (argv[1], "no-ubit"))
    {
        p_zebra_msg_prefix->flag = NO_UBIT;
    }
    else
    {
        free (p_zebra_msg);
        free (p_zebra_msg_prefix);
        vty_out (vty, "%% Malformed ubit%s", VTY_NEWLINE);
        return CMD_WARNING;
    }

    p_zebra_msg->len = sizeof (struct zebra_config_message) + sizeof (struct ivi_prefix_message);	//len

    if (-1 == zebra_connect_dpdk_send_message_two (p_zebra_msg, p_zebra_msg->len))
    {
        free (p_zebra_msg_prefix);
        free (p_zebra_msg);
        //vty_out(vty,"connect server fail%s",VTY_NEWLINE);
        return CMD_SUCCESS;
    }

    ivi_prefix_head = p_zebra_msg_prefix;
    return CMD_SUCCESS;
}

DEFUN (no_ivi_prefix, no_ivi_prefix_cmd, "no ivi prefix X:X::X:X/M", NO_STR "configure ivi prefix\n" "ivi ipv6 prefix\n" "prefix/prefix_length\n")
{
    if (ivi_prefix_head == NULL)
        return CMD_WARNING;
    struct zebra_config_message *p_zebra_msg = (struct zebra_config_message *) malloc (sizeof (struct zebra_config_message));
    memset (p_zebra_msg, 0, sizeof (struct zebra_config_message));
    struct ivi_prefix_message *p_zebra_msg_prefix = (struct ivi_prefix_message *) malloc (sizeof (struct ivi_prefix_message));
    memset (p_zebra_msg_prefix, 0, sizeof (struct ivi_prefix_message));
    p_zebra_msg->data = p_zebra_msg_prefix;

    int ret = 0;
    /*start get info and fill ivi message */
    p_zebra_msg->type = DEL_IVI_PREFIX;	//type
    //prefix
    ret = str2prefix_ipv6 (argv[0], &(p_zebra_msg_prefix->prefix6));
    if (ret <= 0)
    {
        free (p_zebra_msg);
        free (p_zebra_msg_prefix);
        vty_out (vty, "%% Malformed address%s", VTY_NEWLINE);
        return CMD_WARNING;
    }

    p_zebra_msg_prefix->flag = 0;
    p_zebra_msg->len = sizeof (struct zebra_config_message) + sizeof (struct ivi_prefix_message);	//len
    if (-1 == zebra_connect_dpdk_send_message_two (p_zebra_msg, p_zebra_msg->len))
    {
        free (p_zebra_msg_prefix);
        free (p_zebra_msg);
        vty_out (vty, "connect server fail%s", VTY_NEWLINE);
        return CMD_SUCCESS;
    }
    //delete
    if (!memcmp (&(ivi_prefix_head->prefix6), &(p_zebra_msg_prefix->prefix6), sizeof (struct prefix_ipv6)))
    {
        free (ivi_prefix_head);
        ivi_prefix_head = NULL;
    }

    free (p_zebra_msg_prefix);
    free (p_zebra_msg);
    return CMD_SUCCESS;
}

////add by ccc for ivi_pool
DEFUN (ivi_pool, ivi_pool_cmd,
       "ivi pool X:X:X:X/M ",
       "configure ivi pool\n"
       "ivi ipv4 prefix\n"
       "ivi ipv4 prefix length\n")
{
    if (ivi_pool_head != NULL)
    {
        vty_out (vty, "IVI IPv4 pool is alreay exist%s", VTY_NEWLINE);
        return CMD_WARNING;
    }

    struct zebra_config_message *p_zebra_msg = (struct zebra_config_message *) malloc (sizeof (struct zebra_config_message));
    memset (p_zebra_msg, 0, sizeof (struct zebra_config_message));
    struct ivi_pool_message *p_ivi_pool_msg = (struct ivi_pool_message *) malloc (sizeof (struct ivi_pool_message));
    memset (p_ivi_pool_msg, 0, sizeof (struct ivi_pool_message));
    p_zebra_msg->data = p_ivi_pool_msg;

    int ret = 0;

    printf("will send ADD_IVI_POOL msg to dpdk.\n");
    /*start get info and fill ivi message */
    p_zebra_msg->type = ADD_IVI_POOL;	//type
    //prefix
    ret = str2prefix_ipv4 (argv[0], &(p_ivi_pool_msg->prefix4));
    if (ret <= 0)
    {
        free (p_zebra_msg);
        free (p_ivi_pool_msg);
        vty_out (vty, "%% Malformed address%s", VTY_NEWLINE);
        return CMD_WARNING;
    }

    p_zebra_msg->len = sizeof (struct zebra_config_message) + sizeof (struct ivi_pool_message);	//len

    printf("%s()%d type:%d.\n", __func__, __LINE__, p_zebra_msg->type);
    //if (-1 == zebra_connect_dpdk_send_message_two (p_zebra_msg, p_zebra_msg->len))
    if (-1 ==zebra_connect_dpdk_send_message_two(p_zebra_msg, p_zebra_msg->len))
    {
        free (p_ivi_pool_msg);
        free (p_zebra_msg);
        vty_out (vty, "connect server fail%s", VTY_NEWLINE);
        return CMD_SUCCESS;
    }

    ivi_pool_head = p_ivi_pool_msg;
    return CMD_SUCCESS;

}

DEFUN (no_ivi_pool, no_ivi_pool_cmd, "no ivi pool X:X:X:X/M ", NO_STR "configure ivi pool\n" "ivi ipv4 prefix\n" "ivi ipv4 prefix length\n")
{
    if (ivi_pool_head == NULL)
        return CMD_WARNING;
    struct zebra_config_message *p_zebra_msg = (struct zebra_config_message *) malloc (sizeof (struct zebra_config_message));
    memset (p_zebra_msg, 0, sizeof (struct zebra_config_message));
    struct ivi_pool_message *p_ivi_pool_msg = (struct ivi_pool_message *) malloc (sizeof (struct ivi_pool_message));
    memset (p_ivi_pool_msg, 0, sizeof (struct ivi_pool_message));
    p_zebra_msg->data = p_ivi_pool_msg;

    int ret = 0;
    /*start get info and fill ivi message */
    p_zebra_msg->type = DEL_IVI_POOL;	//type
    //prefix
    ret = str2prefix_ipv4 (argv[0], &(p_ivi_pool_msg->prefix4));
    if (ret <= 0)
    {
        free (p_zebra_msg);
        free (p_ivi_pool_msg);
        vty_out (vty, "%% Malformed address%s", VTY_NEWLINE);
        return CMD_WARNING;
    }

    p_zebra_msg->len = sizeof (struct zebra_config_message) + sizeof (struct ivi_pool_message);	//len
    if (-1 == zebra_connect_dpdk_send_message_two (p_zebra_msg, p_zebra_msg->len))
    {
        free (p_ivi_pool_msg);
        free (p_zebra_msg);
        vty_out (vty, "connect server fail%s", VTY_NEWLINE);
        return CMD_SUCCESS;
    }
    //delete
    if (!memcmp (&(ivi_pool_head->prefix4), &(p_ivi_pool_msg->prefix4), sizeof (struct prefix_ipv4)))
    {
        free (ivi_pool_head);
        ivi_pool_head = NULL;
    }

    free (p_ivi_pool_msg);
    free (p_zebra_msg);
    return CMD_SUCCESS;
}

struct tunnel_info *link_search (unsigned int tunnel_num)
{
    struct tunnel_info *p = tunnel_head;
    while (p != NULL)
    {
        if (p->tunnel_num == tunnel_num)
        {
            return p;
        }
        p = p->tunnel_next;
    }
    return NULL;
}

int link_create (struct tunnel_info **p, unsigned int tunnel_num)
{
    *p = (struct tunnel_info *) malloc (sizeof (struct tunnel_info));
    bzero (*p, sizeof (struct tunnel_info));
    (*p)->tunnel_num = tunnel_num;
    if (*p == NULL)
        return -1;
    else
    {
        if (tunnel_head == NULL)
            tunnel_head = *p;
        else
        {
            struct tunnel_info *p_insert = tunnel_head;
            if ((*p)->tunnel_num < tunnel_head->tunnel_num)
            {
                tunnel_head = *p;
                tunnel_head->tunnel_next = p_insert;
            }
            else
            {
                struct tunnel_info *p_front = p_insert;
                while (p_insert != NULL)
                {
                    if ((*p)->tunnel_num < p_insert->tunnel_num)
                    {
                        p_front->tunnel_next = (*p);
                        (*p)->tunnel_next = p_insert;
                        break;
                    }
                    p_front = p_insert;
                    p_insert = p_insert->tunnel_next;
                }
                p_front->tunnel_next = (*p);
                (*p)->tunnel_next = NULL;
            }
        }
        return 0;
    }
}

int link_del (struct vty *vty, unsigned int tunnel_num)
{
    struct tunnel_info *p_tunnel = link_search (tunnel_num);
    if (p_tunnel == NULL)
        return -1;
    else
    {
        struct tunnel_info *p = tunnel_head;
        if (tunnel_num == tunnel_head->tunnel_num)
        {
            if (0 == check_tunnel (vty, p, DEL_TUNNEL))
            {
                tunnel_head = tunnel_head->tunnel_next;
                free (p);
                return 0;
            }
            return -1;
        }
        else
        {
            struct tunnel_info *p_front = p;
            while (p != NULL)
            {
                if (tunnel_num == p->tunnel_num)
                {

                    p_front->tunnel_next = p->tunnel_next;
                    if (0 == check_tunnel (vty, p, DEL_TUNNEL))
                    {
                        free (p);
                        return 0;
                    }
                    else
                        return -1;
                }
                p_front = p;
                p = p->tunnel_next;
            }					//end while
        }						//end if

    }
    return 0;
}

DEFUN (interface_tunnel,
       interface_tunnel_cmd,
       "interface tunnel <0-1500>",
       "select one interface tunnel to configure \n"
       "configure 4over6 tunnel\n"
       "tunnel number\n")
{
    unsigned int tunnel_num = atoi (argv[0]);
    if (tunnel_num < 0 || tunnel_num > 1500)
    {
        vty_out (vty, "tunnel num should be <0-1500>");
        return CMD_WARNING;
    }
    struct tunnel_info *p_tunnel = link_search (tunnel_num);
    if (p_tunnel == NULL)
        if (0 < link_create (&p_tunnel, tunnel_num))
        {
            vty_out (vty, "malloc tunnel_info fail");
            return CMD_WARNING;
        }

    vty->index = p_tunnel;
    vty->node = TUNNEL_NODE;
    return CMD_SUCCESS;
}

DEFUN (no_interface_tunnel,
       no_interface_tunnel_cmd,
       "no interface tunnel <0-32>",
       NO_STR
       "select one interface tunnel to configure \n"
       "configure 4over6 tunnel\n"
       "tunnel number\n")
{
    unsigned int tunnel_num = atoi (argv[0]);
    if (tunnel_num < 0 || tunnel_num > 1500)
    {
        vty_out (vty, "tunnel num should in <0-1500>");
        return CMD_WARNING;
    }

    int ret = link_del (vty, tunnel_num);
    if (ret < 0)
    {
        vty_out (vty, "no this tunnel");
        return CMD_WARNING;
    }

    return CMD_SUCCESS;
}

int check_tunnel (struct vty *vty, struct tunnel_info *p, int flag)
{
    struct zebra_config_message p_zebra_msg;
    bzero (&p_zebra_msg, sizeof (struct zebra_config_message));
    struct in6_addr zero_6;
    bzero (&zero_6, sizeof (struct in6_addr));
    struct in_addr zero_4;
    bzero (&zero_4, sizeof (struct in_addr));

    if ((memcmp (&(p->tunnel_source), &zero_6, sizeof (struct in6_addr))) && (memcmp (&(p->tunnel_dest), &zero_6, sizeof (struct in6_addr)))
            && (memcmp (&(p->ip_prefix.prefix), &zero_4, sizeof (struct in_addr))))
    {
        if (flag == ADD_TUNNEL)
            p_zebra_msg.type = ADD_TUNNEL;
        else
            p_zebra_msg.type = DEL_TUNNEL;
        p_zebra_msg.len = sizeof (struct zebra_config_message) + sizeof (struct tunnel_info);
        p_zebra_msg.data = p;
        return zebra_connect_dpdk_send_message_two (&p_zebra_msg, p_zebra_msg.len);
    }
    else
        return 0;

}

//sangmeng mark here for 4over6 tunnel source
DEFUN (tunnel_source,
       tunnel_source_cmd,
       "tunnel source X:X::X:X",
       "configure tunnel\n"
       "configure 4over6 tunnel source address\n"
       "ipv6 address\n")
{
    struct in6_addr prefix;
    bzero (&prefix, sizeof (struct in6_addr));
    if (!strncmp (argv[0], "fe80", 4))
    {
        //vty_out(vty,"%% Malformed address %s",VTY_NEWLINE);
        return CMD_WARNING;
    }
    int ret = inet_pton (AF_INET6, argv[0], &prefix);
    if (ret < 0)
    {
        vty_out (vty, "%% Malformed address %s", VTY_NEWLINE);
        return CMD_WARNING;
    }
    int count = 0;
    struct tunnel_info *p = vty->index;	//get_point();
    struct listnode *node;
    struct interface *ifp;
    if (iflist != NULL)
    {
        for (ALL_LIST_ELEMENTS_RO (iflist, node, ifp))
        {
            struct listnode *addrnode;
            struct connected *ifc;
            struct prefix *p_if_prefix;
            for (ALL_LIST_ELEMENTS_RO (ifp->connected, addrnode, ifc))
            {
                p_if_prefix = ifc->address;
                if (p_if_prefix->family == AF_INET6)
                {
                    if (!memcmp (&(p_if_prefix->u.prefix6), &(prefix), sizeof (struct in6_addr)))
                        count++;
                }
            }					//end for
        }						//end for
    }
    else
    {
        vty_out (vty, "interface list is NULL%s", VTY_NEWLINE);
        return CMD_WARNING;
    }
    if (count == 0)
    {
        vty_out (vty, "no interface has this ipv6 address%s", VTY_NEWLINE);
        return CMD_WARNING;
    }
    struct in6_addr last;		//save last source message
    bzero (&last, sizeof (struct in6_addr));
    memcpy (&last, &p->tunnel_source, sizeof (struct in6_addr));

    memcpy (&p->tunnel_source, &prefix, sizeof (struct in6_addr));
    if (0 != check_tunnel (vty, p, ADD_TUNNEL))
    {
        memcpy (&p->tunnel_source, &last, sizeof (struct in6_addr));
        vty_out (vty, "connect server fail,tunnel_source%s", VTY_NEWLINE);
    }
    return CMD_SUCCESS;
}

DEFUN (no_tunnel_source,
       no_tunnel_source_cmd,
       "no tunnel source X:X::X:X",
       NO_STR
       "configure tunnel\n"
       "configure source address\n"
       "ipv6 address\n")
{
    struct in6_addr prefix;
    int ret = inet_pton (AF_INET6, argv[0], &prefix);
    if (ret < 0)
    {
        vty_out (vty, "%% Malformed address %s", VTY_NEWLINE);
        return CMD_WARNING;
    }
    struct tunnel_info *p = vty->index;	//get_point();
    if (!memcmp (&p->tunnel_source, &prefix, sizeof (struct in6_addr)))
    {
        if (0 == check_tunnel (vty, p, DEL_TUNNEL_SRC))
        {
            bzero (&p->tunnel_source, sizeof (struct in6_addr));
        }
        else
        {
            vty_out (vty, "connect server fail%s", VTY_NEWLINE);
        }
    }
    return CMD_SUCCESS;
}

//sangmeng mark here for add 4over6 tunnel destination
DEFUN (tunnel_destination,
       tunnel_destination_cmd,
       "tunnel destination X:X::X:X",
       "configure tunnel\n"
       "configure destination address\n"
       "ipv6 address\n")
{
    struct in6_addr prefix;
    int ret = inet_pton (AF_INET6, argv[0], &prefix);
    if (ret < 0)
    {
        vty_out (vty, "%% Malformed address %s", VTY_NEWLINE);
        return CMD_WARNING;
    }
    //check route table
    int count = 0;
    struct route_table *table;
    struct route_node *rn;
    struct rib *rib;
    table = vrf_table (AFI_IP6, SAFI_UNICAST, 0);
    if (!table)
        return CMD_SUCCESS;

    /* Show all IPv6 route. */
    for (rn = route_top (table); rn; rn = route_next (rn))
        for (rib = rn->info; rib; rib = rib->next)
        {
            //vty_show_ipv6_route (vty, rn, rib);
            struct nexthop *nexthop;
            //int len = 0;
            char buf[BUFSIZ];
            for (nexthop = rib->nexthop; nexthop; nexthop = nexthop->next)
            {
                if (nexthop == rib->nexthop)
                {
                    if (strcmp ("fe80::", inet_ntop (AF_INET6, &rn->p.u.prefix6, buf, BUFSIZ)) != 0 && strcmp ("::1", inet_ntop (AF_INET6, &rn->p.u.prefix6, buf, BUFSIZ)) != 0)
                    {
                        int i = rn->p.prefixlen / 8;
                        int j = rn->p.prefixlen % 8;
                        uint8_t k = rn->p.u.prefix6.__in6_u.__u6_addr8[i];
                        uint8_t l = prefix.__in6_u.__u6_addr8[i];
                        if (!memcmp (&(rn->p.u.prefix6), &prefix, (rn->p.prefixlen) / 8) && ((k >> j) == ((k >> j) & (l >> j))))
                        {
                            count++;
                            break;
                        }
                    }
                }
            }					//end for
        }						//end for
    if (count == 0)
    {
        vty_out (vty, "not match route table%s", VTY_NEWLINE);
        return CMD_WARNING;
    }
    //end check
    struct tunnel_info *p = vty->index;	//get_point();

    struct in6_addr last;		//save last source message
    bzero (&last, sizeof (struct in6_addr));
    memcpy (&last, &p->tunnel_dest, sizeof (struct in6_addr));

    memcpy (&p->tunnel_dest, &prefix, sizeof (struct in6_addr));
    if (0 != check_tunnel (vty, p, ADD_TUNNEL))
    {
        memcpy (&p->tunnel_dest, &last, sizeof (struct in6_addr));
        vty_out (vty, "connect server fail,tunnel_dest%s", VTY_NEWLINE);
    }
    return CMD_SUCCESS;
}

DEFUN (no_tunnel_destination, no_tunnel_destination_cmd, "no tunnel destination X:X::X:X", NO_STR "configure tunnel\n" "configure destination address\n" "ipv6 address\n")
{
    struct in6_addr prefix;
    int ret = inet_pton (AF_INET6, argv[0], &prefix);
    if (ret < 0)
    {
        vty_out (vty, "%% Malformed address %s", VTY_NEWLINE);
        return CMD_WARNING;
    }
    struct tunnel_info *p = vty->index;	//get_point();
    if (!memcmp (&p->tunnel_dest, &prefix, sizeof (struct in6_addr)))
    {
        if (0 == check_tunnel (vty, p, DEL_TUNNEL_DEST))
            bzero (&p->tunnel_dest, sizeof (struct in6_addr));
        else
            vty_out (vty, "connect server fail%s", VTY_NEWLINE);
    }
    return CMD_SUCCESS;
}

DEFUN (tunnel_ip_prefix, tunnel_ip_prefix_cmd, "ip prefix A.B.C.D/M", "configure tunnel ip subnet\n" "configure ipv4 prefix\n" "ip subnet/length\n")
{
    struct prefix_ipv4 p_ipv4;
    bzero (&p_ipv4, sizeof (struct prefix_ipv4));
    int ret = str2prefix_ipv4 (argv[0], &p_ipv4);
    if (ret < 0)
    {
        vty_out (vty, "%% Malformed address %s", VTY_NEWLINE);
        return CMD_WARNING;
    }
    struct tunnel_info *p = vty->index;	//get_point();
    struct prefix_ipv4 last;
    bzero (&last, sizeof (struct prefix_ipv4));
    memcpy (&last, &(p->ip_prefix), sizeof (struct prefix_ipv4));

    memcpy (&p->ip_prefix, &p_ipv4, sizeof (struct prefix_ipv4));
    if (0 != check_tunnel (vty, p, ADD_TUNNEL))
    {
        memcpy (&p->ip_prefix, &last, sizeof (struct prefix_ipv4));
        vty_out (vty, "connect server fail,ip_prefix%s", VTY_NEWLINE);
    }
    return CMD_SUCCESS;
}

DEFUN (no_tunnel_ip_prefix, no_tunnel_ip_prefix_cmd, "no ip prefix A.B.C.D/M", NO_STR "configure tunnel ip subnet\n" "configure ipv4 prefix\n" "ip subnet/length\n")
{
    struct prefix_ipv4 p_ipv4;
    bzero (&p_ipv4, sizeof (struct prefix_ipv4));
    int ret = str2prefix_ipv4 (argv[0], &p_ipv4);
    if (ret < 0)
    {
        vty_out (vty, "%% Malformed address %s", VTY_NEWLINE);
        return CMD_WARNING;
    }
    struct tunnel_info *p = vty->index;	//get_point();
    if (!memcmp (&(p->ip_prefix), &p_ipv4, sizeof (struct prefix_ipv4)))
    {
        if (0 == check_tunnel (vty, p, DEL_TUNNEL_IP))
            bzero (&p->ip_prefix, sizeof (struct prefix_ipv4));
        else
        {
            vty_out (vty, "connect server fail%s", VTY_NEWLINE);
        }
    }
    return CMD_SUCCESS;
}

char *myitoa (int num, char *str, int radix)
{
    /* ??? */
    char index[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    unsigned unum;				/* ???? */
    int i = 0, j, k;
    /* ??unum?? */
    if (radix == 10 && num < 0)	/* ????? */
    {
        unum = (unsigned) -num;
        str[i++] = '-';
    }
    else
        unum = (unsigned) num;	/* ???? */
    /* ?? */
    do
    {
        str[i++] = index[unum % (unsigned) radix];
        unum /= radix;
    }
    while (unum);
    str[i] = '\0';
    /* ?? */
    if (str[0] == '-')
        k = 1;					/* ????? */
    else
        k = 0;
    char temp;
    for (j = k; j <= (i - k - 1) / 2; j++)
    {
        temp = str[j];
        str[j] = str[i - 1 + k - j];
        str[i - j - 1] = temp;
    }
    return str;
}

DEFUN (show_ipv6_tunnel, show_ipv6_tunnel_cmd, "show ipv6 tunnel", SHOW_STR "ipv6 info\n" "tunnel info\n")
{
    struct tunnel_info *p = tunnel_head;
    vty_out (vty, "%-10s %-20s %-20s %-15s%s", "tunnel_num", "source", "dest", "ip_prefix", VTY_NEWLINE);
    while (p != NULL)
    {
        char buf[40] = "";
        vty_out (vty, "%-10s ", myitoa (p->tunnel_num, buf, 10));
        bzero (buf, 40);
        inet_ntop (AF_INET6, &p->tunnel_source, buf, 40);
        vty_out (vty, "%-20s ", buf);
        bzero (buf, 40);
        inet_ntop (AF_INET6, &p->tunnel_dest, buf, 40);
        vty_out (vty, "%-20s ", buf);
        bzero (buf, 40);
        inet_ntop (AF_INET, &(p->ip_prefix.prefix), buf, 40);
        vty_out (vty, "%-15s/%-d%s", buf, p->ip_prefix.prefixlen, VTY_NEWLINE);
        p = p->tunnel_next;
    }
    return CMD_SUCCESS;

}

#if 1							//sangmeng add


//sangmeng add for get mib
int connect_dpdk (struct vty *vty)
{
    int fd;
    int ret = 0;
    struct sockaddr_in socketaddress;

    fd = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd <= 0)
    {
        vty_out (vty, "socket fail%s", VTY_NEWLINE);
        return -1;
    }

    //vty_out (vty, "mib socket create success %s",  VTY_NEWLINE);

    socketaddress.sin_family = AF_INET;
    socketaddress.sin_port = htons (DPDK_SERVER_PORT);
    socketaddress.sin_addr.s_addr = inet_addr (DPDK_SERVER_ADDRESS);
    memset (&(socketaddress.sin_zero), 0, 8);
    /*start connect */
    ret = connect (fd, &socketaddress, sizeof (struct sockaddr));
    if (ret < 0)
    {
        vty_out (vty, "connect server fail%s", VTY_NEWLINE);
        close (fd);
        return -1;
    }
    return fd;
}

int ge_mib_fwd_clear (struct vty *vty, int sockfd)
{
    int ret;
    char clear_mib_msg[8];

    memset (clear_mib_msg, 0, 8);
    *(int *) &clear_mib_msg[0] = REQUEST_CLEAR_L3FWD_MIB;
    *(int *) &clear_mib_msg[4] = htonl (8);

    ret = send (sockfd, clear_mib_msg, 8, 0);
    //vty_out (vty, "%% mib send  %d byte to server %s", ret, VTY_NEWLINE);
    if (ret < 0)
    {
        vty_out (vty, "send clear mib message fail %s", VTY_NEWLINE);
        return -1;
    }

    vty_out (vty, "Mib have been reset %s", VTY_NEWLINE);
    return 0;
}

int ge_mib_kni_clear (struct vty *vty, int sockfd)
{
    int ret;
    char clear_mib_msg[8];

    memset (clear_mib_msg, 0, 8);
    *(int *) &clear_mib_msg[0] = REQUEST_CLEAR_KNI_MIB;
    *(int *) &clear_mib_msg[4] = htonl (8);

    ret = send (sockfd, clear_mib_msg, 8, 0);
    //vty_out (vty, "%% mib send  %d byte to server %s", ret, VTY_NEWLINE);
    if (ret < 0)
    {
        vty_out (vty, "send clear mib message fail%s", VTY_NEWLINE);
        return -1;
    }

    vty_out (vty, "Mib have been reset %s", VTY_NEWLINE);
    return 0;
}

int ge_mib_people_traffic_clear(struct vty *vty, int sockfd)
{
    int ret;
    char clear_mib_msg[8];

    memset (clear_mib_msg, 0, 8);
    *(int *) &clear_mib_msg[0] = REQUEST_CLEAR_SOLDIER_PEOPLR_TRAFFIC_MIB;
    *(int *) &clear_mib_msg[4] = htonl (8);

    ret = send (sockfd, clear_mib_msg, 8, 0);
    //vty_out (vty, "%% mib send  %d byte to server %s", ret, VTY_NEWLINE);
    if (ret < 0)
    {
        vty_out (vty, "send clear mib message fail%s", VTY_NEWLINE);
        return -1;
    }

    vty_out (vty, "Mib have been reset %s", VTY_NEWLINE);
    return 0;

}

int ge_mib_fwd_read (struct vty *vty, int sockfd)
{

    int ret = 0;
    int i, j, k;
    //char buf[4096];
    char buf[8192 * 2];
    char get_mib_msg[8];

    memset (get_mib_msg, 0, 8);
    *(int *) &get_mib_msg[0] = REQUEST_L3FWD_MIB;
    *(int *) &get_mib_msg[4] = htonl (8);
    ret = send (sockfd, get_mib_msg, 8, 0);
    //vty_out (vty, "%% mib send  %d byte to server %s", ret, VTY_NEWLINE);
    if (ret < 0)
    {
        vty_out (vty, "send get mib message fail%s", VTY_NEWLINE);
        return -1;
    }

    //ssize_t recv(int sockfd, void *buf, size_t len, int flags);
    memset (buf, 0, sizeof(buf));
    ret = recv (sockfd, buf, sizeof(buf), 0);

    if (ret < 0)
    {
        vty_out (vty, "recv mib from server fail%s", VTY_NEWLINE);
        return -1;
    }

    //vty_out(vty,"recv %d bytes from server success:%s", ret, VTY_NEWLINE);

    for (i = 0, j = 0, k = 0; i < ret; i += ntohl (*(int *) &buf[i + 4]))
    {
        if (*(int *) &buf[i] == RESPONSE_L3FWD_MIB)
        {

            //vty_out(vty,"type %d :%s", *(int *)&buf[i], VTY_NEWLINE);
            memcpy (&l3fwd_stats[j], (char *) &buf[i] + 8, ntohl (*(int *) &buf[i + 4]) - 8);
            j++;
            continue;
        }
        if (*(int *) &buf[i] == RESPONSE_L3FWD_MIB_VPORT)
        {

            //vty_out(vty,"type %d :%s", *(int *)&buf[i], VTY_NEWLINE);
            memcpy (&vport_stats[k], (char *) &buf[i] + 8, ntohl (*(int *) &buf[i + 4]) - 8);
            k++;
        }
        //i += ntohl(*(int *)&buf[i+4]);
    }
    /*print l3fwd mib*/
    vty_out (vty, "=*=*=*=*=*=*=*=*=*=*Statistics List=*=*=*=*=*=*=*=*=*=* %s", VTY_NEWLINE);
    for (i = 0; i < j; i++)
    {

#if 0
        vty_out (vty,
                 "\nL3FWD Statistics for port %u ------------------------------" "\nPackets rx_packets: %17" PRIu64 "\nPackets tx_packets: %17" PRIu64 "\nPackets dropped: %20" PRIu64
                 "\nPackets rx_packets_ipv4: %12" PRIu64 "\nPackets tx_packets_ipv4: %12" PRIu64 "\nPackets dropped_ipv4: %15" PRIu64 "\nPackets rx_packets_ipv6: %12" PRIu64
                 "\nPackets tx_packets_ipv6: %12" PRIu64 "\nPackets dropped_ipv6: %15" PRIu64 "\nPackets rx_packets_other: %11" PRIu64 "\nPackets tx_packets_other: %11" PRIu64
                 "\nPackets dropped_other: %14" PRIu64 "\n", l3fwd_stats[i].portid, l3fwd_stats[i].rx_packets, l3fwd_stats[i].tx_packets, l3fwd_stats[i].dropped, l3fwd_stats[i].rx_packets_ipv4,
                 l3fwd_stats[i].tx_packets_ipv4, l3fwd_stats[i].dropped_ipv4, l3fwd_stats[i].rx_packets_ipv6, l3fwd_stats[i].tx_packets_ipv6, l3fwd_stats[i].dropped_ipv6,
                 l3fwd_stats[i].rx_packets_other, l3fwd_stats[i].tx_packets_other, l3fwd_stats[i].dropped_other);
#endif

#if 1
        vty_out (vty, "Pkts Received from port%-12u:" "%8" PRIu64 "\n", l3fwd_stats[i].portid, l3fwd_stats[i].rx_packets);
        vty_out (vty, "Octets Received from port%-10u:" "%8" PRIu64 "\n", l3fwd_stats[i].portid, l3fwd_stats[i].rx_packets_octets);
        vty_out (vty, "IPV4 Pkts Received from port%-7u:" "%8" PRIu64 "\n", l3fwd_stats[i].portid, l3fwd_stats[i].rx_packets_ipv4);
        vty_out (vty, "IPV6 Pkts Received from port%-7u:" "%8" PRIu64 "\n", l3fwd_stats[i].portid, l3fwd_stats[i].rx_packets_ipv6);
        vty_out (vty, "Other Pkts Received from port%-6u:" "%8" PRIu64 "\n", l3fwd_stats[i].portid, l3fwd_stats[i].rx_packets_other);
        vty_out (vty, "ARP Pkts Received from port%-8u:" "%8" PRIu64 "\n", l3fwd_stats[i].portid, l3fwd_stats[i].rx_packets_arp);
        vty_out (vty, "NO MAC Pkts Received from port%-5u:" "%8" PRIu64 "\n", l3fwd_stats[i].portid, l3fwd_stats[i].packets_no_mac_up);
        vty_out (vty, "%s", VTY_NEWLINE);
#endif

    }

    for (i = 0; i < j; i++)
    {
        //vty_out (vty, "Pkts Dropped from port%-13u:" "%8" PRIu64 "\n", l3fwd_stats[i].portid, l3fwd_stats[i].dropped);
        vty_out (vty, "Pkts Rx Dropped from port%-10u:" "%8" PRIu64 "\n", l3fwd_stats[i].portid, l3fwd_stats[i].rx_dropped);
        vty_out (vty, "Pkts Tx Dropped from port%-10u:" "%8" PRIu64 "\n", l3fwd_stats[i].portid, l3fwd_stats[i].tx_dropped);
        vty_out (vty, "Octest Dropped from port%-11u:" "%8" PRIu64 "\n", l3fwd_stats[i].portid, l3fwd_stats[i].dropped_octets);
        vty_out (vty, "IPV4 Pkts Dropped from port%-8u:" "%8" PRIu64 "\n", l3fwd_stats[i].portid, l3fwd_stats[i].dropped_ipv4);
        vty_out (vty, "IPV6 Pkts Dropped from port%-8u:" "%8" PRIu64 "\n", l3fwd_stats[i].portid, l3fwd_stats[i].dropped_ipv6);
        vty_out (vty, "ARP Pkts Recv Dropped from port%-4u:" "%8" PRIu64 "\n", l3fwd_stats[i].portid, l3fwd_stats[i].rx_dropped_arp);
        vty_out (vty, "ARP Pkts Tran Dropped from port%-4u:" "%8" PRIu64 "\n", l3fwd_stats[i].portid, l3fwd_stats[i].tx_dropped_arp);
        vty_out (vty, "NO MAC Pkts Dropped from port%-6u:" "%8" PRIu64 "\n", l3fwd_stats[i].portid, l3fwd_stats[i].packets_no_mac_dropped);
        vty_out (vty, "NO ROUTE Pkts Dropped from port%-4u:" "%8" PRIu64 "\n", l3fwd_stats[i].portid, l3fwd_stats[i].packets_no_route_dropped);
        vty_out (vty, "Other Pkts Dropped from port%-7u:" "%8" PRIu64 "\n", l3fwd_stats[i].portid, l3fwd_stats[i].dropped_other);
        vty_out (vty, "%s", VTY_NEWLINE);
    }

#if 0
    for (i = 0; i < j; i++)
    {

        vty_out (vty, "IPV4 Pkts Dropped from port%u:" "%18" PRIu64 "\n", l3fwd_stats[i].portid, l3fwd_stats[i].dropped_ipv4);
        vty_out (vty, "IPV6 Pkts Dropped from port%u:" "%18" PRIu64 "\n", l3fwd_stats[i].portid, l3fwd_stats[i].dropped_ipv6);
        vty_out (vty, "%s", VTY_NEWLINE);
    }
#endif

    for (i = 0; i < j; i++)
    {
        vty_out (vty, "Pkts Transmitted to port%-11u:" "%8" PRIu64 "\n", l3fwd_stats[i].portid, l3fwd_stats[i].tx_packets);
        vty_out (vty, "Octest Transmitted to port%-9u:" "%8" PRIu64 "\n", l3fwd_stats[i].portid, l3fwd_stats[i].tx_packets_octets);
        vty_out (vty, "IPV4 Pkts Transmitted to port%-6u:" "%8" PRIu64 "\n", l3fwd_stats[i].portid, l3fwd_stats[i].tx_packets_ipv4);
        vty_out (vty, "IPV6 Pkts Transmitted to port%-6u:" "%8" PRIu64 "\n", l3fwd_stats[i].portid, l3fwd_stats[i].tx_packets_ipv6);
        vty_out (vty, "ARP Pkts Transmitted to port%-7u:" "%8" PRIu64 "\n", l3fwd_stats[i].portid, l3fwd_stats[i].tx_packets_arp);
        vty_out (vty, "Other Pkts Transmitted to port%-5u:" "%8" PRIu64 "\n", l3fwd_stats[i].portid, l3fwd_stats[i].tx_packets_other);
        vty_out (vty, "%s", VTY_NEWLINE);
    }
#if 0
    for (i = 0; i < k; i++)
    {
        //printf("vport_stats[%d].portid=%d\n",i,vport_stats[i].portid);
        vty_out (vty, "Pkts Forwarding to port%d_%-10u:" "%8" PRIu64 "\n", (vport_stats[i].portid)/5, (vport_stats[i].portid)%5, vport_stats[i].fw_packets);
        vty_out (vty, "Octest Forwarding to port%d_%-8u:" "%8" PRIu64 "\n", (vport_stats[i].portid)/5, (vport_stats[i].portid)%5, vport_stats[i].fw_packets_octets);
        vty_out (vty, "IPV4 Pkts Forwarding to port%d_%-5u:" "%8" PRIu64 "\n", (vport_stats[i].portid)/5, (vport_stats[i].portid)%5, vport_stats[i].fw_packets_ipv4);
        vty_out (vty, "IPV6 Pkts Forwarding to port%d_%-5u:" "%8" PRIu64 "\n", (vport_stats[i].portid)/5, (vport_stats[i].portid)%5, vport_stats[i].fw_packets_ipv6);
        vty_out (vty, "%s", VTY_NEWLINE);
    }
#endif
#if 1
    for (i = 0; i < k; i++)
    {


#if 1
        vty_out (vty, "Pkts Received from port%d_%-10u:" "%8" PRIu64 "\n", (vport_stats[i].portid)/5, (vport_stats[i].portid)%5, vport_stats[i].rx_packets);
        vty_out (vty, "Octets Received from port%d_%-8u:" "%8" PRIu64 "\n", (vport_stats[i].portid)/5, (vport_stats[i].portid)%5, vport_stats[i].rx_packets_octets);
        vty_out (vty, "IPV4 Pkts Received from port%d_%-5u:" "%8" PRIu64 "\n", (vport_stats[i].portid)/5, (vport_stats[i].portid)%5, vport_stats[i].rx_packets_ipv4);
        vty_out (vty, "IPV6 Pkts Received from port%d_%-5u:" "%8" PRIu64 "\n", (vport_stats[i].portid)/5, (vport_stats[i].portid)%5, vport_stats[i].rx_packets_ipv6);
        vty_out (vty, "Other Pkts Received from port%d_%-4u:" "%8" PRIu64 "\n", (vport_stats[i].portid)/5, (vport_stats[i].portid)%5, vport_stats[i].rx_packets_other);
        vty_out (vty, "ARP Pkts Received from port%d_%-6u:" "%8" PRIu64 "\n", (vport_stats[i].portid)/5, (vport_stats[i].portid)%5, vport_stats[i].rx_packets_arp);
        vty_out (vty, "NO MAC Pkts Received from port%d_%-3u:" "%8" PRIu64 "\n", (vport_stats[i].portid)/5, (vport_stats[i].portid)%5, vport_stats[i].packets_no_mac_up);
        vty_out (vty, "%s", VTY_NEWLINE);
#endif

    }

    for (i = 0; i < k; i++)
    {
        //vty_out (vty, "Pkts Dropped from port%d_%-11u:" "%8" PRIu64 "\n", (vport_stats[i].portid)/5, (vport_stats[i].portid)%5, vport_stats[i].dropped);
        vty_out (vty, "Pkts Rx Dropped from port%d_%-8u:" "%8" PRIu64 "\n", (vport_stats[i].portid)/5, (vport_stats[i].portid)%5, vport_stats[i].rx_dropped);
        vty_out (vty, "Pkts Tx Dropped from port%d_%-8u:" "%8" PRIu64 "\n", (vport_stats[i].portid)/5, (vport_stats[i].portid)%5, vport_stats[i].tx_dropped);
        vty_out (vty, "Octest Dropped from port%d_%-9u:" "%8" PRIu64 "\n", (vport_stats[i].portid)/5, (vport_stats[i].portid)%5, vport_stats[i].dropped_octets);
        vty_out (vty, "IPV4 Pkts Dropped from port%d_%-6u:" "%8" PRIu64 "\n", (vport_stats[i].portid)/5, (vport_stats[i].portid)%5, vport_stats[i].dropped_ipv4);
        vty_out (vty, "IPV6 Pkts Dropped from port%d_%-6u:" "%8" PRIu64 "\n", (vport_stats[i].portid)/5, (vport_stats[i].portid)%5, vport_stats[i].dropped_ipv6);
        vty_out (vty, "ARP Pkts Recv Dropped from port%d_%-2u:" "%8" PRIu64 "\n", (vport_stats[i].portid)/5, (vport_stats[i].portid)%5, vport_stats[i].rx_dropped_arp);
        vty_out (vty, "ARP Pkts Tran Dropped from port%d_%-2u:" "%8" PRIu64 "\n", (vport_stats[i].portid)/5, (vport_stats[i].portid)%5, vport_stats[i].tx_dropped_arp);
        vty_out (vty, "NO MAC Pkts Dropped from port%d_%-4u:" "%8" PRIu64 "\n", (vport_stats[i].portid)/5, (vport_stats[i].portid)%5, vport_stats[i].packets_no_mac_dropped);
        vty_out (vty, "NO ROUTE Pkts Dropped from port%d_%-2u:" "%8" PRIu64 "\n", (vport_stats[i].portid)/5, (vport_stats[i].portid)%5, vport_stats[i].packets_no_route_dropped);
        vty_out (vty, "Other Pkts Dropped from port%d_%-5u:" "%8" PRIu64 "\n", (vport_stats[i].portid)/5, (vport_stats[i].portid)%5, vport_stats[i].dropped_other);
        vty_out (vty, "%s", VTY_NEWLINE);
    }


    for (i = 0; i < k; i++)
    {
        vty_out (vty, "Pkts Transmitted to port%d_%-9u:" "%8" PRIu64 "\n", (vport_stats[i].portid)/5, (vport_stats[i].portid)%5, vport_stats[i].tx_packets);
        vty_out (vty, "Octest Transmitted to port%d_%-7u:" "%8" PRIu64 "\n", (vport_stats[i].portid)/5, (vport_stats[i].portid)%5, vport_stats[i].tx_packets_octets);
        vty_out (vty, "IPV4 Pkts Transmitted to port%d_%-4u:" "%8" PRIu64 "\n", (vport_stats[i].portid)/5, (vport_stats[i].portid)%5, vport_stats[i].tx_packets_ipv4);
        vty_out (vty, "IPV6 Pkts Transmitted to port%d_%-4u:" "%8" PRIu64 "\n", (vport_stats[i].portid)/5, (vport_stats[i].portid)%5, vport_stats[i].tx_packets_ipv6);
        vty_out (vty, "ARP Pkts Transmitted to port%d_%-5u:" "%8" PRIu64 "\n", (vport_stats[i].portid)/5, (vport_stats[i].portid)%5, vport_stats[i].tx_packets_arp);
        vty_out (vty, "Other Pkts Transmitted to port%d_%-3u:" "%8" PRIu64 "\n", (vport_stats[i].portid)/5, (vport_stats[i].portid)%5, vport_stats[i].tx_packets_other);
        vty_out (vty, "%s", VTY_NEWLINE);
    }
#endif
    vty_out (vty, "=*=*=*=*=*=*=*=*=*=*=*=*=*THE END=*=*=*=*=*=*=*=*=*=*=*=*=*");
    return 0;

}

int ge_mib_kni_read (struct vty *vty, int sockfd)
{

    int ret = 0;
    int i, j;
    //char buf[4096];
    char buf[8192];
    char get_mib_msg[8];

    memset (get_mib_msg, 0, 8);
    *(int *) &get_mib_msg[0] = REQUEST_KNI_MIB;
    *(int *) &get_mib_msg[4] = htonl (8);
    ret = send (sockfd, get_mib_msg, 8, 0);
    //vty_out (vty, "%% mib send  %d byte to server %s", ret, VTY_NEWLINE);
    if (ret < 0)
    {
        return -1;
    }

    //ssize_t recv(int sockfd, void *buf, size_t len, int flags);
    memset (buf, 0, sizeof(buf));
    ret = recv (sockfd, buf, sizeof(buf), 0);

    if (ret < 0)
    {
        vty_out (vty, "recv mib from server fail%s", VTY_NEWLINE);
        return -1;
    }

    //vty_out(vty,"recv %d bytes from server success:%s", ret, VTY_NEWLINE);

    for (i = 0, j = 0; i < ret; i += ntohl (*(int *) &buf[i + 4]))
    {
        if (*(int *) &buf[i] == RESPONSE_KNI_MIB)
        {
            memcpy (&kni_stats[j], (char *) &buf[i] + 8, ntohl (*(int *) &buf[i + 4]) - 8);
            j++;
        }

        //i += ntohl(*(int *)&buf[i+4]);
    }

    vty_out (vty, "=*=*=*=*=*=*=*=*=*=*KNI Statistics List=*=*=*=*=*=*=*=*=*=* %s", VTY_NEWLINE);
    for (i = 0; i < j; i++)
    {
#if 0
        vty_out (vty,
                 "\nKNI Statistics for port %u ------------------------------" "\nPackets rx_packets: %17" PRIu64 "\nPackets rx_dropped: %17" PRIu64 "\nPackets tx_packets: %17" PRIu64
                 "\nPackets tx_dropped: %17" PRIu64 "\nPackets rx_packets_ipv4: %12" PRIu64 "\nPackets rx_dropped_ipv4: %12" PRIu64 "\nPackets tx_packets_ipv4: %12" PRIu64
                 "\nPackets tx_dropped_ipv4: %12" PRIu64 "\nPackets rx_packets_ipv6: %12" PRIu64 "\nPackets rx_dropped_ipv6: %12" PRIu64 "\nPackets tx_packets_ipv6: %12" PRIu64
                 "\nPackets tx_dropped_ipv6: %12" PRIu64 "\nPackets rx_packets_arp: %13" PRIu64 "\nPackets rx_dropped_arp: %13" PRIu64 "\nPackets tx_packets_arp: %13" PRIu64
                 "\nPackets tx_dropped_arp: %13" PRIu64 "\nPackets rx_packets_other: %11" PRIu64 "\nPackets rx_dropped_other: %11" PRIu64 "\nPackets tx_packets_other: %11" PRIu64
                 "\nPackets tx_dropped_other: %11" PRIu64 "\n", kni_stats[i].portid, kni_stats[i].rx_packets, kni_stats[i].rx_dropped, kni_stats[i].tx_packets, kni_stats[i].tx_dropped,
                 kni_stats[i].rx_packets_ipv4, kni_stats[i].rx_dropped_ipv4, kni_stats[i].tx_packets_ipv4, kni_stats[i].tx_dropped_ipv4, kni_stats[i].rx_packets_ipv6, kni_stats[i].rx_dropped_ipv6,
                 kni_stats[i].tx_packets_ipv6, kni_stats[i].tx_dropped_ipv6, kni_stats[i].rx_packets_arp, kni_stats[i].rx_dropped_arp, kni_stats[i].tx_packets_arp, kni_stats[i].tx_dropped_arp,
                 kni_stats[i].rx_packets_other, kni_stats[i].rx_dropped_other, kni_stats[i].tx_packets_other, kni_stats[i].tx_dropped_other);
#endif

        vty_out (vty, "Pkts Received from port%d_%-12u:" "%8" PRIu64 "\n", (kni_stats[i].portid)/5,(kni_stats[i].portid)%5, kni_stats[i].rx_packets);
        vty_out (vty, "Octets Received from port%d_%-10u:" "%8" PRIu64 "\n", (kni_stats[i].portid)/5,(kni_stats[i].portid)%5, kni_stats[i].rx_packets_octets);
        vty_out (vty, "IPV4 Pkts Received from port%d_%-7u:" "%8" PRIu64 "\n", (kni_stats[i].portid)/5,(kni_stats[i].portid)%5, kni_stats[i].rx_packets_ipv4);
        vty_out (vty, "IPV6 Pkts Received from port%d_%-7u:" "%8" PRIu64 "\n", (kni_stats[i].portid)/5,(kni_stats[i].portid)%5, kni_stats[i].rx_packets_ipv6);
        vty_out (vty, "%s", VTY_NEWLINE);

    }
    for (i = 0; i < j; i++)
    {
        vty_out (vty, "Pkts Dropped from port%d_%-13u:" "%8" PRIu64 "\n", (kni_stats[i].portid)/5,(kni_stats[i].portid)%5, kni_stats[i].rx_dropped + kni_stats[i].tx_dropped);
        vty_out (vty, "Octest Dropped from port%d_%-11u:" "%8" PRIu64 "\n", (kni_stats[i].portid)/5,(kni_stats[i].portid)%5, kni_stats[i].dropped_octets);
        vty_out (vty, "IPV4 Pkts Dropped from port%d_%-8u:" "%8" PRIu64 "\n", (kni_stats[i].portid)/5,(kni_stats[i].portid)%5, kni_stats[i].rx_dropped_ipv4 + kni_stats[i].tx_dropped_ipv4);
        //vty_out(vty, "ARP Pkts Received Dropped from port%u:" "%10" PRIu64 "\n", kni_stats[i].portid, kni_stats[i].rx_dropped_arp);
        vty_out (vty, "IPV6 Pkts Dropped from port%d_%-8u:" "%8" PRIu64 "\n", (kni_stats[i].portid)/5,(kni_stats[i].portid)%5, kni_stats[i].rx_dropped_ipv6 + kni_stats[i].tx_dropped_ipv6);
        vty_out (vty, "%s", VTY_NEWLINE);
    }

    for (i = 0; i < j; i++)
    {
        vty_out (vty, "Pkts Transmitted to port%d_%-11u:" "%8" PRIu64 "\n", (kni_stats[i].portid)/5,(kni_stats[i].portid)%5, kni_stats[i].tx_packets);
        vty_out (vty, "Octest Transmitted to port%d_%-9u:" "%8" PRIu64 "\n", (kni_stats[i].portid)/5,(kni_stats[i].portid)%5, kni_stats[i].tx_packets_octets);
        vty_out (vty, "IPV4 Pkts Transmitted to port%d_%-6u:" "%8" PRIu64 "\n", (kni_stats[i].portid)/5,(kni_stats[i].portid)%5, kni_stats[i].tx_packets_ipv4);
        vty_out (vty, "IPV6 Pkts Transmitted to port%d_%-6u:" "%8" PRIu64 "\n", (kni_stats[i].portid)/5,(kni_stats[i].portid)%5, kni_stats[i].tx_packets_ipv6);
        vty_out (vty, "%s", VTY_NEWLINE);
    }
    vty_out (vty, "=*=*=*=*=*=*=*=*=*=*=*=*=*=*THE END=*=*=*=*=*=*=*=*=*=*=*=*=*=*");

    return 0;

}

int ge_mib_people_traffic_read (struct vty *vty, int sockfd)
{

    int ret = 0;
    int i, j;
    //char buf[4096];
    char buf[8192 * 2];
    char get_mib_msg[8];

    memset (get_mib_msg, 0, 8);
    *(int *) &get_mib_msg[0] = REQUSET_SOLDIER_PEOPLR_TRAFFIC_MIB;
    *(int *) &get_mib_msg[4] = htonl (8);
    ret = send (sockfd, get_mib_msg, 8, 0);
    //vty_out (vty, "%% mib send  %d byte to server %s", ret, VTY_NEWLINE);
    if (ret < 0)
    {
        return -1;
    }

    //ssize_t recv(int sockfd, void *buf, size_t len, int flags);
    memset (buf, 0, sizeof(buf));
    ret = recv (sockfd, buf, sizeof(buf), 0);

    if (ret < 0)
    {
        vty_out (vty, "recv mib from server fail%s", VTY_NEWLINE);
        return -1;
    }
    printf("ret:%d\n",ret);
    //vty_out(vty,"recv %d bytes from server success:%s", ret, VTY_NEWLINE);

    for (i = 0, j = 0; i < ret; i += ntohl (*(int *) &buf[i + 4]))
    {
        printf("type:%02x",*(int *) &buf[i]);
        if (*(int *) &buf[i] == RESPONSE_SOLDIER_PEOPLR_TRAFFIC_MIB)
        {
            memcpy (&people_traffic_statistics[j], (char *) &buf[i] + 8, ntohl (*(int *) &buf[i + 4]) - 8);
            j++;
        }

        //i += ntohl(*(int *)&buf[i+4]);
    }
    printf("j:%d\n",j);

    vty_out (vty, "=*=*=*=*=*=*=*=*=*=*PEOPLE Tarffic Statistics List=*=*=*=*=*=*=*=*=*=* %s", VTY_NEWLINE);
    for (i = 0; i < j; i++)
    {
        vty_out (vty, "Pkts Received from port%d_%-12u:" "%8" PRIu64 "\n", (people_traffic_statistics[i].portid)/5,(people_traffic_statistics[i].portid)%5, people_traffic_statistics[i].rx_packets);
        vty_out (vty, "Octets Received from port%d_%-10u:" "%8" PRIu64 "\n", (people_traffic_statistics[i].portid)/5,(people_traffic_statistics[i].portid)%5, people_traffic_statistics[i].rx_packets_octets);
        vty_out (vty, "Pkts tag Received from port%d_%-8u:" "%8" PRIu64 "\n", (people_traffic_statistics[i].portid)/5,(people_traffic_statistics[i].portid)%5, people_traffic_statistics[i].rx_packets_tag);
        vty_out (vty, "Pkts Dropped from port%d_%-13u:" "%8" PRIu64 "\n", (people_traffic_statistics[i].portid)/5,(people_traffic_statistics[i].portid)%5, people_traffic_statistics[i].rx_packets_drop);
        vty_out (vty, "Pkts Transmitted to port%d_%-11u:" "%8" PRIu64 "\n", (people_traffic_statistics[i].portid)/5,(people_traffic_statistics[i].portid)%5, people_traffic_statistics[i].tx_packets);
        vty_out (vty, "Octest Transmitted to port%d_%-9u:" "%8" PRIu64 "\n", (people_traffic_statistics[i].portid)/5,(people_traffic_statistics[i].portid)%5, people_traffic_statistics[i].tx_packets_octets);
        vty_out (vty, "Pkts tag Transmitted to port%d_%-7u:" "%8" PRIu64 "\n", (people_traffic_statistics[i].portid)/5,(people_traffic_statistics[i].portid)%5, people_traffic_statistics[i].tx_packets_tag);
        vty_out (vty, "Pkts Transmitted drop%d_%-14u:" "%8" PRIu64 "\n", (people_traffic_statistics[i].portid)/5,(people_traffic_statistics[i].portid)%5, people_traffic_statistics[i].tx_packets_drop);
        vty_out (vty, "%s", VTY_NEWLINE);

    }
    vty_out (vty, "=*=*=*=*=*=*=*=*=*=*=*=*=*=*THE END=*=*=*=*=*=*=*=*=*=*=*=*=*=*");

    return 0;

}
int v4_route_read (struct vty *vty, int sockfd)
{

    int i;
    int ret = 0;
    char buf[4096];
    char get_route_msg[8];
    char tmp[192];
    struct route_info rtInfo;

    memset (get_route_msg, 0, 8);
    *(int *) &get_route_msg[0] = REQUEST_V4_ROUTE_TABLE;
    *(int *) &get_route_msg[4] = htonl (8);
    ret = send (sockfd, get_route_msg, 8, 0);
    //vty_out (vty, "%% mib send  %d byte to server %s", ret, VTY_NEWLINE);
    if (ret < 0)
    {
        vty_out (vty, "send get ipv4 route table fail%s", VTY_NEWLINE);
        return -1;
    }

    //ssize_t recv(int sockfd, void *buf, size_t len, int flags);
    ret = recv (sockfd, buf, sizeof(buf), 0);

    if (ret < 0)
    {
        vty_out (vty, "recv ipv4 route table from server fail%s", VTY_NEWLINE);
        return -1;
    }

    //vty_out(vty,"recv %d bytes from server success:%s", ret, VTY_NEWLINE);

#if 1

    vty_out (vty, "IPV4 ROUTE TABLE %s", VTY_NEWLINE);
    vty_out (vty, "Destination     Gateway         Netmask Forward If %s", VTY_NEWLINE);
    for (i = 0; i < ret; i += ntohl (*(int *) &buf[i + 4]))
    {
        if (*(int *) &buf[i] == RESPONSE_V4_ROUTE_TABLE)
        {
            memset (&rtInfo, 0, sizeof (struct route_info));
            memcpy (&rtInfo, (char *) &buf[i] + 8, ntohl (*(int *) &buf[i + 4]) - 8);

            memset (tmp, 0, sizeof (tmp));
            inet_ntop (rtInfo.af, (char *) &rtInfo.ipv4_route_dstaddr, tmp, sizeof (tmp));
            vty_out (vty, "%-16s", tmp);
            memset (tmp, 0, sizeof (tmp));
            inet_ntop (rtInfo.af, (char *) &rtInfo.ipv4_route_gateway, tmp, sizeof (tmp));
            vty_out (vty, "%-16s", tmp);

            vty_out (vty, "%-7d %-7u %-3s %s", rtInfo.dstLen, rtInfo.forward, rtInfo.ifName, VTY_NEWLINE);
        }
        //i += ntohl(*(int *)&buf[i+4]);
    }

#endif
    return 0;

}

void private_read_route_info_from_buf(struct vty *vty, int len, char *buf, int type)
{

    char tmp[64];
    char tmp_2[256];
    int i;
    struct route_info rtInfo;
    int tmp_len;
    int flag;
#if 0
    char *tmp_pointer = NULL;
    char *tmp_pointer1 = NULL;
    char table_name[32];
#endif
    if (type == AF_INET)
    {
        vty_out (vty, "IPV4 CUSTOMIZE ROUTE TABLE %s", VTY_NEWLINE);
        vty_out (vty, "Destination     Gateway         Netmask Forward If %s", VTY_NEWLINE);
    }
    else if (type == AF_INET6)
    {
        vty_out (vty, "IPV6 ROUTE TABLE %s", VTY_NEWLINE);
        vty_out (vty, "Destination                    Next Hop                   Forward If \t Flag%s", VTY_NEWLINE);
    }
#if 0
    for (i = 0; i < len; i += ntohl (*(int *) &buf[i + 4]))
    {
        if (*(int *) &buf[i] == RESPONSE_V4_ROUTE_TABLE)
        {
            memset (&rtInfo, 0, sizeof (struct route_info));
            memcpy (&rtInfo, (char *) &buf[i] + 8, ntohl (*(int *) &buf[i + 4]) - 8);

            memset (tmp, 0, sizeof (tmp));
            inet_ntop (rtInfo.af, (char *) &rtInfo.ipv4_route_dstaddr, tmp, sizeof (tmp));
            vty_out (vty, "%-16s", tmp);
            memset (tmp, 0, sizeof (tmp));
            inet_ntop (rtInfo.af, (char *) &rtInfo.ipv4_route_gateway, tmp, sizeof (tmp));
            vty_out (vty, "%-16s", tmp);

            vty_out (vty, "%-7d %-7u %-3s %s", rtInfo.dstLen, rtInfo.forward, rtInfo.ifName, VTY_NEWLINE);
        }
        else if (*(int *) &buf[i] == RESPONSE_V6_ROUTE_TABLE)
        {
            memset (&rtInfo, 0, sizeof (struct route_info));
            memcpy (&rtInfo, (char *) &buf[i] + 8, ntohl (*(int *) &buf[i + 4]) - 8);

            memset (tmp, 0, sizeof (tmp));
            inet_ntop (rtInfo.af, rtInfo.ipv6_route_dstaddr, tmp, sizeof (tmp));
            memset (tmp_2, 0, sizeof (tmp_2));
            sprintf (tmp_2, "%s/%d", tmp, rtInfo.dstLen);
            vty_out (vty, "%-31s", tmp_2);
            memset (tmp, 0, sizeof (tmp));
            inet_ntop (rtInfo.af, rtInfo.ipv6_route_gateway, tmp, sizeof (tmp));
            vty_out (vty, "%-27s", tmp);

            vty_out (vty, "%-7u %-2s %s", rtInfo.forward, rtInfo.ifName, VTY_NEWLINE);
        }

    }
#endif
#if 1
    i = 0;
    tmp_len = 0;
    flag = 1;
    int total=0,valid=0,invalid=0;
    while(flag)
    {
        vty_out(vty,"table name:%s\n",((struct route_table_info *)(buf+tmp_len))->table_name);
        i = tmp_len + sizeof(struct route_table_info);
        tmp_len = ((struct route_table_info *)(buf+tmp_len))->table_len;
        if(tmp_len == len)
            flag = 0;

        total=0;
        valid=0;
        invalid=0;

        for (i; i < tmp_len; i += ntohl (*(int *) &buf[i + 4]))
        {

            memset (&rtInfo, 0, sizeof (struct route_info));
            memcpy (&rtInfo, (char *) &buf[i] + 8, ntohl (*(int *) &buf[i + 4]) - 8);

            memset (tmp, 0, sizeof (tmp));



            //if (*(int *) &buf[i] == RESPONSE_V4_ROUTE_TABLE)
            if (rtInfo.af== AF_INET)
            {
                //memset (&rtInfo, 0, sizeof (struct route_info));
                //memcpy (&rtInfo, (char *) &buf[i] + 8, ntohl (*(int *) &buf[i + 4]) - 8);

                //memset (tmp, 0, sizeof (tmp));
                inet_ntop (rtInfo.af, (char *) &rtInfo.ipv4_route_dstaddr, tmp, sizeof (tmp));
                vty_out (vty, "%-16s", tmp);
                memset (tmp, 0, sizeof (tmp));
                inet_ntop (rtInfo.af, (char *) &rtInfo.ipv4_route_gateway, tmp, sizeof (tmp));
                vty_out (vty, "%-16s", tmp);

                vty_out (vty, "%-7d %-7u %-3s %s", rtInfo.dstLen, rtInfo.forward, rtInfo.ifName, VTY_NEWLINE);
            }
            //else if (*(int *) &buf[i] == RESPONSE_V6_ROUTE_TABLE)
            else
            {
                //memset (&rtInfo, 0, sizeof (struct route_info));
                //memcpy (&rtInfo, (char *) &buf[i] + 8, ntohl (*(int *) &buf[i + 4]) - 8);

                //memset (tmp, 0, sizeof (tmp));
                inet_ntop (rtInfo.af, rtInfo.ipv6_route_dstaddr, tmp, sizeof (tmp));
                memset (tmp_2, 0, sizeof (tmp_2));
                sprintf (tmp_2, "%s/%d", tmp, rtInfo.dstLen);
                vty_out (vty, "%-31s", tmp_2);
                memset (tmp, 0, sizeof (tmp));
                inet_ntop (rtInfo.af, rtInfo.ipv6_route_gateway, tmp, sizeof (tmp));
                vty_out (vty, "%-27s", tmp);

                if(rtInfo.forward == 0)
                {

                    vty_out (vty, "%-7u %-2s \t %d%s", rtInfo.forward, "--",*(int *) &buf[i], VTY_NEWLINE);
                }
                else
                {

                    vty_out (vty, "%-7u %-2s \t %d%s", rtInfo.forward, rtInfo.ifName,*(int *) &buf[i], VTY_NEWLINE);
                }
                total++;
                if(*(int *) &buf[i] == 0)
                    valid++;
                else
                    invalid++;
            }

        }
        vty_out (vty, " total:%d\t valid:%d \t invalid:%d %s",total,valid,invalid, VTY_NEWLINE);
    }
#endif
    return;
}

void read_route_info_from_buf(struct vty *vty, int len, char *buf, int type)
{

    char tmp[64];
    char tmp_2[256];
    int i;
    struct route_info rtInfo;
    int tmp_len;
    int flag;
#if 0
    char *tmp_pointer = NULL;
    char *tmp_pointer1 = NULL;
    char table_name[32];
#endif
    if (type == AF_INET)
    {
        vty_out (vty, "IPV4 CUSTOMIZE ROUTE TABLE %s", VTY_NEWLINE);
        vty_out (vty, "Destination     Gateway         Netmask Forward If %s", VTY_NEWLINE);
    }
    else if (type == AF_INET6)
    {
        vty_out (vty, "IPV6 ROUTE TABLE %s", VTY_NEWLINE);
        vty_out (vty, "Destination                    Next Hop                   Forward If \t Flag%s", VTY_NEWLINE);
    }
#if 0
    for (i = 0; i < len; i += ntohl (*(int *) &buf[i + 4]))
    {
        if (*(int *) &buf[i] == RESPONSE_V4_ROUTE_TABLE)
        {
            memset (&rtInfo, 0, sizeof (struct route_info));
            memcpy (&rtInfo, (char *) &buf[i] + 8, ntohl (*(int *) &buf[i + 4]) - 8);

            memset (tmp, 0, sizeof (tmp));
            inet_ntop (rtInfo.af, (char *) &rtInfo.ipv4_route_dstaddr, tmp, sizeof (tmp));
            vty_out (vty, "%-16s", tmp);
            memset (tmp, 0, sizeof (tmp));
            inet_ntop (rtInfo.af, (char *) &rtInfo.ipv4_route_gateway, tmp, sizeof (tmp));
            vty_out (vty, "%-16s", tmp);

            vty_out (vty, "%-7d %-7u %-3s %s", rtInfo.dstLen, rtInfo.forward, rtInfo.ifName, VTY_NEWLINE);
        }
        else if (*(int *) &buf[i] == RESPONSE_V6_ROUTE_TABLE)
        {
            memset (&rtInfo, 0, sizeof (struct route_info));
            memcpy (&rtInfo, (char *) &buf[i] + 8, ntohl (*(int *) &buf[i + 4]) - 8);

            memset (tmp, 0, sizeof (tmp));
            inet_ntop (rtInfo.af, rtInfo.ipv6_route_dstaddr, tmp, sizeof (tmp));
            memset (tmp_2, 0, sizeof (tmp_2));
            sprintf (tmp_2, "%s/%d", tmp, rtInfo.dstLen);
            vty_out (vty, "%-31s", tmp_2);
            memset (tmp, 0, sizeof (tmp));
            inet_ntop (rtInfo.af, rtInfo.ipv6_route_gateway, tmp, sizeof (tmp));
            vty_out (vty, "%-27s", tmp);

            vty_out (vty, "%-7u %-2s %s", rtInfo.forward, rtInfo.ifName, VTY_NEWLINE);
        }

    }
#endif
#if 1
    i = 0;
    tmp_len = 0;
    flag = 1;
    int total=0,valid=0,invalid=0;
    while(flag)
    {
        vty_out(vty,"table name:%s\n",((struct route_table_info *)(buf+tmp_len))->table_name);
        i = tmp_len + sizeof(struct route_table_info);
        tmp_len = ((struct route_table_info *)(buf+tmp_len))->table_len;
        if(tmp_len == len)
            flag = 0;

        total=0;
        valid=0;
        invalid=0;

        for (i; i < tmp_len; i += ntohl (*(int *) &buf[i + 4]))
        {

            memset (&rtInfo, 0, sizeof (struct route_info));
            memcpy (&rtInfo, (char *) &buf[i] + 8, ntohl (*(int *) &buf[i + 4]) - 8);

            memset (tmp, 0, sizeof (tmp));



            //if (*(int *) &buf[i] == RESPONSE_V4_ROUTE_TABLE)
            if (rtInfo.af== AF_INET)
            {
                //memset (&rtInfo, 0, sizeof (struct route_info));
                //memcpy (&rtInfo, (char *) &buf[i] + 8, ntohl (*(int *) &buf[i + 4]) - 8);

                //memset (tmp, 0, sizeof (tmp));
                inet_ntop (rtInfo.af, (char *) &rtInfo.ipv4_route_dstaddr, tmp, sizeof (tmp));
                vty_out (vty, "%-16s", tmp);
                memset (tmp, 0, sizeof (tmp));
                inet_ntop (rtInfo.af, (char *) &rtInfo.ipv4_route_gateway, tmp, sizeof (tmp));
                vty_out (vty, "%-16s", tmp);

                vty_out (vty, "%-7d %-7u %-3s %s", rtInfo.dstLen, rtInfo.forward, rtInfo.ifName, VTY_NEWLINE);
            }
            //else if (*(int *) &buf[i] == RESPONSE_V6_ROUTE_TABLE)
            else
            {
                //memset (&rtInfo, 0, sizeof (struct route_info));
                //memcpy (&rtInfo, (char *) &buf[i] + 8, ntohl (*(int *) &buf[i + 4]) - 8);

                //memset (tmp, 0, sizeof (tmp));

                if(*(int *) &buf[i] == 0)
                {
                    inet_ntop (rtInfo.af, rtInfo.ipv6_route_dstaddr, tmp, sizeof (tmp));
                    memset (tmp_2, 0, sizeof (tmp_2));
                    sprintf (tmp_2, "%s/%d", tmp, rtInfo.dstLen);
                    vty_out (vty, "%-31s", tmp_2);
                    memset (tmp, 0, sizeof (tmp));
                    inet_ntop (rtInfo.af, rtInfo.ipv6_route_gateway, tmp, sizeof (tmp));
                    vty_out (vty, "%-27s", tmp);
                    if(rtInfo.forward == 0)
                    {
                        vty_out (vty, "%-7u %-2s \t %d%s", rtInfo.forward, "--",*(int *) &buf[i], VTY_NEWLINE);

                    }
                    else
                    {
                        vty_out (vty, "%-7u %-2s \t %d%s", rtInfo.forward, rtInfo.ifName,*(int *) &buf[i], VTY_NEWLINE);
                    }
                }
                total++;
                if(*(int *) &buf[i] == 0)
                    valid++;
                else
                    invalid++;
            }

        }
        //    vty_out (vty, " total:%d\t valid:%d \t invalid:%d %s",total,valid,invalid, VTY_NEWLINE);
    }
#endif
    return;
}

int customize_route_read (struct vty *vty, int sockfd, int type)
{
    int ret = 0;
    char buf[4096];
    char get_route_msg[9];

    memset (get_route_msg, 0, 9);
    *(int *) &get_route_msg[0] = REQUEST_CUSTOMIZE_ROUTE;
    *(int *) &get_route_msg[4] = htonl (9);
    printf("type:%d.\n", type);
    if (type == AF_INET)
        *(char *)&get_route_msg[8] = 1;
    else if (type == AF_INET6)
        *(char *)&get_route_msg[8] = 2;
    ret = send (sockfd, get_route_msg, 9, 0);
    //vty_out (vty, "%% mib send  %d byte to server %s", ret, VTY_NEWLINE);
    if (ret < 0)
    {
        vty_out (vty, "send get ipv4 customize route table fail%s", VTY_NEWLINE);
        return -1;
    }
    ret = recv (sockfd, buf, sizeof(buf), 0);

    if (ret < 0)
    {
        vty_out (vty, "recv ipv4 route table from server fail%s", VTY_NEWLINE);
        return -1;
    }
    //vty_out(vty,"recv %d bytes from server success:%s", ret, VTY_NEWLINE);
    read_route_info_from_buf(vty, ret, buf, type);
    return 0;

}


int private_customize_route_read (struct vty *vty, int sockfd, int type)
{
    int ret = 0;
    char buf[4096];
    char get_route_msg[9];

    memset (get_route_msg, 0, 9);
    *(int *) &get_route_msg[0] = REQUEST_CUSTOMIZE_ROUTE;
    *(int *) &get_route_msg[4] = htonl (9);
    printf("type:%d.\n", type);
    if (type == AF_INET)
        *(char *)&get_route_msg[8] = 1;
    else if (type == AF_INET6)
        *(char *)&get_route_msg[8] = 2;
    ret = send (sockfd, get_route_msg, 9, 0);
    //vty_out (vty, "%% mib send  %d byte to server %s", ret, VTY_NEWLINE);
    if (ret < 0)
    {
        vty_out (vty, "send get ipv4 customize route table fail%s", VTY_NEWLINE);
        return -1;
    }
    ret = recv (sockfd, buf, sizeof(buf), 0);

    if (ret < 0)
    {
        vty_out (vty, "recv ipv4 route table from server fail%s", VTY_NEWLINE);
        return -1;
    }
    //vty_out(vty,"recv %d bytes from server success:%s", ret, VTY_NEWLINE);
    private_read_route_info_from_buf(vty, ret, buf, type);
    return 0;

}

int v6_interface_status_read (struct vty *vty, int sockfd,int flag)
{

    int i;
    int ret = 0;
    char buf[4096*10];
    char get_route_msg[8];
    char tmp[192];
    char tmp_2[256];
    struct route_info rtInfo;
    int total = 0;
#if 1
    int interface_array[4][5] = {0};
    char name[20];
    int k,j;
#endif

    memset (get_route_msg, 0, 8);
    *(int *) &get_route_msg[0] = RESPONSE_INTERFACE_STATUS;
    *(int *) &get_route_msg[4] = htonl (8);
    ret = send (sockfd, get_route_msg, 8, 0);
    //vty_out (vty, "%% mib send  %d byte to server %s", ret, VTY_NEWLINE);
    if (ret < 0)
    {
        vty_out (vty, "send get ipv6 route table fail%s", VTY_NEWLINE);
        return -1;
    }

    //ssize_t recv(int sockfd, void *buf, size_t len, int flags);
    memset(buf,0,4096*10);
    ret = recv (sockfd, buf, sizeof(buf), 0);

    if (ret < 0)
    {
        vty_out (vty, "recv ipv4 route table from server fail%s", VTY_NEWLINE);
        return -1;
    }

    vty_out(vty,"recv %d bytes from server success:%s", ret, VTY_NEWLINE);

    struct comm_head *p = (struct comm_head *)buf;

#if 0

    total++;
    if (*(int *) &buf[i] == RESPONSE_V6_ROUTE_TABLE)
    {
        memset (&rtInfo, 0, sizeof (struct route_info));
        memcpy (&rtInfo, (char *) &buf[i] + 8, ntohl (*(int *) &buf[i + 4]) - 8);

        memset (tmp, 0, sizeof (tmp));
        inet_ntop (rtInfo.af, rtInfo.ipv6_route_dstaddr, tmp, sizeof (tmp));
        memset (tmp_2, 0, sizeof (tmp_2));
        sprintf (tmp_2, "%s/%d", tmp, rtInfo.dstLen);
        vty_out (vty, "%d>%-31s",total, tmp_2);
        //vty_out (vty, "%-31s", tmp);
        memset (tmp, 0, sizeof (tmp));
        inet_ntop (rtInfo.af, rtInfo.ipv6_route_gateway, tmp, sizeof (tmp));
        vty_out (vty, "%-27s", tmp);

        vty_out (vty, "%-7u %-2s %s", rtInfo.forward, rtInfo.ifName, VTY_NEWLINE);
        //memset(name,0,20);
        sscanf(rtInfo.ifName,"vEth%d_%d",&k,&j);
        //sprintf(name,"vEth%d_%d",k,j);
        interface_array[k][j]++;


        if(flag)
        {
            for(k=0; k<4; k++)
            {
                for(j=0; j<5; j++)
                {
                    vty_out (vty, "vEth%d_%d : %d\t", k,j,interface_array[k][j]);
                }
                vty_out (vty, " %s", VTY_NEWLINE);
            }
        }
    }
#endif
    for(k=0; k<4; k++)
    {
        for(j=0; j<4; j++)
        {
            vty_out (vty, "vEth%d_%d : %d\t", k+1,j,p->data[k*5+j]);
        }
        vty_out (vty, " %s", VTY_NEWLINE);
    }

    return 0;
}

int v6_route_read (struct vty *vty, int sockfd,int flag)
{

    int i;
    int ret = 0;
    char buf[4096*10];
    char get_route_msg[8];
    char tmp[192];
    char tmp_2[256];
    struct route_info rtInfo;
    int total = 0;
#if 1
    int interface_array[4][5] = {0};
    char name[20];
    int k,j;
#endif

    memset (get_route_msg, 0, 8);
    *(int *) &get_route_msg[0] = REQUEST_V6_ROUTE_TABLE;
    *(int *) &get_route_msg[4] = htonl (8);
    ret = send (sockfd, get_route_msg, 8, 0);
    //vty_out (vty, "%% mib send  %d byte to server %s", ret, VTY_NEWLINE);
    if (ret < 0)
    {
        vty_out (vty, "send get ipv6 route table fail%s", VTY_NEWLINE);
        return -1;
    }

    //ssize_t recv(int sockfd, void *buf, size_t len, int flags);
    memset(buf,0,4096*10);
    ret = recv (sockfd, buf, sizeof(buf), 0);

    if (ret < 0)
    {
        vty_out (vty, "recv ipv4 route table from server fail%s", VTY_NEWLINE);
        return -1;
    }

    //vty_out(vty,"recv %d bytes from server success:%s", ret, VTY_NEWLINE);

#if 1

    vty_out (vty, "IPV6 ROUTE TABLE %s", VTY_NEWLINE);
    vty_out (vty, "Destination                    Next Hop                   Forward If %s", VTY_NEWLINE);
    vty_out (vty, "table name:kernel route table\n");
    for (i = 0; i < ret; i += ntohl (*(int *) &buf[i + 4]))
    {
        total++;
        if (*(int *) &buf[i] == RESPONSE_V6_ROUTE_TABLE)
        {
            memset (&rtInfo, 0, sizeof (struct route_info));
            memcpy (&rtInfo, (char *) &buf[i] + 8, ntohl (*(int *) &buf[i + 4]) - 8);

            memset (tmp, 0, sizeof (tmp));
            inet_ntop (rtInfo.af, rtInfo.ipv6_route_dstaddr, tmp, sizeof (tmp));
            memset (tmp_2, 0, sizeof (tmp_2));
            sprintf (tmp_2, "%s/%d", tmp, rtInfo.dstLen);
            vty_out (vty, "%d>%-31s",total, tmp_2);
            //vty_out (vty, "%-31s", tmp);
            memset (tmp, 0, sizeof (tmp));
            inet_ntop (rtInfo.af, rtInfo.ipv6_route_gateway, tmp, sizeof (tmp));
            vty_out (vty, "%-27s", tmp);

            vty_out (vty, "%-7u %-2s %s", rtInfo.forward, rtInfo.ifName, VTY_NEWLINE);
            //memset(name,0,20);
            sscanf(rtInfo.ifName,"vEth%d_%d",&k,&j);
            //sprintf(name,"vEth%d_%d",k,j);
            interface_array[k][j]++;

        }
        //i += ntohl(*(int *)&buf[i+4]);
    }

    if(flag)
    {
        for(k=0; k<4; k++)
        {
            for(j=0; j<5; j++)
            {
                vty_out (vty, "vEth%d_%d : %d\t", k,j,interface_array[k][j]);
            }
            vty_out (vty, " %s", VTY_NEWLINE);
        }
    }
#endif
    return 0;

}




struct userdata
{

    uint32_t userdata;      /**< Associated with the rule user data. */
    uint32_t gate[4];
    uint32_t ifindex;

};

struct rte_acl_rule_data
{
    uint32_t category_mask; /**< Mask of categories for that rule. */
    int32_t  priority;      /**< Priority for that rule. */
    //uint32_t userdata;      /**< Associated with the rule user data. */
    struct  userdata userdata;      /**< Associated with the rule user data. */
};

union rte_acl_field_types
{
    uint8_t  u8;
    uint16_t u16;
    uint32_t u32;
    uint64_t u64;
};

struct rte_acl_field
{
    union rte_acl_field_types value;
    /**< a 1,2,4, or 8 byte value of the field. */
    union rte_acl_field_types mask_range;
    /**<
     * depending on field type:
     * mask -> 1.2.3.4/32 value=0x1020304, mask_range=32,
     * range -> 0 : 65535 value=0, mask_range=65535,
     * bitmask -> 0x06/0xff value=6, mask_range=0xff.
     */
};
enum
{
    RTE_ACL_FIELD_TYPE_MASK = 0,
    RTE_ACL_FIELD_TYPE_RANGE,
    RTE_ACL_FIELD_TYPE_BITMASK
};


#define	RTE_ACL_RULE_DEF(name, fld_num)	struct name {\
	struct rte_acl_rule_data data;               \
	struct rte_acl_field field[fld_num];         \
}

RTE_ACL_RULE_DEF(acl6_rule, 12);

int v6_acl_read(struct vty *vty, int sockfd)
{
    //vty_out (vty, "sizeof struct acl6_rule= %d %s",sizeof(struct acl6_rule), VTY_NEWLINE);

    int i;
    int ret = 0;
    char *buf;
    char get_route_msg[8];
    char tmp[192];
    char tmp_2[256];
    struct route_info rtInfo;

    struct prefix src_prefix,dst_prefix;
    //int src_len,dst_len;

    memset (get_route_msg, 0, 8);
    *(int *) &get_route_msg[0] = REQUEST_V6_ACL_TABLE;
    *(int *) &get_route_msg[4] = htonl (8);
    ret = send (sockfd, get_route_msg, 8, 0);
    //vty_out (vty, "%% mib send  %d byte to server %s", ret, VTY_NEWLINE);
    if (ret < 0)
    {
        vty_out (vty, "send get ipv6 route table fail%s", VTY_NEWLINE);
        return -1;
    }

    //ssize_t recv(int sockfd, void *buf, size_t len, int flags);
    buf = (char *)malloc(1024*20);
    memset(buf,0,1024*20);
    ret = recv (sockfd, buf, 1024*20, 0);

    if (ret < 0)
    {
        vty_out (vty, "recv acl route table from server fail%s", VTY_NEWLINE);
        return -1;
    }

    //vty_out(vty,"recv %d bytes from server success:%s", ret, VTY_NEWLINE);
    //vty_out(vty,">*DD : default <>*RF :real source address permit<>*RD :real source address permit deny< >*p : policy route<>*S  :section route<>*C  :header compression <%s",  VTY_NEWLINE);

#if 0
    vty_out(vty,"--%02x--%02x--%02x--%02x--\n",buf[0],buf[1],buf[2],buf[3]);

    uint32_t acl_rules_len = *(uint32_t *)buf;
    vty_out(vty,"len = %02x\n",acl_rules_len);

    free(buf);
    buf = (char *)malloc(acl_rules_len + 4);
    memset(buf,0,acl_rules_len + 4);

    ret = recv (sockfd, buf, acl_rules_len + 4, 0);
    vty_out(vty,"recv %d bytes from server success:%s", ret, VTY_NEWLINE);
#endif

    if(ret<=100)
        return -1;



    int j;
    for(i=0; i<ret; i=i+288)
    {
        struct acl6_rule *p = buf+i;
        char type[20];

#if 0
        for(j=0; j<13; j++)
        {

            vty_out(vty,"%d values = %02x  mask = %02x %s",j,p->field[j].value,p->field[j].mask_range,VTY_NEWLINE);
        }
#endif
        if(p->field[1].value.u32 == 0)
        {
            strcpy(type,"any");
        }
        else if(p->field[1].value.u32 == htonl(0x3a))
        {
            strcpy(type,"icmp");
        }
        else if(p->field[1].value.u32 == htonl(0x29))
        {
            strcpy(type,"ipv6");
        }
        else if(p->field[1].value.u32 == htonl(0x06))
        {
            strcpy(type,"tcp");
        }
        else if(p->field[1].value.u32 == htonl(0x11))
        {
            strcpy(type,"udp");
        }

        char src_buf[BUFSIZ];
        char dst_buf[BUFSIZ];
        uint32_t tmp = 0;

        memset((uint8_t *)&dst_prefix,0,sizeof(struct prefix));
        memset((uint8_t *)&src_prefix,0,sizeof(struct prefix));

        if(p->field[2].value.u32 == (0x08000000))
        {
#if 1
            tmp = ntohl(p->field[14].value.u32);
            src_prefix.prefixlen = p->field[14].mask_range.u32 ;
            memcpy((uint8_t *)&src_prefix.u.prefix6,&tmp,4);
            src_prefix.family = 0x02;
            prefix2str(&src_prefix,src_buf,BUFSIZ);
#else
            strcpy(src_buf,"0.0.0.0/0");
#endif
            tmp = ntohl(p->field[15].value.u32);


            dst_prefix.prefixlen = p->field[15].mask_range.u32 ;
            memcpy((uint8_t *)&dst_prefix.u.prefix6,&tmp,4);

            dst_prefix.family = 0x02;
            prefix2str(&dst_prefix,dst_buf,BUFSIZ);
        }
        else
        {

            tmp = ntohl(p->field[3].value.u32);
            memcpy((uint8_t *)&src_prefix.u.prefix6,&tmp,4);
            tmp = ntohl(p->field[4].value.u32);
            memcpy((uint8_t *)&src_prefix.u.prefix6+4,&tmp,4);
            tmp = ntohl(p->field[5].value.u32);
            memcpy((uint8_t *)&src_prefix.u.prefix6+2*4,&tmp,4);
            tmp = ntohl(p->field[6].value.u32);
            memcpy((uint8_t *)&src_prefix.u.prefix6+3*4,&tmp,4);


            src_prefix.prefixlen = p->field[3].mask_range.u32 + p->field[4].mask_range.u32 + p->field[5].mask_range.u32 + p->field[6].mask_range.u32;
            src_prefix.family = 10;

            prefix2str(&src_prefix,src_buf,BUFSIZ);

            tmp = ntohl(p->field[7].value.u32);
            memcpy((uint8_t *)&dst_prefix.u.prefix6,&tmp,4);
            tmp = ntohl(p->field[8].value.u32);
            memcpy((uint8_t *)&dst_prefix.u.prefix6+4,&tmp,4);
            tmp = ntohl(p->field[9].value.u32);
            memcpy((uint8_t *)&dst_prefix.u.prefix6+2*4,&tmp,4);
            tmp = ntohl(p->field[10].value.u32);
            memcpy((uint8_t *)&dst_prefix.u.prefix6+3*4,&tmp,4);

            dst_prefix.prefixlen = p->field[7].mask_range.u32 + p->field[8].mask_range.u32 + p->field[9].mask_range.u32 + p->field[10].mask_range.u32;
            dst_prefix.family = 10;

            prefix2str(&dst_prefix,dst_buf,BUFSIZ);

        }

        if(p->data.userdata.userdata>=1 && p->data.userdata.userdata <8)
        {
            vty_out(vty,"*S\t");//section-engine rule
        }
        else if(p->data.userdata.userdata == 8)
        {
            vty_out(vty,"*P\t");//policy-route rule
        }
        else if(p->data.userdata.userdata == 9)
        {
            vty_out(vty,"*RF\t");//real src fw rule
        }
        else if(p->data.userdata.userdata == 10)
        {
            vty_out(vty,"*RD\t");//real src drop  rule
        }
        else if(p->data.userdata.userdata == 11)
        {
            vty_out(vty,"*DD\t");//default drop  rule
        }
        else if(p->data.userdata.userdata == 12)
        {
            vty_out(vty,"*HC\t");//default drop  rule
        }
        else
        {
            vty_out(vty,"*\t");//other
        }




        vty_out(vty,"%s\t", type);
        vty_out(vty,"%s\t", src_buf);
        vty_out(vty,"%s\t", dst_buf);


        if(p->data.userdata.userdata <= 7)
        {

            vty_out(vty,"%d\t", p->data.userdata.userdata);
        }
        if(p->data.userdata.userdata == 8)
        {
            char gate[40];
            memset(gate,0,40);
            inet_ntop (AF_INET6, p->data.userdata.gate, gate, 40);
            vty_out(vty,"%s\t", gate);
            vty_out(vty,"%s\t",dpdk_ifindex2ifname(p->data.userdata.ifindex));
        }

        if(p->data.userdata.userdata == 9 || p->data.userdata.userdata ==10)
            vty_out(vty,"%s\t", dpdk_ifindex2ifname((ntohl(p->field[13].value.u32))));

#if 0
        vty_out(vty,"protocol : %s\t", type);
        vty_out(vty,"src_prefix : %s\t", src_buf);
        vty_out(vty,"dst_prefix : %s\t", dst_buf);
        vty_out(vty,"priority : %02x\t", p->data.priority);
        vty_out(vty,"ifindex: %02x\t", ntohl(p->field[12].value.u32));
#endif

        vty_out(vty,"%s ",VTY_NEWLINE);
    }



    vty_out(vty,"%s",VTY_NEWLINE);
    return 0;

}




int v4_arp_read (struct vty *vty, int sockfd)
{

    int i;
    int ret = 0;
    char buf[4096];
    char get_arp_msg[8];
    char tmp[192];
    char tmp_2[64];
    struct arp_info arpInfo;

    memset (get_arp_msg, 0, 8);
    *(int *) &get_arp_msg[0] = REQUEST_V4_ARP_TABLE;
    *(int *) &get_arp_msg[4] = htonl (8);
    ret = send (sockfd, get_arp_msg, 8, 0);
    //vty_out (vty, "%% mib send  %d byte to server %s", ret, VTY_NEWLINE);
    if (ret < 0)
    {
        vty_out (vty, "send get arp table fail%s", VTY_NEWLINE);
        return -1;
    }

    //ssize_t recv(int sockfd, void *buf, size_t len, int flags);
    ret = recv (sockfd, buf, sizeof(buf), 0);

    if (ret < 0)
    {
        vty_out (vty, "recv ipv4 arp table from server fail%s", VTY_NEWLINE);
        return -1;
    }

    //vty_out(vty,"recv %d bytes from server success:%s", ret, VTY_NEWLINE);

    vty_out (vty, "IPV4 ARP TABLE %s", VTY_NEWLINE);
    vty_out (vty, "Address         HWaddress            If %s", VTY_NEWLINE);
    for (i = 0; i < ret; i += ntohl (*(int *) &buf[i + 4]))
    {
        if (*(int *) &buf[i] == RESPONSE_V4_ARP_TABLE)
        {
            memset (&arpInfo, 0, sizeof (struct arp_info));
            memcpy (&arpInfo, (char *) &buf[i] + 8, ntohl (*(int *) &buf[i + 4]) - 8);

            memset (tmp, 0, sizeof (tmp));
            inet_ntop (arpInfo.af, (char *) &arpInfo.ipv4_arp_dstaddr, tmp, sizeof (tmp));
            vty_out (vty, "%-16s", tmp);

            memset (tmp_2, 0, sizeof (tmp_2));
            sprintf (tmp_2, "%02X:%02X:%02X:%02X:%02X:%02X", arpInfo.lladdr[0], arpInfo.lladdr[1], arpInfo.lladdr[2], arpInfo.lladdr[3], arpInfo.lladdr[4], arpInfo.lladdr[5]);
            vty_out (vty, "%-21s", tmp_2);

            vty_out (vty, "%-2s %s", arpInfo.ifName, VTY_NEWLINE);
        }
    }

    return 0;
}

int v6_nd_read (struct vty *vty, int sockfd)
{

    int i;
    int ret = 0;
    char buf[4096];
    char get_nd_msg[8];
    char tmp[192];
    char tmp_2[64];
    struct arp_info arpInfo;

    memset (get_nd_msg, 0, 8);
    *(int *) &get_nd_msg[0] = REQUEST_V6_ND_TABLE;
    *(int *) &get_nd_msg[4] = htonl (8);
    ret = send (sockfd, get_nd_msg, 8, 0);
    //vty_out (vty, "%% mib send  %d byte to server %s", ret, VTY_NEWLINE);
    if (ret < 0)
    {
        vty_out (vty, "send get arp table fail%s", VTY_NEWLINE);
        return -1;
    }

    //ssize_t recv(int sockfd, void *buf, size_t len, int flags);
    ret = recv (sockfd, buf, sizeof(buf), 0);

    if (ret < 0)
    {
        vty_out (vty, "recv ipv4 arp table from server fail%s", VTY_NEWLINE);
        return -1;
    }

    //vty_out(vty,"recv %d bytes from server success:%s", ret, VTY_NEWLINE);

    vty_out (vty, "IPV6 NEIGHBOUR TABLE %s", VTY_NEWLINE);
    vty_out (vty, "Address                        HWaddress            If %s", VTY_NEWLINE);
    for (i = 0; i < ret; i += ntohl (*(int *) &buf[i + 4]))
    {
        if (*(int *) &buf[i] == RESPONSE_V6_ND_TABLE)
        {
            memset (&arpInfo, 0, sizeof (struct arp_info));
            memcpy (&arpInfo, (char *) &buf[i] + 8, ntohl (*(int *) &buf[i + 4]) - 8);

            memset (tmp, 0, sizeof (tmp));
            inet_ntop (arpInfo.af, (char *) &arpInfo.ipv6_nd_dstaddr, tmp, sizeof (tmp));
            vty_out (vty, "%-31s", tmp);

            memset (tmp_2, 0, sizeof (tmp_2));
            sprintf (tmp_2, "%02X:%02X:%02X:%02X:%02X:%02X", arpInfo.lladdr[0], arpInfo.lladdr[1], arpInfo.lladdr[2], arpInfo.lladdr[3], arpInfo.lladdr[4], arpInfo.lladdr[5]);
            vty_out (vty, "%-21s", tmp_2);

            vty_out (vty, "%-2s %s", arpInfo.ifName, VTY_NEWLINE);
        }
    }

    return 0;
}
int debug_model(struct vty *vty, int sockfd, int model)
{
    char debug_msg[8];
    int ret;
    memset (debug_msg, 0, 8);

    if (model == 0)
        *(int *) &debug_msg[0] = REQUEST_NODEBUG;
    else
        *(int *) &debug_msg[0] = REQUEST_DEBUG;

    *(int *) &debug_msg[4] = htonl (8);
    ret = send (sockfd, debug_msg, 8, 0);
    if (ret < 0)
    {
        vty_out (vty, "send debug cmd fail%s", VTY_NEWLINE);
        return -1;
    }
    return 0;
}
DEFUN (shell_slot, shell_slot_cmd, "shell <1-32> WORD", "Executive shell command\n" "Slot number\n" "Command string\n")
{
    int sockfd;
    int slot_number;
    int ret;
    char cmd[30];
    memset (cmd, 0, sizeof (char) * 30);

    slot_number = atoi (argv[0]);
    strcpy (cmd, argv[1]);

    //vty_out(vty, "slot_number:%d cmd:%s %s", slot_number, cmd, VTY_NEWLINE);
    //???how can i get slot number
    if (slot_number != 1)
    {
        vty_out (vty, "the board card not avaliable %s", VTY_NEWLINE);
        return CMD_WARNING;
    }

    sockfd = connect_dpdk (vty);
    if (sockfd == -1)
    {
        return CMD_WARNING;
    }

    if (!strcmp (cmd, "geMibFwdRead"))
    {
        ret = ge_mib_fwd_read (vty, sockfd);
    }
    else if (!strcmp (cmd, "geMibKniRead"))
    {
        ret = ge_mib_kni_read (vty, sockfd);
    }
    else if (!strcmp (cmd, "geMibFwdClear"))
    {
        ret = ge_mib_fwd_clear (vty, sockfd);
    }
    else if (!strcmp (cmd, "geMibKniClear"))
    {
        ret = ge_mib_kni_clear (vty, sockfd);
    }
    else if (!strcmp (cmd, "v4ArpRead"))
    {
        ret = v4_arp_read (vty, sockfd);
    }
    else if (!strcmp (cmd, "v6NdRead"))
    {
        ret = v6_nd_read (vty, sockfd);
    }
    else if (!strcmp (cmd, "v4RouteRead"))
    {
        ret = v4_route_read (vty, sockfd);
    }
    else if (!strcmp (cmd, "v6RouteRead"))
    {
        ret = v6_route_read (vty, sockfd,0);
    }
    else if (!strcmp (cmd, "privatev6RouteRead"))
    {
        ret = v6_route_read (vty, sockfd,1);
    }
    else if (!strcmp (cmd, "privateinterfacestatus"))
    {
        ret = v6_interface_status_read (vty, sockfd,1);
    }


    else if (!strcmp (cmd, "v6AclRead"))
    {
        ret = v6_acl_read (vty, sockfd);
    }

    else if (!strcmp(cmd, "debugOn"))
    {
        ret = debug_model(vty, sockfd, 1);
    }
    else if (!strcmp(cmd, "debugOff"))
    {
        ret = debug_model(vty, sockfd, 0);
    }
    else if (!strcmp(cmd, "v4CRouteRead"))
    {
        ret = customize_route_read(vty, sockfd, AF_INET);
    }
    else if (!strcmp(cmd, "v6CRouteRead"))
    {
        ret = customize_route_read(vty, sockfd, AF_INET6);
    }
    else if (!strcmp(cmd, "privatev6CRouteRead"))
    {
        ret = private_customize_route_read(vty, sockfd, AF_INET6);
    }
    else if (!strcmp (cmd, "geMibPeopleTrafficRead"))
    {
        ret = ge_mib_people_traffic_read (vty, sockfd);
    }
    else if (!strcmp (cmd, "geMibPeopleTrafficClear"))
    {
        ret = ge_mib_people_traffic_clear (vty, sockfd);
    }

    else
    {
        vty_out (vty, "Command not found:%s.%s", cmd, VTY_NEWLINE);
        close (sockfd);
        return CMD_WARNING;
    }

    if (ret != 0)
    {
        vty_out (vty, "Command request error.%s", VTY_NEWLINE);
        close (sockfd);
        return CMD_WARNING;
    }

    close (sockfd);
    return CMD_SUCCESS;
}

#endif //end sangmeng add

int zebra_ivi_write_config (struct vty *vty, char *ifname)
{
    char pre[40] = "";

    vty_out (vty, "!%s", VTY_NEWLINE);
    /*ivi_prefix */
    if (ivi_prefix_head != NULL)
    {
        memset (pre, 0, 40);
        inet_ntop (AF_INET6, &(ivi_prefix_head->prefix6.prefix), pre, 40);
        vty_out (vty, "ivi prefix %s/%d ", pre, ivi_prefix_head->prefix6.prefixlen);
        if (ivi_prefix_head->flag == UBIT)
            vty_out (vty, "ubit%s", VTY_NEWLINE);
        else
            vty_out (vty, "no-ubit%s", VTY_NEWLINE);
        vty_out (vty, "!%s", VTY_NEWLINE);
    }
    /*ivi_pool */
    if (ivi_pool_head != NULL)
    {
        bzero (pre, 40);
        inet_ntop (AF_INET, &(ivi_pool_head->prefix4.prefix), pre, 40);
        vty_out (vty, "ivi pool %s/%d%s", pre, ivi_pool_head->prefix4.prefixlen, VTY_NEWLINE);
        vty_out (vty, "!%s", VTY_NEWLINE);
    }
    /*nat_prefix */
    if (nat_prefix_head != NULL)
    {
        memset (pre, 0, 40);
        inet_ntop (AF_INET6, &(nat_prefix_head->prefix6.prefix), pre, 40);
        vty_out (vty, "nat64 prefix %s/%d ", pre, nat_prefix_head->prefix6.prefixlen);
        if (nat_prefix_head->flag == UBIT)
            vty_out (vty, "ubit%s", VTY_NEWLINE);
        else
            vty_out (vty, "no-ubit%s", VTY_NEWLINE);
    }
    /*nat_pool */
    if (nat_pool_head != NULL)
    {
        bzero (pre, 40);
        inet_ntop (AF_INET, &(nat_pool_head->prefix4.prefix), pre, 40);
        vty_out (vty, "nat64 v4pool %s/%d%s", pre, nat_pool_head->prefix4.prefixlen, VTY_NEWLINE);
        vty_out (vty, "!%s", VTY_NEWLINE);
    }
    /*nat timeout */
    if (nat_timeout_head != NULL)
    {
        char buf[10] = "";
        //if(nat_timeout_head->nat_timeout == NAT_TIMEOUT_TCP)
        {
            vty_out (vty, "nat64 timeout %s %s%s", "tcp", myitoa (nat_timeout_head->nat_timeout_tcp, buf, 10), VTY_NEWLINE);
            bzero (buf, 10);
        }
        //else if(nat_timeout_head->nat_timeout == NAT_TIMEOUT_UDP)
        {
            vty_out (vty, "nat64 timeout %s %s%s", "udp", myitoa (nat_timeout_head->nat_timeout_udp, buf, 10), VTY_NEWLINE);
            bzero (buf, 10);
        }
        //else if(nat_timeout_head->nat_timeout == NAT_TIMEOUT_ICMP)
        {
            vty_out (vty, "nat64 timeout %s %s%s", "icmp", myitoa (nat_timeout_head->nat_timeout_icmp, buf, 10), VTY_NEWLINE);
            bzero (buf, 10);
        }
        //else
        ;

        vty_out (vty, "!%s", VTY_NEWLINE);
    }
    else
    {

        ;
    }

    return CMD_SUCCESS;
}

#if 0
int zebra_ivi_write_config (struct vty *vty, char *ifname)
{
#define SIOCGETPREFIX SIOCGETTUNNEL
    struct ifreq ifr;
    struct tnl_parm ivi46;
    struct ivi64_tnl_parm ivi64;
    int socketfd;
    int ret = 0;
    char pre[40];
    //char argv[2][16] = {{"ivi46"},{"ivi64"}};
    socketfd = socket (AF_INET6, SOCK_DGRAM, 0);
    if (socketfd < 0)
    {
        //vty_out(vty,"socket error\n");
        return -1;
    }
    memcpy (ifr.ifr_name, ifname, strlen (ifname) + 1);
    if (strcmp (ifname, "ivi46") == 0)
    {
        ifr.ifr_data = &ivi46;
        ret = ioctl (socketfd, SIOCGETPREFIX, &ifr);
        if (ret == -1)
        {
            //vty_out(vty,"ioctl error: %d\n",errno);
            close (socketfd);
            return -1;
        }
        if (ivi46.prefix.len == 0 && ivi46.prefix.ubit == 0)
        {
            //vty_out(vty,"the prefix is 0\n");
        }
        else
        {
            ivi46.prefix.prefix.s6_addr32[0] = ntohl (ivi46.prefix.prefix.s6_addr32[0]);
            ivi46.prefix.prefix.s6_addr32[1] = ntohl (ivi46.prefix.prefix.s6_addr32[1]);
            ivi46.prefix.prefix.s6_addr32[2] = ntohl (ivi46.prefix.prefix.s6_addr32[2]);
            ivi46.prefix.prefix.s6_addr32[3] = ntohl (ivi46.prefix.prefix.s6_addr32[3]);
            inet_ntop (AF_INET6, &(ivi46.prefix.prefix), pre, 40);
            vty_out (vty, "ivi prefix %s/", pre);
            vty_out (vty, "%d ", ivi46.prefix.len);
            if (ivi46.prefix.ubit == 1)
            {
                vty_out (vty, "ubit");
            }
            else
            {
                vty_out (vty, "no-ubit");
            }
            //vty_out(vty,"%s", ifname);
            vty_out (vty, "%s", VTY_NEWLINE);
        }
    }
    close (socketfd);
    return CMD_SUCCESS;
}

#endif

/*nat64 timeout*/
DEFUN (nat64_timeout,
       nat64_timeout_cmd,
       "nat64 timeout (tcp|udp|icmp) TIMEOUT_VALUE",
       "Configure nat64 protocol\n"
       "Configure nat64 map item's timeout parameter\n" "tcp Transmission Control Protocol\n" "udp User Datagram Protocol\n" "Internet Control Message Protocol\n" "timeout value\n")
{
    if (nat_timeout_head == NULL)
    {
        nat_timeout_head = (struct nat_timeout_message *) malloc (sizeof (struct nat_timeout_message));
        //vty_out(vty,"this type is already exist%s",VTY_NEWLINE);
        //return CMD_WARNING;
    }
    struct zebra_config_message *p_zebra_msg = (struct zebra_config_message *) malloc (sizeof (struct zebra_config_message));
    memset (p_zebra_msg, 0, sizeof (struct zebra_config_message));
    struct nat_timeout_message *p_nat_timeout = (struct nat_timeout_message *) malloc (sizeof (struct nat_timeout_message));
    memset (p_nat_timeout, 0, sizeof (struct nat_timeout_message));
    p_zebra_msg->data = p_nat_timeout;

    //int ret = 0;
    /*start get info and fill ivi message */
    p_zebra_msg->type = ADD_NAT64_TIMEOUT;	//type

    if (!strcmp (argv[0], "tcp"))
    {
        p_nat_timeout->nat_timeout = NAT_TIMEOUT_TCP;
        p_nat_timeout->nat_timeout_tcp = atoi (argv[1]);
    }
    else if (!strcmp (argv[0], "udp"))
    {
        p_nat_timeout->nat_timeout = NAT_TIMEOUT_UDP;	//flag
        p_nat_timeout->nat_timeout_udp = atoi (argv[1]);
    }
    else if (!strcmp (argv[0], "icmp"))
    {
        p_nat_timeout->nat_timeout = NAT_TIMEOUT_ICMP;	//flag
        p_nat_timeout->nat_timeout_icmp = atoi (argv[1]);
    }
    else
    {
        free (p_zebra_msg);
        free (p_nat_timeout);
        vty_out (vty, "%% Malformed arg%s", VTY_NEWLINE);
        return CMD_WARNING;
    }

    p_zebra_msg->len = sizeof (struct zebra_config_message) + sizeof (struct nat_timeout_message);	//len

    if (-1 == zebra_connect_dpdk_send_message_two (p_zebra_msg, p_zebra_msg->len))
    {
        free (p_nat_timeout);
        free (p_zebra_msg);
        //vty_out(vty,"connect server fail%s",VTY_NEWLINE);
        return CMD_SUCCESS;
    }

    if (!strcmp (argv[0], "tcp"))
    {
        nat_timeout_head->nat_timeout_tcp = p_nat_timeout->nat_timeout_tcp;

    }

    if (!strcmp (argv[0], "udp"))
    {
        nat_timeout_head->nat_timeout_udp = p_nat_timeout->nat_timeout_udp;
    }
    if (!strcmp (argv[0], "icmp"))
    {
        nat_timeout_head->nat_timeout_icmp = p_nat_timeout->nat_timeout_icmp;
    }
    free (p_nat_timeout);
    return CMD_SUCCESS;
    /*
    #define TYPE_LEN 10
    #define NAT64_CONFIG_TIMER (SIOCCHGTUNNEL + 12)
    struct ifreq ifr;
    struct nat64_timer{
    char date_type[TYPE_LEN];
    int value;
    };
    int socketfd;
    int ret=0;
    struct nat64_timer time;
    socketfd=socket(AF_INET6,SOCK_DGRAM,0);
    if(socketfd<0)
    {
    vty_out(vty,"socket error\n");
    return -1;
    }
    memcpy(ifr.ifr_name,"nat64",6);
    memcpy(time.date_type,argv[0],strlen(argv[0])+1);
    time.value = atoi(argv[1]);
     */

}

/*nat64 timeout*/
DEFUN (no_nat64_timeout,
       no_nat64_timeout_cmd,
       "no nat64 timeout (tcp|udp|icmp) TIMEOUT_VALUE",
       NO_STR
       "Configure nat64 protocol\n"
       "Configure nat64 map item's timeout parameter\n" "tcp Transmission Control Protocol\n" "udp User Datagram Protocol\n" "Internet Control Message Protocol\n" "timeout value\n")
{

    if (nat_timeout_head == NULL)
        return CMD_WARNING;

    struct zebra_config_message *p_zebra_msg = (struct zebra_config_message *) malloc (sizeof (struct zebra_config_message));
    memset (p_zebra_msg, 0, sizeof (struct zebra_config_message));
    struct nat_timeout_message *p_nat_timeout = (struct nat_timeout_message *) malloc (sizeof (struct nat_timeout_message));
    memset (p_nat_timeout, 0, sizeof (struct nat_timeout_message));
    if (!strcmp (argv[0], "tcp"))
    {
        p_nat_timeout->nat_timeout = NAT_TIMEOUT_TCP;
    }
    else if (!strcmp (argv[0], "udp"))
    {
        p_nat_timeout->nat_timeout = NAT_TIMEOUT_UDP;
    }
    else if (!strcmp (argv[0], "icmp"))
    {
        p_nat_timeout->nat_timeout = NAT_TIMEOUT_ICMP;
    }
    else
    {
        free (p_nat_timeout);
        free (p_zebra_msg);
        vty_out (vty, "%% Malformed arg%s", VTY_NEWLINE);
        return CMD_WARNING;
    }

    p_zebra_msg->data = p_nat_timeout;
    p_zebra_msg->type = DEL_NAT64_TIMEOUT;	//type
    p_zebra_msg->len = sizeof (struct zebra_config_message) + sizeof (struct nat_timeout_message);	//len

    if (-1 == zebra_connect_dpdk_send_message_two (p_zebra_msg, p_zebra_msg->len))
    {
        free (p_nat_timeout);
        free (p_zebra_msg);
        vty_out (vty, "connect server fail%s", VTY_NEWLINE);
        return CMD_SUCCESS;
    }
    if (!strcmp (argv[0], "tcp"))
    {
        nat_timeout_head->nat_timeout_tcp = 0;
    }

    if (!strcmp (argv[0], "udp"))
    {
        nat_timeout_head->nat_timeout_udp = 0;
    }

    if (!strcmp (argv[0], "icmp"))
    {
        nat_timeout_head->nat_timeout_icmp = 0;
    }
    free (p_nat_timeout);
    //free(nat_timeout_head);
    free (p_zebra_msg);
    return CMD_SUCCESS;
    //nat_timeout_head = NULL;
    /*
    #define TYPE_LEN 10
    #define NAT64_DEL_TIMER (SIOCCHGTUNNEL + 13)
    struct ifreq ifr;
    struct nat64_timer{
    char date_type[TYPE_LEN];
    int value;
    };
    int socketfd;
    int ret=0;
    struct nat64_timer time;
    socketfd=socket(AF_INET6,SOCK_DGRAM,0);
    if(socketfd<0)
    {
    vty_out(vty,"socket error\n");
    return -1;
    }
    memcpy(ifr.ifr_name,"nat64",6);
    memcpy(time.date_type,argv[0],strlen(argv[0])+1);
    time.value = atoi(argv[1]);
    ifr.ifr_data=&time;

    ret=ioctl(socketfd,NAT64_DEL_TIMER,&ifr);
    if(ret == -1)
    {
    vty_out(vty,"ioctl error: %d\n",errno);
    close(socketfd);
    return -1;
    }
    close(socketfd);
    return CMD_SUCCESS;
     */
}

#ifdef HAVE_4OVER6_TCPMSS
/*tunnel4o6 tcp mss  cmd */
DEFUN (tunnel4o6_tcp_mss,
       tunnel4o6_tcp_mss_cmd,
       "tunnel4o6 tcp mss <1400-1500>",
       "IPv4 over IPv6 tunnle\n"
       "Transmission Control Protocol\n"
       "Maxitum Segment Size\n"
       "<1400-1500>\n")
{
#define SIOCTCPMSSSET (SIOCCHGTUNNEL + 9)
#define MSS_OVERFLOW 40

    struct tcp_mss
    {
        int mss;
        int flag;
    };
    struct tcp_mss set_mss;

    struct ifreq ifr;

    struct zebra_4over6_tunnel_entry *pNew;
    struct zebra_4over6_tunnel_entry *pNext;

    pNew = &zebra4over6TunnelEntry;
    pNext = zebra4over6TunnelEntry.next;

    int socketfd;
    int ret = 0;
    int cmd = 0;
    int num = 0;
    char *c4OVER6;

    //  vty_out(vty, "come here!: %d\n", num);
    while (pNext != NULL)
    {

        if (pNext->name != NULL)
        {
            c4OVER6 = pNext->name;

            //  vty_out(vty, "name : %s\n", c4OVER6);
            set_mss.mss = atoi (argv[0]);
            set_mss.flag = 1;

            memset (&save_tunnel4o6_tcpmss, 0, sizeof (save_tunnel4o6_tcpmss));
            save_tunnel4o6_tcpmss.mss_value = set_mss.mss;
            save_tunnel4o6_tcpmss.mss_flag = set_mss.flag;

            socketfd = socket (AF_INET6, SOCK_DGRAM, 0);

            if (socketfd < 0)
            {
                vty_out (vty, "socket_error\n");
                return -1;
            }
            cmd = SIOCTCPMSSSET;

            strcpy (ifr.ifr_name, c4OVER6);
            //  vty_out(vty, "ifr.ifr_name: %s argv[0] %d\n",ifr.ifr_name, atoi(argv[0]));
            ifr.ifr_data = &set_mss;

            ret = ioctl (socketfd, cmd, &ifr);
            if (ret == -1)
            {
                vty_out (vty, "ioctl error13: %d\n", errno);

                if (errno == MSS_OVERFLOW)
                {
                    vty_out (vty, "you input mss is over range<1-1500>\n");
                }

                close (socketfd);
                return -1;
            }
        }
        num++;
        pNext = pNext->next;
    }

    //  vty_out(vty, "leave here!: %d\n", num);
    close (socketfd);
    return CMD_SUCCESS;
}
#endif

#if 1
DEFUN (no_tunnel4o6_tcp_mss,
       no_tunnel4o6_tcp_mss_cmd,
       "no tunnel4o6 tcp mss <1400-1500>",
       NO_STR
       //TCP_STR
       "IPv4 over IPv6 tunnle\n"
       "Transmission Control Protocol\n"
       "Maxitum Segment Size\n"
       "the configured size for mss\n")
{
#define SIOCTCPMSSDEL (SIOCCHGTUNNEL + 10)
#define DEL_ERR 41

    struct tcp_mss
    {
        int mss;
        int flag;
    };
    struct tcp_mss set_mss;

    struct ifreq ifr;

    struct zebra_4over6_tunnel_entry *pNew;
    struct zebra_4over6_tunnel_entry *pNext;

    pNew = &zebra4over6TunnelEntry;
    pNext = zebra4over6TunnelEntry.next;

    int socketfd = -1;
    int ret = 0;
    int cmd = 0;
    int num = 0;
    char *c4OVER6;

    //  vty_out(vty, "come here!: %d\n", num);
    while (pNext != NULL)
    {

        if (pNext->name != NULL)
        {
            c4OVER6 = pNext->name;

            //vty_out(vty, "name : %s\n", c4OVER6);
            set_mss.mss = atoi (argv[0]);
            set_mss.flag = 1;

            memset (&save_tunnel4o6_tcpmss, 0, sizeof (save_tunnel4o6_tcpmss));
            save_tunnel4o6_tcpmss.mss_value = 0;
            save_tunnel4o6_tcpmss.mss_flag = 0;

            socketfd = socket (AF_INET6, SOCK_DGRAM, 0);

            if (socketfd < 0)
            {
                vty_out (vty, "socket_error\n");
                return -1;
            }
            cmd = SIOCTCPMSSDEL;

            strcpy (ifr.ifr_name, c4OVER6);
            //vty_out(vty, "ifr.ifr_name: %s argv[0] %d\n",ifr.ifr_name, atoi(argv[0]));
            ifr.ifr_data = &set_mss;

            ret = ioctl (socketfd, cmd, &ifr);
            if (ret == -1)
            {
                vty_out (vty, "ioctl error*: %d\n", errno);
                if (errno == DEL_ERR)
                {
                    vty_out (vty, "ret=%d,4over6 tcp mss is not existed,delete fail!\n", ret);
                }
                close (socketfd);
                return -1;
            }
        }
        num++;
        pNext = pNext->next;
    }

    //  vty_out(vty, "leave here!: %d\n", num);
    close (socketfd);
    return CMD_SUCCESS;
}
#endif

#if 0

/* manage 4over6 tunnel */
DEFUN (fover6_tunnel,
       fover6_tunnel_cmd,
       "4over6 tunnel OPTION TUNNEL_NAME X:X::X:X  X:X::X:X [STATE]",
       TUNNEL_STR "--OPTION='add'/'del'/'chg'  create/delete 4over6 tunnel,or change 4over6 tunnel state\n" "tunnel_name\n" "local ipv6 addr\n" "remote ipv6 addr\n" "[up/down]  tunnel state\n")
{
    struct ifreq ifr;
    struct ip6_tnl_parm ip6;

    int socketfd;
    int ret = 0;
    int cmd = 0;

    socketfd = socket (AF_INET6, SOCK_DGRAM, 0);
    if (socketfd < 0)
    {
        vty_out (vty, "socket error\n");
        return -1;
    }

    if (strcmp ("del", argv[0]) == 0)
    {
        memcpy (ifr.ifr_name, argv[1], strlen (argv[1]) + 1);
        ifr.ifr_flags = 0;		//IFF_DOWN;
        ret = ioctl (socketfd, SIOCSIFFLAGS, &ifr);
        if (ret == -1)
        {
            vty_out (vty, "ioctl error: %d\n", errno);
            close (socketfd);
            return -1;
        }

        ip6.proto = IPPROTO_IPIP;
        cmd = SIOCDELTUNNEL;
        ifr.ifr_data = &ip6;
        memcpy (ifr.ifr_name, argv[1], strlen (argv[1]) + 1);
        ret = ioctl (socketfd, cmd, &ifr);
        if (ret == -1)
        {
            vty_out (vty, "ioctl error: %d\n", errno);
            close (socketfd);
            return -1;
        }
    }
    else
    {

        if (strcmp ("chg", argv[0]) == 0)
        {
            if (argc == 5)
            {
                if (strcmp (argv[4], "up") == 0)
                    ifr.ifr_flags = IFF_UP;	//up
                else if (strcmp (argv[4], "down") == 0)
                    ifr.ifr_flags = 0;	//down
                memcpy (ifr.ifr_name, argv[1], strlen (argv[1]) + 1);
                ret = ioctl (socketfd, SIOCSIFFLAGS, &ifr);
                if (ret == -1)
                {
                    vty_out (vty, "set flags down ioctl error : %d\n", errno);
                    close (socketfd);
                    return -1;
                }
            }
        }
        else if (strcmp ("add", argv[0]) == 0)
        {
            cmd = SIOCADDTUNNEL;
            memcpy (ifr.ifr_name, "ip6tnl0", 8);
            memcpy (ip6.name, argv[1], strlen (argv[1]) + 1);

            ip6.proto = IPPROTO_IPIP;
            ret = inet_pton (AF_INET6, argv[2], &(ip6.laddr));
            if (ret == 0)
            {
                vty_out (vty, "error LOACAL_ADDRESS\n");
                close (socketfd);
                return -1;
            }
            ret = inet_pton (AF_INET6, argv[3], &(ip6.raddr));
            if (ret == 0)
            {
                vty_out (vty, "error REMOTE_ADDRESS\n");
                close (socketfd);
                return -1;
            }
            ip6.hop_limit = 64;
            ifr.ifr_data = &ip6;
            ret = ioctl (socketfd, cmd, &ifr);
            if (ret == -1)
            {
                vty_out (vty, "ioctl error: %d\n", errno);
                close (socketfd);
                return -1;
            }
            memcpy (ifr.ifr_name, argv[1], strlen (argv[1]) + 1);
            ifr.ifr_flags = IFF_UP;
            ret = ioctl (socketfd, SIOCSIFFLAGS, &ifr);
            if (ret == -1)
            {
                vty_out (vty, "ioctl error: %d\n", errno);
                close (socketfd);
                return -1;
            }
        }
        else
        {
            vty_out (vty, "error OPTION: %s\n", argv[3]);
            close (socketfd);
            return -1;
        }
    }
    close (socketfd);
    return CMD_SUCCESS;
}

#endif

DEFUN (ipv6_route,
       ipv6_route_cmd,
       "ipv6 route X:X::X:X/M (X:X::X:X|INTERFACE)",
       IP_STR
       "Establish static routes\n"
       "IPv6 destination prefix (e.g. 3ffe:506::/32)\n"
       "IPv6 gateway address\n"
       "IPv6 gateway interface name\n")
{
    return static_ipv6_func (vty, 1, argv[0], argv[1], NULL, NULL, NULL);
}

DEFUN (ipv6_route_flags,
       ipv6_route_flags_cmd,
       "ipv6 route X:X::X:X/M (X:X::X:X|INTERFACE) (reject|blackhole)",
       IP_STR
       "Establish static routes\n"
       "IPv6 destination prefix (e.g. 3ffe:506::/32)\n" "IPv6 gateway address\n" "IPv6 gateway interface name\n" "Emit an ICMP unreachable when matched\n" "Silently discard pkts when matched\n")
{
    return static_ipv6_func (vty, 1, argv[0], argv[1], NULL, argv[2], NULL);
}

DEFUN (ipv6_route_ifname,
       ipv6_route_ifname_cmd,
       "ipv6 route X:X::X:X/M X:X::X:X INTERFACE",
       IP_STR
       "Establish static routes\n"
       "IPv6 destination prefix (e.g. 3ffe:506::/32)\n"
       "IPv6 gateway address\n"
       "IPv6 gateway interface name\n")
{
    return static_ipv6_func (vty, 1, argv[0], argv[1], argv[2], NULL, NULL);
}

DEFUN (ipv6_route_ifname_flags,
       ipv6_route_ifname_flags_cmd,
       "ipv6 route X:X::X:X/M X:X::X:X INTERFACE (reject|blackhole)",
       IP_STR
       "Establish static routes\n"
       "IPv6 destination prefix (e.g. 3ffe:506::/32)\n"
       "IPv6 gateway address\n"
       "IPv6 gateway interface name\n"
       "Emit an ICMP unreachable when matched\n"
       "Silently discard pkts when matched\n")
{
    return static_ipv6_func (vty, 1, argv[0], argv[1], argv[2], argv[3], NULL);
}

DEFUN (ipv6_route_pref,
       ipv6_route_pref_cmd,
       "ipv6 route X:X::X:X/M (X:X::X:X|INTERFACE) <1-255>",
       IP_STR
       "Establish static routes\n"
       "IPv6 destination prefix (e.g. 3ffe:506::/32)\n"
       "IPv6 gateway address\n"
       "IPv6 gateway interface name\n"
       "Distance value for this prefix\n")
{
    return static_ipv6_func (vty, 1, argv[0], argv[1], NULL, NULL, argv[2]);
}

DEFUN (ipv6_route_flags_pref,
       ipv6_route_flags_pref_cmd,
       "ipv6 route X:X::X:X/M (X:X::X:X|INTERFACE) (reject|blackhole) <1-255>",
       IP_STR
       "Establish static routes\n"
       "IPv6 destination prefix (e.g. 3ffe:506::/32)\n"
       "IPv6 gateway address\n"
       "IPv6 gateway interface name\n"
       "Emit an ICMP unreachable when matched\n"
       "Silently discard pkts when matched\n"
       "Distance value for this prefix\n")
{
    return static_ipv6_func (vty, 1, argv[0], argv[1], NULL, argv[2], argv[3]);
}

DEFUN (ipv6_route_ifname_pref,
       ipv6_route_ifname_pref_cmd,
       "ipv6 route X:X::X:X/M X:X::X:X INTERFACE <1-255>",
       IP_STR
       "Establish static routes\n"
       "IPv6 destination prefix (e.g. 3ffe:506::/32)\n"
       "IPv6 gateway address\n"
       "IPv6 gateway interface name\n"
       "Distance value for this prefix\n")
{
    return static_ipv6_func (vty, 1, argv[0], argv[1], argv[2], NULL, argv[3]);
}

DEFUN (ipv6_route_ifname_flags_pref,
       ipv6_route_ifname_flags_pref_cmd,
       "ipv6 route X:X::X:X/M X:X::X:X INTERFACE (reject|blackhole) <1-255>",
       IP_STR
       "Establish static routes\n"
       "IPv6 destination prefix (e.g. 3ffe:506::/32)\n"
       "IPv6 gateway address\n"
       "IPv6 gateway interface name\n"
       "Emit an ICMP unreachable when matched\n"
       "Silently discard pkts when matched\n"
       "Distance value for this prefix\n")
{
    return static_ipv6_func (vty, 1, argv[0], argv[1], argv[2], argv[3], argv[4]);
}

DEFUN (no_ipv6_route,
       no_ipv6_route_cmd,
       "no ipv6 route X:X::X:X/M (X:X::X:X|INTERFACE)",
       NO_STR IP_STR
       "Establish static routes\n"
       "IPv6 destination prefix (e.g. 3ffe:506::/32)\n"
       "IPv6 gateway address\n"
       "IPv6 gateway interface name\n")
{
    return static_ipv6_func (vty, 0, argv[0], argv[1], NULL, NULL, NULL);
}

ALIAS (no_ipv6_route,
       no_ipv6_route_flags_cmd,
       "no ipv6 route X:X::X:X/M (X:X::X:X|INTERFACE) (reject|blackhole)",
       NO_STR
       IP_STR
       "Establish static routes\n"
       "IPv6 destination prefix (e.g. 3ffe:506::/32)\n"
       "IPv6 gateway address\n"
       "IPv6 gateway interface name\n"
       "Emit an ICMP unreachable when matched\n"
       "Silently discard pkts when matched\n")
DEFUN (no_ipv6_route_ifname,
       no_ipv6_route_ifname_cmd,
       "no ipv6 route X:X::X:X/M X:X::X:X INTERFACE",
       NO_STR IP_STR
       "Establish static routes\n"
       "IPv6 destination prefix (e.g. 3ffe:506::/32)\n"
       "IPv6 gateway address\n"
       "IPv6 gateway interface name\n")
{
    return static_ipv6_func (vty, 0, argv[0], argv[1], argv[2], NULL, NULL);
}

ALIAS (no_ipv6_route_ifname,
       no_ipv6_route_ifname_flags_cmd,
       "no ipv6 route X:X::X:X/M X:X::X:X INTERFACE (reject|blackhole)",
       NO_STR
       IP_STR
       "Establish static routes\n"
       "IPv6 destination prefix (e.g. 3ffe:506::/32)\n"
       "IPv6 gateway address\n"
       "IPv6 gateway interface name\n"
       "Emit an ICMP unreachable when matched\n"
       "Silently discard pkts when matched\n")
DEFUN (no_ipv6_route_pref,
       no_ipv6_route_pref_cmd,
       "no ipv6 route X:X::X:X/M (X:X::X:X|INTERFACE) <1-255>",
       NO_STR IP_STR "Establish static routes\n" "IPv6 destination prefix (e.g. 3ffe:506::/32)\n" "IPv6 gateway address\n" "IPv6 gateway interface name\n" "Distance value for this prefix\n")
{
    return static_ipv6_func (vty, 0, argv[0], argv[1], NULL, NULL, argv[2]);
}

DEFUN (no_ipv6_route_flags_pref,
       no_ipv6_route_flags_pref_cmd,
       "no ipv6 route X:X::X:X/M (X:X::X:X|INTERFACE) (reject|blackhole) <1-255>",
       NO_STR
       IP_STR
       "Establish static routes\n"
       "IPv6 destination prefix (e.g. 3ffe:506::/32)\n"
       "IPv6 gateway address\n" "IPv6 gateway interface name\n" "Emit an ICMP unreachable when matched\n" "Silently discard pkts when matched\n" "Distance value for this prefix\n")
{
    /* We do not care about argv[2] */
    return static_ipv6_func (vty, 0, argv[0], argv[1], NULL, argv[2], argv[3]);
}

DEFUN (no_ipv6_route_ifname_pref,
       no_ipv6_route_ifname_pref_cmd,
       "no ipv6 route X:X::X:X/M X:X::X:X INTERFACE <1-255>",
       NO_STR IP_STR "Establish static routes\n" "IPv6 destination prefix (e.g. 3ffe:506::/32)\n" "IPv6 gateway address\n" "IPv6 gateway interface name\n" "Distance value for this prefix\n")
{
    return static_ipv6_func (vty, 0, argv[0], argv[1], argv[2], NULL, argv[3]);
}

DEFUN (no_ipv6_route_ifname_flags_pref,
       no_ipv6_route_ifname_flags_pref_cmd,
       "no ipv6 route X:X::X:X/M X:X::X:X INTERFACE (reject|blackhole) <1-255>",
       NO_STR
       IP_STR
       "Establish static routes\n"
       "IPv6 destination prefix (e.g. 3ffe:506::/32)\n"
       "IPv6 gateway address\n" "IPv6 gateway interface name\n" "Emit an ICMP unreachable when matched\n" "Silently discard pkts when matched\n" "Distance value for this prefix\n")
{
    return static_ipv6_func (vty, 0, argv[0], argv[1], argv[2], argv[3], argv[4]);
}

/* New RIB.  Detailed information for IPv6 route. */
static void vty_show_ipv6_route_detail (struct vty *vty, struct route_node *rn)
{
    struct rib *rib;
    struct nexthop *nexthop;
    char buf[BUFSIZ];

    for (rib = rn->info; rib; rib = rib->next)
    {
        vty_out (vty, "Routing entry for %s/%d%s", inet_ntop (AF_INET6, &rn->p.u.prefix6, buf, BUFSIZ), rn->p.prefixlen, VTY_NEWLINE);
        vty_out (vty, "  Known via \"%s\"", zebra_route_string (rib->type));
        vty_out (vty, ", distance %d, metric %d", rib->distance, rib->metric);
        if (CHECK_FLAG (rib->flags, ZEBRA_FLAG_SELECTED))
            vty_out (vty, ", best");
        if (rib->refcnt)
            vty_out (vty, ", refcnt %ld", rib->refcnt);
        if (CHECK_FLAG (rib->flags, ZEBRA_FLAG_BLACKHOLE))
            vty_out (vty, ", blackhole");
        if (CHECK_FLAG (rib->flags, ZEBRA_FLAG_REJECT))
            vty_out (vty, ", reject");
        vty_out (vty, "%s", VTY_NEWLINE);

#define ONE_DAY_SECOND 60*60*24
#define ONE_WEEK_SECOND 60*60*24*7
        if (rib->type == ZEBRA_ROUTE_RIPNG || rib->type == ZEBRA_ROUTE_OSPF6 || rib->type == ZEBRA_ROUTE_BABEL || rib->type == ZEBRA_ROUTE_ISIS || rib->type == ZEBRA_ROUTE_BGP)
        {
            time_t uptime;
            struct tm *tm;

            uptime = time (NULL);
            uptime -= rib->uptime;
            tm = gmtime (&uptime);

            vty_out (vty, "  Last update ");

            if (uptime < ONE_DAY_SECOND)
                vty_out (vty, "%02d:%02d:%02d", tm->tm_hour, tm->tm_min, tm->tm_sec);
            else if (uptime < ONE_WEEK_SECOND)
                vty_out (vty, "%dd%02dh%02dm", tm->tm_yday, tm->tm_hour, tm->tm_min);
            else
                vty_out (vty, "%02dw%dd%02dh", tm->tm_yday / 7, tm->tm_yday - ((tm->tm_yday / 7) * 7), tm->tm_hour);
            vty_out (vty, " ago%s", VTY_NEWLINE);
        }

        for (nexthop = rib->nexthop; nexthop; nexthop = nexthop->next)
        {
            vty_out (vty, "  %c", CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB) ? '*' : ' ');

            switch (nexthop->type)
            {
            case NEXTHOP_TYPE_IPV6:
            case NEXTHOP_TYPE_IPV6_IFINDEX:
            case NEXTHOP_TYPE_IPV6_IFNAME:
                vty_out (vty, " %s", inet_ntop (AF_INET6, &nexthop->gate.ipv6, buf, BUFSIZ));
                if (nexthop->type == NEXTHOP_TYPE_IPV6_IFNAME)
                    vty_out (vty, ", %s", nexthop->ifname);
                else if (nexthop->ifindex)
                    vty_out (vty, ", via %s", ifindex2ifname (nexthop->ifindex));
                break;
            case NEXTHOP_TYPE_IFINDEX:
                vty_out (vty, " directly connected, %s", ifindex2ifname (nexthop->ifindex));
                break;
            case NEXTHOP_TYPE_IFNAME:
                vty_out (vty, " directly connected, %s", nexthop->ifname);
                break;
            default:
                break;
            }
            if (!CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE))
                vty_out (vty, " inactive");

            if (CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_RECURSIVE))
            {
                vty_out (vty, " (recursive");

                switch (nexthop->rtype)
                {
                case NEXTHOP_TYPE_IPV6:
                case NEXTHOP_TYPE_IPV6_IFINDEX:
                case NEXTHOP_TYPE_IPV6_IFNAME:
                    vty_out (vty, " via %s)", inet_ntop (AF_INET6, &nexthop->rgate.ipv6, buf, BUFSIZ));
                    if (nexthop->rifindex)
                        vty_out (vty, ", %s", ifindex2ifname (nexthop->rifindex));
                    break;
                case NEXTHOP_TYPE_IFINDEX:
                case NEXTHOP_TYPE_IFNAME:
                    vty_out (vty, " is directly connected, %s)", ifindex2ifname (nexthop->rifindex));
                    break;
                default:
                    break;
                }
            }
            vty_out (vty, "%s", VTY_NEWLINE);
        }
        vty_out (vty, "%s", VTY_NEWLINE);
    }
}

#if 1
static void vty_show_c_ipv6_route (struct vty *vty, struct route_node *rn, struct rib *rib)
{
    struct nexthop *nexthop;
    int len = 0;
    char buf[BUFSIZ];

    /* Nexthop information. */
    for (nexthop = rib->nexthop; nexthop; nexthop = nexthop->next)
    {
        if (nexthop == rib->nexthop)
        {
            if (strcmp ("fe80::", inet_ntop (AF_INET6, &rn->p.u.prefix6, buf, BUFSIZ)) != 0 && strcmp ("::1", inet_ntop (AF_INET6, &rn->p.u.prefix6, buf, BUFSIZ)) != 0)
            {
                /* Prefix information. */
                len = vty_out (vty, "%c%c%c %s/%d",
                               zebra_route_char (rib->type),
                               CHECK_FLAG (rib->flags, ZEBRA_FLAG_SELECTED)
                               //? '>' : ' ', CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB) ? '*' : ' ', inet_ntop (AF_INET6, &rn->p.u.prefix6, buf, BUFSIZ), rn->p.prefixlen);
                               ? '>' : ' ', CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB) ? '*' : '*', inet_ntop (AF_INET6, &rn->p.u.prefix6, buf, BUFSIZ), rn->p.prefixlen);

                /* Distance and metric display. */
                if (rib->type != ZEBRA_ROUTE_CONNECT && rib->type != ZEBRA_ROUTE_KERNEL)
                    len += vty_out (vty, " [%d/%d]", rib->distance, rib->metric);
            }
        }
        else if (strcmp ("fe80::", inet_ntop (AF_INET6, &rn->p.u.prefix6, buf, BUFSIZ)) != 0 && strcmp ("::1", inet_ntop (AF_INET6, &rn->p.u.prefix6, buf, BUFSIZ)) != 0)
        {
            vty_out (vty, "  %c%*c", CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB) ? '*' : ' ', len - 3, ' ');
        }

        if (strcmp ("fe80::", inet_ntop (AF_INET6, &rn->p.u.prefix6, buf, BUFSIZ)) != 0 && strcmp ("::1", inet_ntop (AF_INET6, &rn->p.u.prefix6, buf, BUFSIZ)) != 0)
        {
            switch (nexthop->type)
            {
            case NEXTHOP_TYPE_IPV6:
            case NEXTHOP_TYPE_IPV6_IFINDEX:
            case NEXTHOP_TYPE_IPV6_IFNAME:
                vty_out (vty, " via %s", inet_ntop (AF_INET6, &nexthop->gate.ipv6, buf, BUFSIZ));
                if (nexthop->type == NEXTHOP_TYPE_IPV6_IFNAME)
                    vty_out (vty, ", %s", nexthop->ifname);
                else if (nexthop->ifindex)
                    vty_out (vty, ", %s", ifindex2ifname (nexthop->ifindex));
                break;
            case NEXTHOP_TYPE_IFINDEX:
                vty_out (vty, " is directly connected, %s", ifindex2ifname (nexthop->ifindex));
                break;
            case NEXTHOP_TYPE_IFNAME:
                vty_out (vty, " is directly connected, %s", nexthop->ifname);
                break;
            default:
                break;
            }
            if (!CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE))
                //vty_out (vty, " inactive");

                if (CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_RECURSIVE))
                {
                    vty_out (vty, " (recursive");

                    switch (nexthop->rtype)
                    {
                    case NEXTHOP_TYPE_IPV6:
                    case NEXTHOP_TYPE_IPV6_IFINDEX:
                    case NEXTHOP_TYPE_IPV6_IFNAME:
                        vty_out (vty, " via %s)", inet_ntop (AF_INET6, &nexthop->rgate.ipv6, buf, BUFSIZ));
                        if (nexthop->rifindex)
                            vty_out (vty, ", %s", ifindex2ifname (nexthop->rifindex));
                        break;
                    case NEXTHOP_TYPE_IFINDEX:
                    case NEXTHOP_TYPE_IFNAME:
                        vty_out (vty, " is directly connected, %s)", ifindex2ifname (nexthop->rifindex));
                        break;
                    default:
                        break;
                    }
                }

            if (CHECK_FLAG (rib->flags, ZEBRA_FLAG_BLACKHOLE))
                vty_out (vty, ", bh");
            if (CHECK_FLAG (rib->flags, ZEBRA_FLAG_REJECT))
                vty_out (vty, ", rej");

            if (rib->type == ZEBRA_ROUTE_RIPNG || rib->type == ZEBRA_ROUTE_OSPF6 || rib->type == ZEBRA_ROUTE_BABEL || rib->type == ZEBRA_ROUTE_ISIS || rib->type == ZEBRA_ROUTE_BGP)
            {
                time_t uptime;
                struct tm *tm;

                uptime = time (NULL);
                uptime -= rib->uptime;
                tm = gmtime (&uptime);

#define ONE_DAY_SECOND 60*60*24
#define ONE_WEEK_SECOND 60*60*24*7

                if (uptime < ONE_DAY_SECOND)
                    vty_out (vty, ", %02d:%02d:%02d", tm->tm_hour, tm->tm_min, tm->tm_sec);
                else if (uptime < ONE_WEEK_SECOND)
                    vty_out (vty, ", %dd%02dh%02dm", tm->tm_yday, tm->tm_hour, tm->tm_min);
                else
                    vty_out (vty, ", %02dw%dd%02dh", tm->tm_yday / 7, tm->tm_yday - ((tm->tm_yday / 7) * 7), tm->tm_hour);
            }
            vty_out (vty, "%s", VTY_NEWLINE);
        }
    }
}
#endif

static void vty_show_ipv6_route (struct vty *vty, struct route_node *rn, struct rib *rib)
{
    struct nexthop *nexthop;
    int len = 0;
    char buf[BUFSIZ];

    /* Nexthop information. */
    for (nexthop = rib->nexthop; nexthop; nexthop = nexthop->next)
    {
        if (nexthop == rib->nexthop)
        {
            if (strcmp ("fe80::", inet_ntop (AF_INET6, &rn->p.u.prefix6, buf, BUFSIZ)) != 0 && strcmp ("::1", inet_ntop (AF_INET6, &rn->p.u.prefix6, buf, BUFSIZ)) != 0)
            {
                /* Prefix information. */
                len = vty_out (vty, "%c%c%c %s/%d",
                               zebra_route_char (rib->type),
                               CHECK_FLAG (rib->flags, ZEBRA_FLAG_SELECTED)
                               ? '>' : ' ', CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB) ? '*' : ' ', inet_ntop (AF_INET6, &rn->p.u.prefix6, buf, BUFSIZ), rn->p.prefixlen);

                /* Distance and metric display. */
                if (rib->type != ZEBRA_ROUTE_CONNECT && rib->type != ZEBRA_ROUTE_KERNEL)
                    len += vty_out (vty, " [%d/%d]", rib->distance, rib->metric);
            }
        }
        else if (strcmp ("fe80::", inet_ntop (AF_INET6, &rn->p.u.prefix6, buf, BUFSIZ)) != 0 && strcmp ("::1", inet_ntop (AF_INET6, &rn->p.u.prefix6, buf, BUFSIZ)) != 0)
        {
            vty_out (vty, "  %c%*c", CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB) ? '*' : ' ', len - 3, ' ');
        }

        if (strcmp ("fe80::", inet_ntop (AF_INET6, &rn->p.u.prefix6, buf, BUFSIZ)) != 0 && strcmp ("::1", inet_ntop (AF_INET6, &rn->p.u.prefix6, buf, BUFSIZ)) != 0)
        {
            switch (nexthop->type)
            {
            case NEXTHOP_TYPE_IPV6:
            case NEXTHOP_TYPE_IPV6_IFINDEX:
            case NEXTHOP_TYPE_IPV6_IFNAME:
                vty_out (vty, " via %s", inet_ntop (AF_INET6, &nexthop->gate.ipv6, buf, BUFSIZ));
                if (nexthop->type == NEXTHOP_TYPE_IPV6_IFNAME)
                    vty_out (vty, ", %s", nexthop->ifname);
                else if (nexthop->ifindex)
                    vty_out (vty, ", %s", ifindex2ifname (nexthop->ifindex));
                break;
            case NEXTHOP_TYPE_IFINDEX:
                vty_out (vty, " is directly connected, %s", ifindex2ifname (nexthop->ifindex));
                break;
            case NEXTHOP_TYPE_IFNAME:
                vty_out (vty, " is directly connected, %s", nexthop->ifname);
                break;
            default:
                break;
            }
            if (!CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE))
                vty_out (vty, " inactive");

            if (CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_RECURSIVE))
            {
                vty_out (vty, " (recursive");

                switch (nexthop->rtype)
                {
                case NEXTHOP_TYPE_IPV6:
                case NEXTHOP_TYPE_IPV6_IFINDEX:
                case NEXTHOP_TYPE_IPV6_IFNAME:
                    vty_out (vty, " via %s)", inet_ntop (AF_INET6, &nexthop->rgate.ipv6, buf, BUFSIZ));
                    if (nexthop->rifindex)
                        vty_out (vty, ", %s", ifindex2ifname (nexthop->rifindex));
                    break;
                case NEXTHOP_TYPE_IFINDEX:
                case NEXTHOP_TYPE_IFNAME:
                    vty_out (vty, " is directly connected, %s)", ifindex2ifname (nexthop->rifindex));
                    break;
                default:
                    break;
                }
            }

            if (CHECK_FLAG (rib->flags, ZEBRA_FLAG_BLACKHOLE))
                vty_out (vty, ", bh");
            if (CHECK_FLAG (rib->flags, ZEBRA_FLAG_REJECT))
                vty_out (vty, ", rej");

            if (rib->type == ZEBRA_ROUTE_RIPNG || rib->type == ZEBRA_ROUTE_OSPF6 || rib->type == ZEBRA_ROUTE_BABEL || rib->type == ZEBRA_ROUTE_ISIS || rib->type == ZEBRA_ROUTE_BGP)
            {
                time_t uptime;
                struct tm *tm;

                uptime = time (NULL);
                uptime -= rib->uptime;
                tm = gmtime (&uptime);

#define ONE_DAY_SECOND 60*60*24
#define ONE_WEEK_SECOND 60*60*24*7

                if (uptime < ONE_DAY_SECOND)
                    vty_out (vty, ", %02d:%02d:%02d", tm->tm_hour, tm->tm_min, tm->tm_sec);
                else if (uptime < ONE_WEEK_SECOND)
                    vty_out (vty, ", %dd%02dh%02dm", tm->tm_yday, tm->tm_hour, tm->tm_min);
                else
                    vty_out (vty, ", %02dw%dd%02dh", tm->tm_yday / 7, tm->tm_yday - ((tm->tm_yday / 7) * 7), tm->tm_hour);
            }
            vty_out (vty, "%s", VTY_NEWLINE);
        }
    }
}

DEFUN (show_ipv6_policy_route,
       show_ipv6_policy_route_cmd,
       "show ipv6 policy route",
       SHOW_STR
       IPV6_STR
       "IPv6 policy routing table\n")
{

    struct acl_route_table *pos = NULL;
    char buf[BUFSIZ];
    char type[8];
    int i=0;
    char gateway[40];

    for(pos = acl_route_table_head; pos!= NULL; pos = pos->next)
    {

        prefix2str(&pos->node.s_prefix, buf, BUFSIZ);

        if (!strcmp(buf, "::"))
            vty_out (vty, "policy-route");
        else
            continue;

        prefix2str(&pos->node.prefix, buf, BUFSIZ);
        vty_out (vty, " %s", buf);

        inet_ntop(AF_INET6,pos->node.gateway,gateway,40);
        vty_out (vty, " %s", gateway);
        if(pos->node.status == 0)
        {
            vty_out (vty, " %s", "inactive");
        }
        else
        {

            vty_out (vty, " %s", pos->node.ifp->name);
        }
        vty_out (vty, "%s",VTY_NEWLINE);
    }


    return CMD_SUCCESS;

}


DEFUN (show_ipv6_twod_route,
       show_ipv6_twod_route_cmd,
       "show ipv6 twod route",
       SHOW_STR
       IPV6_STR
       "IPv6 two dimensional routing table\n")
{

    struct acl_route_table *pos = NULL;
    char buf[BUFSIZ];
    char type[8];
    int i=0;
    char gateway[40];

    for(pos = acl_route_table_head; pos!= NULL; pos = pos->next)
    {

        prefix2str(&pos->node.s_prefix, buf, BUFSIZ);

        if (!strcmp(buf, "::"))
            continue;
        else
        {
            vty_out (vty, "ipv6 twod-route");
            vty_out (vty, " %s", buf);
        }

        prefix2str(&pos->node.prefix, buf, BUFSIZ);
        vty_out (vty, " %s", buf);

        inet_ntop(AF_INET6,pos->node.gateway,gateway,40);
        vty_out (vty, " %s", gateway);
        if(pos->node.status == 0)
        {
            vty_out (vty, " %s", "inactive");
        }
        else
        {

            vty_out (vty, " %s", pos->node.ifp->name);
        }
        vty_out (vty, "%s",VTY_NEWLINE);
    }


    return CMD_SUCCESS;

}



DEFUN (show_ipv6_route,
       show_ipv6_route_cmd,
       "show ipv6 route",
       SHOW_STR IP_STR
       "IPv6 routing table\n")
{
    struct route_table *table;
    struct route_table *table_customize;
    struct route_node *rn;
    struct rib *rib;
    int first = 1;
    int i = 0;

    table = vrf_table (AFI_IP6, SAFI_UNICAST, 0);
    if (!table)
        return CMD_SUCCESS;

    /* Show all IPv6 route. */
    for (rn = route_top (table); rn; rn = route_next (rn))
        for (rib = rn->info; rib; rib = rib->next)
        {
            if (first)
            {
                vty_out (vty, SHOW_ROUTE_V6_HEADER);
                first = 0;
            }
            vty_show_ipv6_route (vty, rn, rib);
        }
#if 0
    table_customize = vrf_table (AFI_IP6, SAFI_CUSTOMIZE_ONE, 0);
    if (!table_customize)
        return CMD_SUCCESS;

    /* Show all IPv6 route. */
    for (rn = route_top (table_customize); rn; rn = route_next (rn))
        for (rib = rn->info; rib; rib = rib->next)
        {
            vty_show_ipv6_route (vty, rn, rib);
        }
#endif
    //vty_out (vty, SHOW_C_ROUTE_V6_HEADER);
    int first_show =0;
    for(i = 6; i < 14; i++)
    {
        table_customize = vrf_table (AFI_IP6, i, 0);
        if (!table_customize)
            continue;
        if(table_customize->use_flag == 0)
            continue;
        if(first_show == 0)
        {
            first_show = 1;
            vty_out (vty,"\n       ----< SDN route table >-----        \n");
        }
        vty_out(vty,"route table name:%s\n",table_customize->table_name);
        vty_out(vty,"describe:%s\n",table_customize->describe);
        //printf("route table name:%s",table_customize->table_name);
        //printf("describe:%s",table_customize->describe);
        /* Show all IPv6 route. */
        for (rn = route_top (table_customize); rn; rn = route_next (rn))
            for (rib = rn->info; rib; rib = rib->next)
            {
                vty_show_c_ipv6_route (vty, rn, rib);
            }
    }
    return CMD_SUCCESS;
}
DEFUN (show_ipv6_route_table_name,
       show_ipv6_route_table_name_cmd,
       "show ipv6 route WORD",
       SHOW_STR
       IP_STR
       "IPv6 routing table\n")
{
    printf("show ipv6 route table name\n");
    struct route_table *table;
    struct route_table *table_customize;
    struct route_node *rn;
    struct rib *rib;
    int first = 1;
    int i = 0;
    struct vrf *vrf;
    vrf = vrf_lookup (0);
    for(i = 6; i < 14; i++)
    {
        if(!strcmp(vrf->table[AFI_IP6][i]->table_name, argv[0]))
        {
            break;
        }
    }
    if(i < 14)
    {
        table_customize = vrf_table (AFI_IP6, i, 0);
        if (!table_customize)
            return CMD_SUCCESS;
        vty_out(vty,"route table name:%s\n",table_customize->table_name);
        vty_out(vty,"describe:%s\n",table_customize->describe);
        //printf("route table name:%s",table_customize->table_name);
        //printf("describe:%s",table_customize->describe);
        /* Show all IPv6 route. */
        for (rn = route_top (table_customize); rn; rn = route_next (rn))
            for (rib = rn->info; rib; rib = rib->next)
            {
                vty_show_c_ipv6_route (vty, rn, rib);
            }
    }
    else
        return CMD_SUCCESS;
}


DEFUN (show_ipv6_route_prefix_longer,
       show_ipv6_route_prefix_longer_cmd,
       "show ipv6 route X:X::X:X/M longer-prefixes",
       SHOW_STR IP_STR
       "IPv6 routing table\n"
       "IPv6 prefix\n"
       "Show route matching the specified Network/Mask pair only\n")
{
    struct route_table *table;
    struct route_node *rn;
    struct rib *rib;
    struct prefix p;
    int ret;
    int first = 1;

    table = vrf_table (AFI_IP6, SAFI_UNICAST, 0);
    if (!table)
        return CMD_SUCCESS;

    ret = str2prefix (argv[0], &p);
    if (!ret)
    {
        vty_out (vty, "%% Malformed Prefix%s", VTY_NEWLINE);
        return CMD_WARNING;
    }

    /* Show matched type IPv6 routes. */
    for (rn = route_top (table); rn; rn = route_next (rn))
        for (rib = rn->info; rib; rib = rib->next)
            if (prefix_match (&p, &rn->p))
            {
                if (first)
                {
                    vty_out (vty, SHOW_ROUTE_V6_HEADER);
                    first = 0;
                }
                vty_show_ipv6_route (vty, rn, rib);
            }
    return CMD_SUCCESS;
}

DEFUN (show_ipv6_route_protocol,
       show_ipv6_route_protocol_cmd,
       "show ipv6 route "
       QUAGGA_IP6_REDIST_STR_ZEBRA,
       SHOW_STR IP_STR
       "IP routing table\n"
       QUAGGA_IP6_REDIST_HELP_STR_ZEBRA)
{
    int type;
    struct route_table *table;
    struct route_node *rn;
    struct rib *rib;
    int first = 1;

    type = proto_redistnum (AFI_IP6, argv[0]);
    if (type < 0)
    {
        vty_out (vty, "Unknown route type%s", VTY_NEWLINE);
        return CMD_WARNING;
    }

    table = vrf_table (AFI_IP6, SAFI_UNICAST, 0);
    if (!table)
        return CMD_SUCCESS;

    /* Show matched type IPv6 routes. */
    for (rn = route_top (table); rn; rn = route_next (rn))
        for (rib = rn->info; rib; rib = rib->next)
            if (rib->type == type)
            {
                if (first)
                {
                    vty_out (vty, SHOW_ROUTE_V6_HEADER);
                    first = 0;
                }
                vty_show_ipv6_route (vty, rn, rib);
            }
    return CMD_SUCCESS;
}

DEFUN (show_ipv6_frt_route_addr,
       show_ipv6_frt_route_addr_cmd,
       "show ipv6 frt route X:X::X:X",
       SHOW_STR
       IP_STR
       "forward route table\n"
       "IPv6 routing table\n"
       "IPv6 Address\n")
{
    int ret;
    struct prefix_ipv6 p;
    struct route_table *table;
    struct route_node *rn;

    ret = str2prefix_ipv6 (argv[0], &p);
    if (ret <= 0)
    {
        vty_out (vty, "Malformed IPv6 address%s", VTY_NEWLINE);
        return CMD_WARNING;
    }

    struct zebra_config_message msg_to_dpdk;
    bzero (&msg_to_dpdk, sizeof (struct zebra_config_message));
    msg_to_dpdk.type = SHOW_ROUTE_FROM_LPM;
    msg_to_dpdk.len = sizeof (struct zebra_config_message) + strlen(argv[0])+1;
    msg_to_dpdk.data = argv[0];
    zebra_connect_dpdk_send_route_lookup(vty, &msg_to_dpdk, msg_to_dpdk.len - sizeof (struct zebra_config_message));

    return CMD_SUCCESS;
}


DEFUN (show_ipv6_route_addr,
       show_ipv6_route_addr_cmd,
       "show ipv6 route X:X::X:X",
       SHOW_STR
       IP_STR
       "IPv6 routing table\n"
       "IPv6 Address\n")
{
    int ret;
    struct prefix_ipv6 p;
    struct route_table *table;
    struct route_node *rn;

    ret = str2prefix_ipv6 (argv[0], &p);
    if (ret <= 0)
    {
        vty_out (vty, "Malformed IPv6 address%s", VTY_NEWLINE);
        return CMD_WARNING;
    }

    table = vrf_table (AFI_IP6, SAFI_UNICAST, 0);
    if (!table)
        return CMD_SUCCESS;

    rn = route_node_match (table, (struct prefix *) &p);
    if (!rn)
    {
        vty_out (vty, "%% Network not in table%s", VTY_NEWLINE);
        return CMD_WARNING;
    }

    vty_show_ipv6_route_detail (vty, rn);

    route_unlock_node (rn);

    return CMD_SUCCESS;
}

DEFUN (show_ipv6_route_prefix, show_ipv6_route_prefix_cmd, "show ipv6 route X:X::X:X/M", SHOW_STR IP_STR "IPv6 routing table\n" "IPv6 prefix\n")
{
    int ret;
    struct prefix_ipv6 p;
    struct route_table *table;
    struct route_node *rn;

    ret = str2prefix_ipv6 (argv[0], &p);
    if (ret <= 0)
    {
        vty_out (vty, "Malformed IPv6 prefix%s", VTY_NEWLINE);
        return CMD_WARNING;
    }

    table = vrf_table (AFI_IP6, SAFI_UNICAST, 0);
    if (!table)
        return CMD_SUCCESS;

    rn = route_node_match (table, (struct prefix *) &p);
    if (!rn || rn->p.prefixlen != p.prefixlen)
    {
        vty_out (vty, "%% Network not in table%s", VTY_NEWLINE);
        return CMD_WARNING;
    }

    vty_show_ipv6_route_detail (vty, rn);

    route_unlock_node (rn);

    return CMD_SUCCESS;
}

/* Show route summary.  */
DEFUN (show_ipv6_route_summary, show_ipv6_route_summary_cmd, "show ipv6 route summary", SHOW_STR IP_STR "IPv6 routing table\n" "Summary of all IPv6 routes\n")
{
    struct route_table *table;

    table = vrf_table (AFI_IP6, SAFI_UNICAST, 0);
    if (!table)
        return CMD_SUCCESS;

    vty_show_ip_route_summary (vty, table);

    return CMD_SUCCESS;
}

/*
 * Show IP mroute command to dump the BGP Multicast
 * routing table
 */
DEFUN (show_ip_mroute,
       show_ip_mroute_cmd,
       "show ip mroute",
       SHOW_STR IP_STR
       "IP Multicast routing table\n")
{
    struct route_table *table;
    struct route_node *rn;
    struct rib *rib;
    int first = 1;

    table = vrf_table (AFI_IP, SAFI_MULTICAST, 0);
    if (!table)
        return CMD_SUCCESS;

    /* Show all IPv4 routes. */
    for (rn = route_top (table); rn; rn = route_next (rn))
        for (rib = rn->info; rib; rib = rib->next)
        {
            if (first)
            {
                vty_out (vty, SHOW_ROUTE_V4_HEADER);
                first = 0;
            }
            vty_show_ip_route (vty, rn, rib);
        }
    return CMD_SUCCESS;
}

/*
 * Show IPv6 mroute command.Used to dump
 * the Multicast routing table.
 */

DEFUN (show_ipv6_mroute,
       show_ipv6_mroute_cmd,
       "show ipv6 mroute",
       SHOW_STR IP_STR
       "IPv6 Multicast routing table\n")
{
    struct route_table *table;
    struct route_node *rn;
    struct rib *rib;
    int first = 1;

    table = vrf_table (AFI_IP6, SAFI_MULTICAST, 0);
    if (!table)
        return CMD_SUCCESS;

    /* Show all IPv6 route. */
    for (rn = route_top (table); rn; rn = route_next (rn))
        for (rib = rn->info; rib; rib = rib->next)
        {
            if (first)
            {
                vty_out (vty, SHOW_ROUTE_V6_HEADER);
                first = 0;
            }
            vty_show_ipv6_route (vty, rn, rib);
        }
    return CMD_SUCCESS;
}

/* Write IPv6 static route configuration. */
static int static_config_ipv6 (struct vty *vty)
{
    struct route_node *rn;
    struct static_ipv6 *si;
    int write;
    char buf[BUFSIZ];
    struct route_table *stable;

    write = 0;

    /* Lookup table.  */
    stable = vrf_static_table (AFI_IP6, SAFI_UNICAST, 0);
    if (!stable)
        return -1;

    for (rn = route_top (stable); rn; rn = route_next (rn))
        for (si = rn->info; si; si = si->next)
        {
            vty_out (vty, "ipv6 route %s/%d", inet_ntop (AF_INET6, &rn->p.u.prefix6, buf, BUFSIZ), rn->p.prefixlen);

            switch (si->type)
            {
            case STATIC_IPV6_GATEWAY:
                vty_out (vty, " %s", inet_ntop (AF_INET6, &si->ipv6, buf, BUFSIZ));
                break;
            case STATIC_IPV6_IFNAME:
                vty_out (vty, " %s", si->ifname);
                break;
            case STATIC_IPV6_GATEWAY_IFNAME:
                vty_out (vty, " %s %s", inet_ntop (AF_INET6, &si->ipv6, buf, BUFSIZ), si->ifname);
                break;
            }

            if (CHECK_FLAG (si->flags, ZEBRA_FLAG_REJECT))
                vty_out (vty, " %s", "reject");

            if (CHECK_FLAG (si->flags, ZEBRA_FLAG_BLACKHOLE))
                vty_out (vty, " %s", "blackhole");

            if (si->distance != ZEBRA_STATIC_DISTANCE_DEFAULT)
                vty_out (vty, " %d", si->distance);
            vty_out (vty, "%s", VTY_NEWLINE);

            write = 1;
        }
    return write;
}
#endif /* HAVE_IPV6 */

#ifdef HAVE_DNS64
void dns64_prfix_dns_set (char *v6p, char *v4Dnstr)
{
    char v6_str[INET6_ADDRSTRLEN];
    struct prefix stv6p;

    struct prefix_ipv4 v4p;

    str2prefix (v6p, &stv6p);
    memset (&v6prefix, 0x0, sizeof (struct prefix));
    memcpy (&v6prefix, &stv6p, sizeof (struct prefix));
    str2prefix_ipv4 (v4Dnstr, &v4p);
    v4Dns = v4p.prefix.s_addr;

    printf ("v4dns is %d\n", v4Dns);

    //与dns64进程进行socket通信
}

void dns64_prfix_dns_unset ()
{
    memset (&v6prefix, 0x0, sizeof (struct prefix));
    v4Dns = 0;
    //与dns64进程进行socket通信
}

BYTE dns64_config_check ()
{

    if (v6prefix.prefixlen < 0 || v6prefix.prefixlen > 96)
    {
        return 1;
    }
    if ((v6prefix.u.prefix6.s6_addr32[0] == 0) && (v6prefix.u.prefix6.s6_addr32[1] == 0) && (v6prefix.u.prefix6.s6_addr32[2] == 0) && (v6prefix.u.prefix6.s6_addr32[3] == 0))
    {
        return 1;
    }
    return 0;
}

DEFUN (dns64_prefix,
       dns64_prefix_cmd,
       "dns64 prefix X:X::X:X/M (ubit|no-ubit) dns A.B.C.D",
       "ipv6 dns to IPv4 dns translator\n" "Nat64 or ivi ipv6 prefix\n" "Prefix/prefix_length\n" "with ubit\n" "without ubit\n" "Configure IPv4 dns\n" "IPv4 address of dns\n")
{
    int ret;
    struct prefix v6p;
    struct prefix_ipv4 v4p;

    ret = str2prefix (argv[0], &v6p);
    if (ret <= 0)
    {
        vty_out (vty, "%% Malformed IPv6 address%s", VTY_NEWLINE);
        return CMD_WARNING;
    }

    if (v6p.prefixlen < 0 || v6p.prefixlen > 96)
    {
        vty_out (vty, "%% Malformed IPv6 prefix length%s", VTY_NEWLINE);
        return CMD_WARNING;
    }

    if ((v6p.u.prefix6.s6_addr32[0] == 0) && (v6p.u.prefix6.s6_addr32[1] == 0) && (v6p.u.prefix6.s6_addr32[2] == 0) && (v6p.u.prefix6.s6_addr32[3] == 0))
    {
        vty_out (vty, "%% Malformed IPv6 address%s", VTY_NEWLINE);
        return CMD_WARNING;
    }

    ret = str2prefix_ipv4 (argv[2], &v4p);

    if (ret <= 0)
    {
        vty_out (vty, "%% Malformed IPv4 address%s", VTY_NEWLINE);
        return CMD_WARNING;
    }

    if (v4p.prefix.s_addr == 0)
    {
        vty_out (vty, "%% Malformed IPv4 address%s", VTY_NEWLINE);
    }
    dns64_prfix_dns_set (argv[0], argv[2]);
#if 0
    if (strcmp ("ubit", argv[2]) == 0)
    {
        dns64_ubit = 1;
    }
    else if (strcmp ("no-ubit", argv[2]) == 0)
    {
        dns64_ubit = 0;
    }
    else
    {
        vty_out (vty, "%% Malformed bubit%s", VTY_NEWLINE);
        //close(socketfd);
        return CMD_WARNING;
    }
#endif
    struct sockaddr_in my_addr;
    bzero (&my_addr, sizeof (my_addr));
    my_addr.sin_family = AF_INET;
    my_addr.sin_port = htons (8899);
    my_addr.sin_addr.s_addr = inet_addr ("127.0.0.1");

    int fd;
    char buf[1024] = { 0 };

    fd = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd == -1)
    {
        vty_out (vty, "socket fault!\n");
        return CMD_WARNING;
    }

    if (connect (fd, (struct sockaddr *) &my_addr, sizeof (my_addr)) == -1)
    {
        return CMD_SUCCESS;
    }
    strcpy (dnsprefix, argv[0]);
    strcpy (dnsv4, argv[2]);
    strcpy (dns64_ubit, argv[1]);
    if (dns64_ubit[0] == 'u')
        strcpy (dns64_ubit, "ubit");
    else if (dns64_ubit[0] == 'n')
        strcpy (dns64_ubit, "no-ubit");
    memset (buf, 0, sizeof (buf));
    strncpy (buf, "dns64 prefix ", strlen ("dns64 prefix "));
    strncpy (buf + strlen ("dns64 prefix "), argv[0], strlen (argv[0]));
    strncpy (buf + strlen ("dns64 prefix ") + strlen (argv[0]), " dns ", strlen (" dns "));
    strncpy (buf + strlen ("dns64 prefix ") + strlen (argv[0]) + strlen (" dns "), argv[2], strlen (argv[2]));
    strcat (buf, " ");
    strcat (buf, argv[1]);
    if (send (fd, buf, sizeof (buf), 0) == -1)
    {
        vty_out (vty, "send fault!\n");
        return CMD_WARNING;
    }

    close (fd);
    return CMD_SUCCESS;
}


void addnodeforsectionenginetable(struct sectionengine_table *newnode)
{
    struct sectionengine_table *pos = NULL;
    if(sectionengine_table_head == NULL)
    {
        sectionengine_table_head = newnode;
        sectionengine_table_head->next = NULL;
        sectionengine_table_head->prev = NULL;
        return;
    }

    for(pos = sectionengine_table_head; pos->next != NULL; pos = pos->next)
    {

    }
    newnode->prev = pos;
    pos->next =  newnode;

}

void addnodeforprocessingenginetable(struct processing_engine_table *newnode)
{
    struct processing_engine_table *pos = NULL;
    if(processingengine_table_head == NULL)
    {
        processingengine_table_head = newnode;
        processingengine_table_head->next = NULL;
        processingengine_table_head->prev = NULL;
        return;
    }

    for(pos = processingengine_table_head; pos->next != NULL; pos = pos->next)
    {

    }
    newnode->prev = pos;
    pos->next =  newnode;

}

void addnodeforflowenginetable(struct flow_engine_table *newnode)
{
    struct flow_engine_table *pos = NULL;
    if(flowengine_table_head == NULL)
    {
        flowengine_table_head = newnode;
        flowengine_table_head->next = NULL;
        flowengine_table_head->prev = NULL;
        return;
    }

    for(pos = flowengine_table_head; pos->next != NULL; pos = pos->next)
    {

    }
    newnode->prev = pos;
    pos->next =  newnode;

}




void delnode(struct sectionengine_table *pos)
{
    if(pos == sectionengine_table_head)
    {
        sectionengine_table_head = sectionengine_table_head->next;
        if(sectionengine_table_head != NULL)
        {
            sectionengine_table_head->prev = NULL;
        }
        free(pos);
        return ;
    }

    pos->prev->next = pos->next;
    if(pos->next != NULL)
    {
        pos->next->prev = pos->prev;
    }

}


void delnodefromprocessingenginetable(struct processing_engine_table *pos)
{
    if(pos == processingengine_table_head)
    {
        processingengine_table_head = processingengine_table_head->next;
        if(processingengine_table_head != NULL)
        {
            processingengine_table_head->prev = NULL;
        }
        free(pos);
        return ;
    }

    pos->prev->next = pos->next;
    if(pos->next != NULL)
    {
        pos->next->prev = pos->prev;
    }


}

void delnodefromflowenginetable(struct flow_engine_table *pos)
{
    if(pos == flowengine_table_head)
    {
        flowengine_table_head = flowengine_table_head->next;
        if(flowengine_table_head != NULL)
        {
            flowengine_table_head->prev = NULL;
        }
        free(pos);
        return ;
    }

    pos->prev->next = pos->next;
    if(pos->next != NULL)
    {
        pos->next->prev = pos->prev;
    }


}




int delnodeforsectionenginetable(struct vty *vty,char *name)
{
    struct sectionengine_table *pos = NULL;
    if(sectionengine_table_head == NULL)
    {
        return -1;
    }

    for(pos = sectionengine_table_head; pos!= NULL; pos = pos->next)
    {
        if(!strcmp(name,pos->sectionengine.sectionenginename))
        {

            if(pos->sectionengine.isused ==1)
            {
                vty_out (vty, "%% section-engine name is already binded %s", VTY_NEWLINE);
                return CMD_WARNING;

            }


            delnode(pos);
            return 0;
        }
    }
    return -1;

}



int delnodeforprocessingenginetable(struct vty *vty,char *name)
{

    struct processing_engine_table *pos = NULL;
    if(processingengine_table_head == NULL)
    {
        return -1;
    }

    for(pos = processingengine_table_head; pos!= NULL; pos = pos->next)
    {
        if(!strcmp(name,pos->processingengine.processingenginename))
        {
            if(pos->processingengine.isused ==1)
            {
                vty_out (vty, "%% process-engine name is already binded %s", VTY_NEWLINE);
                return CMD_WARNING;

            }
            if(pos->processingengine.routetable != NULL)
                pos->processingengine.routetable->isbinded = 0;
            delnodefromprocessingenginetable(pos);

            return 0;
        }
    }
    return -1;

}
int delnodeforflowenginetable(char *name)
{
    printf("del name:%s.\n", name);
    int clientid = -1;
    struct flow_engine_table *pos = NULL;
    if(flowengine_table_head == NULL)
    {
        return -1;
    }

    for(pos = flowengine_table_head; pos!= NULL; pos = pos->next)
    {
        if(!strcmp(name,pos->flowengine.flowenginename))
        {
            client_id[pos->flowengine.client_id]=0;
            clientid = pos->flowengine.client_id;
            printf("del node:%d.\n", clientid);
            pos->flowengine.sectionenginename->sectionengine.isused = 0;
            pos->flowengine.processingenginename->processingengine.isused = 0;
            delnodefromflowenginetable(pos);
            printf("clientid:%d.\n", clientid);
            return clientid;
        }
    }
    return -1;
}

struct sectionengine_table * sectionenginenameLegalitycheck(char *name)
{
    struct sectionengine_table *pos = NULL;
    if(sectionengine_table_head == NULL)
    {
        return NULL;
    }

    for(pos = sectionengine_table_head; pos!= NULL; pos = pos->next)
    {
        if(!strcmp(name,pos->sectionengine.sectionenginename))
        {
            return pos;
        }
    }

    return NULL;

}

struct processing_engine_table * processingenginenameLegalitycheck(char *name)
{
    struct processing_engine_table *pos = NULL;
    if(processingengine_table_head == NULL)
    {
        return NULL;
    }

    for(pos = processingengine_table_head; pos!= NULL; pos = pos->next)
    {
        if(!strcmp(name,pos->processingengine.processingenginename))
        {

            return pos;
        }
    }

    return NULL;

}
int flowenginenameLegalitycheck(char *name)
{
    struct flow_engine_table *pos = NULL;
    if(flowengine_table_head == NULL)
    {
        return 0;
    }

    for(pos = flowengine_table_head; pos!= NULL; pos = pos->next)
    {
        if(!strcmp(name,pos->flowengine.flowenginename))
        {

            return -1;
        }
    }

    return 0;

}



int g_U8_t_DataMemcmp(u8_t  * pbySrc, u8_t  * pbyDest, u8_t byLen)
{
    if(byLen==0)
    {
        return 0;
    }

    if(pbySrc==NULL || pbyDest==NULL)
    {
        return 1;
    }

    u8_t *pbySrcCmp, *pbyDestCmp;
    u8_t byBit=0xff;
    u8_t byQuotient=0x00;
    u8_t byRemainder=0x00;
    byQuotient=byLen/8;
    byRemainder=byLen%8;
    int i=0;

    if(byQuotient>0)
    {
        pbySrcCmp = pbySrc;
        pbyDestCmp = pbyDest;
        for(i=0; i<byQuotient; i++)
        {
            if(pbySrcCmp[i]!=pbyDestCmp[i])
            {
                return 1;
            }
        }
    }

    if(byRemainder>0)
    {
        pbySrcCmp = pbySrc;
        pbyDestCmp = pbyDest;
        byBit=byBit>>(8-byRemainder);
        byBit=byBit<<(8-byRemainder);

        if((pbySrcCmp[i]&byBit)!=(pbyDestCmp[i]&byBit))
        {
            return 1;
        }
    }

    return 0;
}


int sectionroutecheck(struct vty *vty,	struct prefix v6prefix,char *sec_name,int *comp_j)
{
    int i=0;
    struct sectionengine_table *pos = NULL;

    if(sectionengine_table_head == NULL)
    {
        return 0;
    }

    for(pos = sectionengine_table_head; pos!= NULL; pos = pos->next)
    {
        for(i=0; i<pos->sectionengine.prefixnum; i++)
        {

            /*
               if(pos->sectionengine.v6prefix[i].prefixlen == 0)
               {
               break;
               }
             */
            /*
               if(pos->sectionengine.v6prefix[i].prefixlen >= v6prefix.prefixlen)
               {
               if(!g_U8_t_DataMemcmp(&pos->sectionengine.v6prefix[i].u.prefix6,&v6prefix.u.prefix6,v6prefix.prefixlen))
               {
               return -1;
               }

               }
               else
               {
               if(!g_U8_t_DataMemcmp(&pos->sectionengine.v6prefix[i].u.prefix6,&v6prefix.u.prefix6,pos->sectionengine.v6prefix[i].prefixlen))
               {
               return -1;
               }

               }
             */

            if(pos->sectionengine.v6prefix[i].family != v6prefix.family)
                continue;

            if(pos->sectionengine.v6prefix[i].prefixlen == v6prefix.prefixlen)
            {
                if(!g_U8_t_DataMemcmp(&pos->sectionengine.v6prefix[i].u.prefix6,&v6prefix.u.prefix6,v6prefix.prefixlen))
                {
                    memcpy(sec_name,pos->sectionengine.sectionenginename,20);
                    *comp_j = i;
                    return -1;
                }

            }
            else
            {
                //if(!g_U8_t_DataMemcmp(&pos->sectionengine.v6prefix[i].u.prefix6,&v6prefix.u.prefix6,pos->sectionengine.v6prefix[i].prefixlen))
                //{
                //    return -1;
                //}

            }

        }

    }

}





int routeLegalitycheck(struct vty *vty,int argc,char **argv,char *sec_name,int *comp_i,int *comp_j)
{
    int i,j;
    int ret =0;
    struct prefix v6p_i;
    struct prefix v6p_j;

    for(i = 1; i<argc; i++)
    {

        ret = str2prefix (argv[i], &v6p_i);
        if (ret <= 0)
        {
            return CMD_WARNING;
        }


        for(j =i+1; j< argc; j++)
        {
            //if(i == j)
            // continue;
            ret = str2prefix (argv[j], &v6p_j);
            if (ret <= 0)
            {
                return CMD_WARNING;
            }


            if(v6p_i.family != v6p_j.family)
                continue;
            if(v6p_i.prefixlen >= v6p_j.prefixlen)
            {
                if(!g_U8_t_DataMemcmp(&v6p_i.u.prefix6,&v6p_j.u.prefix6,v6p_j.prefixlen))
                {
                    *comp_i = i;
                    *comp_j = j;
                    return -1;
                }
            }
            else
            {
                if(!g_U8_t_DataMemcmp(&v6p_i.u.prefix6,&v6p_j.u.prefix6,v6p_i.prefixlen))
                {
                    *comp_i = i;
                    *comp_j = j;
                    return -1;
                }
            }


        }
        ret = sectionroutecheck(vty,v6p_i,sec_name,comp_j);
        if(ret == -1)
        {
            *comp_i = i;
            return -2;
        }

    }

    return 0;

}








int addsectionengine(struct vty *vty,int argc ,char **argv)
{

    int ret;
    int i = 0;
    struct prefix v6p;
    char *name;
    struct sectionengine_table *pos;
    name = argv[0];
    char sec_name[20];
    int comp_i,comp_j;
    if(strlen(name)> 20)
    {
        vty_out(vty,"%% name is too long%s ",VTY_NEWLINE);
        return CMD_WARNING;
    }
    pos = sectionenginenameLegalitycheck(name);
    if(pos != NULL )
    {
        vty_out (vty, "%% section-engine name %s already exists %s",argv[0], VTY_NEWLINE);
        return CMD_WARNING;

    }


    ret = routeLegalitycheck(vty,argc,argv,sec_name,&comp_i,&comp_j);
    if(ret == -1)
    {
        vty_out (vty, "%% Prefix parameter %d (%s) crosses parameter %d (%s) %s",comp_i,argv[comp_i],comp_j,argv[comp_j], VTY_NEWLINE);
        return CMD_WARNING;

    }
    else if(ret == -2)
    {
        vty_out (vty, "%% prefix parameter %d (%s) has been bound by %s%s",comp_i,argv[comp_i],sec_name, VTY_NEWLINE);
        return CMD_WARNING;

    }



    struct sectionengine_table *newnode = (struct sectionengine_table *)malloc(sizeof(struct sectionengine_table));
    memset(newnode,0,sizeof(struct sectionengine_table));

    memcpy(newnode->sectionengine.sectionenginename,argv[0],strlen(argv[0]));
    newnode->sectionengine.prefixnum = argc - 1;
    for(i =1 ; i<argc; i++)
    {
        newnode->sectionengine.v6prefix[i-1].family = 10;
        ret = str2prefix (argv[i], &newnode->sectionengine.v6prefix[i-1]);
        if (ret <= 0)
        {
            vty_out (vty, "%% Malformed IPv6 address%s", VTY_NEWLINE);
            return CMD_WARNING;
        }
    }
    addnodeforsectionenginetable(newnode);




}



DEFUN (slicing_engine2,
       slicing_engine2_cmd,
       "section-engine WROD (X:X::X:X/M|A.B.C.D/M)(X:X::X:X/M|A.B.C.D/M)",
       "Configure the rules of the section-engine\n" "section-engine rule name\n" "Prefix/prefix_length\n")
{
    addsectionengine(vty,argc ,argv);

    write_file_for_dpdk_conf(vty);
    return CMD_SUCCESS;

}
DEFUN (slicing_engine3,
       slicing_engine3_cmd,
       "section-engine WROD (X:X::X:X/M|A.B.C.D/M)(X:X::X:X/M|A.B.C.D/M)(X:X::X:X/M|A.B.C.D/M)",
       "Configure the rules of the section-engine\n" "section-engine rule name\n" "Prefix/prefix_length\n")
{

    addsectionengine(vty,argc ,argv);
    write_file_for_dpdk_conf(vty);
    return CMD_SUCCESS;

}
DEFUN (slicing_engine4,
       slicing_engine4_cmd,
       "section-engine WROD (X:X::X:X/M|A.B.C.D/M)(X:X::X:X/M|A.B.C.D/M)(X:X::X:X/M|A.B.C.D/M)(X:X::X:X/M|A.B.C.D/M)",
       "Configure the rules of the section-engine\n" "section-engine rule name\n" "Prefix/prefix_length\n")
{

    addsectionengine(vty,argc ,argv);
    write_file_for_dpdk_conf(vty);
    return CMD_SUCCESS;

}

DEFUN (slicing_engine5,
       slicing_engine5_cmd,
       "section-engine WROD (X:X::X:X/M|A.B.C.D/M)(X:X::X:X/M|A.B.C.D/M)(X:X::X:X/M|A.B.C.D/M)(X:X::X:X/M|A.B.C.D/M)(X:X::X:X/M|A.B.C.D/M)",
       "Configure the rules of the section-engine\n" "section-engine rule name\n" "Prefix/prefix_length\n")
{

    addsectionengine(vty,argc ,argv);
    write_file_for_dpdk_conf(vty);
    return CMD_SUCCESS;

}


DEFUN (slicing_engine6,
       slicing_engine6_cmd,
       "section-engine WROD (X:X::X:X/M|A.B.C.D/M)(X:X::X:X/M|A.B.C.D/M)(X:X::X:X/M|A.B.C.D/M)(X:X::X:X/M|A.B.C.D/M)(X:X::X:X/M|A.B.C.D/M)(X:X::X:X/M|A.B.C.D/M)",
       "Configure the rules of the section-engine\n" "section-engine rule name\n" "Prefix/prefix_length\n")
{

    addsectionengine(vty,argc ,argv);
    write_file_for_dpdk_conf(vty);
    return CMD_SUCCESS;

}










DEFUN (slicing_engine,
       slicing_engine_cmd,
       "section-engine WROD (X:X::X:X/M|A.B.C.D/M)",
       "Configure the rules of the section-engine\n" "section-engine rule name\n" "Prefix/prefix_length\n")
{
    addsectionengine(vty,argc ,argv);
    write_file_for_dpdk_conf(vty);
    return CMD_SUCCESS;

}
DEFUN (no_slicing_engine,
       no_slicing_engine_cmd,
       "no section-engine WROD ",
       "no Configure the rules of the section-engine\n" "section-engine rule name\n")
{

    int ret;
    struct prefix v6p;
    char *name;

    name = argv[0];
    if(strlen(name)> 20)
    {
        vty_out(vty,"%% name is too long%s ",VTY_NEWLINE);
        return CMD_WARNING;
    }


    delnodeforsectionenginetable(vty,name);

    write_file_for_dpdk_conf(vty);
    return CMD_SUCCESS;

}




DEFUN (processing_engine,
       processing_engine_cmd,
       "processing-engine WROD <1-65535> <1-65536> (ivi|nat64|4over6|FW) WORD",
       "Configure the rules of the process-engine\n"
       "process-engine rule name\n"
       "route table entry value K\n"
       "bandwidth-value Mbps\n"
       "a prefix-specific and stateless address mapping mechanism for 'an IPv6 network to the IPv4 Internet' and 'the IPv4 Internet to an IPv6 network' scenarios\n"
       "Network Address and Protocol Translation from IPv6 Clients to IPv4 Servers\n"
       "ipv4 over ipv6 tunnel\n"
       "packet forwarding\n"
       "The name of the routing table that guides forwarding")
{

    int ret,i=0;
    struct vrf *vrf;
    safi_t no_use;
    safi_t  safi;
    struct processing_engine_table *pos;
    pos = processingenginenameLegalitycheck(argv[0]);
    if(pos != NULL)
    {
        vty_out (vty, "%% processing-engine name %s already exists %s",argv[0], VTY_NEWLINE);
        return CMD_WARNING;

    }

    if(!strcmp("kernelRoute",argv[4]))
    {

    }
    else
    {
        vrf = vrf_lookup (0);
        for(i = 6; i < 14; i++)
        {
            if(vrf->table[AFI_IP6][i]->use_flag == 1)
            {
                if(!strcmp(vrf->table[AFI_IP6][i]->table_name, argv[4]))
                {
                    if(vrf->table[AFI_IP6][i]->isbinded == 1)
                    {
                        vty_out (vty, "%% forwarding routing table %s is already binded  %s", VTY_NEWLINE);
                        return CMD_WARNING;

                    }
                    vrf->table[AFI_IP6][i]->isbinded = 1;
                    break;
                }
            }
            else
            {
                no_use = i;
            }
        }

        if(i < 14)
        {

        }
        else
        {
            if(no_use == 0)
            {

                vty_out (vty, "%% route table %s does not exist %s",argv[4], VTY_NEWLINE);
                return CMD_WARNING;
            }
            else
            {
                safi = no_use;
                vrf->table[AFI_IP6][safi]->use_flag = 1;
                vrf->table[AFI_IP6][safi]->isbinded = 1;
                i = safi;
                strcpy(vrf->table[AFI_IP6][safi]->table_name, argv[4]);
                strcpy(vrf->table[AFI_IP6][safi]->describe, "free table created by processing-engine");
            }
        }
#if 0
        if(i>=14)
        {
            vty_out (vty, "%% route table %s does not exist %s",argv[4], VTY_NEWLINE);
            return CMD_WARNING;
        }
#endif

    }

    struct processing_engine_table *newnode = (struct processing_engine_table *)malloc(sizeof(struct processing_engine_table));
    memset(newnode,0,sizeof(struct processing_engine_table));

    memcpy(newnode->processingengine.processingenginename,argv[0],strlen(argv[0]));
    newnode->processingengine.memoryvalue = atoi(argv[1]);
    newnode->processingengine.bandwidthvalue = atoi(argv[2]);
    if(!strcmp(argv[3],"ivi"))
    {
        newnode->processingengine.type = 1;
    }
    else if(!strcmp(argv[3],"nat64"))
    {
        newnode->processingengine.type = 2;
    }
    else if(!strcmp(argv[3],"4over6"))
    {
        newnode->processingengine.type = 3;
    }
    else if(!strcmp(argv[3],"FW"))
    {
        newnode->processingengine.type = 4;
    }
    else
    {
        vty_out (vty, "%% %s: processing engine business logic type does not exist %s", argv[3],VTY_NEWLINE);
        free(newnode);
        return CMD_WARNING;
    }


    memcpy(newnode->processingengine.rt_name,argv[4],strlen(argv[4]));
    if(!strcmp("kernelRoute",argv[4]))
    {

        newnode->processingengine.routetable = NULL;
    }
    else
    {

        newnode->processingengine.routetable = vrf->table[AFI_IP6][i];
    }



    //processing_table_head = newnode;



    addnodeforprocessingenginetable(newnode);


    write_file_for_dpdk_conf(vty);
    return CMD_SUCCESS;

}

DEFUN (no_processing_engine,
       no_processing_engine_cmd,
       "no processing-engine WROD",
       "no Configure the processing-engine\n" "processing-engine name\n" "\n")
{

    int ret;
    char *name;

    name = argv[0];
    if(strlen(name)> 20)
    {
        vty_out(vty,"%% name is too long%s ",VTY_NEWLINE);
        return CMD_WARNING;
    }

    delnodeforprocessingenginetable(vty,name);

    write_file_for_dpdk_conf(vty);
    return CMD_SUCCESS;

}



int send_real_ipv6_source_address_msg_to_dpdk(int type ,struct vty *vty,int len,char *buf)
{
    int sockfd;
    int ret;
    struct comm_head *comm;

    comm = (struct comm_head *) malloc (sizeof (struct comm_head) + len);
    if (comm == NULL)
    {
        fprintf (stderr, "%s\n", "flow engine info head malloc failed");
        return -1;
    }
    memset (comm, 0, sizeof (struct comm_head) + len);
    if(type == 0)
        comm->type =0x32;
    else
        comm->type =0x33;

    comm->len = htonl(sizeof (struct comm_head) + len);

    memcpy (comm->data, buf, len);

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


/*added by wjh for send flow-engine to dpdk*/
int send_flow_engine_to_dpdk (struct vty *vty,int len,char *buf)
{
    int sockfd;
    int ret;
    struct comm_head *comm;

    comm = (struct comm_head *) malloc (sizeof (struct comm_head) + len);
    if (comm == NULL)
    {
        fprintf (stderr, "%s\n", "flow engine info head malloc failed");
        return -1;
    }
    memset (comm, 0, sizeof (struct comm_head) + len);

    comm->type =0x2e;
    comm->len = htonl(sizeof (struct comm_head) + len);

    memcpy (comm->data, buf, len);

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

int send_del_flow_to_dpdk (struct vty *vty,int len, char *buf)
{
    int sockfd;
    int ret;
    struct comm_head *comm;

    comm = (struct comm_head *) malloc (sizeof (struct comm_head) + len);
    if (comm == NULL)
    {
        fprintf (stderr, "%s\n", "flow engine info head malloc failed");
        return -1;
    }
    memset (comm, 0, sizeof (struct comm_head) + len);

    comm->type =0x2f;
    comm->len = htonl(sizeof (struct comm_head) + len);

    memcpy (comm->data, buf, len);

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


DEFUN (addrouteforroute1,
       add_route_for_route1_cmd,
       "ipv6 route X:X::X:X/M X:X::X:X INTERFACE to WORD",
       "add route for test\n")
{

    //char file[100] = "/usr/local/etc/dpdk_customize_route2.conf";
    install_customize_route_by_file_name(argc,argv);
}



DEFUN ( acl_for_rohc_comp,
        acl_for_rohc_comp_cmd,
        "header-compression X:X::X:X/M",
        "header compression \n" "IPv6 destination prefix (e.g. 3ffe:506::/32)\n")
{

    int ret =header_compression_func (vty,0,argv[0]);
    write_file_for_dpdk_conf(vty);
    return ret;
}

DEFUN ( no_acl_for_rohc_comp,
        no_acl_for_rohc_comp_cmd,
        "no header-compression X:X::X:X/M",
        "header compression \n" "IPv6 destination prefix (e.g. 3ffe:506::/32)\n")
{

    int ret = header_compression_func (vty,1,argv[0]);
    write_file_for_dpdk_conf(vty);
    return ret;
}

DEFUN ( policy_based_route,
        policy_based_route_cmd,
        "policy-route X:X::X:X/M X:X::X:X",
        "add one policy-route\n"
        "IPv6 destination prefix (e.g. 3ffe:506::/32)\n"
        "IPv6 nexthop address\n")
{
    int ret = static_policy_based_route_func(vty,0, NULL, argv[0],argv[1], NULL);

    write_file_for_dpdk_conf(vty);
    return ret;
}
#if 1
DEFUN ( ipv6_twod_based_route,
        ipv6_twod_based_route_cmd,
        "ipv6 twod-route X:X::X:X/M X:X::X:X/M X:X::X:X",
        IPV6_STR
        "add one two dimensional route\n"
        "IPv6 source prefix (e.g. 3ff3::/64)\n"
        "IPv6 destination prefix (e.g. 3ff2::/64)\n"
        "IPv6 nexthop address\n")
{
    int ret = static_policy_based_route_func(vty,0, argv[0], argv[1], argv[2], NULL);

    write_file_for_dpdk_conf(vty);
    return ret;
}
DEFUN (no_ipv6_twod_based_route,
       no_ipv6_twod_based_route_cmd,
       "no ipv6 twod-route X:X::X:X/M X:X::X:X/M X:X::X:X",
       NO_STR
       IPV6_STR
       "IPv6 source prefix (e.g. 3ff3::/64)\n"
       "IPv6 destination prefix (e.g. 3ff2::/64)\n"
       "IPv6 nexthop address\n")
{
    int ret = static_policy_based_route_func(vty, 1, argv[0], argv[1], argv[2], NULL);

    write_file_for_dpdk_conf(vty);
    return ret;
}

#endif

DEFUN ( no_policy_based_route,
        no_policy_based_route_cmd,
        "no policy-route X:X::X:X/M X:X::X:X",
        NO_STR
        "del one policy-route\n" "IPv6 destination prefix (e.g. 3ffe:506::/32)\n" "IPv6 gateway address\n")
{

    int ret = static_policy_based_route_func(vty, 1, NULL, argv[0],argv[1],NULL);

    write_file_for_dpdk_conf(vty);
    return ret;
}


#if 1
struct inter_in_area *inter_area_head;
int flow_check_inter_area(char *ifname)
{
    struct inter_in_area *p= inter_area_head;
    if(inter_area_head == NULL)
        return 0;
    else
    {
        while(p!=NULL)
        {
            if(strcmp(ifname,p->ifname)==0)
                return -1;
            p=p->next;
        }
        return 0;
    }
}
int flow_add_area_list(char *ifname,char flag)
{
    struct inter_in_area *p= inter_area_head;
    if(inter_area_head == NULL)
    {
        inter_area_head=(struct inter_in_area *)malloc(sizeof(struct inter_in_area));
        memset(inter_area_head,0,sizeof(struct inter_in_area));
        memcpy(inter_area_head->ifname,ifname,16);
        inter_area_head->area_value = flag;
    }
    else
    {
        while(p->next!=NULL)
        {
            p=p->next;
        }
        p->next = (struct inter_in_area *)malloc(sizeof(struct inter_in_area));
        p=p->next;
        memset(p,0,sizeof(struct inter_in_area));
        memcpy(p->ifname,ifname,16);
        p->area_value = flag;
    }
    return 0;
}
#define  NETLINK_GENERIC 16
#define  MAX_PAYLOAD 1024
#define IF_MSG 1
#if 1
struct tlv_flow1
{
    unsigned char flag_switch;
    unsigned char type;
    int length;
    char data[0];
};
#endif
#if 0
struct my_test
{
    char ifname[16];
};
#endif
int send_control_msg_dpdk(struct vty*vty)
{
    int sock_fd = 0;
    int ret = 0;
    sock_fd = connect_dpdk(vty);
    if(sock_fd == -1)
    {
        printf("connect dpdk fail\n");
        return -1;
    }

    //Fill in the netlink message payload
    struct tlv_flow1 p;
    memset(&p,0,sizeof(struct tlv_flow1));
    p.flag_switch = 10;
    p.type = IF_MSG;
    struct inter_in_area *p_if= inter_area_head;
    char if_msg[MAX_PAYLOAD-sizeof(struct tlv_flow1)]="";
    int count_i = 0;
    while(p_if!= NULL)
    {
        if(p_if->area_value==INTEGRATION)
        {
            memcpy((if_msg+count_i*16),&(p_if->ifname),16);
            count_i++;
        }
        p_if=p_if->next;
    }


    p.length=16*count_i;
    char msg_load[MAX_PAYLOAD]="";
    memcpy((msg_load),&p,sizeof(struct tlv_flow1));
    memcpy((msg_load+sizeof(struct tlv_flow1)),&if_msg,16*count_i);
#if 0
    memcpy((NLMSG_DATA(nlh)),msg_load,sizeof(struct tlv_flow)+16*count_i);

    struct tlv_flow *p_test =(struct tlv_flow*)NLMSG_DATA(nlh);
    //vty_out(vty,"type is %d",p_test->type);
    int i =0;
    struct my_test *mm = (struct my_test *)(p_test->data);
    /*
       for(i=0;i<p_test->length/16;i++)
       {
       struct my_test *mm = (struct my_test *)(p_test->data + 16*i);
       vty_out(vty,"%s\n",mm->ifname);
       }
     */
    //strcpy(NLMSG_DATA(nlh),"Request IPV4 ArpTable");
    //vty_out(vty,"msg:%s%s",NLMSG_DATA(nlh),VTY_NEWLINE);

    struct iovec iov;
    memset(&iov,0,sizeof(iov));
    iov.iov_base = (void *)nlh;
    iov.iov_len =nlh->nlmsg_len;
    memset(&msg,0,sizeof(msg));
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    ret = sendmsg(sock_fd,&msg,0);
    //vty_out(vty,"send %d%s",ret,VTY_NEWLINE);
#endif
    printf ("length:%d,bytes:%d msg:%d\n", p.length, 16, p.length / 16);
    char send_msg[MAX_PAYLOAD + 8] = "";
    *(int *)&send_msg[0] = SOLDIER_PEOPLE_TRAFFIC_CONFIG_INFO;
    *(int *)&send_msg[1] = htonl(sizeof (struct tlv_flow1) + 16 * count_i + 8);
    memcpy (&send_msg[8], msg_load, sizeof (struct tlv_flow1) + 16 * count_i);
    ret = send (sock_fd, send_msg, ntohl((*(int *)&send_msg[1])), 0);
    if (ret < 0)
    {
        printf("send message to dpdk fail\n");
        close(sock_fd);
        return -1;
    }
    close(sock_fd);
    return 0;
}
int update_control_msg_to_dpdk(char *ifname,struct vty*vty)
{
#if 0
    //open file and update area_flag
    int fd_read = open("/usr/local/etc/control.conf",O_RDONLY|O_CREAT,00777);
    int fd_write = open("/usr/local/etc/control_to_kernel.conf",O_WRONLY|O_CREAT|O_TRUNC,00777);
    write_conf(fd_read,fd_write);
    close(fd_read);
    close(fd_write);
#endif
    //send to kernel
    send_control_msg_dpdk(vty);
    return 0;
}
DEFUN(enable_interface_area,
      enable_interface_area_cmd,
      "flowsp IFNAME area integration",  //(integration|people)",
      "enable flow separation by people and soldier"
      "interface name"
      "enable interface area for flow separation"
      "enable interface in integration area\n"
      //"enable interface in people area\n"
     )
{
    if(if_lookup_by_name(argv[0])==NULL)
    {
        vty_out(vty,"No such Interface%s",VTY_NEWLINE);
        return CMD_WARNING;
    }

    if(flow_check_inter_area(argv[0])<0)
    {
        vty_out(vty,"this interface has enable area%s",VTY_NEWLINE);
        return CMD_WARNING;
    }
    char flag = INTEGRATION;
    //if(!strcmp(argv[1],"people"))
    //flag = PEOPLE;
    flow_add_area_list(argv[0],flag);
    update_control_msg_to_dpdk(argv[0],vty);

    write_file_for_dpdk_conf(vty);
    return CMD_SUCCESS;
}
int flow_del_area_list(char *ifname)
{
    struct inter_in_area *p= inter_area_head;
    struct inter_in_area *p_front= p;
    if(inter_area_head == NULL)
        return 0;
    else if(!strcmp(inter_area_head->ifname,ifname))
    {
        inter_area_head=inter_area_head->next;
        free(p);
    }
    else
    {
        while(p!=NULL)
        {
            if(!strcmp(p->ifname,ifname))
            {
                p_front->next = p->next;
                free(p);
                break;
            }
            p_front = p;
            p=p->next;
        }
    }
    return 0;
}
DEFUN(no_enable_interface_area,
      no_enable_interface_area_cmd,
      "no flowsp IFNAME area",
      NO_STR
      INTERFACE_STR
      "enable interface area for flow separation"
      "enable interface in integration area\n"
      "enable interface in people area\n"
     )
{
    if(if_lookup_by_name(argv[0])==NULL)
    {
        vty_out(vty,"No such Interface%s",VTY_NEWLINE);
        return CMD_WARNING;
    }
    flow_del_area_list(argv[0]);
    update_control_msg_to_dpdk(argv[0],vty);

    write_file_for_dpdk_conf(vty);
    return CMD_SUCCESS;
}
#if 1
struct comm_head_1
{
    unsigned short len;
    char data[0];
};
struct msg_head_1
{
    char chrType;
    unsigned short len;
    char data[0];
};

struct prefix_msg_1
{
    struct in6_addr prefix;
    unsigned char prefixlen;
    unsigned char flag_swich;
};
#endif
void show_configure_info(struct vty* vty, char *recv_buf)
{
    char prefix[128];
    int i;
    int count;
    int total_msg_len;
    int single_msg_len;
    //analyze control_msg
    struct comm_head_1 *commhead = (struct comm_head_1 *) recv_buf;
    total_msg_len = ntohs (commhead->len) - sizeof (struct comm_head_1);
    single_msg_len = sizeof (struct msg_head_1) + sizeof (struct prefix_msg_1);


    count = total_msg_len / single_msg_len;
#if 1
    for (i = 0; i < count; i++)
    {
        struct msg_head_1 *msghead = (struct msg_head_1 *) (commhead->data + i * (sizeof (struct msg_head_1) + sizeof (struct prefix_msg_1)));

        //analyze prefix_msg
        struct prefix_msg_1 *prefixmsg = (struct prefix_msg_1 *) (msghead->data);

        memset (prefix, 0, sizeof (prefix));
        inet_ntop (AF_INET6, &(prefixmsg->prefix), prefix, sizeof (prefix));
        vty_out (vty, "ipv6 address:%s prefix:%d", prefix, prefixmsg->prefixlen);

        if (msghead->chrType & PEOPLE_TYPE)
        {
            if (msghead->chrType & IN_AREA)
                vty_out (vty, " people prefix, in area %s", VTY_NEWLINE);
            else
                vty_out (vty, " people prefix, out area %s", VTY_NEWLINE);

        }
        else
        {
            if (msghead->chrType & IN_AREA)
                vty_out (vty, " army prefix, in area %s", VTY_NEWLINE);
            else
                vty_out (vty, " army prefix, out area %s", VTY_NEWLINE);
        }
    }

#endif
    return 0;

}

DEFUN (show_control_server_configure,
       show_control_server_configure_cmd,
       "show control-server configrue",
       SHOW_STR
       "control server\n"
       "configrue\n")
{
    int sockfd;
    int ret;
    size_t n;
    struct sockaddr_in socketaddress;

    sockfd = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sockfd <= 0)
    {
        fprintf (stdout, "Create socket failed:%s\n", strerror (errno));
        return -1;
    }

    socketaddress.sin_family = AF_INET;
    socketaddress.sin_port = htons (LOCAL_PORT);
    socketaddress.sin_addr.s_addr = inet_addr (LOCAL_ADDRESS);

    ret = connect (sockfd, (struct sockaddr *) &socketaddress, sizeof (struct sockaddr));
    if (ret < 0)
    {
        vty_out(vty, "Connect to %s:%d failed:%s %s", LOCAL_ADDRESS, LOCAL_PORT, strerror (errno), VTY_NEWLINE);
        close (sockfd);
        return CMD_WARNING;
    }

    char recv_buf[1024*48];
    memset (recv_buf, 0, sizeof (recv_buf));
    if ((n = recv (sockfd, recv_buf, sizeof (recv_buf), 0)) < 0)
    {
        vty_out (vty, "Read failed, errno is: %s:%d %s", strerror (errno), errno, VTY_NEWLINE);
        close(sockfd);
        return CMD_WARNING;
    }
    else if (n == 0)
    {
        vty_out (vty, "Read %ld bytes %s", n, VTY_NEWLINE);
        close(sockfd);
        return CMD_WARNING;
    }
    else
    {
        show_configure_info(vty, recv_buf);
    }

    close(sockfd);
    return CMD_SUCCESS;
}
#endif
#if 1 //dpdk HA service resource transfer
DEFUN(HA_resource_transfer,
      HA_resource_transfer_cmd,
      "HA resource transfer",""
     )
{
#if 1
    FILE *fpid = NULL;
    char opvbuf[28]="";
    int num = 0;
    fpid = popen("/bin/ps |grep heartbeat | grep -v \"grep\" |wc -l","r");
    memset(opvbuf,0,sizeof(opvbuf));
    fgets(opvbuf,sizeof(opvbuf),fpid);
    num = atoi(opvbuf);
    pclose(fpid);
    if(num == 0)
        vty_out(vty,"HA service not runing%s",VTY_NEWLINE);
    else
        system("/bitway/run/dpdk_heartbeat_dir/HA_resource_transfer.sh");
#endif
    return CMD_SUCCESS;
}
#endif

int add_node_for_real_ipv6_source_address_link(struct vty *vty,struct real_ipv6_source_address_link *new_node)
{

    struct real_ipv6_source_address_link *pos;
    struct real_ipv6_source_address_link *prev;
    pos = real_ipv6_source_address_link_head;

    if(pos == NULL)
    {
        real_ipv6_source_address_link_head = new_node;
        real_ipv6_source_address_link_head->prev = NULL;
        real_ipv6_source_address_link_head->next = NULL;
        return 0;
    }

    for(; pos != NULL; pos = pos->next)
    {
        prev = pos;

        if(pos->node.source_addr_prefix.prefixlen == new_node->node.source_addr_prefix.prefixlen)
        {
            vty_out(vty,"%% find 1 %s ",VTY_NEWLINE);
            if(!g_U8_t_DataMemcmp(&pos->node.source_addr_prefix.u.prefix6,&new_node->node.source_addr_prefix.u.prefix6,new_node->node.source_addr_prefix.prefixlen))
            {
                vty_out(vty,"%% find 2 %s ",VTY_NEWLINE);
                vty_out(vty,"%% %s %s %d  %s ",pos->node.ifname,new_node->node.ifname,sizeof(new_node->node.ifname),VTY_NEWLINE);

                if(!memcmp(pos->node.ifname,new_node->node.ifname,sizeof(new_node->node.ifname)))
                {
                    vty_out(vty,"%% find 3 %s ",VTY_NEWLINE);
                    return 1;
                }
            }

        }
#if 0
        if(!memcmp(&new_node->node,&pos->node,sizeof(struct real_ipv6_source_address)))
        {

            vty_out(vty,"%% already exist %s ",VTY_NEWLINE);
            return 1;
        }
#endif
    }

    prev->next = new_node;
    new_node->prev = prev;
    new_node->next = NULL;

    return 0;

}


int del_node_for_real_ipv6_source_address_link(struct vty *vty,struct real_ipv6_source_address_link *new_node)
{

    struct real_ipv6_source_address_link *pos;
    struct real_ipv6_source_address_link *prev;
    pos = real_ipv6_source_address_link_head;

    for(; pos != NULL; pos = pos->next)
    {
        prev = pos;

        if(pos->node.source_addr_prefix.prefixlen == new_node->node.source_addr_prefix.prefixlen)
        {

            vty_out(vty,"%% find 1 %s ",VTY_NEWLINE);
            if(!g_U8_t_DataMemcmp(&pos->node.source_addr_prefix.u.prefix6,&new_node->node.source_addr_prefix.u.prefix6,new_node->node.source_addr_prefix.prefixlen))

            {

                vty_out(vty,"%% find 2 %s ",VTY_NEWLINE);
                vty_out(vty,"%% %s %s %d  %s ",pos->node.ifname,new_node->node.ifname,sizeof(new_node->node.ifname),VTY_NEWLINE);

                if(!memcmp(pos->node.ifname,new_node->node.ifname,sizeof(pos->node.ifname)))
                {
                    vty_out(vty,"%% find 3 %s ",VTY_NEWLINE);

                    vty_out(vty,"%% find  %s ",VTY_NEWLINE);
                    if(pos->prev != NULL)
                        pos->prev->next = pos->next;
                    if(pos->next!= NULL)
                        pos->next->prev = pos->prev;
                    if(pos == real_ipv6_source_address_link_head)
                        real_ipv6_source_address_link_head = pos->next;
                    free(pos);
                    return 0;
                }
            }
        }
    }

    return 1;

}






DEFUN ( access_real_ipv6_source_address,
        access_real_ipv6_source_address_cmd,
        "access-ipv6 permit X:X::X:X/M on WORD",
        "add access permit ipv6 source address\n" "IPv6 destination prefix (e.g. 3ffe:506::/32)\n" "interface name\n")
{
    int ret;
    vty_out(vty,"%% permint %s %s %s ",argv[0],argv[1],VTY_NEWLINE);

    struct real_ipv6_source_address_link *new_node;
    new_node = (struct real_ipv6_source_addrss_link *)malloc(sizeof(struct real_ipv6_source_address_link));
    if(new_node == NULL)
    {
        vty_out(vty,"%% Application RAM failure!%s ",VTY_NEWLINE);
        return CMD_WARNING;
    }

    memset(new_node,0,sizeof(struct real_ipv6_source_address_link));

    ret = str2prefix (argv[0], &new_node->node.source_addr_prefix);
    if (ret <= 0)
    {
        vty_out (vty, "%% Malformed IPv6 address%s", VTY_NEWLINE);
        return CMD_WARNING;
    }

    memcpy(new_node->node.ifname,argv[1],strlen(argv[1]));
    ret = add_node_for_real_ipv6_source_address_link(vty,new_node);

    vty_out(vty,"%% add ret = %d  %s ",ret,VTY_NEWLINE);
    if(ret == 0)
    {
        send_real_ipv6_source_address_msg_to_dpdk(0,vty,sizeof(struct real_ipv6_source_address),(char *)&new_node->node);
    }
    else
    {

        free(new_node);
    }

    write_file_for_dpdk_conf(vty);

}

DEFUN ( no_access_real_ipv6_source_address,
        no_access_real_ipv6_source_address_cmd,
        "no access-ipv6 permit X:X::X:X/M on WORD",
        "no add access permit ipv6 source address\n" "IPv6 destination prefix (e.g. 3ffe:506::/32)\n" "interface name\n")
{

    int ret;
    vty_out(vty,"%% permint %s %s %s ",argv[0],argv[1],VTY_NEWLINE);

    struct real_ipv6_source_address_link *new_node;
    new_node = (struct real_ipv6_source_addrss_link *)malloc(sizeof(struct real_ipv6_source_address_link));
    if(new_node == NULL)
    {
        vty_out(vty,"%% Application RAM failure!%s ",VTY_NEWLINE);
        return CMD_WARNING;
    }

    memset(new_node,0,sizeof(struct real_ipv6_source_address_link));
    ret = str2prefix (argv[0], &new_node->node.source_addr_prefix);
    if (ret <= 0)
    {
        vty_out (vty, "%% Malformed IPv6 address%s", VTY_NEWLINE);
        return CMD_WARNING;
    }

    memcpy(new_node->node.ifname,argv[1],strlen(argv[1]));
    ret = del_node_for_real_ipv6_source_address_link(vty,new_node);

    vty_out(vty,"%% del ret = %d  %s ",ret,VTY_NEWLINE);
    if(ret == 0)
    {
        send_real_ipv6_source_address_msg_to_dpdk(1,vty,sizeof(struct real_ipv6_source_address),(char *)&new_node->node);
    }


    free(new_node);

    write_file_for_dpdk_conf(vty);
}


int send_ipv6_server_forwarding_status_to_dpdk (struct vty *vty, uint8_t status)
{
    int sockfd;
    int ret;
    struct comm_head *comm;

    comm = (struct comm_head *) malloc (sizeof (struct comm_head) + 1);
    if (comm == NULL)
    {
        fprintf (stderr, "%s\n", "flow engine info head malloc failed");
        return -1;
    }
    memset (comm, 0, sizeof (struct comm_head) + 1);

    comm->type =0x36;
    comm->len = htonl(sizeof (struct comm_head) + 1);

    comm->data[0] = status;

    sockfd = connect_dpdk(vty);
    ret = send (sockfd, (char *) comm, sizeof (struct comm_head) + 1, 0);
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



DEFUN (ipv6_server_forwarding,
       ipv6_server_forwarding_cmd,
       "ip server forwarding",
       "set server default action is forwarding\n")
{
    ipv6_server_forwarding_status  = 1;
    send_ipv6_server_forwarding_status_to_dpdk (vty, 1);
    write_file_for_dpdk_conf(vty);
    return CMD_SUCCESS;
}

DEFUN (no_ipv6_server_forwarding,
       no_ipv6_server_forwarding_cmd,
       "no ip server forwarding",
       "set server default action is not forwarding\n")
{
    ipv6_server_forwarding_status  = 0;
    send_ipv6_server_forwarding_status_to_dpdk (vty, 0);
    write_file_for_dpdk_conf(vty);
    return CMD_SUCCESS;
}


int ifmpclientexist(int client_id)
{
    FILE *ptr = NULL;
    char cmd[128];
    int status = 0;
    char buf[150];
    int count;

    memset(cmd,0,128);
    sprintf(cmd,"ps -ef | grep mp_client%d | grep -v grep | wc -l",client_id);

    if((ptr = popen(cmd, "r"))==NULL)
    {
        printf("popen err\n");
    }

    memset(buf, 0, sizeof(buf));

    if((fgets(buf, sizeof(buf),ptr))!= NULL)//靠靠靠靠靠�
    {
        count = atoi(buf);
        if(count <= 0)//靠靠靠靠0靠靠靠靠�
        {
            printf("not exist \n");
            return 0;
        }
        else
        {

            printf("exist \n");
            return 1;
        }

    }

    return 0;
}



DEFUN (flow_engine,
       flow_engine_cmd,
       "flow-engine WROD WROD WROD",
       "Configure one flow-engine\n" "flow-engine name\n" "section-engine name\n" "processing-engine name\n")
{

    struct flow_engine_table *newnode;
    struct sectionengine_table *pos;
    struct processing_engine_table *process_pos;
    int i,index,j;
    if(strlen(argv[0])> 20)
    {
        vty_out(vty,"%% flow-engine name is too long%s ",VTY_NEWLINE);
        return CMD_WARNING;
    }

    if(strlen(argv[1])> 20)
    {
        vty_out(vty,"%% section-engine name is too long%s ",VTY_NEWLINE);
        return CMD_WARNING;
    }

    if(strlen(argv[2])> 20)
    {
        vty_out(vty,"%% processing-engine name is too long%s ",VTY_NEWLINE);
        return CMD_WARNING;
    }

    int ret;
    ret = flowenginenameLegalitycheck(argv[0]);
    if(ret == -1)
    {
        vty_out (vty, "%% flow-engine name %s already exists %s",argv[0], VTY_NEWLINE);
        return CMD_WARNING;

    }

    pos = sectionenginenameLegalitycheck(argv[1]);
    if(pos == NULL )
    {
        vty_out (vty, "%% section-engine name %s is not exist %s",argv[1], VTY_NEWLINE);
        return CMD_WARNING;

    }
    else if(pos->sectionengine.isused == 1)
    {
        vty_out (vty, "%% section-engine name %s has been bound %s",argv[1], VTY_NEWLINE);
        return CMD_WARNING;

    }
    process_pos= processingenginenameLegalitycheck(argv[2]);
    if(process_pos == NULL)
    {
        vty_out (vty, "%% processing-engine name %s is not exist %s",argv[2], VTY_NEWLINE);
        return CMD_WARNING;

    }
    else if(process_pos->processingengine.isused == 1)
    {
        vty_out (vty, "%% processing-engine name %s has been bound %s",argv[2], VTY_NEWLINE);
        return CMD_WARNING;

    }



    newnode = (struct flow_engine_table *)malloc(sizeof(struct flow_engine_table));
    memset(newnode,0,sizeof(struct flow_engine_table));
    memcpy(newnode->flowengine.flowenginename,argv[0],strlen(argv[0]));
    //  memcpy(newnode->flowengine.sectionenginename,argv[1],strlen(argv[1]));
    //  memcpy(newnode->flowengine.processingenginename,argv[2],strlen(argv[2]));
    newnode->flowengine.sectionenginename = pos;
    newnode->flowengine.processingenginename = process_pos;


    char *buf;
    int buf_len = 20+1+sizeof(struct prefix)*pos->sectionengine.prefixnum+sizeof(struct processingengine_info);


    buf = (char *)malloc(buf_len);
    memset(buf,0,buf_len);


    memcpy(buf,argv[0],20);
    unsigned char num = pos->sectionengine.prefixnum;
    buf[20] = num;
    for(i=0; i<num; i++)
    {
        char pfx_buf[128];
        struct prefix *prefix;
        prefix = (struct prefix *)malloc(sizeof(struct prefix));
        memset(prefix,0,sizeof(struct prefix));
        prefix2str (&pos->sectionengine.v6prefix[i], pfx_buf, sizeof (pfx_buf));
        //vty_out (vty, "%% pfx_buf:%s%s", pfx_buf,VTY_NEWLINE);

        ret = str2prefix (pfx_buf,prefix);
        memcpy(buf+20+1+sizeof(struct prefix)*i,prefix,sizeof(struct prefix));
        /*
           vty_out (vty, "%% family = :%d%s", prefix->family,VTY_NEWLINE);
           vty_out (vty, "%% prelen = :%d%s", prefix->prefixlen,VTY_NEWLINE);
           vty_out (vty, "%% prelen = :%d%s", buf[20+1+sizeof(struct prefix)*i+1],VTY_NEWLINE);
           vty_out (vty, "%% family = :%d%s", buf[20+1+sizeof(struct prefix)*i],VTY_NEWLINE);
         */
    }
    struct processingengine_info *processinginfo;
    processinginfo = (struct processingengine_info *)malloc(sizeof(struct processingengine_info));
    memset(processinginfo,0,sizeof(struct processingengine_info));
    *(int *) &processinginfo->memory = htonl(process_pos->processingengine.memoryvalue);
    *(int *) &processinginfo->bandwidth = htonl(process_pos->processingengine.bandwidthvalue);
    processinginfo->type = process_pos->processingengine.type;
    memcpy(processinginfo->rtname,process_pos->processingengine.rt_name,32);
    for(j=0; j< CLENT_ID_UNM; j++)
    {
        if(client_id[j] == 0)
        {
            client_id[j] = 1;
            break;
        }
    }
    if(j>= CLENT_ID_UNM)
    {
        vty_out (vty, "%% the number of traffic engines reaches the upper limit  %s", VTY_NEWLINE);
        return CMD_WARNING;

    }
    processinginfo->id = j;

    //vty_out (vty, "%% processinginfo->id = %d  %s",processinginfo->id, VTY_NEWLINE);
    pos->sectionengine.isused = 1;
    process_pos->processingengine.isused = 1;

    memcpy(buf+20+1+sizeof(struct prefix)*num,processinginfo,sizeof(struct processingengine_info));

    //vty_out (vty, "%% memory = :%d%s", ntohl(*(int *) &buf[20+1+sizeof(struct prefix)*i]),VTY_NEWLINE);
    //vty_out (vty, "%% bandwidth = :%d%s", ntohl(*(int *) &buf[20+1+sizeof(struct prefix)*i+4]),VTY_NEWLINE);

    if(!ifmpclientexist(processinginfo->id))
        send_flow_engine_to_dpdk(vty,buf_len,buf);


    newnode->flowengine.client_id = j;
    addnodeforflowenginetable(newnode);

#if 0
    char cmd[256];
    memset(cmd, 0, sizeof(cmd));
    //sprintf(cmd, "/bin/cp /bitway/mp_client/mp_client /bitway/mp_client/mp_client%d", processinginfo->id);
    sprintf(cmd, "/bin/cp /root/hbl/dpdk-2.1.0/work_code_dir/mp_server_client/mp_client/build/mp_client /root/hbl/dpdk-2.1.0/work_code_dir/mp_server_client/mp_client/build/mp_client%d", processinginfo->id);
    printf("cmd:%s.\n", cmd);
    system(cmd);

    memset(cmd, 0, sizeof(cmd));
    //sprintf(cmd, "/bitway/mp_client/mp_client%d -l 2 -n 4 --proc-type=auto -- -n 1 >> \"/root/dpdk_logs/`date`.log\" &", processinginfo->id);
    sprintf(cmd, "/root/hbl/dpdk-2.1.0/work_code_dir/mp_server_client/mp_client/build/mp_client%d -l 3 -n 4 --proc-type=auto  -- -P -p 0x03 -n %d --l3fwd_config=\"(0,0,3),(1,0,3)\" --kni_config=\"(0,2,3,3,3,3,3,3),(1,3,3,3,3,3,3,3)\" >> \"/root/dpdk_logs/`date`.log\" &", processinginfo->id, processinginfo->id);
    printf("cmd:%s.\n", cmd);
    system(cmd);
#endif
    //system("/bin/sh /root/hbl/dpdk-2.1.0/work_code_dir/mp_server_client/mp_client/client_start.sh");
#if 1
    char cmd[512];
    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "/bin/cp /bitway/run/mp_client /bitway/mp_client/mp_client%d", processinginfo->id);
    printf("cmd:%s.\n", cmd);
    system(cmd);

    int k=0;
    for(k=0; k<6; k++)
    {
        system("umount /mnt/huge");
    }

    memset(cmd, 0, sizeof(cmd));
    //sprintf(cmd, "/bitway/mp_client/mp_client%d -l 2 -n 4 --proc-type=auto -- -n 1 >> \"/root/dpdk_logs/`date`.log\" &", processinginfo->id);
    //sprintf(cmd, "gdb --args /bitway/mp_client/mp_client%d -l %d -n 4 --proc-type=auto  -- -n %d 0</bitway/mp_client/cmd.txt >> \"/root/dpdk_logs/`date`_%d.log\" &", processinginfo->id,processinginfo->id+3, processinginfo->id, processinginfo->id);
    //sprintf(cmd, "/bitway/mp_client/mp_client%d -l %d -n 4 --proc-type=secondary  --socket-mem=512  -- -n %d >> \"/logs_directories/dpdk_logs/`date`_%d.log\" &", processinginfo->id,processinginfo->id+3, processinginfo->id, processinginfo->id);

    sprintf(cmd, "/bitway/mp_client/mp_client%d -l %d -n 4 --proc-type=secondary  --socket-mem=512  -- -n %d >> /logs_directories/dpdk_logs/mp_client%d_on_core%d.log &", processinginfo->id,processinginfo->id+3, processinginfo->id, processinginfo->id,processinginfo->id+3);

    printf("cmd:%s.\n", cmd);

    if(!ifmpclientexist(processinginfo->id))
        system(cmd);
#endif
    //system("/bin/sh /root/hbl/dpdk-2.1.0/work_code_dir/mp_server_client/mp_client/client_start.sh");


    write_file_for_dpdk_conf(vty);
    return CMD_SUCCESS;
}

int kill_process_by_name(char *processname)
{
    FILE *pstr;
    char cmd[128],buff[512],*p;
    pid_t pID;
    int pidnum;

    int ret= -1;
    memset(cmd,0,sizeof(cmd));
    sprintf(cmd, "ps -ef|grep %s ",processname);
    pstr=popen(cmd, "r");
    if(pstr==NULL)
    {
        return 1;
    }
    memset(buff,0,sizeof(buff));
    fgets(buff,512,pstr);
    p=strtok(buff, " ");
    p=strtok(NULL, " ");
    pclose(pstr);
    if(p==NULL)
    {
        return 1;
    }
    if(strlen(p)==0)
    {
        return 1;
    }
    if((pidnum=atoi(p))==0)
    {
        return 1;
    }
    printf("pidnum: %d\n",pidnum);
    pID=(pid_t)pidnum;
    //ret=kill(pID,0);
    ret=kill(pID, 9);
    printf("ret= %d \n",ret);
    if(0==ret)
        printf("process: %s kill!\n", processname);
    else
        printf("process: %s not kill!\n",processname);
    return 0;
}

DEFUN (no_flow_engine,
       no_flow_engine_cmd,
       "no flow-engine WROD ",
       "no one flow-engine\n")
{
    char *name;
    char processname[32];
    int ret;

    name = argv[0];
    if(strlen(name)> 20)
    {
        vty_out(vty,"%% name is too long%s ",VTY_NEWLINE);
        return CMD_WARNING;
    }

    ret = delnodeforflowenginetable(name);
    if(ret == -1)
    {
        vty_out(vty,"%% threr is no %s this flow-engine %s ",name,VTY_NEWLINE);
    }

    send_del_flow_to_dpdk(vty, 20, name);

    sprintf(processname, "mp_client%d", ret);
    //printf("processname:%s.\n", processname);
    kill_process_by_name(processname);

    write_file_for_dpdk_conf(vty);
    return CMD_SUCCESS;
}


DEFUN (GigabitEthernet,
       GigabitEthernet_cmd,
       "interface gigabitethernet WROD",
       "select one interface tunnel to configure \n"
       "Enable the configuration of the virtual sub-interface, associated physical port, and IPv4/IPv6 address of the interface.\n" "name phynum_virnum\n" )
{



#if 1
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



#endif






}

DEFUN (no_dns64_prefix, no_dns64_prefix_cmd, "no dns64 prefix", NO_STR "ipv6 dns to IPv4 dns translator\n" "Nat64 or ivi ipv6 prefix\n")
{
    dns64_prfix_dns_unset ();

    struct sockaddr_in my_addr;
    bzero (&my_addr, sizeof (my_addr));
    my_addr.sin_family = AF_INET;
    my_addr.sin_port = htons (8899);
    my_addr.sin_addr.s_addr = inet_addr ("127.0.0.1");

    int fd;
    char buf[1024] = { 0 };

    if ((dnsprefix[0] == '\0') && (dnsv4[0] == '\0'))
    {
        vty_out (vty, "You does not config dnsprefix,can't delete!\n");
        return CMD_SUCCESS;
    }

    fd = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd == -1)
    {
        vty_out (vty, "socket fault!\n");
        return CMD_WARNING;
    }

    if (connect (fd, (struct sockaddr *) &my_addr, sizeof (my_addr)) == -1)
    {
        return CMD_SUCCESS;
    }
    /*
       vty_out(vty,"------%s-----\n",dnsprefix);
       vty_out(vty,"------%s-----\n",dnsv4);
       vty_out(vty,"------%d--%d---\n",sizeof(dnsv4),strlen(dnsv4));
     */
    memset (buf, 0, sizeof (buf));
    strncpy (buf, "no dns64 prefix ", strlen ("no dns64 prefix "));
    strncpy (buf + strlen ("no dns64 prefix "), dnsprefix, strlen (dnsprefix));
    strncpy (buf + strlen ("no dns64 prefix ") + strlen (dnsprefix), " dns ", strlen (" dns "));
    strncpy (buf + strlen ("no dns64 prefix ") + strlen (dnsprefix) + strlen (" dns "), dnsv4, strlen (dnsv4));
    strcat (buf, " ");
    strcat (buf, dns64_ubit);

    if (send (fd, buf, sizeof (buf), 0) == -1)
    {
        vty_out (vty, "send fault!\n");
        return CMD_WARNING;
    }

    memset (dnsprefix, 0, sizeof (dnsprefix));
    memset (dnsv4, 0, sizeof (dnsv4));
    close (fd);

    return CMD_SUCCESS;
}
#endif
#ifdef HAVE_SNMP
//added for snmp community config  2013.7.31
#define TCP_SNMP_PORT 12345
#define MAX_STRING_LEN  1024

#pragma pack(push)
#pragma pack(1)
typedef struct msg
{
    char type;
    uint32_t len;
    char buf[1];
} sendMsg;
#pragma pack(pop)

static struct config_cmd_string *snmp_config_string = NULL;

static struct config_cmd_string *add_snmp_config_string (char *buf)
{
    struct config_cmd_string *pHead = snmp_config_string;
    while (pHead)
    {
        if (strcmp (pHead->config_string, buf) == 0)
        {
            return snmp_config_string;
        }
        pHead = pHead->next;
    }
    struct config_cmd_string *pNode = (struct config_cmd_string *) malloc (sizeof (struct config_cmd_string));
    if (pNode)
    {
        pNode->config_string = (char *) malloc (strlen (buf) + 1);
        memset (pNode->config_string, 0, strlen (buf) + 1);
        memcpy (pNode->config_string, buf, strlen (buf) + 1);
        pNode->next = NULL;
        pNode->tail = NULL;
        if (snmp_config_string == NULL)
        {
            snmp_config_string = pNode;
            snmp_config_string->tail = pNode;
        }
        else
        {
            snmp_config_string->tail->next = pNode;
            snmp_config_string->tail = pNode;
        }
    }
    return snmp_config_string;
}

static struct config_cmd_string *find_snmp_config_string (char *string)
{
    struct config_cmd_string *pCurrentNode = snmp_config_string;
    while (pCurrentNode)
    {
        if (strcmp (pCurrentNode->config_string, string) == 0)
        {
            return pCurrentNode;
        }
        pCurrentNode = pCurrentNode->next;
    }
    return NULL;
}

static struct config_cmd_string *delete_snmp_config_string (struct vty *vty, char *string)
{
    struct config_cmd_string *pFrontNode = snmp_config_string;
    struct config_cmd_string *pCurrentNode = snmp_config_string;
    while (pCurrentNode)
    {
        if (strcmp (pCurrentNode->config_string, string) == 0)
        {
            if (snmp_config_string == pCurrentNode)
            {
                if (pCurrentNode->next == NULL)
                {
                    free (pCurrentNode->config_string);
                    free (pCurrentNode);
                    snmp_config_string = NULL;
                    return NULL;
                }
                snmp_config_string = pCurrentNode->next;
                snmp_config_string->tail = pCurrentNode->tail;
            }
            else if (snmp_config_string->tail == pCurrentNode)
            {
                pFrontNode->next = pCurrentNode->next;
                snmp_config_string->tail = pFrontNode;
            }
            else
            {
                pFrontNode->next = pCurrentNode->next;
            }
            free (pCurrentNode->config_string);
            free (pCurrentNode);
            return snmp_config_string;
        }
        pFrontNode = pCurrentNode;
        pCurrentNode = pCurrentNode->next;
    }
    return NULL;
}

void free_snmp_config_string ()
{
    struct config_cmd_string *temp_snmp_config_string = NULL;
    while (snmp_config_string)
    {
        temp_snmp_config_string = snmp_config_string;
        free (temp_snmp_config_string->config_string);
        free (temp_snmp_config_string);
        snmp_config_string = snmp_config_string->next;
    }
}

static int snmp_init_socket (int fd)
{
    struct sockaddr_in addr;
    memset (&addr, 0, sizeof (addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons (TCP_SNMP_PORT);
    addr.sin_addr.s_addr = inet_addr ("127.0.0.1");

    fd = socket (AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
    {
        return -1;
    }
    if (connect (fd, (struct sockaddr *) &addr, sizeof (addr)) != 0)
    {
        return -1;
    }
    return fd;
}

static int snmp_send_config_msg (int fd, char type, char *buf)
{
    int len = strlen (buf);
    sendMsg *msg = (sendMsg *) malloc (5 + len);
    msg->type = type;
    msg->len = ntohl (5 + len);
    memcpy (msg->buf, buf, len);
    send (fd, (char *) msg, 5 + len, 0);
    close (fd);
    free (msg);
    return CMD_SUCCESS;
}

DEFUN (snmp_community_config, snmp_community_config_cmd, "snmp community WORD", SNMP_STR "snmp community config\n" "community string for snmp\n")
{
    int fd = 0;
    fd = snmp_init_socket (fd);
    if (fd < 0)
    {
        vty_out (vty, "socket fault!\r\n");
        return CMD_WARNING;
    }
    char buf[MAX_STRING_LEN] = "";
    sprintf (buf, "snmp community %.*s", strlen (argv[0]), argv[0]);
    snmp_config_string = add_snmp_config_string (buf);
    return snmp_send_config_msg (fd, 1, buf);
}

DEFUN (no_snmp_community_config, no_snmp_community_config_cmd, "no snmp community WORD", SNMP_STR "no snmp community config\n" "community string for snmp\n")
{
    int fd = 0;
    fd = snmp_init_socket (fd);
    if (fd < 0)
    {
        vty_out (vty, "socket fault!\r\n");
        return CMD_WARNING;
    }
    char buf[MAX_STRING_LEN] = "";
    sprintf (buf, "snmp community %.*s", strlen (argv[0]), argv[0]);
    struct config_cmd_string *pNode = find_snmp_config_string (buf);
    if (pNode)
    {
        snmp_config_string = delete_snmp_config_string (vty, buf);
        return snmp_send_config_msg (fd, 5, buf);
    }
    else
    {
        vty_out (vty, "config cmd not find!please check again...\r\n");
        return CMD_WARNING;
    }
}

DEFUN (snmp_v3_config,
       snmp_v3_config_cmd,
       "snmpv3 user WORD (MD5|SHA) WORD (DES|AES) WORD",
       SNMP_STR
       "snmpv3 user config\n"
       "user name\n"
       "Use HMAC MD5 algorithm for authentication\n"
       "Use HMAC SHA algorithm for authentication\n"
       "authentication password for user(no less than 8 words)\n" "Use DES EncryptionAlgorithm\n" "Use AES EncryptionAlgorithm\n" "password for user(no less than 8 words)\n")
{
    int fd = 0;
    fd = snmp_init_socket (fd);
    if (fd < 0)
    {
        vty_out (vty, "socket fault!\r\n");
        return CMD_WARNING;
    }
    char buf[MAX_STRING_LEN] = "";
    sprintf (buf, "snmpv3 user %.*s %.*s %.*s %.*s %.*s", strlen (argv[0]), argv[0], strlen (argv[1]), argv[1], strlen (argv[2]), argv[2], strlen (argv[3]), argv[3], strlen (argv[4]), argv[4]);
    snmp_config_string = add_snmp_config_string (buf);
    return snmp_send_config_msg (fd, 2, buf);
}

DEFUN (no_snmp_v3_config,
       no_snmp_v3_config_cmd,
       "no snmpv3 user WORD (MD5|SHA) WORD (DES|AES) WORD",
       SNMP_STR
       "snmpv3 user config\n"
       "user name\n"
       "Use HMAC MD5 algorithm for authentication\n"
       "Use HMAC SHA algorithm for authentication\n"
       "authentication password for user(no less than 8 words)\n" "Use DES EncryptionAlgorithm\n" "Use AES EncryptionAlgorithm\n" "password for user(no less than 8 words)\n")
{
    int fd = 0;
    fd = snmp_init_socket (fd);
    if (fd < 0)
    {
        vty_out (vty, "socket fault!\r\n");
        return CMD_WARNING;
    }

    char buf[MAX_STRING_LEN] = "";
    sprintf (buf, "snmpv3 user %.*s %.*s %.*s %.*s %.*s", strlen (argv[0]), argv[0], strlen (argv[1]), argv[1], strlen (argv[2]), argv[2], strlen (argv[3]), argv[3], strlen (argv[4]), argv[4]);
    struct config_cmd_string *pNode = find_snmp_config_string (buf);
    if (pNode)
    {
        snmp_config_string = delete_snmp_config_string (vty, buf);
        return snmp_send_config_msg (fd, 5, buf);
    }
    else
    {
        vty_out (vty, "config cmd not find!please check again...\r\n");
        return CMD_WARNING;
    }
}

DEFUN (snmp_trap_enable, snmp_trap_enable_cmd, "snmp enable traps", SNMP_STR "snmp trap enable\n" "snmp trap enable config\n")
{
    int fd = 0;
    fd = snmp_init_socket (fd);
    if (fd < 0)
    {
        vty_out (vty, "socket fault!\r\n");
        return CMD_WARNING;
    }

    char buf[MAX_STRING_LEN] = "snmp enable traps";
    snmp_config_string = add_snmp_config_string (buf);
    return snmp_send_config_msg (fd, 3, buf);
}

DEFUN (snmp_trap_disable, snmp_trap_disable_cmd, "no snmp enable traps", SNMP_STR "snmp traps disable\n" "snmp traps disable\n" "snmp traps disable\n")
{
    int fd = 0;
    fd = snmp_init_socket (fd);
    if (fd < 0)
    {
        vty_out (vty, "socket fault!\r\n");
        return CMD_WARNING;
    }
    char buf[MAX_STRING_LEN] = "snmp enable traps";
    struct config_cmd_string *pNode = find_snmp_config_string (buf);
    if (pNode)
    {
        snmp_config_string = delete_snmp_config_string (vty, buf);
        return snmp_send_config_msg (fd, 5, buf);
    }
    else
    {
        vty_out (vty, "config cmd not find!please check again...\r\n");
        return CMD_WARNING;
    }
}

DEFUN (snmp_trap_host_config,
       snmp_trap_host_config_cmd,
       "snmp host (WORD | A.B.C.D:162 | A.B.C.D)",
       SNMP_STR
       "snmp host config\n" "hostname of SNMP notification host\n" "IP address of SNMP notification host with port num 162\n" "IP address of SNMP notification host with default port num 162\n")
{
    int fd = 0;
    fd = snmp_init_socket (fd);
    if (fd < 0)
    {
        vty_out (vty, "socket fault!\r\n");
        return CMD_WARNING;
    }
    char buf[MAX_STRING_LEN] = "";
    sprintf (buf, "snmp host %.*s", strlen (argv[0]), argv[0]);
    snmp_config_string = add_snmp_config_string (buf);
    return snmp_send_config_msg (fd, 4, buf);
}

DEFUN (no_snmp_trap_host_config,
       no_snmp_trap_host_config_cmd,
       "no snmp host (WORD | A.B.C.D:162 | A.B.C.D)",
       SNMP_STR
       "no snmp host config\n"
       "no snmp host config\n" "hostname of SNMP notification host\n" "IP address of SNMP notification host with port num 162\n" "IP address of SNMP notification host with default port num 162\n")
{
    int fd = 0;
    fd = snmp_init_socket (fd);
    if (fd < 0)
    {
        vty_out (vty, "socket fault!\r\n");
        return CMD_WARNING;
    }

    char buf[MAX_STRING_LEN] = "";
    sprintf (buf, "snmp host %.*s", strlen (argv[0]), argv[0]);
    struct config_cmd_string *pNode = find_snmp_config_string (buf);
    if (pNode)
    {
        snmp_config_string = delete_snmp_config_string (vty, buf);
        return snmp_send_config_msg (fd, 5, buf);
    }
    else
    {
        vty_out (vty, "config cmd not find!please check again...\r\n");
        return CMD_WARNING;
    }
}

DEFUN (snmp_trap_host_community_config,
       snmp_trap_host_community_config_cmd,
       "snmp host (WORD | A.B.C.D:162 | A.B.C.D) traps WORD",
       SNMP_STR
       "snmp host and community config\n"
       "hostname of SNMP notification host\n"
       "IP address of SNMP notification host with port num 162\n" "IP address of SNMP notification host with default port num 162\n" "snmp trap host config\n" "community string for traps\n")
{
    int fd = 0;
    fd = snmp_init_socket (fd);
    if (fd < 0)
    {
        vty_out (vty, "socket fault!\r\n");
        return CMD_WARNING;
    }
    char buf[MAX_STRING_LEN] = "";
    sprintf (buf, "snmp host %.*s traps %.*s", strlen (argv[0]), argv[0], strlen (argv[1]), argv[1]);
    snmp_config_string = add_snmp_config_string (buf);
    return snmp_send_config_msg (fd, 4, buf);
}

DEFUN (no_snmp_trap_host_community_config,
       no_snmp_trap_host_community_config_cmd,
       "no snmp host (WORD | A.B.C.D:162 | A.B.C.D) traps WORD",
       SNMP_STR
       "no snmp host and community config"
       "hostname of SNMP notification host\n"
       "IP address of SNMP notification host with port num 162\n" "IP address of SNMP notification host with default port num 162\n" "snmp trap host config\n" "community string for traps\n")
{
    int fd = 0;
    fd = snmp_init_socket (fd);
    if (fd < 0)
    {
        vty_out (vty, "socket fault!\r\n");
        return CMD_WARNING;
    }
    char buf[MAX_STRING_LEN] = "";
    sprintf (buf, "snmp host %.*s traps %.*s", strlen (argv[0]), argv[0], strlen (argv[1]), argv[1]);
    struct config_cmd_string *pNode = find_snmp_config_string (buf);
    if (pNode)
    {
        snmp_config_string = delete_snmp_config_string (vty, buf);
        return snmp_send_config_msg (fd, 5, buf);
    }
    else
    {
        vty_out (vty, "config cmd not find!please check again...\r\n");
        return CMD_WARNING;
    }
}

//add by limingyuan 2013.8.19
int zebra_snmp_write_config (struct vty *vty)
{
    struct config_cmd_string *pHead = snmp_config_string;
    while (pHead)
    {
        if (strncmp (pHead->config_string, "snmpv3 user", strlen ("snmpv3 user")) != 0)
            vty_out (vty, "%s\r\n", pHead->config_string);
        pHead = pHead->next;
    }
    return CMD_SUCCESS;
}

#endif
int zebra_flowengine_write_config (struct vty *vty)
{

    struct flow_engine_table *fpos = NULL;
    struct sectionengine_table *spos = NULL;
    struct processing_engine_table *ppos = NULL;
    char buf[BUFSIZ];
    char type[8];
    int i=0;


    //vty_out (vty, "! flow engine table %s",VTY_NEWLINE);
    for(spos = sectionengine_table_head; spos!= NULL; spos = spos->next)
    {
        vty_out (vty, "section-engine %s",spos->sectionengine.sectionenginename);
        for(i =0; i<spos->sectionengine.prefixnum; i++)
        {

            prefix2str(&spos->sectionengine.v6prefix[i],buf,BUFSIZ);
            vty_out (vty, " %s", buf);
        }
        //vty_out (vty, " isused: %d %s",spos->sectionengine.isused, VTY_NEWLINE);
        vty_out (vty, "%s",VTY_NEWLINE);
    }



    for(ppos = processingengine_table_head; ppos!= NULL; ppos = ppos->next)
    {

        if(ppos->processingengine.type == 1)
        {
            strcpy(type,"ivi");
        }
        else if(ppos->processingengine.type == 2)
        {
            strcpy(type,"nat64");
        }
        else if(ppos->processingengine.type == 3)
        {
            strcpy(type,"4over6");
        }
        else if(ppos->processingengine.type == 4)
        {
            strcpy(type,"FW");
        }

        vty_out (vty, "processing-engine %s %d %d %s %s ",ppos->processingengine.processingenginename,ppos->processingengine.memoryvalue,ppos->processingengine.bandwidthvalue,type,ppos->processingengine.rt_name);

        //vty_out (vty, " isused: %d%s",ppos->processingengine.isused, VTY_NEWLINE);
        vty_out (vty, " %s", VTY_NEWLINE);
    }




    for(fpos = flowengine_table_head; fpos!= NULL; fpos = fpos->next)
    {


        vty_out (vty, "flow-engine %s %s %s ",fpos->flowengine.flowenginename,fpos->flowengine.sectionenginename->sectionengine.sectionenginename,fpos->flowengine.processingenginename->processingengine.processingenginename);

        vty_out (vty, " %s", VTY_NEWLINE);
    }


    return 1;
    //return CMD_SUCCESS;
}

int zebra_header_compression_write_config (struct vty *vty)
{

    struct header_compression_table *pos = NULL;
    char buf[BUFSIZ];
    char type[8];
    int i=0;

    //vty_out (vty, "! header compression table%s",VTY_NEWLINE);

    for(pos = header_compression_table_head; pos!= NULL; pos = pos->next)
    {

        vty_out (vty, "header-compression");
        prefix2str(&pos->node.prefix,buf,BUFSIZ);
        vty_out (vty, " %s", buf);
        vty_out (vty, "%s",VTY_NEWLINE);
    }



    return 1;
}

int zebra_policy_based_route_write_config (struct vty *vty)
{

    struct acl_route_table *pos = NULL;
    char buf[BUFSIZ];
    char type[8];
    int i=0;
    char gateway[40];

    for(pos = acl_route_table_head; pos!= NULL; pos = pos->next)
    {

        prefix2str(&pos->node.s_prefix,buf,BUFSIZ);

        if (!strcmp(buf, "::"))
            vty_out (vty, "policy-route");
        else
        {
            vty_out (vty, "ipv6 twod-route");
            vty_out (vty, " %s", buf);
        }

        prefix2str(&pos->node.prefix,buf,BUFSIZ);
        vty_out (vty, " %s", buf);

        inet_ntop(AF_INET6,pos->node.gateway,gateway,40);
        vty_out (vty, " %s", gateway);
        vty_out (vty, "%s",VTY_NEWLINE);
    }
    return 1;
}


int zebra_ipv6_server_forwarding_status_write_config (struct vty *vty)
{
    if(ipv6_server_forwarding_status == 1)
    {
        vty_out (vty, "ip server forwarding %s",VTY_NEWLINE);
    }

    return CMD_SUCCESS;
}
int zebra_area_table__write_config (struct vty *vty)
{
    struct inter_in_area *p_if= inter_area_head;
    vty_out (vty, "!%s",VTY_NEWLINE);
    while(p_if!= NULL)
    {
        if(p_if->area_value==INTEGRATION)
        {
            vty_out (vty, "flowsp %s area integration %s", p_if->ifname,VTY_NEWLINE);
        }
        p_if=p_if->next;
    }

    return CMD_SUCCESS;
}

int zebra_real_ipv6_source_address_write_config (struct vty *vty)
{
    struct real_ipv6_source_address_link *pos = NULL;
    char buf[BUFSIZ];
    char type[8];
    int i=0;
    char gateway[40];

    //vty_out (vty, "! real ipv6 source address link%s",VTY_NEWLINE);

    for(pos = real_ipv6_source_address_link_head ; pos!= NULL; pos = pos->next)
    {
        i++;

        vty_out (vty, "access-ipv6 permit ");
        prefix2str(&pos->node.source_addr_prefix,buf,BUFSIZ);
        vty_out (vty, " %s", buf);

        vty_out (vty, " on %s", pos->node.ifname);
        vty_out (vty, " i = %d %s",i,VTY_NEWLINE);
    }

    return 1;

}






#ifdef HAVE_DNS64
int zebra_dns64_write_config (struct vty *vty)
{
    int socketfd;
    int ret = 0;
    char pre[40];

    if (v6prefix.prefixlen > 0 && v6prefix.prefixlen <= 96)
    {
        inet_ntop (AF_INET6, &(v6prefix.u.prefix6), pre, 40);
        vty_out (vty, "dns64 prefix %s/", pre);
        vty_out (vty, "%d ", v6prefix.prefixlen);
        vty_out (vty, "%s ", dns64_ubit);
        {
            inet_ntop (AF_INET, &v4Dns, pre, 40);
            vty_out (vty, "dns %s", pre);
        }
        vty_out (vty, "%s", VTY_NEWLINE);
    }
    return CMD_SUCCESS;
}

#endif
/* add by s 130806 */
#ifdef HAVE_4OVER6_TCPMSS
int zebra_4over6_write_tcp_mss_config (struct vty *vty)
{
    int socketfd;
    int ret = 0;
    if (save_tunnel4o6_tcpmss.mss_value != 0)
    {
        vty_out (vty, "tunnel4o6 tcp mss %d", save_tunnel4o6_tcpmss.mss_value);
        vty_out (vty, "%s", VTY_NEWLINE);
    }

    return CMD_SUCCESS;
}
#endif
/* end add*/
#if 0
int zebra_nat64_write_config (struct vty *vty, char *ifname)
{
    struct nat64_ipv4AddressPool
    {
        unsigned int start;
        unsigned int end;
    } nat64_ipv4AddressPool;

    typedef struct nat64_config
    {
        struct tnl_parm nat64;
        unsigned int nat64_tcpTtimer;
        unsigned int nat64_udpTtimer;
        unsigned int nat64_icmpTtimer;
        struct nat64_ipv4AddressPool stIp4AddPool;
    } nat64_config;

#define SIOCGETPREFIX SIOCGETTUNNEL
    struct ifreq ifr;
    //struct tnl_parm nat64;
    int socketfd;
    int ret = 0;
    char pre[40];
    nat64_config config;

    memset (&config, 0x0, sizeof (config));
    socketfd = socket (AF_INET6, SOCK_DGRAM, 0);
    if (socketfd < 0)
    {
        //vty_out(vty,"socket error\n");
        sprintf (stderr, "socket error\n");
        return -1;
    }
    memcpy (ifr.ifr_name, ifname, strlen (ifname) + 1);
    ifr.ifr_data = &config;
    ret = ioctl (socketfd, SIOCGETPREFIX, &ifr);
    if (ret == -1)
    {
        //vty_out(vty,"ioctl error: %d\n",errno);
        close (socketfd);
        return -1;
    }
    close (socketfd);
    //write config nat64 prefix
    if (config.nat64.prefix.len == 0)
    {
        //vty_out(vty,"prefix is 0\n");
    }
    else
    {
        inet_ntop (AF_INET6, &(config.nat64.prefix.prefix), pre, 40);
        vty_out (vty, "nat64 prefix %s/", pre);
        vty_out (vty, "%d ", config.nat64.prefix.len);
        //vty_out(vty,"%s ", ifname);
        if (config.nat64.prefix.ubit == 1)
        {
            vty_out (vty, "ubit");
        }
        else
        {
            vty_out (vty, "no-ubit");
        }
        vty_out (vty, "%s", VTY_NEWLINE);
    }
    //write config nat64 timer icmp
    if (config.nat64_icmpTtimer != 10)
    {
        vty_out (vty, "nat64 timeout icmp %d", config.nat64_icmpTtimer);
        vty_out (vty, "%s", VTY_NEWLINE);
    }

    //write config nat64 timer udp
    if (config.nat64_udpTtimer != 30)
    {
        vty_out (vty, "nat64 timeout udp %d", config.nat64_udpTtimer);
        vty_out (vty, "%s", VTY_NEWLINE);
    }
    //write config nat64 timer tcp
    if (config.nat64_tcpTtimer != 60)
    {
        vty_out (vty, "nat64 timeout tcp %d", config.nat64_tcpTtimer);
        vty_out (vty, "%s", VTY_NEWLINE);
    }
    //write config ipv4 pool create x.x.x.x x.x.x.x
    if (config.stIp4AddPool.start != 0 && config.stIp4AddPool.end != 0)
    {
        config.stIp4AddPool.start = htonl (config.stIp4AddPool.start);
        inet_ntop (AF_INET, &(config.stIp4AddPool.start), pre, 40);
        vty_out (vty, "nat64 v4pool %s", pre);

        //inet_ntop(AF_INET,&config.stIp4AddPool.end,pre,40);
        vty_out (vty, "/%d", config.stIp4AddPool.end);
        vty_out (vty, "%s", VTY_NEWLINE);
    }

    return CMD_SUCCESS;
}
#endif
static int zebra_netwire_config (struct vty *vty)
{
    int write;
    int rc;

    write = 0;

    //show ivi46 prefix config
    rc = zebra_ivi_write_config (vty, "ivi");
    if (rc != 0)
    {
        printf ("Get %s ivi prefix failed: %d", "ivi", rc);
    }
    else
        write += 1;
#if 0
    //show ivi64 prefix config
    rc = zebra_ivi_write_config (vty, "ivi64");
    if (rc != 0)
    {
        printf ("Get %s ivi prefix failed: %d", "ivi46", rc);
    }
    else
        write += 1;
#endif
    //show natware prefix config
#if 0
    zebra_nat64_write_config (vty, "nat64");
    //
#endif
    return write;
}

int get_hw_addr (u_char * buf, char *str)
{
    int i, h;
    unsigned int p[6];
    int j;
    for (j = 0; j < strlen (str); j++)
    {
        if (((str[j] >= '0' && str[j] <= '9') || (str[j] >= 'A' && str[j] <= 'F') || (str[j] >= 'a' && str[j] <= 'f') || str[j] == ':') == 0)
            return 0;
    }
    h = 0;
    for (j = 0; j < strlen (str); j++)
    {
        if (str[j] == ':')
            h++;
    }
    if (h != 5)
    {
        return 0;
    }
    i = sscanf (str, "%x:%x:%x:%x:%x:%x", &p[0], &p[1], &p[2], &p[3], &p[4], &p[5]);

    if (i != 6)
    {
        printf ("%s\n", "error parsing MAC");
        return 0;
    }

    for (i = 0; i < 6; i++)
        buf[i] = p[i];
    return 4;
}

//added by zhangzhibo 2013.9.2 for add arp
DEFUN (arp, arp_cmd, "arp A.B.C.D HH:HH:HH:HH:HH:HH DEV", "Add an arp entry\n" "IP address (e.g. 10.0.0.1)\n" "MAC address (e.g.10:50:56:f4:89:8f)\n" "Interface name\n")
{

    int sd = socket (AF_INET, SOCK_DGRAM, 0);
    struct arpreq arpreq, arpreq1;
    struct sockaddr_in *sin, *sin1;
    struct in_addr ina, ina1;
    int flags;
    int rc;
    char ip[16];
    strcpy (ip, argv[0]);

    char mac[19];
    strcpy (mac, argv[1]);
#if 0
    strcpy (arp_keep_config[arp_count].mac, argv[1]);
#endif
#if 1
    memset (&arpreq, 0, sizeof (struct arpreq));
    memset (&arpreq1, 0, sizeof (struct arpreq));
    sin = (struct sockaddr_in *) &arpreq.arp_pa;
    memset (sin, 0, sizeof (struct sockaddr_in));
    sin->sin_family = AF_INET;
    ina.s_addr = inet_addr (ip);
    memcpy (&sin->sin_addr, (char *) &ina, sizeof (struct in_addr));

    strcpy (arpreq.arp_dev, argv[2]);

    if (get_hw_addr ((unsigned char *) arpreq.arp_ha.sa_data, mac) == 0)
    {
        vty_out (vty, "Invalid MAC address\n");
        return CMD_SUCCESS;
    }

    flags = ATF_PERM | ATF_COM;	//note, must set flag, if not,you will get error

    arpreq.arp_flags = flags;
    int j = 0;
    for (j = 0; j < KEEP_CONFIG_SIZE; j++)
        if (strcmp (arp_keep_config[j].ip, argv[0]) == 0)
        {
            strcpy (arpreq1.arp_dev, arp_keep_config[j].arp_dev);
            sin1 = (struct sockaddr_in *) &arpreq1.arp_pa;
            memset (sin1, 0, sizeof (struct sockaddr_in));
            sin1->sin_family = AF_INET;
            ina1.s_addr = inet_addr (arp_keep_config[j].ip);
            memcpy (&sin1->sin_addr, (char *) &ina1, sizeof (struct in_addr));

            if (ioctl (sd, SIOCDARP, &arpreq1) < 0)
            {
                vty_out (vty, "%s\n", "del arp error...");
                return -1;
            }
            memset (&arp_keep_config[j], 0, sizeof (struct arp_config));
            arp_keep_config[j].flag = 0;
        }
    if (strcmp (arpreq.arp_dev, "lo") != 0 && strcmp (argv[0], "0.0.0.0") != 0 && strcmp (argv[0], "255.255.255.255") != 0 && strcmp (argv[1], "0:0:0:0:0:0") != 0)
    {
        rc = ioctl (sd, SIOCSARP, &arpreq);
        if (rc < 0)
        {
            vty_out (vty, "%s\n", "set arp error...");
            return CMD_SUCCESS;
        }
        else
        {
            if (strcmp (argv[0], "0.0.0.0") != 0 && strcmp (argv[0], "255.255.255.255") != 0 && strcmp (argv[1], "0:0:0:0:0:0") != 0)
            {
                strcpy (arp_keep_config[arp_count].ip, argv[0]);
                strcpy (arp_keep_config[arp_count].mac, argv[1]);
                strcpy (arp_keep_config[arp_count].arp_dev, argv[2]);
                arp_keep_config[arp_count].flag = 1;
                arp_count = (arp_count + 1) % KEEP_CONFIG_SIZE;
            }
        }
    }
#endif

    return CMD_SUCCESS;
}

//added by zhangzhibo 2013.9.2 for del arp
DEFUN (no_arp, no_arp_cmd, "no arp A.B.C.D", "Negate a command or set its defaults\n" "Delete an arp entry\n" "IP Address (e.g. 10.0.0.1)\n")
{
    struct interface *fp1 = vty->index;
    int sd = socket (AF_INET, SOCK_DGRAM, 0);
    struct arpreq arpreq;
    struct sockaddr_in *sin;
    struct in_addr ina;
    int flags;
    int rc;
    char ip[16];
    strcpy (ip, argv[0]);
    memset (&arpreq, 0, sizeof (struct arpreq));
    sin = (struct sockaddr_in *) &arpreq.arp_pa;
    memset (sin, 0, sizeof (struct sockaddr_in));
    sin->sin_family = AF_INET;
    ina.s_addr = inet_addr (ip);
    memcpy (&sin->sin_addr, (char *) &ina, sizeof (struct in_addr));
    int j = 0;
    for (j = 0; j < KEEP_CONFIG_SIZE; j++)
        if (strcmp (arp_keep_config[j].ip, argv[0]) == 0)
        {
            strcpy (arpreq.arp_dev, arp_keep_config[j].arp_dev);
            //strcpy(arpreq.arp_dev,argv[2]);

            rc = ioctl (sd, SIOCDARP, &arpreq);
            if (rc < 0)
            {
                vty_out (vty, "%s\n", "del arp error...");
                return -1;
            }
        }

    for (j = 0; j < KEEP_CONFIG_SIZE; j++)
        if (strcmp (arp_keep_config[j].ip, argv[0]) == 0)
        {
            memset (&arp_keep_config[j], 0, sizeof (struct arp_config));
            arp_keep_config[j].flag = 0;
        }
    return CMD_SUCCESS;
}

int static_config_ipv4_arp (struct vty *vty)
{
    int k = 0;
    int write = 0;
    for (k = 0; k < KEEP_CONFIG_SIZE; k++)
        if (arp_keep_config[k].flag == 1)
        {
            vty_out (vty, "arp %s %s %s", arp_keep_config[k].ip, arp_keep_config[k].mac, arp_keep_config[k].arp_dev);
            vty_out (vty, "%s", VTY_NEWLINE);
            write = 1;
        }
    return write;
}

#if 0
int static_config_ipv6_nd (struct vty *vty)
{
    int k = 0;
    int write = 0;
    for (k = 0; k < KEEP_CONFIG_SIZE; k++)
        if (strcmp (nd_keep_config[k].ip, "\0") != 0)
        {
            vty_out (vty, "ipv6 nd neighbor %s %s", nd_keep_config[k].ip, nd_keep_config[k].mac);
            vty_out (vty, "%s", VTY_NEWLINE);
            write = 1;
        }
    return write;

}
#endif
#if 1							//sangmeng add for filter

/*sangmeng add for ip access list applied to the interface*/
DEFUN (ip_access_group_listnumber,
       ip_access_group_listnumber_cmd, "ip access-group WORD (in|out)", IP_STR "Specify access control for packets\n" "Access-list name\n" "inbound packets\n" "outbound packets\n")
{

    //vty_out(vty, "come here%s", VTY_NEWLINE);
    int ret = filter_add_to_interface (vty, vty->index, argv[0], argv[1], AFI_IP);
    write_file_for_dpdk_conf(vty);
    return ret;
}

/*sangmeng add for no ip access list applied to the interface*/
DEFUN (no_ip_access_group_listnumber,
       no_ip_access_group_listnumber_cmd,
       "no ip access-group WORD (in|out)", "Negate a command or set its defaults\n" IP_STR "Specify access control for packets\n" "Access-list name\n" "inbound packets\n" "outbound packets\n")
{
    int ret = filter_delete_from_interface (vty, vty->index, argv[0], argv[1], AFI_IP);
    write_file_for_dpdk_conf(vty);
    return ret;
}

DEFUN (ipv6_access_group_listnumber,
       ipv6_access_group_listnumber_cmd, "ipv6 access-group WORD ", IPV6_STR "Specify access control for packets\n" "Access-list name\n" "inbound packets\n" "outbound packets\n")
{

    //vty_out(vty, "come here%s", VTY_NEWLINE);
    int ret = filter_add_to_interface (vty, vty->index, argv[0], /*argv[1]*/"in", AFI_IP6);
    write_file_for_dpdk_conf(vty);
    return ret;
}

/*sangmeng add for no ipv6 access list applied to the interface*/
DEFUN (no_ipv6_access_group_listnumber,
       no_ipv6_access_group_listnumber_cmd,
       "no ipv6 access-group WORD ", "Negate a command or set its defaults\n" IP_STR "Specify access control for packets\n" "Access-list name\n" "inbound packets\n" "outbound packets\n")
{
    int ret = filter_delete_from_interface (vty, vty->index, argv[0], "in", AFI_IP6);
    write_file_for_dpdk_conf(vty);
    return ret;
}

#endif // end sagnmeng add for filter
//added for nat 20130508
static int ip_nat_config_pool (struct vty *vty)
{
    struct nat_pool_entry *pLast;
    struct nat_pool_entry *pNext;
    int write = 0;

    pLast = &natPoolEntry;
    pNext = natPoolEntry.next;
    while (pNext != NULL)
    {
        vty_out (vty, "ip nat pool %s %s %s", pNext->name, pNext->startaddr, pNext->endaddr);

        vty_out (vty, "%s", VTY_NEWLINE);

        write = 1;

        pLast = pNext;
        pNext = pNext->next;
    }

    return write;
}

static int ip_nat_config_source_list (struct vty *vty)
{
    struct nat_source_list *pLast;
    struct nat_source_list *pNext;
    int write = 0;

    pLast = &natSourceList;
    pNext = natSourceList.next;
    while (pNext != NULL)
    {
        vty_out (vty, "ip nat source list %s %s", pNext->name, pNext->snet);

        vty_out (vty, "%s", VTY_NEWLINE);

        write = 1;

        pLast = pNext;
        pNext = pNext->next;
    }

    return write;
}

static int ip_nat_config_source_list_pool (struct vty *vty)
{
    struct nat_source_list_pool_entry *pLast;
    struct nat_source_list_pool_entry *pNext;
    int write = 0;

    pLast = &natSourceListPoolEntry;
    pNext = natSourceListPoolEntry.next;
    while (pNext != NULL)
    {
        vty_out (vty, "ip nat inside source list %s pool %s", pNext->source.name, pNext->pool.name);

        vty_out (vty, "%s", VTY_NEWLINE);

        write = 1;

        pLast = pNext;
        pNext = pNext->next;
    }

    return write;
}

static int ip_nat_config (struct vty *vty)
{
    int write = 0;
#ifdef HAVE_IPNAT
    write += ip_nat_config_pool (vty);

    write += ip_nat_config_source_list (vty);

    write += ip_nat_config_source_list_pool (vty);
#endif
    return write;
}

static int ip_dhcp_config (struct vty *vty)
{
    int write = 0;
#ifdef HAVE_DHCPV4
    write += zebra_dhcp_write_config (vty);
#endif
    return write;
}

static int ip_flowengine_config (struct vty *vty)
{
    int write = 0;
    write += zebra_flowengine_write_config (vty);
    return write;
}







/* Static ip route configuration write function. */
static int zebra_ip_config (struct vty *vty)
{
    int write = 0;

    write += static_config_ipv4 (vty);

    //added for 4over6 20130306
    write += static_config_ipv4_4over6 (vty);
    //added for arp 20131024
    write += static_config_ipv4_arp (vty);

#ifdef HAVE_IPV6
    write += static_config_ipv6 (vty);
#endif /* HAVE_IPV6 */

#ifdef HAVE_NETWIRE
    write += zebra_netwire_config (vty);
#endif

#ifdef HAVE_DNS64
    write += zebra_dns64_write_config (vty);
#endif

#ifdef HAVE_SNMP
    write += zebra_snmp_write_config (vty);
#endif

#ifdef HAVE_4OVER6_TCPMSS
    write += zebra_4over6_write_tcp_mss_config (vty);
#endif
    write += zebra_flowengine_write_config (vty);
    write += zebra_policy_based_route_write_config (vty);
    write += zebra_header_compression_write_config (vty);
    write += zebra_real_ipv6_source_address_write_config (vty);

    write += zebra_ipv6_server_forwarding_status_write_config (vty);
    write += zebra_area_table__write_config (vty);

    return write;
}

/* ip protocol configuration write function */
static int config_write_protocol (struct vty *vty)
{
    int i;

    for (i = 0; i < ZEBRA_ROUTE_MAX; i++)
    {
        if (proto_rm[AFI_IP][i])
            vty_out (vty, "ip protocol %s route-map %s%s", zebra_route_string (i), proto_rm[AFI_IP][i], VTY_NEWLINE);
    }
    if (proto_rm[AFI_IP][ZEBRA_ROUTE_MAX])
        vty_out (vty, "ip protocol %s route-map %s%s", "any", proto_rm[AFI_IP][ZEBRA_ROUTE_MAX], VTY_NEWLINE);

    return 1;
}

//add by ccc for tunnel
static int tunnel_config_write (struct vty *vty)
{
    struct tunnel_info *p = tunnel_head;
    char buf[40] = "";
    //struct zebra_config_message *test = (struct zebra_config_message*)malloc(sizeof(struct zebra_config_message));
    //bzero(test,sizeof(struct zebra_config_message));
    //if(0 == zebra_connect_dpdk_send_message_two(test,sizeof(struct zebra_config_message)))
    {
        while (p != NULL)
        {
            bzero (buf, 40);
            vty_out (vty, "interface tunnel %d%s", p->tunnel_num, VTY_NEWLINE);
            inet_ntop (AF_INET6, &(p->tunnel_source), buf, 40);
            vty_out (vty, " tunnel source %s%s", buf, VTY_NEWLINE);
            bzero (buf, 40);
            inet_ntop (AF_INET6, &(p->tunnel_dest), buf, 40);
            vty_out (vty, " tunnel destination %s%s", buf, VTY_NEWLINE);
            bzero (buf, 40);
            inet_ntop (AF_INET, &(p->ip_prefix.prefix), buf, 40);
            vty_out (vty, " ip prefix %s/%d%s", buf, p->ip_prefix.prefixlen, VTY_NEWLINE);

            p = p->tunnel_next;
        }
        vty_out (vty, "!%s", VTY_NEWLINE);
        return CMD_SUCCESS;
    }
    //else
    //{
    //vty_out(vty,"connect server fail,config write%s",VTY_NEWLINE);
    //  return CMD_WARNING;
    //}
}

/* table node for protocol filtering */
static struct cmd_node protocol_node = { PROTOCOL_NODE, "", 1 };

/* IP node for static routes. */
static struct cmd_node ip_node = { IP_NODE, "", 1 };

//added for nat 20130508
static struct cmd_node ip_nat_node = { IP_NAT_NODE, "", 1 };

#if 1
struct cmd_node dhcp_node =
{
    DHCP_NODE,
    "%s(config-dhcp)# ",
    1
};
#endif
//add by ccc for tunnel
struct cmd_node tunnel_node =
{
    TUNNEL_NODE,
    "%s(config-tunnel)# ",
    1
};

#define _NUM_FLD 64
#define DPDK_CUSTOMIZE_ROUTE_CONFIG "/usr/local/etc/dpdk_customize_route.conf"
static int strsplit(char *string, int stringlen,
                    char **tokens, int maxtokens, char delim)
{
    int i, tok = 0;
    int tokstart = 1; /* first token is right at start of string */

    if (string == NULL || tokens == NULL)
        goto einval_error;

    for (i = 0; i < stringlen; i++)
    {
        if (string[i] == '\0' || tok >= maxtokens)
            break;
        if (tokstart)
        {
            tokstart = 0;
            tokens[tok++] = &string[i];
        }
        if (string[i] == delim)
        {
            string[i] = '\0';
            tokstart = 1;
        }
    }
    return tok;

einval_error:
    return -1;
}
void install_customize_route(void)
{
    char buf[256];
    char prefix[64];
    char gateway[64];
    char ifname[16];
    char table_name[32];
    char describe[256];
    char strbuf[96];
    char *end;
    FILE *fp;
    int prefixlen;
    int nb_token;
    int i;
    char *str_fld[_NUM_FLD];

    fp = fopen (DPDK_CUSTOMIZE_ROUTE_CONFIG, "r");
    if (fp == NULL)
    {
        printf( "Can't open configuration file [%s]\n", DPDK_CUSTOMIZE_ROUTE_CONFIG);
        return;
    }

    while (fgets (buf, BUFSIZ, fp))
    {
        char *cp = buf;
        while (*cp != '\r' && *cp != '\n' && *cp != '\0')
            cp++;
        *cp = '\0';

        memset(prefix, 0, sizeof(prefix));
        memset(gateway, 0, sizeof(gateway));
        memset(ifname, 0, sizeof(ifname));
        memset(table_name, 0, sizeof(ifname));
        memset(describe, 0, sizeof(ifname));
        nb_token = strsplit(buf, sizeof(buf), str_fld, _NUM_FLD, '#');
        for (i = 1; i < nb_token; i++)
        {
            if (i == 1)
                strcpy(prefix, str_fld[i]);
            else if (i == 2)
                prefixlen = strtoul(str_fld[i], &end, 0);
            else if (i == 3)
                strcpy(gateway, str_fld[i]);
            else if (i == 4)
                strcpy(ifname, str_fld[i]);
            else if (i == 5)
                strcpy(table_name, str_fld[i]);
            else if (i == 6)
                strcpy(describe, str_fld[i]);
        }

        sprintf(strbuf, "%s/%d", prefix, prefixlen);
        printf("table_name:%s\n,describe:%s\n",table_name, describe);
        printf("%s %s.\n", strbuf, gateway);

        if (!strcmp(str_fld[0], "ip"))
        {
            zebra_ipv4_customize (1, "IPV4_L3FWD_LPM_1",strbuf, NULL, gateway, ifname, NULL);
        }
        else if (!strcmp(str_fld[0], "ipv6"))
        {
            //zebra_ipv6_customize(1, "IPV6_L3FWD_LPM_1", strbuf, gateway, ifname, NULL);
            zebra_ipv6_customize(1, table_name, strbuf, gateway, ifname, NULL, describe);
        }
    }
    fclose(fp);
    return;
}


struct msg_info
{
    uint8_t type;
    char table_name[32];
    uint8_t ipv6_dst[16];
    uint8_t ipv6_mask;

    uint8_t out_port;
    uint8_t action;
    uint8_t next_hop[16];
    uint8_t lladdr[6];
    char describe[0];
};

#define OPENFLOW_ADD 0
#define OPENFLOW_DEL 1

#define ETH_ADDR_ARGS(ea)       \
	(ea)[0], (ea)[1], (ea)[2], (ea)[3], (ea)[4], (ea)[5]

#define ETH_ADDR_IS_EMPTY(ea)       \
	((ea)[0]|(ea)[1]|(ea)[2]|(ea)[3]|(ea)[4]|(ea)[5])


struct sdn_ipv6_lladdr
{
    uint8_t type;//0:add 1:del
    uint8_t ipv6addr[16];
    uint8_t lladdr[6];
    uint8_t ifindex;

};

int send_sdn_lladdr_msg_to_dpdk(char *buf)
{
    int sockfd;
    int ret = 0;
    struct comm_head *msg;
    int len = sizeof(struct comm_head) + sizeof(struct sdn_ipv6_lladdr);
    msg = (struct comm_head *)malloc(len);
    memset(msg,0,len);

    msg->type = 0x41;
    msg->len = len;
    memcpy(msg->data,buf,sizeof(struct sdn_ipv6_lladdr));

    sockfd = connect_dpdk(NULL);
    ret = send (sockfd, (char *) msg, len, 0);
    if (ret < 0)
    {
        fprintf (stderr, "%s\n", "send comm failed");
        close (sockfd);
        free (msg);
        return -1;
    }

    close (sockfd);
    free (msg);
    return 0;


}
#define OPENFLOWMSG 0x70
#define LINK_STATUS_MSG 0x71
struct link_status
{
    //char ifname[20];
    uint16_t port;
    uint8_t status; // 0 :down  1:up
};


void zebra_server_process_msg(char *msg,int len)
{

    struct comm_head *header = msg;
    printf("type = 0x%x\n",header->type);
    printf("len = 0x%x\n",header->len);

    switch(header->type)
    {
    case OPENFLOWMSG:
        handle_openflow_msg(msg,len);
        break;
    case LINK_STATUS_MSG:
        handle_link_status_msg((char *)(header->data));
        break;
    default:
        printf("Unknown type of message : 0x%02x\n",header->type);
        break;

    }

}

int change_interface_link_status(struct interface *ifp,uint8_t status)
{

    if(ifp->link_status == status)
        return 0;
    ifp->link_status = status;


    if(CHECK_FLAG(ifp->status, ZEBRA_INTERFACE_LINKDETECTION))

        return 1;
}

#if 1
void handle_link_status_msg(char *msg)
{
    struct link_status *link_msg;
    struct interface *ifp;
    char ifname[20];
    int i=0;
    int ifport = 0;
    int ret = 0;
    int speed_duplex = 0;
    link_msg = (struct link_status *)msg;
    //printf("--%d-- %d \n",link_msg->port,link_msg->status);
#if 0
    if(link_msg->port == 0 && link_msg->status == 0)
    {
        system("echo \"\[\`date\`\] check vEth1_0 down && service heartbeat stop\" >> /root/dpdk_logs/haResourcestatus");
        system("/bitway/run/dpdk_heartbeat_dir/dpdk_heartbeat_column_brain_process.sh");
    }
#endif
    struct zebra_if *if_data;
    for(i=0; i<5; i++)
    {
        memset(ifname,0,20);
        sprintf(ifname,"vEth%d_%d",link_msg->port+1,i);
        ifp = if_lookup_by_name (ifname);
        if(ifp == NULL)
            continue;


        //ret = change_interface_link_status(ifp,link_msg->status);
        ret = 1;

        if (!CHECK_FLAG(ifp->status, ZEBRA_INTERFACE_LINKDETECTION))
            continue;

        if(ret != 0)
        {

            if(1)
            {
                memset(ifname,0,20);
                sprintf(ifname,"vEth%d_%d",link_msg->port+1,0);
                speed_duplex = doit (ifname, 0, 0);
                printf(" %s --  speed_duplex = %d\n",ifname,speed_duplex);
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

            //add 20190129
#if 1

            if(link_msg->status != 0 && !CHECK_FLAG(ifp->flags, IFF_RUNNING))
                continue;
#endif

            if(link_msg->status == 0)
            {
                printf("ifp->flags = %llu\n",ifp->flags);
                UNSET_FLAG (ifp->flags, IFF_RUNNING);

                if(ifp->flags & IFF_UP)
                {
                    UNSET_FLAG (ifp->flags, IFF_UP);
                    if_delete_update (ifp);
                    ip_address_delete_from_kernel (ifp);
                    SET_FLAG (ifp->flags, IFF_UP);
                }

            }
            else
            {
                if (!CHECK_FLAG (ifp->status, ZEBRA_INTERFACE_ACTIVE))
                {
                    if_add_update (ifp);

                }
                else
                {


#if 1
                    printf("ifp->flags & IFF_UP = %d\n",ifp->flags & IFF_UP);
                    printf("ifp->flags & IFF_RUNNING = %d\n",ifp->flags & IFF_RUNNING);
                    printf("!CHECK_FLAG(ifp->status, ZEBRA_INTERFACE_LINKDETECTION) = %d\n",!CHECK_FLAG(ifp->status, ZEBRA_INTERFACE_LINKDETECTION));
#endif

                    if (if_is_operative (ifp) && CHECK_FLAG(ifp->status, ZEBRA_INTERFACE_LINKDETECTION))
                    {
                        //SET_FLAG (ifp->flags, IFF_UP);
                        ip_address_delete_from_kernel (ifp);
                        if_refresh (ifp);
                        interface_config_recovery (ifp);

                        zebra_interface_up_update (ifp);

                    }
                    else
                    {
                        //SET_FLAG (ifp->flags, IFF_UP);

                        if (if_is_operative (ifp))
                            if_up (ifp);
                    }
#if 0

                    SET_FLAG (ifp->flags, IFF_RUNNING);
                    SET_FLAG (ifp->flags, IFF_UP);
                    speed_duplex = doit (ifp->name, 0, 0);
                    //printf("---------------------speed_duplex = %d\n",speed_duplex);


                    ip_address_delete_from_kernel (ifp);
                    if_refresh (ifp);
                    interface_config_recovery (ifp);

                    zebra_interface_up_update (ifp);
#endif

                }


            }
        }
        else
        {

            //printf("---------------------\n");
        }

    }

}

#endif
void handle_openflow_msg(char *msg,int len)
{
    int i;
    int ret;
    struct prefix p;
    char strbuf[96];

    struct comm_head *header = msg;
    struct msg_info *info = header->data;

    struct sdn_ipv6_lladdr lladdr_info;
#if 1
    printf("type = 0x%x\n",header->type);
    printf("len = 0x%x\n",header->len);

    printf("msg->type:%d\n",info->type);
    printf("table_name:%s\n",info->table_name);
    if(info->type == 0)
    {
        printf("out_port:%d\n",info->out_port);
        printf("action:%d\n",info->action);
        printf("ipv6_mask:%d\n",info->ipv6_mask);
        printf("describe:%s\n",info->describe);
        printf("lladdr:---%02x:%02x:%02x:%02x:%02x:%02x\n",info->lladdr[0],info->lladdr[1],info->lladdr[2],info->lladdr[3],info->lladdr[4],info->lladdr[5]);
    }
    for(i=0; i<16; i++)
    {
        printf("%02x\t",info->ipv6_dst[i]);
    }
    printf("\n");

    for(i=0; i<16; i++)
    {
        printf("%02x\t",info->next_hop[i]);
    }
    printf("\n");
#endif
    p.family = AF_INET6;
    p.prefixlen = info->ipv6_mask;
    memcpy(&p.u,info->ipv6_dst,16);

    prefix2str(&p,strbuf,BUFSIZ);

    u_char distance =1;
    u_int32_t vrf_id = 2;

    char ifname[20];
    if(info->action)
    {
        sprintf(ifname,"vEth%d_%d",info->out_port/10,info->out_port%10);
    }
    else
    {

        sprintf(ifname,"vEth%d_%d",0,0);
    }


    if(ETH_ADDR_IS_EMPTY(info->lladdr))
    {
        lladdr_info.type = info->type;
        memcpy(lladdr_info.ipv6addr,info->next_hop,16);
        memcpy(lladdr_info.lladdr,info->lladdr,6);

        printf("--------------ifname = %s------------\n",ifname);
        lladdr_info.ifindex = get_ifindex_by_ifname(ifname);
        printf("--------------ifindex = %d------------\n",lladdr_info.ifindex);
        //wjh

        send_sdn_lladdr_msg_to_dpdk((char *)&lladdr_info);

    }

    switch(info->type)
    {
    case OPENFLOW_ADD:
        zebra_rib_add_ipv6_customize(info->table_name,&p,(struct in6_addr *)info->next_hop,ifname,distance,vrf_id,info->describe,info->action);
        break;
    case OPENFLOW_DEL:
        zebra_rib_delete_ipv6_customize(info->table_name,&p,(struct in6_addr *)info->next_hop,ifname,vrf_id);
        break;

    }


}

void install_customize_route_by_file_name(int argc,char **argv)
{
    char buf[256];
    char prefix[64];
    char gateway[64];
    char ifname[16];
    char table_name[32];
    char describe[256];
    char strbuf[96];
    FILE *fp;
    int prefixlen;
    int nb_token;
    int i;
    char *str_fld[_NUM_FLD];
    struct prefix p;
    int ret;

    memset(prefix, 0, sizeof(prefix));
    memset(gateway, 0, sizeof(gateway));
    memset(ifname, 0, sizeof(ifname));
    memset(table_name, 0, sizeof(ifname));
    memset(describe, 0, sizeof(ifname));

    strcpy(gateway, argv[1]);
    strcpy(ifname, argv[2]);
    strcpy(table_name, argv[3]);
    strcpy(describe, "dns add rule");

    memcpy(strbuf,argv[0],96);

    //zebra_ipv4_customize (1, "IPV4_L3FWD_LPM_1",strbuf, NULL, gateway, ifname, NULL);
    zebra_ipv6_customize(1, table_name, strbuf, gateway, ifname, NULL, describe);

    return;
}

void del_ipv6_addr_disable_policy_route(struct interface *ifp ,struct prefix_ipv6 *p)
{
    char buf[64];
    prefix_ipv62str (p, buf, sizeof (buf));
    //printf("in del_ipv6_addr_disable_policy_route  --%s--%s\n",ifp->name,buf);
    struct zebra_if *if_data;
    struct acl_route_table *pos=NULL;
    if (acl_route_table_head == NULL)
    {
        return ;

    }
    else
    {

        for(pos = acl_route_table_head; pos!= NULL; pos = pos->next)
        {
            if(pos->node.status == 0)
                continue;
            //printf("--%s--,--%p--,--%p--\n",pos->node.ifp->name,pos->node.ifp,ifp);
            if(pos->node.ifp ==  ifp)
            {
                //  printf("len = %d\n",p->prefixlen);
                if(!g_U8_t_DataMemcmp(&pos->node.gateway,&p->prefix,p->prefixlen))
                {
                    pos->node.status = 0;
                    send_polict_based_route_to_dpdk(NULL, NULL, &pos->node.prefix,&pos->node.gateway,pos->node.ifp,1);
                }
            }
        }
        return ;
    }
}

void add_ipv6_addr_enable_policy_route(struct interface *ifp ,struct prefix_ipv6 *p)
{

    char buf[64];
    prefix_ipv62str (p, buf, sizeof (buf));
    //printf("in del_ipv6_addr_disable_policy_route  --%s--%s\n",ifp->name,buf);

    struct zebra_if *if_data;
    struct acl_route_table *pos=NULL;
    if (acl_route_table_head == NULL)
    {
        return ;
    }
    else
    {
        for(pos = acl_route_table_head; pos!= NULL; pos = pos->next)
        {
            if(pos->node.status != 0)
                continue;
            if(!g_U8_t_DataMemcmp(&pos->node.gateway,&p->prefix,p->prefixlen))
            {
                pos->node.status = 1;
                pos->node.ifp = ifp;
                send_polict_based_route_to_dpdk(NULL, NULL, &pos->node.prefix,&pos->node.gateway,pos->node.ifp,0);
            }
        }
        return ;
    }
}
/* Route VTY.  */
void zebra_vty_init (void)
{
    memset (arp_keep_config, 0, sizeof (arp_keep_config));
    //added for nat 20130508
    install_node (&ip_nat_node, ip_nat_config);
    install_node (&dhcp_node, ip_dhcp_config);	//zebra_dhcpv4_write_config);
    install_default (DHCP_NODE);
    install_node (&ip_node, zebra_ip_config);
    install_node (&protocol_node, config_write_protocol);

    install_element (CONFIG_NODE, &nat64_v4pool_cmd);
    install_element (CONFIG_NODE, &no_nat64_v4pool_cmd);

    install_element (CONFIG_NODE, &nat64_prefix_cmd);
    install_element (CONFIG_NODE, &no_nat64_prefix_cmd);
    //  install_element (CONFIG_NODE, &show_nat64_prefix_cmd);
    install_element (CONFIG_NODE, &nat64_timeout_cmd);
    install_element (CONFIG_NODE, &no_nat64_timeout_cmd);

    /* */
    install_element (CONFIG_NODE, &ivi_prefix_cmd);
    install_element (CONFIG_NODE, &no_ivi_prefix_cmd);
    // install_element (CONFIG_NODE, &show_ivi_prefix_cmd);
    ////add by ccc for cmd
    install_element (CONFIG_NODE, &ivi_pool_cmd);
    install_element (CONFIG_NODE, &no_ivi_pool_cmd);
    install_element (VIEW_NODE, &show_ipv6_tunnel_cmd);
    install_element (ENABLE_NODE, &show_ipv6_tunnel_cmd);

    //sangmeng add for get mib
    install_element (VIEW_NODE, &shell_slot_cmd);
    install_element (ENABLE_NODE, &shell_slot_cmd);

    install_node (&tunnel_node, tunnel_config_write);
    install_default (TUNNEL_NODE);
    //install_node(&tunnel_node,tunnel_config_write);

    install_element (CONFIG_NODE, &interface_tunnel_cmd);
    install_element (CONFIG_NODE, &no_interface_tunnel_cmd);
    install_element (TUNNEL_NODE, &tunnel_source_cmd);
    install_element (TUNNEL_NODE, &tunnel_destination_cmd);
    install_element (TUNNEL_NODE, &tunnel_ip_prefix_cmd);
    install_element (TUNNEL_NODE, &no_tunnel_source_cmd);
    install_element (TUNNEL_NODE, &no_tunnel_destination_cmd);
    install_element (TUNNEL_NODE, &no_tunnel_ip_prefix_cmd);
    ////add end
    // install_element (CONFIG_NODE, &fover6_tunnel_cmd);

#ifdef HAVE_DNS64
    /*added by wangyl fro dns64*/
    install_element (CONFIG_NODE, &dns64_prefix_cmd);
    install_element (CONFIG_NODE, &no_dns64_prefix_cmd);
    /*added end */
#endif

    /*added by wjh for slicing engine*/
    install_element (CONFIG_NODE, &slicing_engine_cmd);
    install_element (CONFIG_NODE, &slicing_engine2_cmd);
    install_element (CONFIG_NODE, &slicing_engine3_cmd);
    install_element (CONFIG_NODE, &slicing_engine4_cmd);
    install_element (CONFIG_NODE, &slicing_engine5_cmd);
    install_element (CONFIG_NODE, &slicing_engine6_cmd);
    install_element (CONFIG_NODE, &no_slicing_engine_cmd);
    /*added end */


    /*added by wjh for processing engine*/
    install_element (CONFIG_NODE, &processing_engine_cmd);
    install_element (CONFIG_NODE, &no_processing_engine_cmd);
    /*added end */
    /*added by wjh for flow engine*/
    install_element (CONFIG_NODE, &flow_engine_cmd);
    install_element (CONFIG_NODE, &no_flow_engine_cmd);
    install_element (CONFIG_NODE, &add_route_for_route1_cmd);

    install_element (CONFIG_NODE, &ipv6_server_forwarding_cmd);
    install_element (CONFIG_NODE, &no_ipv6_server_forwarding_cmd);
    /*added end */
    //install_element (CONFIG_NODE, &GigabitEthernet_cmd);


    install_element (CONFIG_NODE, &policy_based_route_cmd);
#if 1
    install_element (CONFIG_NODE, &ipv6_twod_based_route_cmd);
    install_element (CONFIG_NODE, &no_ipv6_twod_based_route_cmd);
#endif
    install_element (CONFIG_NODE, &no_policy_based_route_cmd);

    install_element (CONFIG_NODE, &acl_for_rohc_comp_cmd);
    install_element (CONFIG_NODE, &no_acl_for_rohc_comp_cmd);

    install_element (CONFIG_NODE, &access_real_ipv6_source_address_cmd);
    install_element (CONFIG_NODE, &no_access_real_ipv6_source_address_cmd);


#ifdef HAVE_4OVER6_TCPMSS
    install_element (CONFIG_NODE, &tunnel4o6_tcp_mss_cmd);
    install_element (CONFIG_NODE, &no_tunnel4o6_tcp_mss_cmd);
#endif
    install_element (CONFIG_NODE, &ip_protocol_cmd);
    install_element (CONFIG_NODE, &no_ip_protocol_cmd);
    install_element (VIEW_NODE, &show_ip_protocol_cmd);
    install_element (ENABLE_NODE, &show_ip_protocol_cmd);

    /*add dhcp ,add by huang jing in 2013 5 14 */
#ifdef HAVE_DHCPV4
    install_element (CONFIG_NODE, &ip_dhcp_excluded_address_cmd);
    install_element (CONFIG_NODE, &no_ip_dhcp_excluded_address_cmd);
    install_element (CONFIG_NODE, &ip_dhcp_excluded_address__distance1_cmd);
    install_element (CONFIG_NODE, &no_ip_dhcp_excluded_address__distance1_cmd);

    install_element (CONFIG_NODE, &ip_dhcp_pool_cmd);
    install_element (CONFIG_NODE, &no_ip_dhcp_pool_cmd);
    install_element (DHCP_NODE, &ip_dhcp_pool_network_cmd);
    install_element (DHCP_NODE, &no_ip_dhcp_pool_network_cmd);

    install_element (DHCP_NODE, &ip_dhcp_pool_dnsserver_cmd);
    //install_element (DHCP_NODE, &no_ip_dhcp_pool_dnsserver_cmd);
    install_element (DHCP_NODE, &ip_dhcp_pool_dnsserver_dnstince1_cmd);
    //install_element (DHCP_NODE, &no_ip_dhcp_pool_dnsserver_dnstince1_cmd);
    install_element (DHCP_NODE, &ip_dhcp_pool_dnsserver_dnstince2_cmd);
    //install_element (DHCP_NODE, &no_ip_dhcp_pool_dnsserver_dnstince2_cmd);
    install_element (DHCP_NODE, &no_ip_dhcp_pool_dnsserver_cmd);

    install_element (DHCP_NODE, &ip_dhcp_pool_defaultroute_cmd);
    //install_element (DHCP_NODE, &no_ip_dhcp_pool_defaultroute_cmd);
    install_element (DHCP_NODE, &ip_dhcp_pool_defaultroute_dnstince1_cmd);
    //install_element (DHCP_NODE, &no_ip_dhcp_pool_defaultroute_dnstince1_cmd);
    install_element (DHCP_NODE, &ip_dhcp_pool_defaultroute_dnstince2_cmd);
    //install_element (DHCP_NODE, &no_ip_dhcp_pool_defaultroute_dnstince2_cmd);
    install_element (DHCP_NODE, &no_ip_dhcp_pool_defaultroute_cmd);

    install_element (DHCP_NODE, &ip_dhcp_pool_lease_cmd);
    install_element (DHCP_NODE, &ip_dhcp_pool_lease_hours_cmd);
    install_element (DHCP_NODE, &ip_dhcp_pool_lease_minutes_cmd);
    install_element (DHCP_NODE, &no_ip_dhcp_pool_lease_cmd);
#endif
#if 0
    install_element (DHCP_NODE, &ip_dhcp_pool_exit_cmd);
#endif
    /*add dhcp */

    install_element (CONFIG_NODE, &ip_route_cmd);
    install_element (CONFIG_NODE, &ip_route_flags_cmd);
    install_element (CONFIG_NODE, &ip_route_flags2_cmd);
    install_element (CONFIG_NODE, &ip_route_mask_cmd);
    install_element (CONFIG_NODE, &ip_route_mask_flags_cmd);
    install_element (CONFIG_NODE, &ip_route_mask_flags2_cmd);
    install_element (CONFIG_NODE, &no_ip_route_cmd);
    install_element (CONFIG_NODE, &no_ip_route_flags_cmd);
    install_element (CONFIG_NODE, &no_ip_route_flags2_cmd);
    install_element (CONFIG_NODE, &no_ip_route_mask_cmd);
    install_element (CONFIG_NODE, &no_ip_route_mask_flags_cmd);
    install_element (CONFIG_NODE, &no_ip_route_mask_flags2_cmd);
    install_element (CONFIG_NODE, &ip_route_distance_cmd);
    install_element (CONFIG_NODE, &ip_route_flags_distance_cmd);
    install_element (CONFIG_NODE, &ip_route_flags_distance2_cmd);
    install_element (CONFIG_NODE, &ip_route_mask_distance_cmd);
    install_element (CONFIG_NODE, &ip_route_mask_flags_distance_cmd);
    install_element (CONFIG_NODE, &ip_route_mask_flags_distance2_cmd);
    install_element (CONFIG_NODE, &no_ip_route_distance_cmd);
    install_element (CONFIG_NODE, &no_ip_route_flags_distance_cmd);
    install_element (CONFIG_NODE, &no_ip_route_flags_distance2_cmd);
    install_element (CONFIG_NODE, &no_ip_route_mask_flags_distance_cmd);
    install_element (CONFIG_NODE, &no_ip_route_mask_flags_distance2_cmd);

    install_element (VIEW_NODE, &show_ip_route_cmd);
    install_element (VIEW_NODE, &show_ip_frt_route_addr_cmd);
    install_element (VIEW_NODE, &show_ip_route_addr_cmd);
    install_element (VIEW_NODE, &show_ip_route_prefix_cmd);
    install_element (VIEW_NODE, &show_ip_route_prefix_longer_cmd);
    install_element (VIEW_NODE, &show_ip_route_protocol_cmd);
    install_element (VIEW_NODE, &show_ip_route_supernets_cmd);
    install_element (VIEW_NODE, &show_ip_route_summary_cmd);
    install_element (ENABLE_NODE, &show_ip_route_cmd);
    install_element (ENABLE_NODE, &show_ip_frt_route_addr_cmd);
    install_element (ENABLE_NODE, &show_ip_route_addr_cmd);
    install_element (ENABLE_NODE, &show_ip_route_prefix_cmd);
    install_element (ENABLE_NODE, &show_ip_route_prefix_longer_cmd);
    install_element (ENABLE_NODE, &show_ip_route_protocol_cmd);
    install_element (ENABLE_NODE, &show_ip_route_supernets_cmd);
    install_element (ENABLE_NODE, &show_ip_route_summary_cmd);

    install_element (VIEW_NODE, &show_ip_mroute_cmd);
    install_element (ENABLE_NODE, &show_ip_mroute_cmd);

    //added for 4over6 20130205
    install_element (CONFIG_NODE, &ip_4over6_route_mask_cmd);
    install_element (CONFIG_NODE, &no_ip_4over6_route_mask_cmd);
    install_element (CONFIG_NODE, &ip_4over6_route_cmd);
    install_element (CONFIG_NODE, &no_ip_4over6_route_cmd);
#ifdef HAVE_IPNAT
    //added for nat 20130505
    install_element (CONFIG_NODE, &ip_nat_pool_cmd);
    install_element (CONFIG_NODE, &no_ip_nat_pool_cmd);
    install_element (CONFIG_NODE, &ip_nat_source_list_cmd);
    install_element (CONFIG_NODE, &no_ip_nat_source_list_cmd);
    install_element (CONFIG_NODE, &ip_nat_inside_source_list_pool_cmd);
    install_element (CONFIG_NODE, &no_ip_nat_inside_source_list_pool_cmd);
    install_element (INTERFACE_NODE, &ip_nat_inside_cmd);
    install_element (INTERFACE_NODE, &no_ip_nat_inside_cmd);
    install_element (INTERFACE_NODE, &ip_nat_outside_cmd);
    install_element (INTERFACE_NODE, &no_ip_nat_outside_cmd);
    //install_element (ENABLE_NODE, &show_arp_cmd);
#endif
#ifdef HAVE_SNMP
    //added by limingyuan for snmp community config 2013.7.31
    install_element (CONFIG_NODE, &snmp_community_config_cmd);
    install_element (CONFIG_NODE, &no_snmp_community_config_cmd);
    //added by limingyuan for snmp v3 config 2013.8.9
    install_element (CONFIG_NODE, &snmp_v3_config_cmd);
    install_element (CONFIG_NODE, &no_snmp_v3_config_cmd);
    //added by limingyuan for snmp trap config 2013.8.16
    install_element (CONFIG_NODE, &snmp_trap_enable_cmd);
    install_element (CONFIG_NODE, &snmp_trap_disable_cmd);
    install_element (CONFIG_NODE, &snmp_trap_host_config_cmd);
    install_element (CONFIG_NODE, &snmp_trap_host_community_config_cmd);
    install_element (CONFIG_NODE, &no_snmp_trap_host_config_cmd);
    install_element (CONFIG_NODE, &no_snmp_trap_host_community_config_cmd);
#endif
    /*added by zhangzhibo 2013.9.2 for add arp*/
    install_element (CONFIG_NODE, &arp_cmd);
    /*added by zhangzhibo 2013.9.2 for del arp*/
    install_element (CONFIG_NODE, &no_arp_cmd);
#ifdef HAVE_IPV6
    install_element (CONFIG_NODE, &ipv6_route_cmd);
    install_element (CONFIG_NODE, &ipv6_route_flags_cmd);
    install_element (CONFIG_NODE, &ipv6_route_ifname_cmd);
    install_element (CONFIG_NODE, &ipv6_route_ifname_flags_cmd);
    install_element (CONFIG_NODE, &no_ipv6_route_cmd);
    install_element (CONFIG_NODE, &no_ipv6_route_flags_cmd);
    install_element (CONFIG_NODE, &no_ipv6_route_ifname_cmd);
    install_element (CONFIG_NODE, &no_ipv6_route_ifname_flags_cmd);
    install_element (CONFIG_NODE, &ipv6_route_pref_cmd);
    install_element (CONFIG_NODE, &ipv6_route_flags_pref_cmd);
    install_element (CONFIG_NODE, &ipv6_route_ifname_pref_cmd);
    install_element (CONFIG_NODE, &ipv6_route_ifname_flags_pref_cmd);
    install_element (CONFIG_NODE, &no_ipv6_route_pref_cmd);
    install_element (CONFIG_NODE, &no_ipv6_route_flags_pref_cmd);
    install_element (CONFIG_NODE, &no_ipv6_route_ifname_pref_cmd);
    install_element (CONFIG_NODE, &no_ipv6_route_ifname_flags_pref_cmd);
    install_element (VIEW_NODE, &show_ipv6_route_cmd);
    install_element (VIEW_NODE, &show_ipv6_route_summary_cmd);
#if 1
    install_element (VIEW_NODE, &show_ipv6_route_table_name_cmd);
#endif
    install_element (VIEW_NODE, &show_ipv6_route_protocol_cmd);
    install_element (VIEW_NODE, &show_ipv6_route_addr_cmd);
    install_element (VIEW_NODE, &show_ipv6_frt_route_addr_cmd);
    install_element (VIEW_NODE, &show_ipv6_route_prefix_cmd);
    install_element (VIEW_NODE, &show_ipv6_route_prefix_longer_cmd);
    install_element (ENABLE_NODE, &show_ipv6_route_cmd);
    install_element (ENABLE_NODE, &show_ipv6_policy_route_cmd);
    install_element (ENABLE_NODE, &show_ipv6_twod_route_cmd);
#if 1
    install_element (ENABLE_NODE, &show_ipv6_route_table_name_cmd);
#endif
    install_element (ENABLE_NODE, &show_ipv6_route_protocol_cmd);
    install_element (ENABLE_NODE, &show_ipv6_route_addr_cmd);
    install_element (ENABLE_NODE, &show_ipv6_frt_route_addr_cmd);
    install_element (ENABLE_NODE, &show_ipv6_route_prefix_cmd);
    install_element (ENABLE_NODE, &show_ipv6_route_prefix_longer_cmd);
    install_element (ENABLE_NODE, &show_ipv6_route_summary_cmd);
    // install_element (ENABLE_NODE, &show_ipv6_neighbor_cmd);

    install_element (VIEW_NODE, &show_ipv6_mroute_cmd);
    install_element (ENABLE_NODE, &show_ipv6_mroute_cmd);
#if 1							//sangmeng add
    install_element (INTERFACE_NODE, &ip_access_group_listnumber_cmd);
    install_element (INTERFACE_NODE, &no_ip_access_group_listnumber_cmd);
    install_element (INTERFACE_NODE, &ipv6_access_group_listnumber_cmd);
    install_element (INTERFACE_NODE, &no_ipv6_access_group_listnumber_cmd);
#endif
#endif /* HAVE_IPV6 */
#if 1
    //add by ccc for flow separation by people and soldier
    install_element (CONFIG_NODE, &enable_interface_area_cmd);
    install_element (CONFIG_NODE, &no_enable_interface_area_cmd);

    install_element (VIEW_NODE, &show_control_server_configure_cmd);
    install_element (ENABLE_NODE, &show_control_server_configure_cmd);
#endif
#if 1
    //dpdk HA service resource transfer
    install_element (CONFIG_NODE, &HA_resource_transfer_cmd);
#endif

    //install_customize_route();
}
