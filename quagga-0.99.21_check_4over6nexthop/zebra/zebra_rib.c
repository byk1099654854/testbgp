/* Routing Information Base.
 * Copyright (C) 1997, 98, 99, 2001 Kunihiro Ishiguro
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

//added for 4over6 20130307
#include <sys/socket.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <linux/ip6_tunnel.h>
#include <linux/if_tunnel.h>
#include <errno.h>
#include <stdio.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <net/if.h>
#include <net/if_arp.h>

#include "prefix.h"
#include "table.h"
#include "memory.h"
#include "str.h"
#include "command.h"
#include "if.h"
#include "log.h"
#include "sockunion.h"
#include "linklist.h"
#include "thread.h"
#include "workqueue.h"
#include "prefix.h"
#include "routemap.h"
#include "zclient.h"

#include "zebra/interface.h"
#include "zebra/rib.h"
#include "zebra/rt.h"
#include "zebra/zserv.h"
#include "zebra/redistribute.h"
#include "zebra/debug.h"

//sangmeng add for customize route 20180703
#define CUSTOMIZEROUTE 1
#define ADDROUTE 1
#define DELROUTE 0
/*return value*/
#define OK 0
#define ERR -1
#define ADD_ROUTE_OK  1
#define ADD_ROUTE_ERR 0
#define NEED_RECV_MSG 1
#define NONEED_RECV_MSG 0

//added for 4over6 20130305
struct zebra_4over6_tunnel_entry zebra4over6TunnelEntry;
int tunnel_Name = 0;
char tnl_number[TUNNELNUMBER];

/* Default rtm_table for all clients */
extern struct zebra_t zebrad;

/* Hold time for RIB process, should be very minimal.
 * it is useful to able to set it otherwise for testing, hence exported
 * as global here for test-rig code.
 */
int rib_process_hold_time = 10;

/* Each route type's string and default distance value. */
static const struct
{
    int key;
    int distance;
} route_info[ZEBRA_ROUTE_MAX] =
{
    [ZEBRA_ROUTE_SYSTEM] =
    {
        ZEBRA_ROUTE_SYSTEM, 0
    },[ZEBRA_ROUTE_KERNEL] =
    {
        ZEBRA_ROUTE_KERNEL, 0
    },[ZEBRA_ROUTE_CONNECT] =
    {
        ZEBRA_ROUTE_CONNECT, 0
    },[ZEBRA_ROUTE_STATIC] =
    {
        ZEBRA_ROUTE_STATIC, 1
    },[ZEBRA_ROUTE_RIP] =
    {
        ZEBRA_ROUTE_RIP, 120
    },[ZEBRA_ROUTE_RIPNG] =
    {
        ZEBRA_ROUTE_RIPNG, 120
    },[ZEBRA_ROUTE_OSPF] =
    {
        ZEBRA_ROUTE_OSPF, 110
    },[ZEBRA_ROUTE_OSPF6] =
    {
        ZEBRA_ROUTE_OSPF6, 110
    },[ZEBRA_ROUTE_ISIS] =
    {
        ZEBRA_ROUTE_ISIS, 115
    },[ZEBRA_ROUTE_BGP] =
    {
        ZEBRA_ROUTE_BGP, 20 /* IBGP is 200. */
    },
    [ZEBRA_ROUTE_BABEL] =
    {
        ZEBRA_ROUTE_BABEL, 95
    },
    /* no entry/default: 150 */
};
//sangmeng add for send msg to dpdk 20180706
int connect_dpdk_multiport (int port)
{
    int fd;
    int ret = 0;
    struct sockaddr_in socketaddress;

    fd = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd <= 0)
    {
        fprintf (stderr, "%s\n", "socket fail");
        return ERR;
    }
    socketaddress.sin_family = AF_INET;
    socketaddress.sin_port = htons (port);
    socketaddress.sin_addr.s_addr = inet_addr (DPDK_SERVER_ADDRESS);
    /*start connect */
    ret = connect (fd, &socketaddress, sizeof (struct sockaddr));
    if (ret < 0)
    {
        fprintf (stderr, "%s\n", "connect server fail");
        close (fd);
        return ERR;
    }
    return fd;
}
int send_msg_to_dpdk(int needrecvmsg ,void *sendmsg, int len, int msgtype, void *recvmsg)
{
    int sockfd;
    int ret;

#if 0
    struct ipv4_route_customize *route_customize;
    route_customize = ((struct comm_head *)sendmsg)->data;
    printf(".............type:%d.\n", route_customize->type);
    char buf[64];
    inet_ntop (AF_INET, &route_customize->p.prefix, buf, 64);
    printf("............%s/%d\n", buf,route_customize->p.prefixlen);
#endif

    if ((sockfd = connect_dpdk_multiport (DPDK_SERVER_PORT)) == -1)
    {
        XFREE (msgtype, sendmsg);
        return ERR;
    }

    ret = send (sockfd, sendmsg, len, 0);
    if (ret < 0)
    {
        fprintf (stderr,"send msg to dpdk failed, %d.\n", ret);
        close (sockfd);
        XFREE (msgtype, sendmsg);
        return ERR;
    }

    printf("send %d bytes to dpdk.\n", ret);
    if (needrecvmsg)
    {
        memset (recvmsg, 0, sizeof (recvmsg));
        ret = recv (sockfd, recvmsg, sizeof (recvmsg), 0);
        if (ret < 0)
        {
            fprintf (stderr, "%s\n", "recv message failed");
            close (sockfd);
            XFREE (msgtype, sendmsg);
            return ERR;
        }
    }
    XFREE (msgtype, sendmsg);
    return OK;
}

/* Vector for routing table.  */
static vector vrf_vector;

/* Allocate new VRF.  */
static struct vrf *vrf_alloc (const char *name)
{
    struct vrf *vrf;

    vrf = XCALLOC (MTYPE_VRF, sizeof (struct vrf));

    /* Put name.  */
    if (name)
        vrf->name = XSTRDUP (MTYPE_VRF_NAME, name);

    /* Allocate routing table and static table.  */
    vrf->table[AFI_IP][SAFI_UNICAST] = route_table_init ();
    vrf->table[AFI_IP6][SAFI_UNICAST] = route_table_init ();
    vrf->stable[AFI_IP][SAFI_UNICAST] = route_table_init ();
    vrf->stable[AFI_IP6][SAFI_UNICAST] = route_table_init ();
    vrf->table[AFI_IP][SAFI_MULTICAST] = route_table_init ();
    vrf->table[AFI_IP6][SAFI_MULTICAST] = route_table_init ();
    vrf->stable[AFI_IP][SAFI_MULTICAST] = route_table_init ();
    vrf->stable[AFI_IP6][SAFI_MULTICAST] = route_table_init ();
    //added for 4over6 20130204
    vrf->table[AFI_IP][SAFI_4OVER6] = route_table_init ();
    vrf->stable[AFI_IP][SAFI_4OVER6] = route_table_init ();
    //add for customize route table init 20180702
#if 0
    vrf->table[AFI_IP][SAFI_CUSTOMIZE_ONE] = route_table_init ();
    vrf->stable[AFI_IP][SAFI_CUSTOMIZE_ONE] = route_table_init ();
    vrf->table[AFI_IP6][SAFI_CUSTOMIZE_ONE] = route_table_init ();
    vrf->stable[AFI_IP6][SAFI_CUSTOMIZE_ONE] = route_table_init ();
#endif

    //sangmeng add for init custoimize route table
    for(int i=6; i< 14; i++)
    {
        vrf->table[AFI_IP][i] = route_table_init ();
        vrf->stable[AFI_IP][i] = route_table_init ();
        vrf->table[AFI_IP6][i] = route_table_init ();
        vrf->stable[AFI_IP6][i] = route_table_init ();
    }

    return vrf;
}

/* Lookup VRF by identifier.  */
struct vrf *vrf_lookup (u_int32_t id)
{
    return vector_lookup (vrf_vector, id);
}

/* Initialize VRF.  */
static void vrf_init (void)
{
    struct vrf *default_table;

    /* Allocate VRF vector.  */
    vrf_vector = vector_init (1);

    /* Allocate default main table.  */
    default_table = vrf_alloc ("Default-IP-Routing-Table");

    /* Default table index must be 0.  */
    vector_set_index (vrf_vector, 0, default_table);
}

/* Lookup route table.  */
struct route_table *vrf_table (afi_t afi, safi_t safi, u_int32_t id)
{
    struct vrf *vrf;

    vrf = vrf_lookup (id);
    if (!vrf)
        return NULL;

    return vrf->table[afi][safi];
}

/* Lookup static route table.  */
struct route_table *vrf_static_table (afi_t afi, safi_t safi, u_int32_t id)
{
    struct vrf *vrf;

    vrf = vrf_lookup (id);
    if (!vrf)
        return NULL;

    return vrf->stable[afi][safi];
}
/* Add nexthop to the end of the list.  */
static void nexthop_add (struct rib *rib, struct nexthop *nexthop)
{
    struct nexthop *last;

    for (last = rib->nexthop; last && last->next; last = last->next)
        ;
    if (last)
        last->next = nexthop;
    else
        rib->nexthop = nexthop;
    nexthop->prev = last;

    rib->nexthop_num++;
}

/* Delete specified nexthop from the list. */
static void nexthop_delete (struct rib *rib, struct nexthop *nexthop)
{
    if (nexthop->next)
        nexthop->next->prev = nexthop->prev;
    if (nexthop->prev)
        nexthop->prev->next = nexthop->next;
    else
        rib->nexthop = nexthop->next;
    rib->nexthop_num--;
}

/* Free nexthop. */
static void nexthop_free (struct nexthop *nexthop)
{
    if (nexthop->ifname)
        XFREE (0, nexthop->ifname);
    XFREE (MTYPE_NEXTHOP, nexthop);
}

struct nexthop *nexthop_ifindex_add (struct rib *rib, unsigned int ifindex)
{
    struct nexthop *nexthop;

    nexthop = XCALLOC (MTYPE_NEXTHOP, sizeof (struct nexthop));
    nexthop->type = NEXTHOP_TYPE_IFINDEX;
    nexthop->ifindex = ifindex;

    nexthop_add (rib, nexthop);

    return nexthop;
}

struct nexthop *nexthop_ifname_add (struct rib *rib, char *ifname)
{
    struct nexthop *nexthop;

    nexthop = XCALLOC (MTYPE_NEXTHOP, sizeof (struct nexthop));
    nexthop->type = NEXTHOP_TYPE_IFNAME;
    nexthop->ifname = XSTRDUP (0, ifname);

    nexthop_add (rib, nexthop);

    return nexthop;
}

struct nexthop *nexthop_ipv4_add (struct rib *rib, struct in_addr *ipv4, struct in_addr *src)
{
    struct nexthop *nexthop;

    nexthop = XCALLOC (MTYPE_NEXTHOP, sizeof (struct nexthop));
    nexthop->type = NEXTHOP_TYPE_IPV4;
    nexthop->gate.ipv4 = *ipv4;
    if (src)
        nexthop->src.ipv4 = *src;

    nexthop_add (rib, nexthop);

    return nexthop;
}

struct nexthop *nexthop_ipv4_ifindex_add (struct rib *rib, struct in_addr *ipv4, struct in_addr *src, unsigned int ifindex)
{
    struct nexthop *nexthop;

    nexthop = XCALLOC (MTYPE_NEXTHOP, sizeof (struct nexthop));
    nexthop->type = NEXTHOP_TYPE_IPV4_IFINDEX;
    nexthop->gate.ipv4 = *ipv4;
    if (src)
        nexthop->src.ipv4 = *src;
    nexthop->ifindex = ifindex;

    nexthop_add (rib, nexthop);

    return nexthop;
}

#ifdef HAVE_IPV6
struct nexthop *nexthop_ipv6_add (struct rib *rib, struct in6_addr *ipv6)
{
    struct nexthop *nexthop;

    nexthop = XCALLOC (MTYPE_NEXTHOP, sizeof (struct nexthop));
    nexthop->type = NEXTHOP_TYPE_IPV6;
    nexthop->gate.ipv6 = *ipv6;

    nexthop_add (rib, nexthop);

    return nexthop;
}

static struct nexthop *nexthop_ipv6_ifname_add (struct rib *rib, struct in6_addr *ipv6, char *ifname)
{
    struct nexthop *nexthop;

    nexthop = XCALLOC (MTYPE_NEXTHOP, sizeof (struct nexthop));
    nexthop->type = NEXTHOP_TYPE_IPV6_IFNAME;
    nexthop->gate.ipv6 = *ipv6;
    nexthop->ifname = XSTRDUP (0, ifname);

    nexthop_add (rib, nexthop);

    return nexthop;
}

static struct nexthop *nexthop_ipv6_ifindex_add (struct rib *rib, struct in6_addr *ipv6, unsigned int ifindex)
{
    struct nexthop *nexthop;

    nexthop = XCALLOC (MTYPE_NEXTHOP, sizeof (struct nexthop));
    nexthop->type = NEXTHOP_TYPE_IPV6_IFINDEX;
    nexthop->gate.ipv6 = *ipv6;
    nexthop->ifindex = ifindex;

    nexthop_add (rib, nexthop);

    return nexthop;
}
#endif /* HAVE_IPV6 */

struct nexthop *nexthop_blackhole_add (struct rib *rib)
{
    struct nexthop *nexthop;

    nexthop = XCALLOC (MTYPE_NEXTHOP, sizeof (struct nexthop));
    nexthop->type = NEXTHOP_TYPE_BLACKHOLE;
    SET_FLAG (rib->flags, ZEBRA_FLAG_BLACKHOLE);

    nexthop_add (rib, nexthop);

    return nexthop;
}

/* If force flag is not set, do not modify falgs at all for uninstall
   the route from FIB. */
static int nexthop_active_ipv4 (struct rib *rib, struct nexthop *nexthop, int set, struct route_node *top)
{
    struct prefix_ipv4 p;
    struct route_table *table;
    struct route_node *rn;
    struct rib *match;
    struct nexthop *newhop;

    if (nexthop->type == NEXTHOP_TYPE_IPV4)
        nexthop->ifindex = 0;

    if (set)
        UNSET_FLAG (nexthop->flags, NEXTHOP_FLAG_RECURSIVE);

    /* Make lookup prefix. */
    memset (&p, 0, sizeof (struct prefix_ipv4));
    p.family = AF_INET;
    p.prefixlen = IPV4_MAX_PREFIXLEN;
    p.prefix = nexthop->gate.ipv4;

    /* Lookup table.  */
    table = vrf_table (AFI_IP, SAFI_UNICAST, 0);
    if (!table)
        return 0;

    rn = route_node_match (table, (struct prefix *) &p);
    while (rn)
    {
        route_unlock_node (rn);

        /* If lookup self prefix return immediately. */
        if (rn == top)
            return 0;

        /* Pick up selected route. */
        for (match = rn->info; match; match = match->next)
        {
            if (CHECK_FLAG (match->status, RIB_ENTRY_REMOVED))
                continue;
            if (CHECK_FLAG (match->flags, ZEBRA_FLAG_SELECTED))
                break;
        }

        /* If there is no selected route or matched route is EGP, go up
           tree. */
        if (!match || match->type == ZEBRA_ROUTE_BGP)
        {
            do
            {
                rn = rn->parent;
            }
            while (rn && rn->info == NULL);
            if (rn)
                route_lock_node (rn);
        }
        else
        {
            if (match->type == ZEBRA_ROUTE_CONNECT)
            {
                /* Directly point connected route. */
                newhop = match->nexthop;
                if (newhop && nexthop->type == NEXTHOP_TYPE_IPV4)
                    nexthop->ifindex = newhop->ifindex;

                return 1;
            }
            else if (CHECK_FLAG (rib->flags, ZEBRA_FLAG_INTERNAL))
            {
                for (newhop = match->nexthop; newhop; newhop = newhop->next)
                    if (CHECK_FLAG (newhop->flags, NEXTHOP_FLAG_FIB) && !CHECK_FLAG (newhop->flags, NEXTHOP_FLAG_RECURSIVE))
                    {
                        if (set)
                        {
                            SET_FLAG (nexthop->flags, NEXTHOP_FLAG_RECURSIVE);
                            nexthop->rtype = newhop->type;
                            if (newhop->type == NEXTHOP_TYPE_IPV4 || newhop->type == NEXTHOP_TYPE_IPV4_IFINDEX)
                                nexthop->rgate.ipv4 = newhop->gate.ipv4;
                            if (newhop->type == NEXTHOP_TYPE_IFINDEX || newhop->type == NEXTHOP_TYPE_IFNAME || newhop->type == NEXTHOP_TYPE_IPV4_IFINDEX)
                                nexthop->rifindex = newhop->ifindex;
                        }
                        return 1;
                    }
                return 0;
            }
            else
            {
                return 0;
            }
        }
    }
    return 0;
}

#ifdef HAVE_IPV6
/* If force flag is not set, do not modify falgs at all for uninstall
   the route from FIB. */
static int nexthop_active_ipv6 (struct rib *rib, struct nexthop *nexthop, int set, struct route_node *top)
{
    struct prefix_ipv6 p;
    struct route_table *table;
    struct route_node *rn;
    struct rib *match;
    struct nexthop *newhop;

    if (nexthop->type == NEXTHOP_TYPE_IPV6)
        nexthop->ifindex = 0;

    if (set)
        UNSET_FLAG (nexthop->flags, NEXTHOP_FLAG_RECURSIVE);

    /* Make lookup prefix. */
    memset (&p, 0, sizeof (struct prefix_ipv6));
    p.family = AF_INET6;
    p.prefixlen = IPV6_MAX_PREFIXLEN;
    p.prefix = nexthop->gate.ipv6;

    /* Lookup table.  */
    table = vrf_table (AFI_IP6, SAFI_UNICAST, 0);
    if (!table)
        return 0;

    rn = route_node_match (table, (struct prefix *) &p);
    while (rn)
    {
        route_unlock_node (rn);

        /* If lookup self prefix return immediately. */
        if (rn == top)
            return 0;

        /* Pick up selected route. */
        for (match = rn->info; match; match = match->next)
        {
            if (CHECK_FLAG (match->status, RIB_ENTRY_REMOVED))
                continue;
            if (CHECK_FLAG (match->flags, ZEBRA_FLAG_SELECTED))
                break;
        }

        /* If there is no selected route or matched route is EGP, go up
           tree. */
        if (!match || match->type == ZEBRA_ROUTE_BGP)
        {
            do
            {
                rn = rn->parent;
            }
            while (rn && rn->info == NULL);
            if (rn)
                route_lock_node (rn);
        }
        else
        {
            if (match->type == ZEBRA_ROUTE_CONNECT)
            {
                /* Directly point connected route. */
                newhop = match->nexthop;

                if (newhop && nexthop->type == NEXTHOP_TYPE_IPV6)
                    nexthop->ifindex = newhop->ifindex;

                return 1;
            }
            else if (CHECK_FLAG (rib->flags, ZEBRA_FLAG_INTERNAL))
            {
                for (newhop = match->nexthop; newhop; newhop = newhop->next)
                    if (CHECK_FLAG (newhop->flags, NEXTHOP_FLAG_FIB) && !CHECK_FLAG (newhop->flags, NEXTHOP_FLAG_RECURSIVE))
                    {
                        if (set)
                        {
                            SET_FLAG (nexthop->flags, NEXTHOP_FLAG_RECURSIVE);
                            nexthop->rtype = newhop->type;
                            if (newhop->type == NEXTHOP_TYPE_IPV6 || newhop->type == NEXTHOP_TYPE_IPV6_IFINDEX || newhop->type == NEXTHOP_TYPE_IPV6_IFNAME)
                                nexthop->rgate.ipv6 = newhop->gate.ipv6;
                            if (newhop->type == NEXTHOP_TYPE_IFINDEX || newhop->type == NEXTHOP_TYPE_IFNAME || newhop->type == NEXTHOP_TYPE_IPV6_IFINDEX || newhop->type == NEXTHOP_TYPE_IPV6_IFNAME)
                                nexthop->rifindex = newhop->ifindex;
                        }
                        return 1;
                    }
                return 0;
            }
            else
            {
                return 0;
            }
        }
    }
    return 0;
}
#endif /* HAVE_IPV6 */

struct rib *rib_match_ipv4 (struct in_addr addr)
{
    struct prefix_ipv4 p;
    struct route_table *table;
    struct route_node *rn;
    struct rib *match;
    struct nexthop *newhop;

    /* Lookup table.  */
    table = vrf_table (AFI_IP, SAFI_UNICAST, 0);
    if (!table)
        return 0;

    memset (&p, 0, sizeof (struct prefix_ipv4));
    p.family = AF_INET;
    p.prefixlen = IPV4_MAX_PREFIXLEN;
    p.prefix = addr;

    rn = route_node_match (table, (struct prefix *) &p);

    while (rn)
    {
        route_unlock_node (rn);

        /* Pick up selected route. */
        for (match = rn->info; match; match = match->next)
        {
            if (CHECK_FLAG (match->status, RIB_ENTRY_REMOVED))
                continue;
            if (CHECK_FLAG (match->flags, ZEBRA_FLAG_SELECTED))
                break;
        }

        /* If there is no selected route or matched route is EGP, go up
           tree. */
        if (!match || match->type == ZEBRA_ROUTE_BGP)
        {
            do
            {
                rn = rn->parent;
            }
            while (rn && rn->info == NULL);
            if (rn)
                route_lock_node (rn);
        }
        else
        {
            if (match->type == ZEBRA_ROUTE_CONNECT)
                /* Directly point connected route. */
                return match;
            else
            {
                for (newhop = match->nexthop; newhop; newhop = newhop->next)
                    if (CHECK_FLAG (newhop->flags, NEXTHOP_FLAG_FIB))
                        return match;
                return NULL;
            }
        }
    }
    return NULL;
}

struct rib *rib_lookup_ipv4 (struct prefix_ipv4 *p)
{
    struct route_table *table;
    struct route_node *rn;
    struct rib *match;
    struct nexthop *nexthop;

    /* Lookup table.  */
    table = vrf_table (AFI_IP, SAFI_UNICAST, 0);
    if (!table)
        return 0;

    rn = route_node_lookup (table, (struct prefix *) p);

    /* No route for this prefix. */
    if (!rn)
        return NULL;

    /* Unlock node. */
    route_unlock_node (rn);

    for (match = rn->info; match; match = match->next)
    {
        if (CHECK_FLAG (match->status, RIB_ENTRY_REMOVED))
            continue;
        if (CHECK_FLAG (match->flags, ZEBRA_FLAG_SELECTED))
            break;
    }

    if (!match || match->type == ZEBRA_ROUTE_BGP)
        return NULL;

    if (match->type == ZEBRA_ROUTE_CONNECT)
        return match;

    for (nexthop = match->nexthop; nexthop; nexthop = nexthop->next)
        if (CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB))
            return match;

    return NULL;
}

/*
 * This clone function, unlike its original rib_lookup_ipv4(), checks
 * if specified IPv4 route record (prefix/mask -> gate) exists in
 * the whole RIB and has ZEBRA_FLAG_SELECTED set.
 *
 * Return values:
 * -1: error
 * 0: exact match found
 * 1: a match was found with a different gate
 * 2: connected route found
 * 3: no matches found
 */
int rib_lookup_ipv4_route (struct prefix_ipv4 *p, union sockunion *qgate)
{
    struct route_table *table;
    struct route_node *rn;
    struct rib *match;
    struct nexthop *nexthop;

    /* Lookup table.  */
    table = vrf_table (AFI_IP, SAFI_UNICAST, 0);
    if (!table)
        return ZEBRA_RIB_LOOKUP_ERROR;

    /* Scan the RIB table for exactly matching RIB entry. */
    rn = route_node_lookup (table, (struct prefix *) p);

    /* No route for this prefix. */
    if (!rn)
        return ZEBRA_RIB_NOTFOUND;

    /* Unlock node. */
    route_unlock_node (rn);

    /* Find out if a "selected" RR for the discovered RIB entry exists ever. */
    for (match = rn->info; match; match = match->next)
    {
        if (CHECK_FLAG (match->status, RIB_ENTRY_REMOVED))
            continue;
        if (CHECK_FLAG (match->flags, ZEBRA_FLAG_SELECTED))
            break;
    }

    /* None such found :( */
    if (!match)
        return ZEBRA_RIB_NOTFOUND;

    if (match->type == ZEBRA_ROUTE_CONNECT)
        return ZEBRA_RIB_FOUND_CONNECTED;

    /* Ok, we have a cood candidate, let's check it's nexthop list... */
    for (nexthop = match->nexthop; nexthop; nexthop = nexthop->next)
        if (CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB))
        {
            /* We are happy with either direct or recursive hexthop */
            if (nexthop->gate.ipv4.s_addr == qgate->sin.sin_addr.s_addr || nexthop->rgate.ipv4.s_addr == qgate->sin.sin_addr.s_addr)
                return ZEBRA_RIB_FOUND_EXACT;
            else
            {
                if (IS_ZEBRA_DEBUG_RIB)
                {
                    char gate_buf[INET_ADDRSTRLEN], rgate_buf[INET_ADDRSTRLEN], qgate_buf[INET_ADDRSTRLEN];
                    inet_ntop (AF_INET, &nexthop->gate.ipv4.s_addr, gate_buf, INET_ADDRSTRLEN);
                    inet_ntop (AF_INET, &nexthop->rgate.ipv4.s_addr, rgate_buf, INET_ADDRSTRLEN);
                    inet_ntop (AF_INET, &qgate->sin.sin_addr.s_addr, qgate_buf, INET_ADDRSTRLEN);
                    zlog_debug ("%s: qgate == %s, gate == %s, rgate == %s", __func__, qgate_buf, gate_buf, rgate_buf);
                }
                return ZEBRA_RIB_FOUND_NOGATE;
            }
        }

    return ZEBRA_RIB_NOTFOUND;
}

#ifdef HAVE_IPV6
struct rib *rib_match_ipv6 (struct in6_addr *addr)
{
    struct prefix_ipv6 p;
    struct route_table *table;
    struct route_node *rn;
    struct rib *match;
    struct nexthop *newhop;

    /* Lookup table.  */
    table = vrf_table (AFI_IP6, SAFI_UNICAST, 0);
    if (!table)
        return 0;

    memset (&p, 0, sizeof (struct prefix_ipv6));
    p.family = AF_INET6;
    p.prefixlen = IPV6_MAX_PREFIXLEN;
    IPV6_ADDR_COPY (&p.prefix, addr);

    rn = route_node_match (table, (struct prefix *) &p);

    while (rn)
    {
        route_unlock_node (rn);

        /* Pick up selected route. */
        for (match = rn->info; match; match = match->next)
        {
            if (CHECK_FLAG (match->status, RIB_ENTRY_REMOVED))
                continue;
            if (CHECK_FLAG (match->flags, ZEBRA_FLAG_SELECTED))
                break;
        }

        /* If there is no selected route or matched route is EGP, go up
           tree. */
        if (!match || match->type == ZEBRA_ROUTE_BGP)
        {
            do
            {
                rn = rn->parent;
            }
            while (rn && rn->info == NULL);
            if (rn)
                route_lock_node (rn);
        }
        else
        {
            if (match->type == ZEBRA_ROUTE_CONNECT)
                /* Directly point connected route. */
                return match;
            else
            {
                for (newhop = match->nexthop; newhop; newhop = newhop->next)
                    if (CHECK_FLAG (newhop->flags, NEXTHOP_FLAG_FIB))
                        return match;
                return NULL;
            }
        }
    }
    return NULL;
}
#endif /* HAVE_IPV6 */

#define RIB_SYSTEM_ROUTE(R) \
        ((R)->type == ZEBRA_ROUTE_KERNEL || (R)->type == ZEBRA_ROUTE_CONNECT)

/* This function verifies reachability of one given nexthop, which can be
 * numbered or unnumbered, IPv4 or IPv6. The result is unconditionally stored
 * in nexthop->flags field. If the 4th parameter, 'set', is non-zero,
 * nexthop->ifindex will be updated appropriately as well.
 * An existing route map can turn (otherwise active) nexthop into inactive, but
 * not vice versa.
 *
 * The return value is the final value of 'ACTIVE' flag.
 */

static unsigned nexthop_active_check (struct route_node *rn, struct rib *rib, struct nexthop *nexthop, int set)
{
    struct interface *ifp;
    route_map_result_t ret = RMAP_MATCH;
    extern char *proto_rm[AFI_MAX][ZEBRA_ROUTE_MAX + 1];
    struct route_map *rmap;
    int family;
    int iRetVal = 0;

    family = 0;
    switch (nexthop->type)
    {
    case NEXTHOP_TYPE_IFINDEX:
        ifp = if_lookup_by_index (nexthop->ifindex);
        if (ifp && if_is_operative (ifp))
            SET_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE);
        else
            UNSET_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE);
        break;
    case NEXTHOP_TYPE_IPV6_IFNAME:
        family = AFI_IP6;
    case NEXTHOP_TYPE_IFNAME:
        zlog_notice ("nexthop_active_check: ifname: %s, set = %d", nexthop->ifname, set);
        ifp = if_lookup_by_name (nexthop->ifname);
        if (ifp)
        {
            iRetVal = if_is_operative (ifp);
            zlog_notice ("nexthop_active_check: iRetVal = %d", iRetVal);
        }

        if (ifp && if_is_operative (ifp))
        {
            if (set)
                nexthop->ifindex = ifp->ifindex;
            SET_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE);
        }
        else
        {
            if (set)
                nexthop->ifindex = 0;
            UNSET_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE);
        }
        break;
    case NEXTHOP_TYPE_IPV4:
    case NEXTHOP_TYPE_IPV4_IFINDEX:
        family = AFI_IP;
        if (nexthop_active_ipv4 (rib, nexthop, set, rn))
            SET_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE);
        else
            UNSET_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE);
        break;
#ifdef HAVE_IPV6
    case NEXTHOP_TYPE_IPV6:
        family = AFI_IP6;
        if (nexthop_active_ipv6 (rib, nexthop, set, rn))
            SET_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE);
        else
            UNSET_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE);
        break;
    case NEXTHOP_TYPE_IPV6_IFINDEX:
        family = AFI_IP6;
        if (IN6_IS_ADDR_LINKLOCAL (&nexthop->gate.ipv6))
        {
            ifp = if_lookup_by_index (nexthop->ifindex);
            if (ifp && if_is_operative (ifp))
                SET_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE);
            else
                UNSET_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE);
        }
        else
        {
            if (nexthop_active_ipv6 (rib, nexthop, set, rn))
                SET_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE);
            else
                UNSET_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE);
        }
        break;
#endif /* HAVE_IPV6 */
    case NEXTHOP_TYPE_BLACKHOLE:
        SET_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE);
        break;
    default:
        break;
    }
    if (!CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE))
        return 0;

    if (RIB_SYSTEM_ROUTE (rib) || (family == AFI_IP && rn->p.family != AF_INET) || (family == AFI_IP6 && rn->p.family != AF_INET6))
        return CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE);

    rmap = 0;
    if (rib->type >= 0 && rib->type < ZEBRA_ROUTE_MAX && proto_rm[family][rib->type])
        rmap = route_map_lookup_by_name (proto_rm[family][rib->type]);
    if (!rmap && proto_rm[family][ZEBRA_ROUTE_MAX])
        rmap = route_map_lookup_by_name (proto_rm[family][ZEBRA_ROUTE_MAX]);
    if (rmap)
    {
        ret = route_map_apply (rmap, &rn->p, RMAP_ZEBRA, nexthop);
    }

    if (ret == RMAP_DENYMATCH)
        UNSET_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE);
    return CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE);
}

/* Iterate over all nexthops of the given RIB entry and refresh their
 * ACTIVE flag. rib->nexthop_active_num is updated accordingly. If any
 * nexthop is found to toggle the ACTIVE flag, the whole rib structure
 * is flagged with ZEBRA_FLAG_CHANGED. The 4th 'set' argument is
 * transparently passed to nexthop_active_check().
 *
 * Return value is the new number of active nexthops.
 */

static int nexthop_active_update (struct route_node *rn, struct rib *rib, int set)
{
    struct nexthop *nexthop;
    unsigned int prev_active, prev_index, new_active;

    rib->nexthop_active_num = 0;
    UNSET_FLAG (rib->flags, ZEBRA_FLAG_CHANGED);

    for (nexthop = rib->nexthop; nexthop; nexthop = nexthop->next)
    {
        prev_active = CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE);
        prev_index = nexthop->ifindex;
        if ((new_active = nexthop_active_check (rn, rib, nexthop, set)))
            rib->nexthop_active_num++;
        if (prev_active != new_active || prev_index != nexthop->ifindex)
            SET_FLAG (rib->flags, ZEBRA_FLAG_CHANGED);
    }
    return rib->nexthop_active_num;
}
static void rib_install_kernel (struct route_node *rn, struct rib *rib)
{
    int ret = 0;
    struct nexthop *nexthop;

    switch (PREFIX_FAMILY (&rn->p))
    {
    case AF_INET:
        ret = kernel_add_ipv4 (&rn->p, rib);
        break;
#ifdef HAVE_IPV6
    case AF_INET6:
        ret = kernel_add_ipv6 (&rn->p, rib);
        break;
#endif /* HAVE_IPV6 */
    }

    /* This condition is never met, if we are using rt_socket.c */
    if (ret < 0)
    {
        for (nexthop = rib->nexthop; nexthop; nexthop = nexthop->next)
            UNSET_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB);
    }
}

/* Uninstall the route from kernel. */
static int rib_uninstall_kernel (struct route_node *rn, struct rib *rib)
{
    int ret = 0;
    struct nexthop *nexthop;

    switch (PREFIX_FAMILY (&rn->p))
    {
    case AF_INET:
        ret = kernel_delete_ipv4 (&rn->p, rib);
        break;
#ifdef HAVE_IPV6
    case AF_INET6:
        ret = kernel_delete_ipv6 (&rn->p, rib);
        break;
#endif /* HAVE_IPV6 */
    }

    for (nexthop = rib->nexthop; nexthop; nexthop = nexthop->next)
        UNSET_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB);

    return ret;
}

/* Uninstall the route from kernel. */
static void rib_uninstall (struct route_node *rn, struct rib *rib)
{
    if (CHECK_FLAG (rib->flags, ZEBRA_FLAG_SELECTED))
    {
        redistribute_delete (&rn->p, rib);
        if (!RIB_SYSTEM_ROUTE (rib))
            rib_uninstall_kernel (rn, rib);
        UNSET_FLAG (rib->flags, ZEBRA_FLAG_SELECTED);
    }
}

static void rib_unlink (struct route_node *, struct rib *);
//sangmeng mark here 20190909
/* Core function for processing routing information base. */
static void rib_process (struct route_node *rn)
{
    struct rib *rib;
    struct rib *next;
    struct rib *fib = NULL;
    struct rib *select = NULL;
    struct rib *del = NULL;
    int installed = 0;
    struct nexthop *nexthop = NULL;
    char buf[INET6_ADDRSTRLEN];

    assert (rn);

    if (IS_ZEBRA_DEBUG_RIB || IS_ZEBRA_DEBUG_RIB_Q)
        inet_ntop (rn->p.family, &rn->p.u.prefix, buf, INET6_ADDRSTRLEN);

    for (rib = rn->info; rib; rib = next)
    {
        /* The next pointer is saved, because current pointer
         * may be passed to rib_unlink() in the middle of iteration.
         */
        next = rib->next;

        /* Currently installed rib. */
        if (CHECK_FLAG (rib->flags, ZEBRA_FLAG_SELECTED))
        {

            assert (fib == NULL);
            if(rib->type_customize != CUSTOMIZEROUTE)
                fib = rib;
        }

        /* Unlock removed routes, so they'll be freed, bar the FIB entry,
         * which we need to do do further work with below.
         */
        if (CHECK_FLAG (rib->status, RIB_ENTRY_REMOVED))
        {
            if (rib != fib)
            {
                if (IS_ZEBRA_DEBUG_RIB)
                    zlog_debug ("%s: %s/%d: rn %p, removing rib %p", __func__, buf, rn->p.prefixlen, rn, rib);
                rib_unlink (rn, rib);
            }
            else
                del = rib;

            continue;
        }

        /* Skip unreachable nexthop. */
        if (!nexthop_active_update (rn, rib, 0))
            continue;

        /* Infinit distance. */
        if (rib->distance == DISTANCE_INFINITY)
            continue;

        /* Newly selected rib, the common case. */
        if (!select)
        {
            select = rib;
            continue;
        }

        /* filter route selection in following order:
         * - connected beats other types
         * - lower distance beats higher
         * - lower metric beats higher for equal distance
         * - last, hence oldest, route wins tie break.
         */

        /* Connected routes. Pick the last connected
         * route of the set of lowest metric connected routes.
         */
        if (rib->type == ZEBRA_ROUTE_CONNECT)
        {
            if (select->type != ZEBRA_ROUTE_CONNECT || rib->metric <= select->metric)
                select = rib;
            continue;
        }
        else if (select->type == ZEBRA_ROUTE_CONNECT)
            continue;

        /* higher distance loses */
        if (rib->distance > select->distance)
            continue;

        /* lower wins */
        if (rib->distance < select->distance)
        {
            select = rib;
            continue;
        }

        /* metric tie-breaks equal distance */
        if (rib->metric <= select->metric)
            select = rib;
    }							/* for (rib = rn->info; rib; rib = next) */

    /* After the cycle is finished, the following pointers will be set:
     * select --- the winner RIB entry, if any was found, otherwise NULL
     * fib    --- the SELECTED RIB entry, if any, otherwise NULL
     * del    --- equal to fib, if fib is queued for deletion, NULL otherwise
     * rib    --- NULL
     */

    /* Same RIB entry is selected. Update FIB and finish. */
    if (select && select == fib)
    {
        if (IS_ZEBRA_DEBUG_RIB)
            zlog_debug ("%s: %s/%d: Updating existing route, select %p, fib %p", __func__, buf, rn->p.prefixlen, select, fib);
        if (CHECK_FLAG (select->flags, ZEBRA_FLAG_CHANGED))
        {
            redistribute_delete (&rn->p, select);
            if (!RIB_SYSTEM_ROUTE (select))
                rib_uninstall_kernel (rn, select);

            /* Set real nexthop. */
            nexthop_active_update (rn, select, 1);

            if (!RIB_SYSTEM_ROUTE (select))
                rib_install_kernel (rn, select);
            redistribute_add (&rn->p, select);
        }
        else if (!RIB_SYSTEM_ROUTE (select))
        {
            /* Housekeeping code to deal with
               race conditions in kernel with linux
               netlink reporting interface up before IPv4 or IPv6 protocol
               is ready to add routes.
               This makes sure the routes are IN the kernel.
             */

            for (nexthop = select->nexthop; nexthop; nexthop = nexthop->next)
                if (CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB))
                {
                    installed = 1;
                    break;
                }
            if (!installed)
                rib_install_kernel (rn, select);
        }
        goto end;
    }

    /* At this point we either haven't found the best RIB entry or it is
     * different from what we currently intend to flag with SELECTED. In both
     * cases, if a RIB block is present in FIB, it should be withdrawn.
     */
    if (fib)
    {
        if (IS_ZEBRA_DEBUG_RIB)
            zlog_debug ("%s: %s/%d: Removing existing route, fib %p", __func__, buf, rn->p.prefixlen, fib);
        redistribute_delete (&rn->p, fib);
        if (!RIB_SYSTEM_ROUTE (fib))
            rib_uninstall_kernel (rn, fib);
        UNSET_FLAG (fib->flags, ZEBRA_FLAG_SELECTED);

        /* Set real nexthop. */
        nexthop_active_update (rn, fib, 1);
    }

    /* Regardless of some RIB entry being SELECTED or not before, now we can
     * tell, that if a new winner exists, FIB is still not updated with this
     * data, but ready to be.
     */
    if (select)
    {
        if (IS_ZEBRA_DEBUG_RIB)
            zlog_debug ("%s: %s/%d: Adding route, select %p", __func__, buf, rn->p.prefixlen, select);
        /* Set real nexthop. */
        nexthop_active_update (rn, select, 1);

        if (!RIB_SYSTEM_ROUTE (select))
            rib_install_kernel (rn, select);
        SET_FLAG (select->flags, ZEBRA_FLAG_SELECTED);
        redistribute_add (&rn->p, select);
    }

    /* FIB route was removed, should be deleted */
    if (del)
    {
        if (IS_ZEBRA_DEBUG_RIB)
            zlog_debug ("%s: %s/%d: Deleting fib %p, rn %p", __func__, buf, rn->p.prefixlen, del, rn);
        rib_unlink (rn, del);
    }

end:
    if (IS_ZEBRA_DEBUG_RIB_Q)
        zlog_debug ("%s: %s/%d: rn %p dequeued", __func__, buf, rn->p.prefixlen, rn);
}

/* Take a list of route_node structs and return 1, if there was a record
 * picked from it and processed by rib_process(). Don't process more,
 * than one RN record; operate only in the specified sub-queue.
 */
static unsigned int process_subq (struct list *subq, u_char qindex)
{
    struct listnode *lnode = listhead (subq);
    struct route_node *rnode;

    if (!lnode)
        return 0;

    rnode = listgetdata (lnode);
    rib_process (rnode);

    if (rnode->info)			/* The first RIB record is holding the flags bitmask. */
        UNSET_FLAG (((struct rib *) rnode->info)->rn_status, RIB_ROUTE_QUEUED (qindex));
#if 0
    else
    {
        zlog_debug ("%s: called for route_node (%p, %d) with no ribs", __func__, rnode, rnode->lock);
        zlog_backtrace (LOG_DEBUG);
    }
#endif
    route_unlock_node (rnode);
    list_delete_node (subq, lnode);
    return 1;
}

/* Dispatch the meta queue by picking, processing and unlocking the next RN from
 * a non-empty sub-queue with lowest priority. wq is equal to zebra->ribq and data
 * is pointed to the meta queue structure.
 */
static wq_item_status meta_queue_process (struct work_queue *dummy, void *data)
{
    struct meta_queue *mq = data;
    unsigned i;

    for (i = 0; i < MQ_SIZE; i++)
        if (process_subq (mq->subq[i], i))
        {
            mq->size--;
            break;
        }
    return mq->size ? WQ_REQUEUE : WQ_SUCCESS;
}

/* Map from rib types to queue type (priority) in meta queue */
static const u_char meta_queue_map[ZEBRA_ROUTE_MAX] =
{
    [ZEBRA_ROUTE_SYSTEM] = 4,
    [ZEBRA_ROUTE_KERNEL] = 0,
    [ZEBRA_ROUTE_CONNECT] = 0,
    [ZEBRA_ROUTE_STATIC] = 1,
    [ZEBRA_ROUTE_RIP] = 2,
    [ZEBRA_ROUTE_RIPNG] = 2,
    [ZEBRA_ROUTE_OSPF] = 2,
    [ZEBRA_ROUTE_OSPF6] = 2,
    [ZEBRA_ROUTE_ISIS] = 2,
    [ZEBRA_ROUTE_BGP] = 3,
    [ZEBRA_ROUTE_HSLS] = 4,
    [ZEBRA_ROUTE_BABEL] = 2,
};

/* Look into the RN and queue it into one or more priority queues,
 * increasing the size for each data push done.
 */
static void rib_meta_queue_add (struct meta_queue *mq, struct route_node *rn)
{
    struct rib *rib;
    char buf[INET6_ADDRSTRLEN];

    if (IS_ZEBRA_DEBUG_RIB_Q)
        inet_ntop (rn->p.family, &rn->p.u.prefix, buf, INET6_ADDRSTRLEN);

    for (rib = rn->info; rib; rib = rib->next)
    {
        u_char qindex = meta_queue_map[rib->type];

        /* Invariant: at this point we always have rn->info set. */
        if (CHECK_FLAG (((struct rib *) rn->info)->rn_status, RIB_ROUTE_QUEUED (qindex)))
        {
            if (IS_ZEBRA_DEBUG_RIB_Q)
                zlog_debug ("%s: %s/%d: rn %p is already queued in sub-queue %u", __func__, buf, rn->p.prefixlen, rn, qindex);
            continue;
        }

        SET_FLAG (((struct rib *) rn->info)->rn_status, RIB_ROUTE_QUEUED (qindex));
        listnode_add (mq->subq[qindex], rn);
        route_lock_node (rn);
        mq->size++;

        if (IS_ZEBRA_DEBUG_RIB_Q)
            zlog_debug ("%s: %s/%d: queued rn %p into sub-queue %u", __func__, buf, rn->p.prefixlen, rn, qindex);
    }
}

/* Add route_node to work queue and schedule processing */
static void rib_queue_add (struct zebra_t *zebra, struct route_node *rn)
{
    char buf[INET_ADDRSTRLEN];
    assert (zebra && rn);

    if (IS_ZEBRA_DEBUG_RIB_Q)
        inet_ntop (AF_INET, &rn->p.u.prefix, buf, INET_ADDRSTRLEN);

    /* Pointless to queue a route_node with no RIB entries to add or remove */
    if (!rn->info)
    {
        zlog_debug ("%s: called for route_node (%p, %d) with no ribs", __func__, rn, rn->lock);
        zlog_backtrace (LOG_DEBUG);
        return;
    }

    if (IS_ZEBRA_DEBUG_RIB_Q)
        zlog_info ("%s: %s/%d: work queue added", __func__, buf, rn->p.prefixlen);

    assert (zebra);

    if (zebra->ribq == NULL)
    {
        zlog_err ("%s: work_queue does not exist!", __func__);
        return;
    }

    /*
     * The RIB queue should normally be either empty or holding the only
     * work_queue_item element. In the latter case this element would
     * hold a pointer to the meta queue structure, which must be used to
     * actually queue the route nodes to process. So create the MQ
     * holder, if necessary, then push the work into it in any case.
     * This semantics was introduced after 0.99.9 release.
     */
    if (!zebra->ribq->items->count)
        work_queue_add (zebra->ribq, zebra->mq);

    rib_meta_queue_add (zebra->mq, rn);

    if (IS_ZEBRA_DEBUG_RIB_Q)
        zlog_debug ("%s: %s/%d: rn %p queued", __func__, buf, rn->p.prefixlen, rn);

    return;
}

/* Create new meta queue.
   A destructor function doesn't seem to be necessary here.
 */
static struct meta_queue *meta_queue_new (void)
{
    struct meta_queue *new;
    unsigned i;

    new = XCALLOC (MTYPE_WORK_QUEUE, sizeof (struct meta_queue));
    assert (new);

    for (i = 0; i < MQ_SIZE; i++)
    {
        new->subq[i] = list_new ();
        assert (new->subq[i]);
    }

    return new;
}

/* initialise zebra rib work queue */
static void rib_queue_init (struct zebra_t *zebra)
{
    assert (zebra);

    if (!(zebra->ribq = work_queue_new (zebra->master, "route_node processing")))
    {
        zlog_err ("%s: could not initialise work queue!", __func__);
        return;
    }

    /* fill in the work queue spec */
    zebra->ribq->spec.workfunc = &meta_queue_process;
    zebra->ribq->spec.errorfunc = NULL;
    /* XXX: TODO: These should be runtime configurable via vty */
    zebra->ribq->spec.max_retries = 3;
    zebra->ribq->spec.hold = rib_process_hold_time;

    if (!(zebra->mq = meta_queue_new ()))
    {
        zlog_err ("%s: could not initialise meta queue!", __func__);
        return;
    }
    return;
}

/* RIB updates are processed via a queue of pointers to route_nodes.
 *
 * The queue length is bounded by the maximal size of the routing table,
 * as a route_node will not be requeued, if already queued.
 *
 * RIBs are submitted via rib_addnode or rib_delnode which set minimal
 * state, or static_install_ipv{4,6} (when an existing RIB is updated)
 * and then submit route_node to queue for best-path selection later.
 * Order of add/delete state changes are preserved for any given RIB.
 *
 * Deleted RIBs are reaped during best-path selection.
 *
 * rib_addnode
 * |-> rib_link or unset RIB_ENTRY_REMOVE        |->Update kernel with
 *       |-------->|                             |  best RIB, if required
 *                 |                             |
 * static_install->|->rib_addqueue...... -> rib_process
 *                 |                             |
 *       |-------->|                             |-> rib_unlink
 * |-> set RIB_ENTRY_REMOVE                           |
 * rib_delnode                                  (RIB freed)
 *
 *
 * Queueing state for a route_node is kept in the head RIB entry, this
 * state must be preserved as and when the head RIB entry of a
 * route_node is changed by rib_unlink / rib_link. A small complication,
 * but saves having to allocate a dedicated object for this.
 *
 * Refcounting (aka "locking" throughout the GNU Zebra and Quagga code):
 *
 * - route_nodes: refcounted by:
 *   - RIBs attached to route_node:
 *     - managed by: rib_link/unlink
 *   - route_node processing queue
 *     - managed by: rib_addqueue, rib_process.
 *
 */

/* Add RIB to head of the route node. */
static void rib_link (struct route_node *rn, struct rib *rib)
{
    struct rib *head;
    char buf[INET6_ADDRSTRLEN];

    assert (rib && rn);

    route_lock_node (rn);		/* rn route table reference */

    if (IS_ZEBRA_DEBUG_RIB)
    {
        inet_ntop (rn->p.family, &rn->p.u.prefix, buf, INET6_ADDRSTRLEN);
        zlog_debug ("%s: %s/%d: rn %p, rib %p", __func__, buf, rn->p.prefixlen, rn, rib);
    }

    head = rn->info;
    if (head)
    {
        if (IS_ZEBRA_DEBUG_RIB)
            zlog_debug ("%s: %s/%d: new head, rn_status copied over", __func__, buf, rn->p.prefixlen);
        head->prev = rib;
        /* Transfer the rn status flags to the new head RIB */
        rib->rn_status = head->rn_status;
    }
    rib->next = head;
    rn->info = rib;

    if (rib->type_customize != CUSTOMIZEROUTE )
        rib_queue_add (&zebrad, rn);
}

static void rib_addnode (struct route_node *rn, struct rib *rib)
{
    /* RIB node has been un-removed before route-node is processed.
     * route_node must hence already be on the queue for processing..
     */
    if (CHECK_FLAG (rib->status, RIB_ENTRY_REMOVED))
    {
        if (IS_ZEBRA_DEBUG_RIB)
        {
            char buf[INET6_ADDRSTRLEN];
            inet_ntop (rn->p.family, &rn->p.u.prefix, buf, INET6_ADDRSTRLEN);
            zlog_debug ("%s: %s/%d: rn %p, un-removed rib %p", __func__, buf, rn->p.prefixlen, rn, rib);
        }
        UNSET_FLAG (rib->status, RIB_ENTRY_REMOVED);
        return;
    }

    rib_link (rn, rib);
}

static void rib_unlink (struct route_node *rn, struct rib *rib)
{
    struct nexthop *nexthop, *next;
    char buf[INET6_ADDRSTRLEN];

    assert (rn && rib);

    if (IS_ZEBRA_DEBUG_RIB)
    {
        inet_ntop (rn->p.family, &rn->p.u.prefix, buf, INET6_ADDRSTRLEN);
        zlog_debug ("%s: %s/%d: rn %p, rib %p", __func__, buf, rn->p.prefixlen, rn, rib);
    }

    if (rib->next)
        rib->next->prev = rib->prev;

    if (rib->prev)
        rib->prev->next = rib->next;
    else
    {
        rn->info = rib->next;

        if (rn->info)
        {
            if (IS_ZEBRA_DEBUG_RIB)
                zlog_debug ("%s: %s/%d: rn %p, rib %p, new head copy", __func__, buf, rn->p.prefixlen, rn, rib);
            rib->next->rn_status = rib->rn_status;
        }
    }

    /* free RIB and nexthops */
    for (nexthop = rib->nexthop; nexthop; nexthop = next)
    {
        next = nexthop->next;
        nexthop_free (nexthop);
    }
    XFREE (MTYPE_RIB, rib);

    route_unlock_node (rn);		/* rn route table reference */
}

static void rib_delnode (struct route_node *rn, struct rib *rib)
{
    if (IS_ZEBRA_DEBUG_RIB)
    {
        char buf[INET6_ADDRSTRLEN];
        inet_ntop (rn->p.family, &rn->p.u.prefix, buf, INET6_ADDRSTRLEN);
        zlog_debug ("%s: %s/%d: rn %p, rib %p, removing", __func__, buf, rn->p.prefixlen, rn, rib);
    }
    SET_FLAG (rib->status, RIB_ENTRY_REMOVED);
    rib_queue_add (&zebrad, rn);
}
int rib_add_ipv4 (int type, int flags, struct prefix_ipv4 *p, struct in_addr *gate, struct in_addr *src, unsigned int ifindex, u_int32_t vrf_id, u_int32_t metric, u_char distance, safi_t safi)
{
    struct rib *rib;
    struct rib *same = NULL;
    struct route_table *table;
    struct route_node *rn;
    struct nexthop *nexthop;

    /* Lookup table.  */
    table = vrf_table (AFI_IP, safi, 0);
    if (!table)
        return 0;

    /* Make it sure prefixlen is applied to the prefix. */
    apply_mask_ipv4 (p);

    /* Set default distance by route type. */
    if (distance == 0)
    {
        if ((unsigned) type >= sizeof (route_info) / sizeof (route_info[0]))
            distance = 150;
        else
            distance = route_info[type].distance;

        /* iBGP distance is 200. */
        if (type == ZEBRA_ROUTE_BGP && CHECK_FLAG (flags, ZEBRA_FLAG_IBGP))
            distance = 200;
    }

    /* Lookup route node. */
    rn = route_node_get (table, (struct prefix *) p);

    /* If same type of route are installed, treat it as a implicit
       withdraw. */
    for (rib = rn->info; rib; rib = rib->next)
    {
        if (CHECK_FLAG (rib->status, RIB_ENTRY_REMOVED))
            continue;

        if (rib->type != type)
            continue;
        if (rib->type != ZEBRA_ROUTE_CONNECT)
        {
            same = rib;
            break;
        }
        /* Duplicate connected route comes in. */
        else if ((nexthop = rib->nexthop) && nexthop->type == NEXTHOP_TYPE_IFINDEX && nexthop->ifindex == ifindex && !CHECK_FLAG (rib->status, RIB_ENTRY_REMOVED))
        {
            rib->refcnt++;
            return 0;
        }
    }

    /* Allocate new rib structure. */
    rib = XCALLOC (MTYPE_RIB, sizeof (struct rib));
    rib->type = type;
    rib->distance = distance;
    rib->flags = flags;
    rib->metric = metric;
    rib->table = vrf_id;
    rib->nexthop_num = 0;
    rib->uptime = time (NULL);

    /* Nexthop settings. */
    if (gate)
    {
        if (ifindex)
            nexthop_ipv4_ifindex_add (rib, gate, src, ifindex);
        else
            nexthop_ipv4_add (rib, gate, src);
    }
    else
        nexthop_ifindex_add (rib, ifindex);

    /* If this route is kernel route, set FIB flag to the route. */
    if (type == ZEBRA_ROUTE_KERNEL || type == ZEBRA_ROUTE_CONNECT)
        for (nexthop = rib->nexthop; nexthop; nexthop = nexthop->next)
            SET_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB);

    /* Link new rib to node. */
    if (IS_ZEBRA_DEBUG_RIB)
        zlog_debug ("%s: calling rib_addnode (%p, %p)", __func__, rn, rib);
    rib_addnode (rn, rib);

    /* Free implicit route. */
    if (same)
    {
        if (IS_ZEBRA_DEBUG_RIB)
            zlog_debug ("%s: calling rib_delnode (%p, %p)", __func__, rn, rib);
        rib_delnode (rn, same);
    }

    route_unlock_node (rn);
    return 0;
}
int send_ipv4_customize_route(int type, char *routetablename, struct prefix_ipv4 *p, struct in_addr *gate, unsigned int ifindex)
{
    struct comm_head *comm;
    struct ipv4_route_customize route_customize;

    char buf[64];
    inet_ntop (AF_INET, &p->prefix, buf, BUFSIZ);
    printf("true %s/%d ", buf, p->prefixlen);

    printf("true gateway is:%s, ifindex:%d.\n", inet_ntoa(*gate), ifindex);

    comm = XCALLOC (MTYPE_ROUTE_CUSTOMIZE, sizeof(struct comm_head) + sizeof(struct ipv4_route_customize));
    memset(&route_customize, 0, sizeof(struct ipv4_route_customize));
    route_customize.type = type;
    strcpy(route_customize.routetablename, routetablename);
    memcpy(&route_customize.p, p, sizeof(struct prefix_ipv4));
    memcpy(&route_customize.gate, gate, sizeof(struct in_addr));
    route_customize.ifindex = ifindex;
    //route_customize.action = 2; //FORWARD
    route_customize.action = 1; //FORWARD

    comm->type = ADD_CUSTOMIZE_IPV4_ROUTE;
    comm->len = htonl(sizeof(struct comm_head) + sizeof(struct ipv4_route_customize));
    memcpy(comm->data, &route_customize, sizeof(struct ipv4_route_customize));

    send_msg_to_dpdk(NONEED_RECV_MSG, (void *)comm, ntohl(comm->len), MTYPE_ROUTE_CUSTOMIZE, NULL);

    return OK;
}
int send_ipv6_customize_route(int type, char *routetablename, struct prefix_ipv6 *p, struct in6_addr *gate, unsigned int ifindex,uint8_t action)
{
    struct comm_head *comm;
    struct ipv6_route_customize route_customize;

    memset(&route_customize, 0, sizeof(struct ipv4_route_customize));
    route_customize.type = type;
    strcpy(route_customize.routetablename, routetablename);
    memcpy(&route_customize.p, p, sizeof(struct prefix_ipv6));
    memcpy(&route_customize.gate, gate, sizeof(struct in6_addr));
    route_customize.ifindex = ifindex;
    //route_customize.action = 1; //FORWARD
    route_customize.action = action; //FORWARD

    comm = XCALLOC (MTYPE_ROUTE_CUSTOMIZE, sizeof(struct comm_head) + sizeof(struct ipv6_route_customize));
    comm->type = ADD_CUSTOMIZE_IPV6_ROUTE;
    comm->len = htonl(sizeof(struct comm_head) + sizeof(struct ipv6_route_customize));
    memcpy(comm->data, &route_customize, sizeof(struct ipv6_route_customize));

    send_msg_to_dpdk(NONEED_RECV_MSG, (void *)comm, ntohl(comm->len), MTYPE_ROUTE_CUSTOMIZE, NULL);
    return OK;
}
int rib_add_ipv4_customize (int type, int flags, char *routetablename, struct prefix_ipv4 *p, struct in_addr *gate, struct in_addr *src, unsigned int ifindex, u_int32_t vrf_id, u_int32_t metric, u_char distance, safi_t safi)
{
    struct rib *rib;
    struct rib *same = NULL;
    struct route_table *table;
    struct route_node *rn;
    struct nexthop *nexthop;

    /* Lookup table.  */
    table = vrf_table (AFI_IP, safi, 0);
    if (!table)
        return 0;

    /* Make it sure prefixlen is applied to the prefix. */
    apply_mask_ipv4 (p);

    /* Set default distance by route type. */
    if (distance == 0)
    {
        if ((unsigned) type >= sizeof (route_info) / sizeof (route_info[0]))
            distance = 150;
        else
            distance = route_info[type].distance;
    }

    /* Lookup route node. */
    rn = route_node_get (table, (struct prefix *) p);

    /* If same type of route are installed, treat it as a implicit
       withdraw. */
    for (rib = rn->info; rib; rib = rib->next)
    {
        if (CHECK_FLAG (rib->status, RIB_ENTRY_REMOVED))
            continue;

        if (rib->type != type)
            continue;
        if (rib->type != ZEBRA_ROUTE_CONNECT)
        {
            same = rib;
            break;
        }
        /* Duplicate connected route comes in. */
        else if ((nexthop = rib->nexthop) && nexthop->type == NEXTHOP_TYPE_IFINDEX && nexthop->ifindex == ifindex && !CHECK_FLAG (rib->status, RIB_ENTRY_REMOVED))
        {
            rib->refcnt++;
            return 0;
        }
    }

    /* Allocate new rib structure. */
    rib = XCALLOC (MTYPE_RIB, sizeof (struct rib));
    rib->type = type;
    rib->type_customize = CUSTOMIZEROUTE;
    rib->distance = distance;
    rib->flags = flags;
    rib->metric = metric;
    rib->table = vrf_id;
    rib->nexthop_num = 0;
    rib->uptime = time (NULL);

    /* Nexthop settings. */
    if (gate)
    {
        if (ifindex)
        {
            nexthop_ipv4_ifindex_add (rib, gate, src, ifindex);
        }
        else
            nexthop_ipv4_add (rib, gate, src);
    }
    else
        nexthop_ifindex_add (rib, ifindex);
#if 0
    /* If this route is openflow route, set FIB flag to the route. */
    if (type == ZEBRA_ROUTE_OPENFLOW)
        for (nexthop = rib->nexthop; nexthop; nexthop = nexthop->next)
            SET_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB);
#endif


    /* Link new rib to node. */
    if (IS_ZEBRA_DEBUG_RIB)
        zlog_debug ("%s: calling rib_addnode (%p, %p)", __func__, rn, rib);

    rib_addnode (rn, rib);

    /* Free implicit route. */
    if (same)
    {
        if (IS_ZEBRA_DEBUG_RIB)
            zlog_debug ("%s: calling rib_delnode (%p, %p)", __func__, rn, rib);

        rib_delnode (rn, same);
    }

    //TODO:send route info to dpdk

    if (!send_ipv4_customize_route(ADDROUTE, routetablename, p, gate, ifindex))
    {
        printf("send ipv4 route add info to dpdk success.\n");
    }

    route_unlock_node (rn);

    return 0;
}

/* This function dumps the contents of a given RIB entry into
 * standard debug log. Calling function name and IP prefix in
 * question are passed as 1st and 2nd arguments.
 */

void rib_dump (const char *func, const struct prefix_ipv4 *p, const struct rib *rib)
{
    char straddr1[INET_ADDRSTRLEN], straddr2[INET_ADDRSTRLEN];
    struct nexthop *nexthop;

    inet_ntop (AF_INET, &p->prefix, straddr1, INET_ADDRSTRLEN);
    zlog_debug ("%s: dumping RIB entry %p for %s/%d", func, rib, straddr1, p->prefixlen);
    zlog_debug ("%s: refcnt == %lu, uptime == %lu, type == %u, table == %d", func, rib->refcnt, (unsigned long) rib->uptime, rib->type, rib->table);
    zlog_debug ("%s: metric == %u, distance == %u, flags == %u, status == %u", func, rib->metric, rib->distance, rib->flags, rib->status);
    zlog_debug ("%s: nexthop_num == %u, nexthop_active_num == %u, nexthop_fib_num == %u", func, rib->nexthop_num, rib->nexthop_active_num, rib->nexthop_fib_num);
    for (nexthop = rib->nexthop; nexthop; nexthop = nexthop->next)
    {
        inet_ntop (AF_INET, &nexthop->gate.ipv4.s_addr, straddr1, INET_ADDRSTRLEN);
        inet_ntop (AF_INET, &nexthop->rgate.ipv4.s_addr, straddr2, INET_ADDRSTRLEN);
        zlog_debug
        ("%s: NH %s (%s) with flags %s%s%s",
         func,
         straddr1,
         straddr2,
         (CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_ACTIVE) ? "ACTIVE " : ""),
         (CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB) ? "FIB " : ""), (CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_RECURSIVE) ? "RECURSIVE" : ""));
    }
    zlog_debug ("%s: dump complete", func);
}

/* This is an exported helper to rtm_read() to dump the strange
 * RIB entry found by rib_lookup_ipv4_route()
 */

void rib_lookup_and_dump (struct prefix_ipv4 *p)
{
    struct route_table *table;
    struct route_node *rn;
    struct rib *rib;
    char prefix_buf[INET_ADDRSTRLEN];

    /* Lookup table.  */
    table = vrf_table (AFI_IP, SAFI_UNICAST, 0);
    if (!table)
    {
        zlog_err ("%s: vrf_table() returned NULL", __func__);
        return;
    }

    inet_ntop (AF_INET, &p->prefix.s_addr, prefix_buf, INET_ADDRSTRLEN);
    /* Scan the RIB table for exactly matching RIB entry. */
    rn = route_node_lookup (table, (struct prefix *) p);

    /* No route for this prefix. */
    if (!rn)
    {
        zlog_debug ("%s: lookup failed for %s/%d", __func__, prefix_buf, p->prefixlen);
        return;
    }

    /* Unlock node. */
    route_unlock_node (rn);

    /* let's go */
    for (rib = rn->info; rib; rib = rib->next)
    {
        zlog_debug
        ("%s: rn %p, rib %p: %s, %s",
         __func__, rn, rib, (CHECK_FLAG (rib->status, RIB_ENTRY_REMOVED) ? "removed" : "NOT removed"), (CHECK_FLAG (rib->flags, ZEBRA_FLAG_SELECTED) ? "selected" : "NOT selected"));
        rib_dump (__func__, p, rib);
    }
}

/* Check if requested address assignment will fail due to another
 * route being installed by zebra in FIB already. Take necessary
 * actions, if needed: remove such a route from FIB and deSELECT
 * corresponding RIB entry. Then put affected RN into RIBQ head.
 */
void rib_lookup_and_pushup (struct prefix_ipv4 *p)
{
    struct route_table *table;
    struct route_node *rn;
    struct rib *rib;
    unsigned changed = 0;

    if (NULL == (table = vrf_table (AFI_IP, SAFI_UNICAST, 0)))
    {
        zlog_err ("%s: vrf_table() returned NULL", __func__);
        return;
    }

    /* No matches would be the simplest case. */
    if (NULL == (rn = route_node_lookup (table, (struct prefix *) p)))
        return;

    /* Unlock node. */
    route_unlock_node (rn);

    /* Check all RIB entries. In case any changes have to be done, requeue
     * the RN into RIBQ head. If the routing message about the new connected
     * route (generated by the IP address we are going to assign very soon)
     * comes before the RIBQ is processed, the new RIB entry will join
     * RIBQ record already on head. This is necessary for proper revalidation
     * of the rest of the RIB.
     */
    for (rib = rn->info; rib; rib = rib->next)
    {
        if (CHECK_FLAG (rib->flags, ZEBRA_FLAG_SELECTED) && !RIB_SYSTEM_ROUTE (rib))
        {
            changed = 1;
            if (IS_ZEBRA_DEBUG_RIB)
            {
                char buf[INET_ADDRSTRLEN];
                inet_ntop (rn->p.family, &p->prefix, buf, INET_ADDRSTRLEN);
                zlog_debug ("%s: freeing way for connected prefix %s/%d", __func__, buf, p->prefixlen);
                rib_dump (__func__, (struct prefix_ipv4 *) &rn->p, rib);
            }
            rib_uninstall (rn, rib);
        }
    }
    if (changed)
        rib_queue_add (&zebrad, rn);
}

int rib_add_ipv4_multipath (struct prefix_ipv4 *p, struct rib *rib, safi_t safi)
{
    struct route_table *table;
    struct route_node *rn;
    struct rib *same;
    struct nexthop *nexthop;

    /* Lookup table.  */
    table = vrf_table (AFI_IP, safi, 0);
    if (!table)
        return 0;

    /* Make it sure prefixlen is applied to the prefix. */
    apply_mask_ipv4 (p);

    /* Set default distance by route type. */
    if (rib->distance == 0)
    {
        rib->distance = route_info[rib->type].distance;

        /* iBGP distance is 200. */
        if (rib->type == ZEBRA_ROUTE_BGP && CHECK_FLAG (rib->flags, ZEBRA_FLAG_IBGP))
            rib->distance = 200;
    }

    /* Lookup route node. */
    rn = route_node_get (table, (struct prefix *) p);

    /* If same type of route are installed, treat it as a implicit
       withdraw. */
    for (same = rn->info; same; same = same->next)
    {
        if (CHECK_FLAG (same->status, RIB_ENTRY_REMOVED))
            continue;

        if (same->type == rib->type && same->table == rib->table && same->type != ZEBRA_ROUTE_CONNECT)
            break;
    }

    /* If this route is kernel route, set FIB flag to the route. */
    if (rib->type == ZEBRA_ROUTE_KERNEL || rib->type == ZEBRA_ROUTE_CONNECT)
        for (nexthop = rib->nexthop; nexthop; nexthop = nexthop->next)
            SET_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB);

    /* Link new rib to node. */
    rib_addnode (rn, rib);
    if (IS_ZEBRA_DEBUG_RIB)
    {
        zlog_debug ("%s: called rib_addnode (%p, %p) on new RIB entry", __func__, rn, rib);
        rib_dump (__func__, p, rib);
    }

    /* Free implicit route. */
    if (same)
    {
        if (IS_ZEBRA_DEBUG_RIB)
        {
            zlog_debug ("%s: calling rib_delnode (%p, %p) on existing RIB entry", __func__, rn, same);
            rib_dump (__func__, p, same);
        }
        rib_delnode (rn, same);
    }

    route_unlock_node (rn);
    return 0;
}
/* XXX factor with rib_delete_ipv6 */
int rib_delete_ipv4 (int type, int flags, struct prefix_ipv4 *p, struct in_addr *gate, unsigned int ifindex, u_int32_t vrf_id, safi_t safi)
{
    struct route_table *table;
    struct route_node *rn;
    struct rib *rib;
    struct rib *fib = NULL;
    struct rib *same = NULL;
    struct nexthop *nexthop;
    char buf1[INET_ADDRSTRLEN];
    char buf2[INET_ADDRSTRLEN];

    /* Lookup table.  */
    table = vrf_table (AFI_IP, safi, 0);
    if (!table)
        return 0;

    /* Apply mask. */
    apply_mask_ipv4 (p);

    if (IS_ZEBRA_DEBUG_KERNEL && gate)
        zlog_debug ("rib_delete_ipv4(): route delete %s/%d via %s ifindex %d", inet_ntop (AF_INET, &p->prefix, buf1, INET_ADDRSTRLEN), p->prefixlen, inet_ntoa (*gate), ifindex);

    /* Lookup route node. */
    rn = route_node_lookup (table, (struct prefix *) p);
    if (!rn)
    {
        if (IS_ZEBRA_DEBUG_KERNEL)
        {
            if (gate)
                zlog_debug ("route %s/%d via %s ifindex %d doesn't exist in rib",
                            inet_ntop (AF_INET, &p->prefix, buf1, INET_ADDRSTRLEN), p->prefixlen, inet_ntop (AF_INET, gate, buf2, INET_ADDRSTRLEN), ifindex);
            else
                zlog_debug ("route %s/%d ifindex %d doesn't exist in rib", inet_ntop (AF_INET, &p->prefix, buf1, INET_ADDRSTRLEN), p->prefixlen, ifindex);
        }
        return ZEBRA_ERR_RTNOEXIST;
    }

    /* Lookup same type route. */
    for (rib = rn->info; rib; rib = rib->next)
    {
        if (CHECK_FLAG (rib->status, RIB_ENTRY_REMOVED))
            continue;

        if (CHECK_FLAG (rib->flags, ZEBRA_FLAG_SELECTED))
            fib = rib;

        if (rib->type != type)
            continue;
        if (rib->type == ZEBRA_ROUTE_CONNECT && (nexthop = rib->nexthop) && nexthop->type == NEXTHOP_TYPE_IFINDEX)
        {
            if (nexthop->ifindex != ifindex)
                continue;
            if (rib->refcnt)
            {
                rib->refcnt--;
                route_unlock_node (rn);
                route_unlock_node (rn);
                return 0;
            }
            same = rib;
            break;
        }
        /* Make sure that the route found has the same gateway. */
        else if (gate == NULL || ((nexthop = rib->nexthop) && (IPV4_ADDR_SAME (&nexthop->gate.ipv4, gate) || IPV4_ADDR_SAME (&nexthop->rgate.ipv4, gate))))
        {
            same = rib;
            break;
        }
    }

    /* If same type of route can't be found and this message is from
       kernel. */
    if (!same)
    {
        if (fib && type == ZEBRA_ROUTE_KERNEL)
        {
            /* Unset flags. */
            for (nexthop = fib->nexthop; nexthop; nexthop = nexthop->next)
                UNSET_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB);

            UNSET_FLAG (fib->flags, ZEBRA_FLAG_SELECTED);
        }
        else
        {
            if (IS_ZEBRA_DEBUG_KERNEL)
            {
                if (gate)
                    zlog_debug ("route %s/%d via %s ifindex %d type %d doesn't exist in rib",
                                inet_ntop (AF_INET, &p->prefix, buf1, INET_ADDRSTRLEN), p->prefixlen, inet_ntop (AF_INET, gate, buf2, INET_ADDRSTRLEN), ifindex, type);
                else
                    zlog_debug ("route %s/%d ifindex %d type %d doesn't exist in rib", inet_ntop (AF_INET, &p->prefix, buf1, INET_ADDRSTRLEN), p->prefixlen, ifindex, type);
            }
            route_unlock_node (rn);
            return ZEBRA_ERR_RTNOEXIST;
        }
    }

    if (same)
        rib_delnode (rn, same);

    route_unlock_node (rn);
    return 0;
}
/*sangmeng add for customize route 20180705*/
/* XXX factor with rib_delete_ipv6 */
int rib_delete_ipv4_customize (int type, int flags, char *routetablename, struct prefix_ipv4 *p, struct in_addr *gate, unsigned int ifindex, u_int32_t vrf_id, safi_t safi)
{
    struct route_table *table;
    struct route_node *rn;
    struct rib *rib;
    struct rib *same = NULL;
    struct nexthop *nexthop;
    char buf1[INET_ADDRSTRLEN];
    char buf2[INET_ADDRSTRLEN];

    /* Lookup table.  */
    table = vrf_table (AFI_IP, safi, 0);
    if (!table)
        return 0;

    /* Apply mask. */
    apply_mask_ipv4 (p);

    if (IS_ZEBRA_DEBUG_KERNEL && gate)
        zlog_debug ("rib_delete_ipv4(): route delete %s/%d via %s ifindex %d", inet_ntop (AF_INET, &p->prefix, buf1, INET_ADDRSTRLEN), p->prefixlen, inet_ntoa (*gate), ifindex);

    /* Lookup route node. */
    rn = route_node_lookup (table, (struct prefix *) p);
    if (!rn)
    {
        if (IS_ZEBRA_DEBUG_KERNEL)
        {
            if (gate)
                zlog_debug ("route %s/%d via %s ifindex %d doesn't exist",
                            inet_ntop (AF_INET, &p->prefix, buf1, INET_ADDRSTRLEN), p->prefixlen, inet_ntop (AF_INET, gate, buf2, INET_ADDRSTRLEN), ifindex);
            else
                zlog_debug ("route %s/%d ifindex %d doesn't exist", inet_ntop (AF_INET, &p->prefix, buf1, INET_ADDRSTRLEN), p->prefixlen, ifindex);
        }
        return ZEBRA_ERR_RTNOEXIST;
    }

    /* Lookup same type route. */
    for (rib = rn->info; rib; rib = rib->next)
    {
        if (CHECK_FLAG (rib->status, RIB_ENTRY_REMOVED))
            continue;

        if (rib->type != type)
            continue;

        /* Make sure that the route found has the same gateway. */
        if (gate == NULL || ((nexthop = rib->nexthop) && (IPV4_ADDR_SAME (&nexthop->gate.ipv4, gate) || IPV4_ADDR_SAME (&nexthop->rgate.ipv4, gate))))
        {
            same = rib;
            break;
        }
    }

    /* If same type of route can't be found and this message is from
       kernel. */
    if (!same)
    {
        if (IS_ZEBRA_DEBUG_KERNEL)
        {
            if (gate)
                zlog_debug ("route %s/%d via %s ifindex %d type %d don't find",
                            inet_ntop (AF_INET, &p->prefix, buf1, INET_ADDRSTRLEN), p->prefixlen, inet_ntop (AF_INET, gate, buf2, INET_ADDRSTRLEN), ifindex, type);
            else
                zlog_debug ("route %s/%d ifindex %d type %d don't find", inet_ntop (AF_INET, &p->prefix, buf1, INET_ADDRSTRLEN), p->prefixlen, ifindex, type);
        }
        route_unlock_node (rn);
        return ZEBRA_ERR_RTNOEXIST;
    }

    if (same)
    {
        rib_delnode (rn, same);
        if(!send_ipv4_customize_route(DELROUTE, routetablename, p, gate, ifindex))
            printf("send ipv4 del route info to dpdk success.\n");
    }

    route_unlock_node (rn);
    return 0;
}
/* Install static route into rib. */
static void static_install_ipv4 (struct prefix *p, struct static_ipv4 *si)
{
    struct rib *rib;
    struct route_node *rn;
    struct route_table *table;

    /* Lookup table.  */
    table = vrf_table (AFI_IP, SAFI_UNICAST, 0);
    if (!table)
        return;

    /* Lookup existing route */
    rn = route_node_get (table, p);
    for (rib = rn->info; rib; rib = rib->next)
    {
        if (CHECK_FLAG (rib->status, RIB_ENTRY_REMOVED))
            continue;

        if (rib->type == ZEBRA_ROUTE_STATIC && rib->distance == si->distance)
            break;
    }

    if (rib)
    {
        /* Same distance static route is there.  Update it with new
           nexthop. */
        route_unlock_node (rn);
        switch (si->type)
        {
        case STATIC_IPV4_GATEWAY:
            nexthop_ipv4_add (rib, &si->gate.ipv4, NULL);
            break;
        case STATIC_IPV4_IFNAME:
            nexthop_ifname_add (rib, si->gate.ifname);
            break;
        case STATIC_IPV4_BLACKHOLE:
            nexthop_blackhole_add (rib);
            break;
        }
        rib_queue_add (&zebrad, rn);
    }
    else
    {
        /* This is new static route. */
        rib = XCALLOC (MTYPE_RIB, sizeof (struct rib));

        rib->type = ZEBRA_ROUTE_STATIC;
        rib->distance = si->distance;
        rib->metric = 0;
        rib->nexthop_num = 0;

        switch (si->type)
        {
        case STATIC_IPV4_GATEWAY:
            nexthop_ipv4_add (rib, &si->gate.ipv4, NULL);
            break;
        case STATIC_IPV4_IFNAME:
            nexthop_ifname_add (rib, si->gate.ifname);
            break;
        case STATIC_IPV4_BLACKHOLE:
            nexthop_blackhole_add (rib);
            break;
        }

        /* Save the flags of this static routes (reject, blackhole) */
        rib->flags = si->flags;

        /* Link this rib to the tree. */
        rib_addnode (rn, rib);
    }
}

/* sangmeng add for dpdk customize route 20180702*/
/*Install static route into rib. */
static void static_install_ipv4_customize (struct prefix *p, struct static_ipv4 *si)
{
    struct rib *rib;
    struct route_node *rn;
    struct route_table *table;

    /* Lookup table.  */
    table = vrf_table (AFI_IP, SAFI_CUSTOMIZE_ONE, 0);
    if (!table)
    {
        printf("%s()%d return here, table is NULL.\n", __func__, __LINE__);
        return;
    }
    /* Lookup existing route */
    rn = route_node_get (table, p);

    for (rib = rn->info; rib; rib = rib->next)
    {
        if (CHECK_FLAG (rib->status, RIB_ENTRY_REMOVED))
            continue;

        if (rib->type == ZEBRA_ROUTE_STATIC && rib->distance == si->distance)
            break;
    }

    if (rib)
    {
        /* Same distance static route is there.  Update it with new
           nexthop. */
        route_unlock_node (rn);
        switch (si->type)
        {
        case STATIC_IPV4_GATEWAY:
            nexthop_ipv4_add (rib, &si->gate.ipv4, NULL);
            break;
        case STATIC_IPV4_IFNAME:
            nexthop_ifname_add (rib, si->gate.ifname);
            break;
        case STATIC_IPV4_BLACKHOLE:
            nexthop_blackhole_add (rib);
            break;
        }

        //rib->type_customize = CUSTOMIZEROUTE;
#if 0
        rib_queue_add (&zebrad, rn);
#endif
    }
    else
    {
        /* This is new static route. */
        rib = XCALLOC (MTYPE_RIB, sizeof (struct rib));

        rib->type = ZEBRA_ROUTE_STATIC;
        rib->type_customize = CUSTOMIZEROUTE;
        rib->distance = si->distance;
        rib->metric = 0;
        rib->nexthop_num = 0;

        switch (si->type)
        {
        case STATIC_IPV4_GATEWAY:
            nexthop_ipv4_add (rib, &si->gate.ipv4, NULL);
            break;
        case STATIC_IPV4_IFNAME:
            nexthop_ifname_add (rib, si->gate.ifname);
            break;
        case STATIC_IPV4_BLACKHOLE:
            nexthop_blackhole_add (rib);
            break;
        }

        /* Save the flags of this static routes (reject, blackhole) */
        rib->flags = si->flags;

        /* Link this rib to the tree. */
        //rib->type_customize = CUSTOMIZEROUTE;
        rib_addnode (rn, rib);
    }
    //TODO:send route info to dpdk
#if 1
    char buf[64];
    inet_ntop (AF_INET, &p->u.prefix, buf, BUFSIZ);
    printf("%s/%d ", buf, p->prefixlen);
    switch (si->type)
    {
    case STATIC_IPV4_GATEWAY:
        printf("gateway is:%s.\n", inet_ntoa(si->gate.ipv4));
        break;
    case STATIC_IPV4_IFNAME:
        printf("ifname:%s.\n", si->gate.ifname);
        break;
    case STATIC_IPV4_BLACKHOLE:
        nexthop_blackhole_add (rib);
        break;
    }
#endif

}



static int static_ipv4_nexthop_same (struct nexthop *nexthop, struct static_ipv4 *si)
{
    if (nexthop->type == NEXTHOP_TYPE_IPV4 && si->type == STATIC_IPV4_GATEWAY && IPV4_ADDR_SAME (&nexthop->gate.ipv4, &si->gate.ipv4))
        return 1;
    if (nexthop->type == NEXTHOP_TYPE_IFNAME && si->type == STATIC_IPV4_IFNAME && strcmp (nexthop->ifname, si->gate.ifname) == 0)
        return 1;
    if (nexthop->type == NEXTHOP_TYPE_BLACKHOLE && si->type == STATIC_IPV4_BLACKHOLE)
        return 1;
    return 0;
}
/* Uninstall static route from RIB. */
static void static_uninstall_ipv4 (struct prefix *p, struct static_ipv4 *si)
{
    struct route_node *rn;
    struct rib *rib;
    struct nexthop *nexthop;
    struct route_table *table;

    /* Lookup table.  */
    table = vrf_table (AFI_IP, SAFI_UNICAST, 0);
    if (!table)
        return;

    /* Lookup existing route with type and distance. */
    rn = route_node_lookup (table, p);
    if (!rn)
        return;

    for (rib = rn->info; rib; rib = rib->next)
    {
        if (CHECK_FLAG (rib->status, RIB_ENTRY_REMOVED))
            continue;

        if (rib->type == ZEBRA_ROUTE_STATIC && rib->distance == si->distance)
            break;
    }

    if (!rib)
    {
        route_unlock_node (rn);
        return;
    }

    /* Lookup nexthop. */
    for (nexthop = rib->nexthop; nexthop; nexthop = nexthop->next)
        if (static_ipv4_nexthop_same (nexthop, si))
            break;

    /* Can't find nexthop. */
    if (!nexthop)
    {
        route_unlock_node (rn);
        return;
    }

    /* Check nexthop. */
    if (rib->nexthop_num == 1)
        rib_delnode (rn, rib);
    else
    {
        if (CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB))
            rib_uninstall (rn, rib);
        nexthop_delete (rib, nexthop);
        nexthop_free (nexthop);
        rib_queue_add (&zebrad, rn);
    }
    /* Unlock node. */
    route_unlock_node (rn);
}

/*sangmeng add for ipv4 customize route 20180703*/
/* Uninstall static route from RIB. */
static void static_uninstall_ipv4_customize (struct prefix *p, struct static_ipv4 *si)
{
    struct route_node *rn;
    struct rib *rib;
    struct nexthop *nexthop;
    struct route_table *table;

    /* Lookup table.  */
    table = vrf_table (AFI_IP, SAFI_CUSTOMIZE_ONE, 0);
    if (!table)
        return;

    /* Lookup existing route with type and distance. */
    rn = route_node_lookup (table, p);
    if (!rn)
        return;

    for (rib = rn->info; rib; rib = rib->next)
    {
        if (CHECK_FLAG (rib->status, RIB_ENTRY_REMOVED))
            continue;

        if (rib->type == ZEBRA_ROUTE_STATIC && rib->distance == si->distance)
            break;
    }

    if (!rib)
    {
        route_unlock_node (rn);
        return;
    }

    /* Lookup nexthop. */
    for (nexthop = rib->nexthop; nexthop; nexthop = nexthop->next)
        if (static_ipv4_nexthop_same (nexthop, si))
            break;

    /* Can't find nexthop. */
    if (!nexthop)
    {
        route_unlock_node (rn);
        return;
    }

    /* Check nexthop. */
    if (rib->nexthop_num == 1)
    {
        //rib->type_customize = CUSTOMIZEROUTE;
        rib_delnode (rn, rib);
        //TODO:send route info to dpdk
    }
    else
    {
        rib->type_customize = CUSTOMIZEROUTE;
#if 0
        if (CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB))
            rib_uninstall (rn, rib);
#endif

        //TODO:send route info to dpdk

        nexthop_delete (rib, nexthop);
        nexthop_free (nexthop);
        rib_queue_add (&zebrad, rn);
    }
    /* Unlock node. */
    route_unlock_node (rn);
}

/* Add static route into static route configuration. */
int static_add_ipv4 (struct prefix *p, struct in_addr *gate, const char *ifname, u_char flags, u_char distance, u_int32_t vrf_id)
{
    u_char type = 0;
    struct route_node *rn;
    struct static_ipv4 *si;
    struct static_ipv4 *pp;
    struct static_ipv4 *cp;
    struct static_ipv4 *update = NULL;
    struct route_table *stable;

    /* Lookup table.  */
    stable = vrf_static_table (AFI_IP, SAFI_UNICAST, vrf_id);
    if (!stable)
        return -1;

    /* Lookup static route prefix. */
    rn = route_node_get (stable, p);

    /* Make flags. */
    if (gate)
        type = STATIC_IPV4_GATEWAY;
    else if (ifname)
        type = STATIC_IPV4_IFNAME;
    else
        type = STATIC_IPV4_BLACKHOLE;

    /* Do nothing if there is a same static route.  */
    for (si = rn->info; si; si = si->next)
    {
        if (type == si->type && (!gate || IPV4_ADDR_SAME (gate, &si->gate.ipv4)) && (!ifname || strcmp (ifname, si->gate.ifname) == 0))
        {
            if (distance == si->distance)
            {
                route_unlock_node (rn);
                return 0;
            }
            else
                update = si;
        }
    }

    /* Distance changed.  */
    if (update)
        static_delete_ipv4 (p, gate, ifname, update->distance, vrf_id);

    /* Make new static route structure. */
    si = XCALLOC (MTYPE_STATIC_IPV4, sizeof (struct static_ipv4));

    si->type = type;
    si->distance = distance;
    si->flags = flags;

    if (gate)
        si->gate.ipv4 = *gate;
    if (ifname)
        si->gate.ifname = XSTRDUP (0, ifname);

    /* Add new static route information to the tree with sort by
       distance value and gateway address. */
    for (pp = NULL, cp = rn->info; cp; pp = cp, cp = cp->next)
    {
        if (si->distance < cp->distance)
            break;
        if (si->distance > cp->distance)
            continue;
        if (si->type == STATIC_IPV4_GATEWAY && cp->type == STATIC_IPV4_GATEWAY)
        {
            if (ntohl (si->gate.ipv4.s_addr) < ntohl (cp->gate.ipv4.s_addr))
                break;
            if (ntohl (si->gate.ipv4.s_addr) > ntohl (cp->gate.ipv4.s_addr))
                continue;
        }
    }

    /* Make linked list. */
    if (pp)
        pp->next = si;
    else
        rn->info = si;
    if (cp)
        cp->prev = si;
    si->prev = pp;
    si->next = cp;

    /* Install into rib. */
    static_install_ipv4 (p, si);

    return 1;
}

/* Delete static route from static route configuration. */
int static_delete_ipv4 (struct prefix *p, struct in_addr *gate, const char *ifname, u_char distance, u_int32_t vrf_id)
{
    u_char type = 0;
    struct route_node *rn;
    struct static_ipv4 *si;
    struct route_table *stable;

    /* Lookup table.  */
    stable = vrf_static_table (AFI_IP, SAFI_UNICAST, vrf_id);
    if (!stable)
        return -1;

    /* Lookup static route prefix. */
    rn = route_node_lookup (stable, p);
    if (!rn)
        return 0;

    /* Make flags. */
    if (gate)
        type = STATIC_IPV4_GATEWAY;
    else if (ifname)
        type = STATIC_IPV4_IFNAME;
    else
        type = STATIC_IPV4_BLACKHOLE;

    /* Find same static route is the tree */
    for (si = rn->info; si; si = si->next)
        if (type == si->type && (!gate || IPV4_ADDR_SAME (gate, &si->gate.ipv4)) && (!ifname || strcmp (ifname, si->gate.ifname) == 0))
            break;

    /* Can't find static route. */
    if (!si)
    {
        route_unlock_node (rn);
        return 0;
    }

    /* Install into rib. */
    static_uninstall_ipv4 (p, si);

    /* Unlink static route from linked list. */
    if (si->prev)
        si->prev->next = si->next;
    else
        rn->info = si->next;
    if (si->next)
        si->next->prev = si->prev;
    route_unlock_node (rn);

    /* Free static route configuration. */
    if (ifname)
        XFREE (0, si->gate.ifname);
    XFREE (MTYPE_STATIC_IPV4, si);

    route_unlock_node (rn);

    return 1;
}



/*sangmeng add for customize route, add from terminal config*/
/* Add static route into static route configuration. */
int static_add_ipv4_customize (struct prefix *p, struct in_addr *gate, const char *ifname, u_char flags, u_char distance, u_int32_t vrf_id)
{
    u_char type = 0;
    struct route_node *rn;
    struct static_ipv4 *si;
    struct static_ipv4 *pp;
    struct static_ipv4 *cp;
    struct static_ipv4 *update = NULL;
    struct route_table *stable;

    /* Lookup table.  */
    stable = vrf_static_table (AFI_IP, SAFI_CUSTOMIZE_ONE, vrf_id);
    if (!stable)
        return -1;

    printf("%s()%d here.\n", __func__, __LINE__);
    /* Lookup static route prefix. */
    rn = route_node_get (stable, p);

    /* Make flags. */
    if (gate)
        type = STATIC_IPV4_GATEWAY;
    else if (ifname)
        type = STATIC_IPV4_IFNAME;
    else
        type = STATIC_IPV4_BLACKHOLE;

    /* Do nothing if there is a same static route.  */
    for (si = rn->info; si; si = si->next)
    {
        if (type == si->type && (!gate || IPV4_ADDR_SAME (gate, &si->gate.ipv4)) && (!ifname || strcmp (ifname, si->gate.ifname) == 0))
        {
            if (distance == si->distance)
            {
                route_unlock_node (rn);
                return 0;
            }
            else
                update = si;
        }
    }

    /* Distance changed.  */
    if (update)
        static_delete_ipv4 (p, gate, ifname, update->distance, vrf_id);

    /* Make new static route structure. */
    si = XCALLOC (MTYPE_STATIC_IPV4, sizeof (struct static_ipv4));

    si->type = type;
    si->distance = distance;
    si->flags = flags;

    if (gate)
        si->gate.ipv4 = *gate;
    if (ifname)
        si->gate.ifname = XSTRDUP (0, ifname);

    /* Add new static route information to the tree with sort by
       distance value and gateway address. */
    for (pp = NULL, cp = rn->info; cp; pp = cp, cp = cp->next)
    {
        if (si->distance < cp->distance)
            break;
        if (si->distance > cp->distance)
            continue;
        if (si->type == STATIC_IPV4_GATEWAY && cp->type == STATIC_IPV4_GATEWAY)
        {
            if (ntohl (si->gate.ipv4.s_addr) < ntohl (cp->gate.ipv4.s_addr))
                break;
            if (ntohl (si->gate.ipv4.s_addr) > ntohl (cp->gate.ipv4.s_addr))
                continue;
        }
    }

    /* Make linked list. */
    if (pp)
        pp->next = si;
    else
        rn->info = si;
    if (cp)
        cp->prev = si;
    si->prev = pp;
    si->next = cp;

    printf("%s()%d here.\n", __func__, __LINE__);
    /* Install into rib. */
    static_install_ipv4_customize (p, si);

    return 1;
}
/*sangmeng add for customize route 20180703*/
/* Delete static route from static route configuration. */
int static_delete_ipv4_customize (struct prefix *p, struct in_addr *gate, const char *ifname, u_char distance, u_int32_t vrf_id)
{
    u_char type = 0;
    struct route_node *rn;
    struct static_ipv4 *si;
    struct route_table *stable;

    /* Lookup table.  */
    stable = vrf_static_table (AFI_IP, SAFI_CUSTOMIZE_ONE, vrf_id);
    if (!stable)
        return -1;

    /* Lookup static route prefix. */
    rn = route_node_lookup (stable, p);
    if (!rn)
        return 0;

    /* Make flags. */
    if (gate)
        type = STATIC_IPV4_GATEWAY;
    else if (ifname)
        type = STATIC_IPV4_IFNAME;
    else
        type = STATIC_IPV4_BLACKHOLE;

    /* Find same static route is the tree */
    for (si = rn->info; si; si = si->next)
        if (type == si->type && (!gate || IPV4_ADDR_SAME (gate, &si->gate.ipv4)) && (!ifname || strcmp (ifname, si->gate.ifname) == 0))
            break;

    /* Can't find static route. */
    if (!si)
    {
        route_unlock_node (rn);
        return 0;
    }

    /* Install into rib. */
    static_uninstall_ipv4_customize (p, si);

    /* Unlink static route from linked list. */
    if (si->prev)
        si->prev->next = si->next;
    else
        rn->info = si->next;
    if (si->next)
        si->next->prev = si->prev;
    route_unlock_node (rn);

    /* Free static route configuration. */
    if (ifname)
        XFREE (0, si->gate.ifname);
    XFREE (MTYPE_STATIC_IPV4, si);

    route_unlock_node (rn);

    return 1;
}
#ifdef HAVE_IPV6
static int rib_bogus_ipv6 (int type, struct prefix_ipv6 *p, struct in6_addr *gate, unsigned int ifindex, int table)
{
    if (type == ZEBRA_ROUTE_CONNECT && IN6_IS_ADDR_UNSPECIFIED (&p->prefix))
    {
#if defined (MUSICA) || defined (LINUX)
        /* IN6_IS_ADDR_V4COMPAT(&p->prefix) */
        if (p->prefixlen == 96)
            return 0;
#endif /* MUSICA */
        return 1;
    }
    if (type == ZEBRA_ROUTE_KERNEL && IN6_IS_ADDR_UNSPECIFIED (&p->prefix) && p->prefixlen == 96 && gate && IN6_IS_ADDR_UNSPECIFIED (gate))
    {
        kernel_delete_ipv6_old (p, gate, ifindex, 0, table);
        return 1;
    }
    return 0;
}

static int static_ipv6_nexthop_same (struct nexthop *nexthop, struct static_ipv6 *si)
{
    if (nexthop->type == NEXTHOP_TYPE_IPV6 && si->type == STATIC_IPV6_GATEWAY && IPV6_ADDR_SAME (&nexthop->gate.ipv6, &si->ipv6))
        return 1;
    if (nexthop->type == NEXTHOP_TYPE_IFNAME && si->type == STATIC_IPV6_IFNAME && strcmp (nexthop->ifname, si->ifname) == 0)
        return 1;
    if (nexthop->type == NEXTHOP_TYPE_IPV6_IFNAME && si->type == STATIC_IPV6_GATEWAY_IFNAME && IPV6_ADDR_SAME (&nexthop->gate.ipv6, &si->ipv6) && strcmp (nexthop->ifname, si->ifname) == 0)
        return 1;
    return 0;
}
int rib_add_ipv6 (int type, int flags, struct prefix_ipv6 *p, struct in6_addr *gate, unsigned int ifindex, u_int32_t vrf_id, u_int32_t metric, u_char distance, safi_t safi)
{
    struct rib *rib;
    struct rib *same = NULL;
    struct route_table *table;
    struct route_node *rn;
    struct nexthop *nexthop;

    /* Lookup table.  */
    table = vrf_table (AFI_IP6, safi, 0);
    if (!table)
        return 0;

    /* Make sure mask is applied. */
    apply_mask_ipv6 (p);

    /* Set default distance by route type. */
    if (!distance)
        distance = route_info[type].distance;

    if (type == ZEBRA_ROUTE_BGP && CHECK_FLAG (flags, ZEBRA_FLAG_IBGP))
        distance = 200;

    /* Filter bogus route. */
    if (rib_bogus_ipv6 (type, p, gate, ifindex, 0))
        return 0;

    /* Lookup route node. */
    rn = route_node_get (table, (struct prefix *) p);

    /* If same type of route are installed, treat it as a implicit
       withdraw. */
    for (rib = rn->info; rib; rib = rib->next)
    {
        if (CHECK_FLAG (rib->status, RIB_ENTRY_REMOVED))
            continue;

        if (rib->type != type)
            continue;
        if (rib->type != ZEBRA_ROUTE_CONNECT)
        {
            same = rib;
            break;
        }
        else if ((nexthop = rib->nexthop) && nexthop->type == NEXTHOP_TYPE_IFINDEX && nexthop->ifindex == ifindex)
        {
            rib->refcnt++;
            return 0;
        }
    }

    /* Allocate new rib structure. */
    rib = XCALLOC (MTYPE_RIB, sizeof (struct rib));

    rib->type = type;
    rib->distance = distance;
    rib->flags = flags;
    rib->metric = metric;
    rib->table = vrf_id;
    rib->nexthop_num = 0;
    rib->uptime = time (NULL);

    /* Nexthop settings. */
    if (gate)
    {
        if (ifindex)
            nexthop_ipv6_ifindex_add (rib, gate, ifindex);
        else
            nexthop_ipv6_add (rib, gate);
    }
    else
        nexthop_ifindex_add (rib, ifindex);

    /* If this route is kernel route, set FIB flag to the route. */
    if (type == ZEBRA_ROUTE_KERNEL || type == ZEBRA_ROUTE_CONNECT)
        for (nexthop = rib->nexthop; nexthop; nexthop = nexthop->next)
            SET_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB);

    /* Link new rib to node. */
    rib_addnode (rn, rib);

    /* Free implicit route. */
    if (same)
        rib_delnode (rn, same);

    route_unlock_node (rn);
    return 0;
}

/*sangmeng add for ipv6 customize*/
int rib_add_ipv6_customize (int type, int flags, char *routetablename, struct prefix_ipv6 *p, struct in6_addr *gate, unsigned int ifindex, u_int32_t vrf_id, u_int32_t metric, u_char distance, safi_t safi,uint8_t action)
{
    struct rib *rib;
    struct rib *same = NULL;
    struct route_table *table;
    struct route_node *rn;
    struct nexthop *nexthop;

    /* Lookup table.  */
    table = vrf_table (AFI_IP6, safi, 0);
    if (!table)
        return 0;

    /* Make sure mask is applied. */
    apply_mask_ipv6 (p);

    /* Set default distance by route type. */
    if (!distance)
        distance = route_info[type].distance;

    if (type == ZEBRA_ROUTE_BGP && CHECK_FLAG (flags, ZEBRA_FLAG_IBGP))
        distance = 200;

    /* Filter bogus route. */
    if (rib_bogus_ipv6 (type, p, gate, ifindex, 0))
        return 0;

    /* Lookup route node. */
    rn = route_node_get (table, (struct prefix *) p);

    /* If same type of route are installed, treat it as a implicit
       withdraw. */
    for (rib = rn->info; rib; rib = rib->next)
    {
        if (CHECK_FLAG (rib->status, RIB_ENTRY_REMOVED))
            continue;

        if (rib->type != type)
            continue;
        if (rib->type != ZEBRA_ROUTE_CONNECT)
        {
            same = rib;
            break;
        }
        else if ((nexthop = rib->nexthop) && nexthop->type == NEXTHOP_TYPE_IFINDEX && nexthop->ifindex == ifindex)
        {
            rib->refcnt++;
            return 0;
        }
    }

    /* Allocate new rib structure. */
    rib = XCALLOC (MTYPE_RIB, sizeof (struct rib));

    rib->type = type;
    rib->type_customize = CUSTOMIZEROUTE;
    rib->distance = distance;
    rib->flags = flags;
    rib->metric = metric;
    rib->table = vrf_id;
    rib->nexthop_num = 0;
    rib->uptime = time (NULL);

    /* Nexthop settings. */
    if (gate)
    {
        if (ifindex)
        {
            nexthop_ipv6_ifindex_add (rib, gate, ifindex);
        }
        else
            nexthop_ipv6_add (rib, gate);
    }
    else
        nexthop_ifindex_add (rib, ifindex);

#if 0
    /* If this route is kernel route, set FIB flag to the route. */
    if (type == ZEBRA_ROUTE_KERNEL || type == ZEBRA_ROUTE_CONNECT)
        for (nexthop = rib->nexthop; nexthop; nexthop = nexthop->next)
            SET_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB);
#endif

    /* Link new rib to node. */

    rib_addnode (rn, rib);

    /* Free implicit route. */
    if (same)
        rib_delnode (rn, same);
#if 1
    char buf[64];
    printf(">>>>>%d %d\n", sizeof(struct prefix_ipv6), sizeof(struct in6_addr));
    inet_ntop (AF_INET6, &p->prefix, buf, BUFSIZ);
    printf("%s/%d ", buf, p->prefixlen);

    inet_ntop (AF_INET6, gate, buf, BUFSIZ);
    printf("gateway is:%s, ifindex:%d.\n", buf, ifindex);
#endif
    (table->count)++;
    //TODO:send route info to dpdk
    if (!send_ipv6_customize_route(ADDROUTE, routetablename, p, gate, ifindex,action))
    {
        printf("send ipv6 route add info to dpdk success.\n");
    }

    route_unlock_node (rn);
    return 0;
}
/* XXX factor with rib_delete_ipv6 */
int rib_delete_ipv6 (int type, int flags, struct prefix_ipv6 *p, struct in6_addr *gate, unsigned int ifindex, u_int32_t vrf_id, safi_t safi)
{
    struct route_table *table;
    struct route_node *rn;
    struct rib *rib;
    struct rib *fib = NULL;
    struct rib *same = NULL;
    struct nexthop *nexthop;
    char buf1[INET6_ADDRSTRLEN];
    char buf2[INET6_ADDRSTRLEN];

    /* Apply mask. */
    apply_mask_ipv6 (p);

    /* Lookup table.  */
    table = vrf_table (AFI_IP6, safi, 0);
    if (!table)
        return 0;

    /* Lookup route node. */
    rn = route_node_lookup (table, (struct prefix *) p);
    if (!rn)
    {
        if (IS_ZEBRA_DEBUG_KERNEL)
        {
            if (gate)
                zlog_debug ("route %s/%d via %s ifindex %d doesn't exist in rib",
                            inet_ntop (AF_INET6, &p->prefix, buf1, INET6_ADDRSTRLEN), p->prefixlen, inet_ntop (AF_INET6, gate, buf2, INET6_ADDRSTRLEN), ifindex);
            else
                zlog_debug ("route %s/%d ifindex %d doesn't exist in rib", inet_ntop (AF_INET6, &p->prefix, buf1, INET6_ADDRSTRLEN), p->prefixlen, ifindex);
        }
        return ZEBRA_ERR_RTNOEXIST;
    }

    /* Lookup same type route. */
    for (rib = rn->info; rib; rib = rib->next)
    {
        if (CHECK_FLAG (rib->status, RIB_ENTRY_REMOVED))
            continue;

        if (CHECK_FLAG (rib->flags, ZEBRA_FLAG_SELECTED))
            fib = rib;

        if (rib->type != type)
            continue;
        if (rib->type == ZEBRA_ROUTE_CONNECT && (nexthop = rib->nexthop) && nexthop->type == NEXTHOP_TYPE_IFINDEX)
        {
            if (nexthop->ifindex != ifindex)
                continue;
            if (rib->refcnt)
            {
                rib->refcnt--;
                route_unlock_node (rn);
                route_unlock_node (rn);
                return 0;
            }
            same = rib;
            break;
        }
        /* Make sure that the route found has the same gateway. */
        else if (gate == NULL || ((nexthop = rib->nexthop) && (IPV6_ADDR_SAME (&nexthop->gate.ipv6, gate) || IPV6_ADDR_SAME (&nexthop->rgate.ipv6, gate))))
        {
            same = rib;
            break;
        }
    }

    /* If same type of route can't be found and this message is from
       kernel. */
    if (!same)
    {
        if (fib && type == ZEBRA_ROUTE_KERNEL)
        {
            /* Unset flags. */
            for (nexthop = fib->nexthop; nexthop; nexthop = nexthop->next)
                UNSET_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB);

            UNSET_FLAG (fib->flags, ZEBRA_FLAG_SELECTED);
        }
        else
        {
            if (IS_ZEBRA_DEBUG_KERNEL)
            {
                if (gate)
                    zlog_debug ("route %s/%d via %s ifindex %d type %d doesn't exist in rib",
                                inet_ntop (AF_INET6, &p->prefix, buf1, INET6_ADDRSTRLEN), p->prefixlen, inet_ntop (AF_INET6, gate, buf2, INET6_ADDRSTRLEN), ifindex, type);
                else
                    zlog_debug ("route %s/%d ifindex %d type %d doesn't exist in rib", inet_ntop (AF_INET6, &p->prefix, buf1, INET6_ADDRSTRLEN), p->prefixlen, ifindex, type);
            }
            route_unlock_node (rn);
            return ZEBRA_ERR_RTNOEXIST;
        }
    }

    if (same)
        rib_delnode (rn, same);

    route_unlock_node (rn);
    return 0;
}
/*sangmeng add for ipv6 customize route*/
/* XXX factor with rib_delete_ipv6 */
int rib_delete_ipv6_customize (int type, int flags, char *routetablename, struct prefix_ipv6 *p, struct in6_addr *gate, unsigned int ifindex, u_int32_t vrf_id, safi_t safi)
{
    struct route_table *table;
    struct route_node *rn;
    struct rib *rib;
    struct rib *fib = NULL;
    struct rib *same = NULL;
    struct nexthop *nexthop;
    char buf1[INET6_ADDRSTRLEN];
    char buf2[INET6_ADDRSTRLEN];

    /* Apply mask. */
    apply_mask_ipv6 (p);

    /* Lookup table.  */
    table = vrf_table (AFI_IP6, safi, 0);
    if (!table)
        return 0;

    /* Lookup route node. */
    rn = route_node_lookup (table, (struct prefix *) p);
    if (!rn)
    {
        if (IS_ZEBRA_DEBUG_KERNEL)
        {
            if (gate)
                zlog_debug ("route %s/%d via %s ifindex %d doesn't exist in rib",
                            inet_ntop (AF_INET6, &p->prefix, buf1, INET6_ADDRSTRLEN), p->prefixlen, inet_ntop (AF_INET6, gate, buf2, INET6_ADDRSTRLEN), ifindex);
            else
                zlog_debug ("route %s/%d ifindex %d doesn't exist in rib", inet_ntop (AF_INET6, &p->prefix, buf1, INET6_ADDRSTRLEN), p->prefixlen, ifindex);
        }
        return ZEBRA_ERR_RTNOEXIST;
    }

    /* Lookup same type route. */
    for (rib = rn->info; rib; rib = rib->next)
    {
        if (CHECK_FLAG (rib->status, RIB_ENTRY_REMOVED))
            continue;

#if 0
        if (CHECK_FLAG (rib->flags, ZEBRA_FLAG_SELECTED))
            fib = rib;
#endif

        if (rib->type != type)
            continue;
#if 0
        if (rib->type == ZEBRA_ROUTE_CONNECT && (nexthop = rib->nexthop) && nexthop->type == NEXTHOP_TYPE_IFINDEX)
        {
            if (nexthop->ifindex != ifindex)
                continue;
            if (rib->refcnt)
            {
                rib->refcnt--;
                route_unlock_node (rn);
                route_unlock_node (rn);
                return 0;
            }
            same = rib;
            break;
        }
        /* Make sure that the route found has the same gateway. */
        else
#endif
            if (gate == NULL || ((nexthop = rib->nexthop) && (IPV6_ADDR_SAME (&nexthop->gate.ipv6, gate) || IPV6_ADDR_SAME (&nexthop->rgate.ipv6, gate))))
            {
                same = rib;
                break;
            }
    }

    /* If same type of route can't be found and this message is from
       kernel. */
    if (!same)
    {
        if (fib && type == ZEBRA_ROUTE_KERNEL)
        {
            /* Unset flags. */
            for (nexthop = fib->nexthop; nexthop; nexthop = nexthop->next)
                UNSET_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB);

            UNSET_FLAG (fib->flags, ZEBRA_FLAG_SELECTED);
        }
        else
        {
            if (IS_ZEBRA_DEBUG_KERNEL)
            {
                if (gate)
                    zlog_debug ("route %s/%d via %s ifindex %d type %d doesn't exist",
                                inet_ntop (AF_INET6, &p->prefix, buf1, INET6_ADDRSTRLEN), p->prefixlen, inet_ntop (AF_INET6, gate, buf2, INET6_ADDRSTRLEN), ifindex, type);
                else
                    zlog_debug ("route %s/%d ifindex %d type %d doesn't exist", inet_ntop (AF_INET6, &p->prefix, buf1, INET6_ADDRSTRLEN), p->prefixlen, ifindex, type);
            }
            route_unlock_node (rn);
            return ZEBRA_ERR_RTNOEXIST;
        }
    }

    if (same)
    {
        printf("del table:%s entry\n",table->table_name);
        if(--(table->count) == 0)
        {
            printf("count == 0,This is a NULL table\n");
            printf("free lpm:[%d]\n,table name:%s\n,describe:%s\n",safi,table->table_name,table->describe);
            table->use_flag = 0;
            bzero(table->table_name, sizeof(table->table_name));
            bzero(table->describe, sizeof(table->describe));
            printf("now use_flag:%d\n",table->use_flag);
        }
        //TODO:send msg to dpdk
        rib_delnode (rn, same);
        if(!send_ipv6_customize_route(DELROUTE, routetablename, p, gate, ifindex,1))
            printf("send ipv6 del route info to dpdk success.\n");
    }

    route_unlock_node (rn);
    return 0;
}
/* Install static route into rib. */
static void static_install_ipv6 (struct prefix *p, struct static_ipv6 *si)
{
    struct rib *rib;
    struct route_table *table;
    struct route_node *rn;

    /* Lookup table.  */
    table = vrf_table (AFI_IP6, SAFI_UNICAST, 0);
    if (!table)
        return;

    /* Lookup existing route */
    rn = route_node_get (table, p);
    for (rib = rn->info; rib; rib = rib->next)
    {
        if (CHECK_FLAG (rib->status, RIB_ENTRY_REMOVED))
            continue;

        if (rib->type == ZEBRA_ROUTE_STATIC && rib->distance == si->distance)
            break;
    }

    if (rib)
    {
        /* Same distance static route is there.  Update it with new
           nexthop. */
        route_unlock_node (rn);

        switch (si->type)
        {
        case STATIC_IPV6_GATEWAY:
            nexthop_ipv6_add (rib, &si->ipv6);
            break;
        case STATIC_IPV6_IFNAME:
            nexthop_ifname_add (rib, si->ifname);
            break;
        case STATIC_IPV6_GATEWAY_IFNAME:
            nexthop_ipv6_ifname_add (rib, &si->ipv6, si->ifname);
            break;
        }
        rib_queue_add (&zebrad, rn);
    }
    else
    {
        /* This is new static route. */
        rib = XCALLOC (MTYPE_RIB, sizeof (struct rib));

        rib->type = ZEBRA_ROUTE_STATIC;
        rib->distance = si->distance;
        rib->metric = 0;
        rib->nexthop_num = 0;

        switch (si->type)
        {
        case STATIC_IPV6_GATEWAY:
            nexthop_ipv6_add (rib, &si->ipv6);
            break;
        case STATIC_IPV6_IFNAME:
            nexthop_ifname_add (rib, si->ifname);
            break;
        case STATIC_IPV6_GATEWAY_IFNAME:
            nexthop_ipv6_ifname_add (rib, &si->ipv6, si->ifname);
            break;
        }

        /* Save the flags of this static routes (reject, blackhole) */
        rib->flags = si->flags;

        /* Link this rib to the tree. */
        rib_addnode (rn, rib);
    }
}
/*sangmeng add for ipv6 customize route  20180703*/
/* Install static route into rib. */
static void static_install_ipv6_customize (struct prefix *p, struct static_ipv6 *si)
{
    struct rib *rib;
    struct route_table *table;
    struct route_node *rn;

    /* Lookup table.  */
    table = vrf_table (AFI_IP6, SAFI_CUSTOMIZE_ONE, 0);
    if (!table)
        return;

    printf("%s()%d enter here.\n", __func__, __LINE__);
    /* Lookup existing route */
    rn = route_node_get (table, p);
    for (rib = rn->info; rib; rib = rib->next)
    {
        if (CHECK_FLAG (rib->status, RIB_ENTRY_REMOVED))
            continue;

        if (rib->type == ZEBRA_ROUTE_STATIC && rib->distance == si->distance)
            break;
    }

    if (rib)
    {
        /* Same distance static route is there.  Update it with new
           nexthop. */
        route_unlock_node (rn);

        switch (si->type)
        {
        case STATIC_IPV6_GATEWAY:
            nexthop_ipv6_add (rib, &si->ipv6);
            break;
        case STATIC_IPV6_IFNAME:
            nexthop_ifname_add (rib, si->ifname);
            break;
        case STATIC_IPV6_GATEWAY_IFNAME:
            nexthop_ipv6_ifname_add (rib, &si->ipv6, si->ifname);
            break;
        }
        //rib->type_customize = CUSTOMIZEROUTE;
#if 0
        rib_queue_add (&zebrad, rn);
#endif
    }
    else
    {
        /* This is new static route. */
        rib = XCALLOC (MTYPE_RIB, sizeof (struct rib));

        rib->type = ZEBRA_ROUTE_STATIC;
        rib->type_customize = CUSTOMIZEROUTE;
        rib->distance = si->distance;
        rib->metric = 0;
        rib->nexthop_num = 0;

        switch (si->type)
        {
        case STATIC_IPV6_GATEWAY:
            nexthop_ipv6_add (rib, &si->ipv6);
            break;
        case STATIC_IPV6_IFNAME:
            nexthop_ifname_add (rib, si->ifname);
            break;
        case STATIC_IPV6_GATEWAY_IFNAME:
            nexthop_ipv6_ifname_add (rib, &si->ipv6, si->ifname);
            break;
        }

        /* Save the flags of this static routes (reject, blackhole) */
        rib->flags = si->flags;

        /* Link this rib to the tree. */
        rib_addnode (rn, rib);
    }
    //TODO:send route info to dpdk
}
static void static_uninstall_ipv6 (struct prefix *p, struct static_ipv6 *si)
{
    struct route_table *table;
    struct route_node *rn;
    struct rib *rib;
    struct nexthop *nexthop;

    /* Lookup table.  */
    table = vrf_table (AFI_IP6, SAFI_UNICAST, 0);
    if (!table)
        return;

    /* Lookup existing route with type and distance. */
    rn = route_node_lookup (table, (struct prefix *) p);
    if (!rn)
        return;

    for (rib = rn->info; rib; rib = rib->next)
    {
        if (CHECK_FLAG (rib->status, RIB_ENTRY_REMOVED))
            continue;

        if (rib->type == ZEBRA_ROUTE_STATIC && rib->distance == si->distance)
            break;
    }

    if (!rib)
    {
        route_unlock_node (rn);
        return;
    }

    /* Lookup nexthop. */
    for (nexthop = rib->nexthop; nexthop; nexthop = nexthop->next)
        if (static_ipv6_nexthop_same (nexthop, si))
            break;

    /* Can't find nexthop. */
    if (!nexthop)
    {
        route_unlock_node (rn);
        return;
    }

    /* Check nexthop. */
    if (rib->nexthop_num == 1)
    {
        rib_delnode (rn, rib);
    }
    else
    {
        if (CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB))
            rib_uninstall (rn, rib);
        nexthop_delete (rib, nexthop);
        nexthop_free (nexthop);
        rib_queue_add (&zebrad, rn);
    }
    /* Unlock node. */
    route_unlock_node (rn);
}
/*sangmeng add for ipv6 customize route*/
static void static_uninstall_ipv6_customize (struct prefix *p, struct static_ipv6 *si)
{
    struct route_table *table;
    struct route_node *rn;
    struct rib *rib;
    struct nexthop *nexthop;

    /* Lookup table.  */
    table = vrf_table (AFI_IP6, SAFI_CUSTOMIZE_ONE, 0);
    if (!table)
        return;

    /* Lookup existing route with type and distance. */
    rn = route_node_lookup (table, (struct prefix *) p);
    if (!rn)
        return;

    for (rib = rn->info; rib; rib = rib->next)
    {
        if (CHECK_FLAG (rib->status, RIB_ENTRY_REMOVED))
            continue;

        if (rib->type == ZEBRA_ROUTE_STATIC && rib->distance == si->distance)
            break;
    }

    if (!rib)
    {
        route_unlock_node (rn);
        return;
    }

    /* Lookup nexthop. */
    for (nexthop = rib->nexthop; nexthop; nexthop = nexthop->next)
        if (static_ipv6_nexthop_same (nexthop, si))
            break;

    /* Can't find nexthop. */
    if (!nexthop)
    {
        route_unlock_node (rn);
        return;
    }

    /* Check nexthop. */
    if (rib->nexthop_num == 1)
    {
        //rib->type_customize = CUSTOMIZEROUTE;
        rib_delnode (rn, rib);
        //TODO:send route info to dpdk
    }
    else
    {
#if 0
        if (CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB))
            rib_uninstall (rn, rib);
#endif
        //rib->type_customize = CUSTOMIZEROUTE;
        //TODO:send route info to dpdk

        nexthop_delete (rib, nexthop);
        nexthop_free (nexthop);
        rib_queue_add (&zebrad, rn);
    }
    /* Unlock node. */
    route_unlock_node (rn);
}
/* Add static route into static route configuration. */
int static_add_ipv6 (struct prefix *p, u_char type, struct in6_addr *gate, const char *ifname, u_char flags, u_char distance, u_int32_t vrf_id)
{
    struct route_node *rn;
    struct static_ipv6 *si;
    struct static_ipv6 *pp;
    struct static_ipv6 *cp;
    struct route_table *stable;

    /* Lookup table.  */
    stable = vrf_static_table (AFI_IP6, SAFI_UNICAST, vrf_id);
    if (!stable)
        return -1;

    if (!gate && (type == STATIC_IPV6_GATEWAY || type == STATIC_IPV6_GATEWAY_IFNAME))
        return -1;

    if (!ifname && (type == STATIC_IPV6_GATEWAY_IFNAME || type == STATIC_IPV6_IFNAME))
        return -1;

    /* Lookup static route prefix. */
    rn = route_node_get (stable, p);

    /* Do nothing if there is a same static route.  */
    for (si = rn->info; si; si = si->next)
    {
        if (distance == si->distance && type == si->type && (!gate || IPV6_ADDR_SAME (gate, &si->ipv6)) && (!ifname || strcmp (ifname, si->ifname) == 0))
        {
            route_unlock_node (rn);
            return 0;
        }
    }

    /* Make new static route structure. */
    si = XCALLOC (MTYPE_STATIC_IPV6, sizeof (struct static_ipv6));

    si->type = type;
    si->distance = distance;
    si->flags = flags;

    switch (type)
    {
    case STATIC_IPV6_GATEWAY:
        si->ipv6 = *gate;
        break;
    case STATIC_IPV6_IFNAME:
        si->ifname = XSTRDUP (0, ifname);
        break;
    case STATIC_IPV6_GATEWAY_IFNAME:
        si->ipv6 = *gate;
        si->ifname = XSTRDUP (0, ifname);
        break;
    }

    /* Add new static route information to the tree with sort by
       distance value and gateway address. */
    for (pp = NULL, cp = rn->info; cp; pp = cp, cp = cp->next)
    {
        if (si->distance < cp->distance)
            break;
        if (si->distance > cp->distance)
            continue;
    }

    /* Make linked list. */
    if (pp)
        pp->next = si;
    else
        rn->info = si;
    if (cp)
        cp->prev = si;
    si->prev = pp;
    si->next = cp;

    /* Install into rib. */
    static_install_ipv6 (p, si);

    return 1;
}

/*sangmeng add for ipv6 customize route*/
/* Add static route into static route configuration. */
int static_add_ipv6_customize (struct prefix *p, u_char type, struct in6_addr *gate, const char *ifname, u_char flags, u_char distance, u_int32_t vrf_id)
{
    struct route_node *rn;
    struct static_ipv6 *si;
    struct static_ipv6 *pp;
    struct static_ipv6 *cp;
    struct route_table *stable;

    /* Lookup table.  */
    stable = vrf_static_table (AFI_IP6, SAFI_CUSTOMIZE_ONE, vrf_id);
    if (!stable)
        return -1;

    printf("%s()%d enter here.\n", __func__, __LINE__);
    if (!gate && (type == STATIC_IPV6_GATEWAY || type == STATIC_IPV6_GATEWAY_IFNAME))
        return -1;

    if (!ifname && (type == STATIC_IPV6_GATEWAY_IFNAME || type == STATIC_IPV6_IFNAME))
        return -1;

    /* Lookup static route prefix. */
    rn = route_node_get (stable, p);

    /* Do nothing if there is a same static route.  */
    for (si = rn->info; si; si = si->next)
    {
        if (distance == si->distance && type == si->type && (!gate || IPV6_ADDR_SAME (gate, &si->ipv6)) && (!ifname || strcmp (ifname, si->ifname) == 0))
        {
            route_unlock_node (rn);
            return 0;
        }
    }

    /* Make new static route structure. */
    si = XCALLOC (MTYPE_STATIC_IPV6, sizeof (struct static_ipv6));

    si->type = type;
    si->distance = distance;
    si->flags = flags;

    switch (type)
    {
    case STATIC_IPV6_GATEWAY:
        si->ipv6 = *gate;
        break;
    case STATIC_IPV6_IFNAME:
        si->ifname = XSTRDUP (0, ifname);
        break;
    case STATIC_IPV6_GATEWAY_IFNAME:
        si->ipv6 = *gate;
        si->ifname = XSTRDUP (0, ifname);
        break;
    }

    /* Add new static route information to the tree with sort by
       distance value and gateway address. */
    for (pp = NULL, cp = rn->info; cp; pp = cp, cp = cp->next)
    {
        if (si->distance < cp->distance)
            break;
        if (si->distance > cp->distance)
            continue;
    }

    /* Make linked list. */
    if (pp)
        pp->next = si;
    else
        rn->info = si;
    if (cp)
        cp->prev = si;
    si->prev = pp;
    si->next = cp;

    /* Install into rib. */
    printf("%s()%d enter here.\n", __func__, __LINE__);
    static_install_ipv6_customize (p, si);

    return 1;
}

/* Delete static route from static route configuration. */
int static_delete_ipv6 (struct prefix *p, u_char type, struct in6_addr *gate, const char *ifname, u_char distance, u_int32_t vrf_id)
{
    struct route_node *rn;
    struct static_ipv6 *si;
    struct route_table *stable;

    /* Lookup table.  */
    stable = vrf_static_table (AFI_IP6, SAFI_UNICAST, vrf_id);
    if (!stable)
        return -1;

    /* Lookup static route prefix. */
    rn = route_node_lookup (stable, p);
    if (!rn)
        return 0;

    /* Find same static route is the tree */
    for (si = rn->info; si; si = si->next)
        if (distance == si->distance && type == si->type && (!gate || IPV6_ADDR_SAME (gate, &si->ipv6)) && (!ifname || strcmp (ifname, si->ifname) == 0))
            break;

    /* Can't find static route. */
    if (!si)
    {
        route_unlock_node (rn);
        return 0;
    }

    /* Install into rib. */
    static_uninstall_ipv6 (p, si);

    /* Unlink static route from linked list. */
    if (si->prev)
        si->prev->next = si->next;
    else
        rn->info = si->next;
    if (si->next)
        si->next->prev = si->prev;

    /* Free static route configuration. */
    if (ifname)
        XFREE (0, si->ifname);
    XFREE (MTYPE_STATIC_IPV6, si);

    return 1;
}
/*sangmeng add for ipv6 customize route 20180704*/
/* Delete static route from static route configuration. */
int static_delete_ipv6_customize (struct prefix *p, u_char type, struct in6_addr *gate, const char *ifname, u_char distance, u_int32_t vrf_id)
{
    struct route_node *rn;
    struct static_ipv6 *si;
    struct route_table *stable;

    /* Lookup table.  */
    stable = vrf_static_table (AFI_IP6, SAFI_CUSTOMIZE_ONE, vrf_id);
    if (!stable)
        return -1;

    /* Lookup static route prefix. */
    rn = route_node_lookup (stable, p);
    if (!rn)
        return 0;

    /* Find same static route is the tree */
    for (si = rn->info; si; si = si->next)
        if (distance == si->distance && type == si->type && (!gate || IPV6_ADDR_SAME (gate, &si->ipv6)) && (!ifname || strcmp (ifname, si->ifname) == 0))
            break;

    /* Can't find static route. */
    if (!si)
    {
        route_unlock_node (rn);
        return 0;
    }

    /* Install into rib. */
    static_uninstall_ipv6_customize (p, si);

    /* Unlink static route from linked list. */
    if (si->prev)
        si->prev->next = si->next;
    else
        rn->info = si->next;
    if (si->next)
        si->next->prev = si->prev;

    /* Free static route configuration. */
    if (ifname)
        XFREE (0, si->ifname);
    XFREE (MTYPE_STATIC_IPV6, si);

    return 1;
}

#endif /* HAVE_IPV6 */
//sangmeng add for customize route 20180705
int zebra_rib_add_ipv4_customize (char *routetablename, struct prefix *p, struct in_addr *gate, const char *ifname, u_char distance, u_int32_t vrf_id)
{
    unsigned int ifindex;
    int type;
    safi_t  safi;
    if (!strcmp(routetablename, "customizeone"))
    {
        type = ZEBRA_ROUTE_OPENFLOW;
        safi = SAFI_CUSTOMIZE_ONE;
    }
    else
    {
        //TODO:
    }

    ifindex = ifname2ifindex(ifname);
    rib_add_ipv4_customize (type, ZEBRA_FLAG_SELECTED, routetablename, p, gate, NULL, ifindex, zebrad.rtm_table_default, 0, distance, safi);

    return 0;
}
//sangmeng add for customize route 20180705
int zebra_rib_del_ipv4_customize (char *routetablename, struct prefix *p, struct in_addr *gate, const char *ifname, u_int32_t vrf_id)
{
    unsigned int ifindex;
    int type;
    safi_t  safi;
    if (!strcmp(routetablename, "customizeone"))
    {
        type = ZEBRA_ROUTE_OPENFLOW;
        safi = SAFI_CUSTOMIZE_ONE;
    }
    else
    {
        //TODO:
    }
    ifindex = ifname2ifindex(ifname);
    rib_delete_ipv4_customize (type, ZEBRA_FLAG_SELECTED, routetablename, p, gate, ifindex, zebrad.rtm_table_default, safi);
    return 0;
}
//sangmeng add for customize route 20180705
//int zebra_rib_add_ipv6_customize (char *routetablename, struct prefix *p, struct in6_addr *gate, const char *ifname, u_char distance, u_int32_t vrf_id)
int zebra_rib_add_ipv6_customize (char *routetablename, struct prefix *p, struct in6_addr *gate, const char *ifname, u_char distance, u_int32_t vrf_id, const char *describe,uint8_t action)

{
    unsigned int ifindex;
    int type;
    safi_t  safi;
    int i = 0;
    safi_t no_use;
    struct vrf *vrf;
#if 0
    if (!strcmp(routetablename, "IPV4_L3FWD_LPM_1"))
    {
        type = ZEBRA_ROUTE_OPENFLOW;
        safi = SAFI_CUSTOMIZE_ONE;
    }
    else
    {
        //TODO:
    }
#endif
#if 0
    vrf = vrf_lookup (0);
    for(i = 6; i < 14; i++)
    {
        if(!strcmp(vrf->table[AFI_IP6][i]->table_name, routetablename))
        {
            break;
        }
        if(vrf->table[AFI_IP6][i]->use_flag != 1)
            no_use = i;
    }
#endif
    vrf = vrf_lookup (0);
    for(i = 6; i < 14; i++)
    {
        if(vrf->table[AFI_IP6][i]->use_flag == 1)
        {
            if(!strcmp(vrf->table[AFI_IP6][i]->table_name, routetablename))
                break;
        }
        else
            no_use = i;
    }
    ifindex = ifname2ifindex(ifname);
    type = ZEBRA_ROUTE_OPENFLOW;
    if(i < 14)
    {
        safi = i;
        if(strcmp(vrf->table[AFI_IP6][safi]->describe, describe))
            strcpy(vrf->table[AFI_IP6][safi]->describe, describe);
        printf("[add]safi:%d,table:%s,describe:%s\n",safi,vrf->table[AFI_IP6][safi]->table_name,vrf->table[AFI_IP6][safi]->describe);
    }
    else
    {
        if(no_use == 0)
        {
            char buf[128];
            bzero(buf,sizeof(buf));
            sprintf(buf,"[%s]No free table was found",routetablename);
            zlog_info(buf);
            return 0;
        }
        safi = no_use;
        vrf->table[AFI_IP6][safi]->use_flag = 1;
        strcpy(vrf->table[AFI_IP6][safi]->table_name, routetablename);
        strcpy(vrf->table[AFI_IP6][safi]->describe, describe);
        printf("use safi:%d,create new table:%s add entry,describe:%s\n",safi,vrf->table[AFI_IP6][safi]->table_name,vrf->table[AFI_IP6][safi]->describe);
    }
    rib_add_ipv6_customize (type, ZEBRA_FLAG_SELECTED, routetablename, p, gate, ifindex, zebrad.rtm_table_default, 0, distance, safi,action);
    return 0;
}
//sangmeng add for customize route 20180705
int zebra_rib_delete_ipv6_customize (char *routetablename, struct prefix *p, struct in6_addr *gate, const char *ifname, u_int32_t vrf_id)
{
    unsigned int ifindex;
    int type;
    safi_t  safi;
    int i;
    struct vrf *vrf;
#if 0
    if (!strcmp(routetablename, "IPV6_L3FWD_LPM_1"))
    {
        type = ZEBRA_ROUTE_OPENFLOW;
        safi = SAFI_CUSTOMIZE_ONE;
    }
    else
    {
        //TODO:
    }
#endif
    vrf = vrf_lookup (0);
    for(i = 6; i < 14; i++)
    {
        if(!strcmp(vrf->table[AFI_IP6][i]->table_name, routetablename))
        {
            break;
        }
    }
    if(i < 14)
        safi = i;
    else
        return -1;
    printf("[del]safi:%d entry\n",safi);
    type = ZEBRA_ROUTE_OPENFLOW;
    ifindex = ifname2ifindex(ifname);
    rib_delete_ipv6_customize (type, ZEBRA_FLAG_SELECTED, routetablename, p, gate, ifindex, zebrad.rtm_table_default, safi);
    return 0;
}

//added for 4over6 20130205
int getInterfaceIndex (char *name)
{
    int sd;
    struct ifreq ifr;
    struct in_addr inaddr;
    int index = 0;

    if ((sd = socket (AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        perror ("socket");
        return 0;
    }

    strcpy (ifr.ifr_name, name);
    if (ioctl (sd, SIOCGIFINDEX, &ifr) < 0)
    {
        perror ("ioctl(SIOCGIFADDR)");
        return 0;
    }

    printf ("eth0 index %d\n", ifr.ifr_ifindex);
    close (sd);
    return ifr.ifr_ifindex;
}

int getIp6Addr (char *buf, int index)
{
    struct ifaddrs *ifAddrStruct = NULL;
    void *tmpAddrPtr = NULL;

    getifaddrs (&ifAddrStruct);

    while (ifAddrStruct != NULL)
    {
        if ((ifAddrStruct->ifa_addr != NULL) && (ifAddrStruct->ifa_addr->sa_family == AF_INET6))
        {
            tmpAddrPtr = &((struct sockaddr_in *) ifAddrStruct->ifa_addr)->sin_addr;
            char addressBuffer[INET6_ADDRSTRLEN];
            inet_ntop (AF_INET6, tmpAddrPtr + 4, addressBuffer, INET6_ADDRSTRLEN);

            if (index == getInterfaceIndex (ifAddrStruct->ifa_name))
            {
                memcpy (buf, tmpAddrPtr + 4, 16);
                printf ("%s get it!!!\n\n\n\n", ifAddrStruct->ifa_name);
                return 0;
            }
            memset (buf, 0xff, 16);
        }

        ifAddrStruct = ifAddrStruct->ifa_next;
    }
    return 0;
}

#if 0
int zebra_4over6_nexthop_check (struct thread *thread)
{
    struct route_table *table;
    struct route_node *rn;
    struct rib *rib;
    struct nexthop *nexthop;
    char buf[BUFSIZ];

    zlog_notice ("zebra_4over6_nexthop_check");

    table = vrf_table (AFI_IP, SAFI_4OVER6, 0);
    if (!table)
        return 0;

    for (rn = route_top (table); rn; rn = route_next (rn))
    {
        for (rib = rn->info; rib; rib = rib->next)
        {
            nexthop_active_update (rn, rib, 1);
        }
    }

    return 0;
}
#endif

#if 0
static void zebra_set_4over6_route_select(struct zebra_4over6_tunnel_entry *tnl_info)
{
    struct route_table *table;
    struct route_node *rn;
    struct rib *rib;
    struct nexthop *nexthop;
    table = vrf_table (AFI_IP, SAFI_4OVER6, 0);
    if (!table)
        return 0;

    TEST_DEBUG("here route select here.\n");
    for (rn = route_top (table); rn; rn = route_next (rn))
    {
        TEST_DEBUG("here route select here....0.\n");
        for (rib = rn->info; rib; rib = rib->next)
        {
            TEST_DEBUG("here route select here...1.\n");
            for (nexthop = rib->nexthop; nexthop; nexthop = nexthop->next)
            {
                TEST_DEBUG(".....here....\n");
                if ((tnl_info->state == 1)&& (&tnl_info->nexthop == rib->nexthop))
                {
                    TEST_DEBUG("set flag here.\n");
                    SET_FLAG(rib->flags, ZEBRA_FLAG_SELECTED);
                    SET_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE);
                }
            }
        }
    }
    return;
}
#endif
int zebra_4over6_nexthop_check (struct thread *thread)
{
    struct route_table *table;
    struct route_table *stable;
    struct route_table *table_ipv6;
    struct zebra_4over6_tunnel_entry *pLast;
    struct zebra_4over6_tunnel_entry *pNext;
    struct route_node *rn;
    struct route_node *srn;
    struct rib *rib;
    struct rib *srib;
    struct in6_addr nexthop;
    char tunnel_name[IFNAMSIZ];
    int ret = 0;
    int iret = 0;
    struct interface *ifp;
    struct zebra_if *if_data;

    zlog_notice ("zebra_4over6_nexthop_check");
    TEST_DEBUG ("zebra_4over6_nexthop_check.\n");

    table_ipv6 = vrf_table (AFI_IP6, SAFI_UNICAST, 0);
    if (!table_ipv6)
    {
        thread_add_timer (zebrad.master, zebra_4over6_nexthop_check, NULL, 60);
        zlog_notice ("zebra_4over6_nexthop_check: table_ipv6 = NULL");
        TEST_DEBUG (">>>zebra_4over6_nexthop_check: table_ipv6 = NULL.\n");
        return 0;
    }

    pLast = &zebra4over6TunnelEntry;
    pNext = zebra4over6TunnelEntry.next;
    while (pNext != NULL)
    {
        if (pNext->state != 1)
        {
            memcpy (&nexthop, &pNext->nexthop, sizeof (struct in6_addr));
            memset (tunnel_name, 0, IFNAMSIZ);
            strlcpy (tunnel_name, pNext->name, IFNAMSIZ);

            ret = zebra_4over6_tunnel_create (nexthop, tunnel_name, pNext);
            if (ret == 0)
            {
                pNext->state = 1;
            }
        }
        pLast = pNext;
        pNext = pNext->next;
    }

    thread_add_timer (zebrad.master, zebra_4over6_nexthop_check, NULL, 60);
#if 1//for no 4over6 route in kernel
    table = vrf_table (AFI_IP, SAFI_4OVER6, 0);
    if (!table)
        return 0;

    for (rn = route_top (table); rn; rn = route_next (rn))
    {
        for (rib = rn->info; rib; rib = rib->next)
        {
            rib_delnode (rn, rib);
            rib_addnode (rn, rib);
        }
    }
#endif

    return 0;
}

int zebra_4over6_nexthop_lookup (struct in6_addr *nexthop, char *tnl_name)
{
    struct zebra_4over6_tunnel_entry *pLast;
    struct zebra_4over6_tunnel_entry *pNext;
    int iRetVal = 0;

    pLast = &zebra4over6TunnelEntry;
    pNext = zebra4over6TunnelEntry.next;
    while (pNext != NULL)
    {
        iRetVal = memcmp (nexthop, &pNext->nexthop, sizeof (struct in6_addr));
        if (iRetVal == 0)
            break;

        pLast = pNext;
        pNext = pNext->next;
    }
    if (pNext != NULL)
    {
        strlcpy (tnl_name, pNext->name, IFNAMSIZ);
        return 0;
    }
    else
        return -1;
}
int zebra_connect_dpdk_send_message (struct zebra_config_message *p_zebra_msg, int size)
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
    /*send ivi message */
    char buf[1024];
    memset(buf, 0, sizeof(buf));
    memcpy (buf, p_zebra_msg, sizeof (struct zebra_config_message));
    if ((p_zebra_msg->type == ADD_TUNNEL) || (p_zebra_msg->type == DEL_TUNNEL))
    {
        printf("send %s msg.\n", (p_zebra_msg->type == ADD_TUNNEL)? "ADD_TUNNEL":"DEL_TUNNEL");
        memcpy (buf + sizeof (struct zebra_config_message), p_zebra_msg->data, sizeof (struct tunnel_info));
    }
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

int send_4over6_static_route_to_dpdk (struct tunnel_info *p, int flag)
{
    struct zebra_config_message p_zebra_msg;
    bzero (&p_zebra_msg, sizeof (struct zebra_config_message));
    struct in6_addr zero_6;
    bzero (&zero_6, sizeof (struct in6_addr));
    struct in_addr zero_4;
    bzero (&zero_4, sizeof (struct in_addr));

    printf("will send 4over6 static route to dpdk, flag:%d, ADD_TUNNEL:%d,DEL_TUNNEL:%d.\n", flag, ADD_TUNNEL, DEL_TUNNEL);
    if ((memcmp (&(p->tunnel_source), &zero_6, sizeof (struct in6_addr))) && (memcmp (&(p->tunnel_dest), &zero_6, sizeof (struct in6_addr)))
            && (memcmp (&(p->ip_prefix.prefix), &zero_4, sizeof (struct in_addr))))
    {
        if (flag == ADD_TUNNEL)
            p_zebra_msg.type = ADD_TUNNEL;
        else
            p_zebra_msg.type = DEL_TUNNEL;
        p_zebra_msg.len = sizeof (struct zebra_config_message) + sizeof (struct tunnel_info);
        p_zebra_msg.data = p;
        printf("will connect dpdk and send %s msg to dpdk.\n", (flag == ADD_TUNNEL) ? "ADD_TUNNEL": "DEL_TUNNEL");
        return zebra_connect_dpdk_send_message (&p_zebra_msg, p_zebra_msg.len);
    }

    return 0;

}
int zebra_4over6_tunnel_create (struct in6_addr remote, char *tunnel_name, struct zebra_4over6_tunnel_entry *tnl_info)
{
    struct ifreq ifr;
    struct ip6_tnl_parm tnl_4over6;
    struct in6_addr local;
    struct route_node *rn;
    struct rib *rib;
    struct route_table *table;
    int socketfd;
    int ret = 0;
    char buf[BUFSIZ];
    struct tunnel_info p;

    inet_ntop (AF_INET6, &remote, buf, BUFSIZ);
    zlog_notice ("zebra_4over6_tunnel_create: tunnel_name: %s, remote = %s", tunnel_name, buf);
    printf ("zebra_4over6_tunnel_create: tunnel_name: %s, remote = %s.\n", tunnel_name, buf);

    /* Lookup table.  */
    table = vrf_table (AFI_IP6, SAFI_UNICAST, 0);
    if (!table)
        return 0;

    rn = route_node_match_ipv6 (table, &remote);
    if (rn != NULL)
    {
        zlog_notice ("zebra_4over6_tunnel_create: rn != NULL");
        TEST_DEBUG ("zebra_4over6_tunnel_create: rn != NULL.\n");
    }
    else
    {
        zlog_notice ("zebra_4over6_tunnel_create: rn == NULL");
        TEST_DEBUG ("zebra_4over6_tunnel_create, not match: rn == NULL.\n");
        return -1;
    }
    for (rib = rn->info; rib; rib = rib->next)
    {
        if (CHECK_FLAG (rib->flags, ZEBRA_FLAG_SELECTED))
        {
            TEST_DEBUG(">>>>rib flag is ZEBRA_FLAG_SELECTED.\n");
            break;
        }
    }
    if (rib == NULL)
    {
        zlog_notice ("zebra_4over6_tunnel_create: rib == NULL");
        TEST_DEBUG ("zebra_4over6_tunnel_create: rib == NULL.\n");
        return -1;
    }

    getIp6Addr (&local, rib->nexthop->ifindex);
    memcpy(&tnl_info->source, &local, sizeof(struct in6_addr));
    memset(&p, 0x00, sizeof(struct tunnel_info));

    memcpy(&p.tunnel_source, &local, sizeof(struct in6_addr));
    memcpy(&p.tunnel_dest, &remote, sizeof(struct in6_addr));
    memcpy(&p.ip_prefix, &tnl_info->ip_prefix, sizeof(struct prefix_ipv4));
    p.tunnel_num = tnl_info->tunnel_number;

    //here send route info to dpdk
    TEST_DEBUG("will send add 4over6 route msg to dpdk, tunnel_num:%d.\n", p.tunnel_num);
    send_4over6_static_route_to_dpdk(&p, ADD_TUNNEL);
#if 0
    socketfd = socket (AF_INET6, SOCK_DGRAM, 0);
    if (socketfd < 0)
    {
        printf ("socket error\n");
        return -1;
    }

    memcpy (ifr.ifr_name, "ip6tnl0", 8);

    memcpy (tnl_4over6.name, tunnel_name, IFNAMSIZ);
    tnl_4over6.proto = IPPROTO_IPIP;
    memcpy (&tnl_4over6.laddr, &local, sizeof (struct in6_addr));
    memcpy (&tnl_4over6.raddr, &remote, sizeof (struct in6_addr));

    ifr.ifr_data = &tnl_4over6;

    ret = ioctl (socketfd, SIOCADDTUNNEL, &ifr);
    if (ret == -1)
    {
        printf ("ioctl error !\n");
        close (socketfd);
        return -1;
    }

    memcpy (ifr.ifr_name, tunnel_name, IFNAMSIZ);
    ifr.ifr_flags = IFF_UP;
    ret = ioctl (socketfd, SIOCSIFFLAGS, &ifr);
    if (ret == -1)
    {
        printf ("ioctl error !\n");
        close (socketfd);
        return -1;
    }

    close (socketfd);

    //set mtu to 1500
    sprintf (setmtucmd, "ifconfig %s mtu 1500", tunnel_name);
    system (setmtucmd);
#endif
    return CMD_SUCCESS;
}

int zebra_4over6_nexthop_add_check (struct in6_addr nexthop, struct prefix_ipv4 *p)
{
    struct zebra_4over6_tunnel_entry *pLast;
    struct zebra_4over6_tunnel_entry *pNext;
    struct zebra_4over6_tunnel_entry *pNew;
    int iRetVal = 0;
    char tunnel_name[IFNAMSIZ];
    int tunnel_number = 0;
    int ret = 0;

    pLast = &zebra4over6TunnelEntry;
    pNext = zebra4over6TunnelEntry.next;
    while (pNext != NULL)
    {
        iRetVal = memcmp (&nexthop, &pNext->nexthop, sizeof (struct in6_addr));
        if (iRetVal == 0)
            break;

        pLast = pNext;
        pNext = pNext->next;
    }
    if (pNext != NULL)
        pNext->num++;
    else
    {
        while (tnl_number[tunnel_number] == ZEBRA_4OVER6_ENABLE)
        {
            if (tunnel_number == TUNNELNUMBER)
            {
                zlog_notice ("zebra_4over6_nexthop_add_check: tnl_number is outof range!");
                return -1;
            }
            tunnel_number++;
        }

        pNew = XCALLOC (MTYPE_TUNNEL, sizeof (struct zebra_4over6_tunnel_entry));
        if (pNew == NULL)
            return -1;
        memset (pNew, 0, sizeof (struct zebra_4over6_tunnel_entry));

        pNew->tunnel_number = tunnel_number;
        memset (tunnel_name, 0, IFNAMSIZ);
        sprintf (tunnel_name, "4o6_tnl_%d", tunnel_number);
        strlcpy (pNew->name, tunnel_name, IFNAMSIZ);
        tnl_number[tunnel_number] = ZEBRA_4OVER6_ENABLE;

        memcpy (&pNew->nexthop, &nexthop, sizeof (struct in6_addr));
        memcpy (&pNew->ip_prefix, p, sizeof (struct prefix_ipv4));
        pNew->num = 1;
        pNew->next = NULL;

        pLast->next = pNew;

        ret = zebra_4over6_tunnel_create (nexthop, tunnel_name, pNew);
        if (ret == 0)
        {
            pNew->state = 1;
        }
    }
    return 0;
}

int rib_add_ipv4_4over6 (int type, int flags, struct prefix_ipv6 *p, struct in6_addr *gate, unsigned int ifindex, u_int32_t vrf_id, u_int32_t metric, u_char distance, safi_t safi)
{
    struct rib *rib;
    struct rib *same = NULL;
    struct route_table *table;
    struct route_node *rn;
    struct nexthop *nexthop;
    char tunnel_name[IFNAMSIZ] = { 0 };
    int ret;

    /* Lookup table.  */
    table = vrf_table (AFI_IP, safi, 0);
    if (!table)
        return 0;

    /* Make sure mask is applied. */
    apply_mask_ipv4 (p);

    /* Set default distance by route type. */
    if (!distance)
        distance = route_info[type].distance;

    if (type == ZEBRA_ROUTE_BGP && CHECK_FLAG (flags, ZEBRA_FLAG_IBGP))
        distance = 200;

    /* Lookup route node. */
    rn = route_node_get (table, (struct prefix *) p);

    /* If same type of route are installed, treat it as a implicit withdraw. */
    for (rib = rn->info; rib; rib = rib->next)
    {
        if (CHECK_FLAG (rib->status, RIB_ENTRY_REMOVED))
            continue;

        if (rib->type != type)
            continue;
        if (rib->type != ZEBRA_ROUTE_CONNECT)
        {
            same = rib;
            break;
        }
        else if ((nexthop = rib->nexthop) && nexthop->type == NEXTHOP_TYPE_IFINDEX && nexthop->ifindex == ifindex && !CHECK_FLAG (rib->status, RIB_ENTRY_REMOVED))
        {
            rib->refcnt++;
            return 0;
        }
    }

    /* Allocate new rib structure. */
    rib = XCALLOC (MTYPE_RIB, sizeof (struct rib));
    rib->type = type;
    rib->distance = distance;
    rib->flags = flags;
    rib->metric = metric;
    rib->table = vrf_id;
    rib->nexthop_num = 0;
    rib->uptime = time (NULL);

    /* Nexthop settings. */
    ret = zebra_4over6_nexthop_lookup (gate, tunnel_name);
    if (ret == 0)
        nexthop_ipv6_ifname_add (rib, gate, tunnel_name);
    else
    {
        if (gate)
        {
            if (ifindex)
                nexthop_ipv6_ifindex_add (rib, gate, ifindex);
            else
                nexthop_ipv6_add (rib, gate);
        }
        else
            nexthop_ifindex_add (rib, ifindex);
    }

    /* If this route is kernel route, set FIB flag to the route. */
    if (type == ZEBRA_ROUTE_KERNEL || type == ZEBRA_ROUTE_CONNECT)
    {
        for (nexthop = rib->nexthop; nexthop; nexthop = nexthop->next)
        {
            SET_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB);
        }
    }

    /* Link new rib to node. */
    rib_addnode (rn, rib);

    /* Free implicit route. */
    if (same)
        rib_delnode (rn, same);

    route_unlock_node (rn);
    return 0;
}

/* XXX factor with rib_delete_ipv6 */
int rib_delete_ipv4_4over6 (int type, int flags, struct prefix_ipv6 *p, struct in6_addr *gate, unsigned int ifindex, u_int32_t vrf_id, safi_t safi)
{
    struct route_table *table;
    struct route_node *rn;
    struct rib *rib;
    struct rib *fib = NULL;
    struct rib *same = NULL;
    struct nexthop *nexthop;
    char buf1[INET6_ADDRSTRLEN];
    char buf2[INET6_ADDRSTRLEN];

    /* Lookup table.  */
    table = vrf_table (AFI_IP, safi, 0);
    if (!table)
        return 0;

    /* Apply mask. */
    apply_mask_ipv4 (p);

    /* Lookup route node. */
    rn = route_node_lookup (table, (struct prefix *) p);
    if (!rn)
    {
        if (IS_ZEBRA_DEBUG_KERNEL)
        {
            if (gate)
                zlog_debug ("route %s/%d via %s ifindex %d doesn't exist in rib",
                            inet_ntop (AF_INET, &p->prefix, buf1, INET_ADDRSTRLEN), p->prefixlen, inet_ntop (AF_INET6, gate, buf2, INET6_ADDRSTRLEN), ifindex);
            else
                zlog_debug ("route %s/%d ifindex %d doesn't exist in rib", inet_ntop (AF_INET, &p->prefix, buf1, INET_ADDRSTRLEN), p->prefixlen, ifindex);
        }
        return ZEBRA_ERR_RTNOEXIST;
    }

    /* Lookup same type route. */
    for (rib = rn->info; rib; rib = rib->next)
    {
        if (CHECK_FLAG (rib->status, RIB_ENTRY_REMOVED))
            continue;

        if (CHECK_FLAG (rib->flags, ZEBRA_FLAG_SELECTED))
            fib = rib;

        if (rib->type != type)
            continue;
        if (rib->type == ZEBRA_ROUTE_CONNECT && (nexthop = rib->nexthop) && nexthop->type == NEXTHOP_TYPE_IFINDEX)
        {
            if (nexthop->ifindex != ifindex)
                continue;
            if (rib->refcnt)
            {
                rib->refcnt--;
                route_unlock_node (rn);
                route_unlock_node (rn);
                return 0;
            }
            same = rib;
            break;
        }
        /* Make sure that the route found has the same gateway. */
        else if (gate == NULL || ((nexthop = rib->nexthop) && (IPV6_ADDR_SAME (&nexthop->gate.ipv6, gate) || IPV6_ADDR_SAME (&nexthop->rgate.ipv6, gate))))
        {
            same = rib;
            break;
        }
    }

    /* If same type of route can't be found and this message is from
       kernel. */
    if (!same)
    {
        if (fib && type == ZEBRA_ROUTE_KERNEL)
        {
            /* Unset flags. */
            for (nexthop = fib->nexthop; nexthop; nexthop = nexthop->next)
            {
                UNSET_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB);
            }
            UNSET_FLAG (fib->flags, ZEBRA_FLAG_SELECTED);
        }
        else
        {
            if (IS_ZEBRA_DEBUG_KERNEL)
            {
                if (gate)
                    zlog_debug ("route %s/%d via %s ifindex %d type %d doesn't exist in rib",
                                inet_ntop (AF_INET, &p->prefix, buf1, INET_ADDRSTRLEN), p->prefixlen, inet_ntop (AF_INET6, gate, buf2, INET6_ADDRSTRLEN), ifindex, type);
                else
                    zlog_debug ("route %s/%d ifindex %d type %d doesn't exist in rib", inet_ntop (AF_INET, &p->prefix, buf1, INET_ADDRSTRLEN), p->prefixlen, ifindex, type);
            }
            route_unlock_node (rn);
            return ZEBRA_ERR_RTNOEXIST;
        }
    }

    if (same)
        rib_delnode (rn, same);

    route_unlock_node (rn);
    return 0;
}


int send_4over6_route_to_dpdk (struct _bgp_4over6_route_message *bgp_4over6_rt_msg, int len, char flag)
{
    int sockfd;
    int ret;
    struct comm_head *comm_send;
    struct comm_head *comm_recv;
    char cType;
    char buf[128];

    comm_send = (struct comm_head *) malloc (sizeof (struct comm_head) + len);
    if (comm_send == NULL)
    {
        fprintf (stderr, "%s\n", "4over6 route info head malloc failed");
        return ERR;
    }
    memset (comm_send, 0, sizeof (struct comm_head) + len);

    if (flag == 1)				//add route
        comm_send->type = ADD_4OVER6_ROUTE;
    else
        comm_send->type = DEL_4OVER6_ROUTE;

    comm_send->len = sizeof (struct comm_head) + len;
    memcpy (comm_send->data, bgp_4over6_rt_msg, sizeof (struct _bgp_4over6_route_message));

    if ((sockfd = connect_dpdk_multiport (DPDK_SERVER_PORT)) == -1)
    {
        free (comm_send);
        return ERR;
    }
    ret = send (sockfd, (char *) comm_send, sizeof (struct comm_head) + len, 0);
    if (ret < 0)
    {
        fprintf (stderr, "%s\n", "send bgp 4over6 route failed");
        close (sockfd);
        free (comm_send);
        return ERR;
    }

    fprintf (stdout, "send %d bytes 4over6 route info to dpdk\n", ret);
    memset (buf, 0, sizeof (buf));
    ret = recv (sockfd, buf, sizeof (buf), 0);
    if (ret < 0)
    {
        fprintf (stderr, "%s\n", "recv 4over6 route return message failed");
        close (sockfd);
        free (comm_send);
        return ERR;
    }
    comm_recv = (struct comm_head *) buf;

    if (comm_recv->type == RESPONSE_ADD_BGP_4OVER6_ROUTE)
    {
        cType = comm_recv->data;
        if (cType == 1)
        {
            fprintf(stderr, "%s\n", "ADD bgp 4over6 route failed, array is full");
            zlog_notice ("Add bgp 4over6 route failed, array is full");
        }
    }
    free (comm_send);
    return OK;

}
void print_v4addr (uint32_t addr, const char *hints)
{
    uint32_t v4addr;
    v4addr = ntohl (addr);
    printf ("%s %d.%d.%d.%d\n", hints, (v4addr >> 24) & 0xFF, ((v4addr) >> 16) & 0xFF, ((v4addr) >> 8) & 0xFF, ((v4addr)) & 0xFF);
}

void get_local_ipv6_address (struct in6_addr *local, struct in6_addr remote, int *ifindex)
{

    struct ifreq ifr;
    struct ip6_tnl_parm tnl_4over6;
    struct route_node *rn;
    struct rib *rib;
    struct route_table *table;
    int socketfd;
    int ret = 0;

    /* Lookup table.  */
    table = vrf_table (AFI_IP6, SAFI_UNICAST, 0);
    if (!table)
    {
        return 0;
    }

    rn = route_node_match_ipv6 (table, &remote);
    if (rn != NULL)
    {
        zlog_notice ("get_local_ipv6_address: rn != NULL");
    }
    else
    {
        zlog_notice ("get_local_ipv6_address: rn == NULL");
        return -1;
    }
    for (rib = rn->info; rib; rib = rib->next)
    {
        if (CHECK_FLAG (rib->flags, ZEBRA_FLAG_SELECTED))
            break;
    }
    if (rib == NULL)
    {
        zlog_notice ("zebra_4over6_tunnel_create: rib == NULL");
        return -1;
    }

    *ifindex = rib->nexthop->ifindex;
    getIp6Addr (local, rib->nexthop->ifindex);
}
static int
zread_ipv4_add_customize (struct zserv *client, u_short length)
{
    int i;

    struct zapi_ipv4 api;
#if 0
    struct rib *rib;
#endif
    struct prefix_ipv4 p;
#if 0
    u_char message;
#endif
    struct in_addr nexthop;
    u_char nexthop_num;
    u_char nexthop_type;
    struct stream *s;
    unsigned int ifindex;
    u_char ifname_len;
#if 0
    safi_t safi;
#endif
#if 1 //TODO

    /* Get input stream.  */
    s = client->ibuf;

#if 0
    /* Allocate new rib. */
    rib = XCALLOC (MTYPE_RIB, sizeof (struct rib));
#endif

    /* Type, flags, message. */

    /* Type, flags, message. */
    api.type = stream_getc (s);
    api.flags = stream_getc (s);
    api.message = stream_getc (s);
    api.safi = stream_getw (s);

#if 0
    rib->type = stream_getc (s);
    rib->flags = stream_getc (s);
    message = stream_getc (s);
    safi = stream_getw (s);
    rib->uptime = time (NULL);
#endif

    /* IPv4 prefix. */
    memset (&p, 0, sizeof (struct prefix_ipv4));
    p.family = AF_INET;
    p.prefixlen = stream_getc (s);
    stream_get (&p.prefix, s, PSIZE (p.prefixlen));

    /* Nexthop parse. */
    if (CHECK_FLAG (api.message, ZAPI_MESSAGE_NEXTHOP))
    {
        nexthop_num = stream_getc (s);

        for (i = 0; i < nexthop_num; i++)
        {
            nexthop_type = stream_getc (s);

            switch (nexthop_type)
            {
            case ZEBRA_NEXTHOP_IFINDEX:
                ifindex = stream_getl (s);
#if 0
                nexthop_ifindex_add (rib, ifindex);
#endif
                break;
            case ZEBRA_NEXTHOP_IFNAME:
                ifname_len = stream_getc (s);
#if 0
                stream_forward_getp (s, ifname_len);
#endif
                break;
            case ZEBRA_NEXTHOP_IPV4:
                nexthop.s_addr = stream_get_ipv4 (s);
#if 0
                nexthop_ipv4_add (rib, &nexthop, NULL);
#endif
                break;
#if 0
            case ZEBRA_NEXTHOP_IPV6:
                stream_forward_getp (s, IPV6_MAX_BYTELEN);
                break;
            case ZEBRA_NEXTHOP_BLACKHOLE:
                nexthop_blackhole_add (rib);
#endif
                break;
            }
        }
    }

    /* Distance. */
    if (CHECK_FLAG (api.message, ZAPI_MESSAGE_DISTANCE))
        api.distance = stream_getc (s);
    else
        api.distance = 0;

    /* Metric. */
    if (CHECK_FLAG (api.message, ZAPI_MESSAGE_METRIC))
        api.metric = stream_getl (s);
    else
        api.metric = 0;

#if 0
    /* Table */
    rib->table=zebrad.rtm_table_default;
    rib_add_ipv4_multipath (&p, rib, safi);
#endif
#endif //TODO:openflow recv

    //rib_add_ipv4_customize(api.type, api.flags, &p, &nexthop, ifindex, zebrad.rtm_table_default, api.metric, api.distance, api.safi);
    return 0;
}
int zread_ipv4_4over6_add (struct zserv *client, u_short length)
{
    int i;
    struct stream *s;
    struct zapi_ipv6 api;
    struct in6_addr nexthop;
    struct in6_addr local_ipv6_address;	//sangmeng add 160311
    unsigned long ifindex;
    struct prefix_ipv4 p;
#if 0
    struct _bgp_4over6_route_message bgp_4over6_rt_msg;
#endif

    s = client->ibuf;
    ifindex = 0;
    memset (&nexthop, 0, sizeof (struct in6_addr));

    /* Type, flags, message. */
    api.type = stream_getc (s);
    api.flags = stream_getc (s);
    api.message = stream_getc (s);
    api.safi = stream_getw (s);

    /* IPv4 prefix. */
    memset (&p, 0, sizeof (struct prefix_ipv4));
    p.family = AF_INET;
    p.prefixlen = stream_getc (s);
    stream_get (&p.prefix, s, PSIZE (p.prefixlen));

#if 1
    print_v4addr (p.prefix.s_addr, "ipv4 prefix");
    printf ("prefixlen:%d\n", p.prefixlen);
#endif

    /* Nexthop, ifindex, distance, metric. */
    if (CHECK_FLAG (api.message, ZAPI_MESSAGE_NEXTHOP))
    {
        u_char nexthop_type;

        api.nexthop_num = stream_getc (s);
        for (i = 0; i < api.nexthop_num; i++)
        {
            nexthop_type = stream_getc (s);

            switch (nexthop_type)
            {
            case ZEBRA_NEXTHOP_IPV6:
                stream_get (&nexthop, s, 16);
                break;
            case ZEBRA_NEXTHOP_IFINDEX:
                ifindex = stream_getl (s);
                break;
            }
        }
    }

#if 0
    printf ("ifindex:%d\n", ifindex);
#endif

    memset (&local_ipv6_address, 0, sizeof (struct in6_addr));
    get_local_ipv6_address (&local_ipv6_address, nexthop, &ifindex);

#if 0
    memset (&bgp_4over6_rt_msg, 0, sizeof (struct _bgp_4over6_route_message));
    memcpy (&bgp_4over6_rt_msg.p, &p, sizeof (struct prefix_ipv4));
    memcpy (&bgp_4over6_rt_msg.local_ipv6_address, &local_ipv6_address, sizeof (struct in6_addr));
    memcpy (&bgp_4over6_rt_msg.remote_ipv6_address, &nexthop, sizeof (struct in6_addr));

    bgp_4over6_rt_msg.ifindex = ifindex;

    send_4over6_route_to_dpdk (&bgp_4over6_rt_msg, sizeof (struct _bgp_4over6_route_message), 1);
#endif

#if 1
    if (CHECK_FLAG (api.message, ZAPI_MESSAGE_DISTANCE))
        api.distance = stream_getc (s);
    else
        api.distance = 0;

    if (CHECK_FLAG (api.message, ZAPI_MESSAGE_METRIC))
        api.metric = stream_getl (s);
    else
        api.metric = 0;

    zebra_4over6_nexthop_add_check (nexthop, &p);

    if (IN6_IS_ADDR_UNSPECIFIED (&nexthop))
        rib_add_ipv4_4over6 (api.type, api.flags, &p, NULL, ifindex, zebrad.rtm_table_default, api.metric, api.distance, api.safi);
    else
        rib_add_ipv4_4over6 (api.type, api.flags, &p, &nexthop, ifindex, zebrad.rtm_table_default, api.metric, api.distance, api.safi);
#endif
    return 0;
}

int zebra_4over6_tunnel_delete (struct zebra_4over6_tunnel_entry *tnl_info)
{
    struct tunnel_info p;
    memset(&p, 0x00, sizeof(struct tunnel_info));

    memcpy(&p.tunnel_source, &tnl_info->source, sizeof(struct in6_addr));
    memcpy(&p.tunnel_dest, &tnl_info->nexthop, sizeof(struct in6_addr));
    memcpy(&p.ip_prefix, &tnl_info->ip_prefix, sizeof(struct prefix_ipv4));
    p.tunnel_num = tnl_info->tunnel_number;
    TEST_DEBUG("will send del 4over6 route msg to dpdk, tunnel_num:%d.\n", p.tunnel_num);
    send_4over6_static_route_to_dpdk(&p, DEL_TUNNEL);

#if 0
    struct ifreq ifr;
    int socketfd;
    int ret = 0;

    socketfd = socket (AF_INET6, SOCK_DGRAM, 0);
    if (socketfd < 0)
    {
        printf ("socket error\n");
        return -1;
    }

    memcpy (ifr.ifr_name, tunnel_name, IFNAMSIZ);
    ret = ioctl (socketfd, SIOCDELTUNNEL, &ifr);
    if (ret == -1)
    {
        printf ("ioctl error !\n");
        close (socketfd);
        return -1;
    }

    close (socketfd);
#endif
    return CMD_SUCCESS;
}

int zebra_4over6_nexthop_del_check (struct in6_addr nexthop)
{
    struct zebra_4over6_tunnel_entry *pLast;
    struct zebra_4over6_tunnel_entry *pNext;
    int iRetVal = 0;
    int tunnel_number;

    pLast = &zebra4over6TunnelEntry;
    pNext = zebra4over6TunnelEntry.next;
    while (pNext != NULL)
    {
        iRetVal = memcmp (&nexthop, &pNext->nexthop, sizeof (struct in6_addr));
        if (iRetVal == 0)
            break;

        pLast = pNext;
        pNext = pNext->next;
    }
    if (pNext != NULL)
    {
        TEST_DEBUG("pNext->num:%d.\n", pNext->num);
        pNext->num--;
        if (pNext->num == 0)
        {
            zebra_4over6_tunnel_delete (pNext);

            tunnel_number = pNext->tunnel_number;
            TEST_DEBUG("tunnel_number:%d.\n", tunnel_number);
            tnl_number[tunnel_number] = ZEBRA_4OVER6_DISABLE;

            pLast->next = pNext->next;
            XFREE (MTYPE_TUNNEL, pNext);
        }
    }
    return 0;
}

/* Zebra server IPv6 prefix delete function. */
int zread_ipv4_4over6_delete (struct zserv *client, u_short length)
{
    int i;
    struct stream *s;
    struct zapi_ipv6 api;
    struct in6_addr nexthop;
    struct in6_addr local_ipv6_address;	//sangmeng add 160311
    int ifindex;
    struct prefix_ipv4 p;
#if 0
    struct _bgp_4over6_route_message bgp_4over6_rt_msg;
#endif

    s = client->ibuf;
    ifindex = 0;
    memset (&nexthop, 0, sizeof (struct in6_addr));

    /* Type, flags, message. */
    api.type = stream_getc (s);
    api.flags = stream_getc (s);
    api.message = stream_getc (s);
    api.safi = stream_getw (s);

    /* IPv4 prefix. */
    memset (&p, 0, sizeof (struct prefix_ipv4));
    p.family = AF_INET;
    p.prefixlen = stream_getc (s);
    stream_get (&p.prefix, s, PSIZE (p.prefixlen));

    /* Nexthop, ifindex, distance, metric. */
    if (CHECK_FLAG (api.message, ZAPI_MESSAGE_NEXTHOP))
    {
        u_char nexthop_type;

        api.nexthop_num = stream_getc (s);
        for (i = 0; i < api.nexthop_num; i++)
        {
            nexthop_type = stream_getc (s);

            switch (nexthop_type)
            {
            case ZEBRA_NEXTHOP_IPV6:
                stream_get (&nexthop, s, 16);
                break;
            case ZEBRA_NEXTHOP_IFINDEX:
                ifindex = stream_getl (s);
                break;
            }
        }
    }
#if 0
    getIp6Addr (&local_ipv6_address, ifindex);
#endif
    memset (&local_ipv6_address, 0, sizeof (struct in6_addr));
    get_local_ipv6_address (&local_ipv6_address, nexthop, &ifindex);

#if 0
    memset (&bgp_4over6_rt_msg, 0, sizeof (struct _bgp_4over6_route_message));
    memcpy (&bgp_4over6_rt_msg.p, &p, sizeof (struct prefix_ipv4));
    memcpy (&bgp_4over6_rt_msg.local_ipv6_address, &local_ipv6_address, sizeof (struct in6_addr));
    memcpy (&bgp_4over6_rt_msg.remote_ipv6_address, &nexthop, sizeof (struct in6_addr));
    bgp_4over6_rt_msg.ifindex = ifindex;

    send_4over6_route_to_dpdk (&bgp_4over6_rt_msg, sizeof (struct _bgp_4over6_route_message), 0);
#endif

#if 1//sangmeng mark here 20190906
    if (CHECK_FLAG (api.message, ZAPI_MESSAGE_DISTANCE))
        api.distance = stream_getc (s);
    else
        api.distance = 0;
    if (CHECK_FLAG (api.message, ZAPI_MESSAGE_METRIC))
        api.metric = stream_getl (s);
    else
        api.metric = 0;

    zebra_4over6_nexthop_del_check (nexthop);

    if (IN6_IS_ADDR_UNSPECIFIED (&nexthop))
        rib_delete_ipv4_4over6 (api.type, api.flags, (struct prefix_ipv6 *)&p, NULL, ifindex, client->rtm_table, api.safi);
    else
        rib_delete_ipv4_4over6 (api.type, api.flags, (struct prefix_ipv6 *)&p, &nexthop, ifindex, client->rtm_table, api.safi);
#endif
    return 0;
}

/* Install static route into rib. */
static int static_install_ipv4_4over6 (struct prefix *p, struct static_ipv6 *si)
{
    struct rib *rib;
    struct route_node *rn;
    struct route_table *table;

    /* Lookup table.  */
    table = vrf_table (AFI_IP, SAFI_4OVER6, 0);
    if (!table)
        return 0;

    /* Lookup existing route */
    rn = route_node_get (table, p);
    for (rib = rn->info; rib; rib = rib->next)
    {
        if (CHECK_FLAG (rib->status, RIB_ENTRY_REMOVED))
            continue;

        if (rib->type == ZEBRA_ROUTE_STATIC && rib->distance == si->distance)
            break;
    }

    if (rib)
    {
        /* Same distance static route is there.  Update it with new nexthop. */
        route_unlock_node (rn);

        switch (si->type)
        {
        case STATIC_IPV6_GATEWAY:
            nexthop_ipv6_add (rib, &si->ipv6);
            break;
        case STATIC_IPV6_IFNAME:
            nexthop_ifname_add (rib, si->ifname);
            break;
        case STATIC_IPV6_GATEWAY_IFNAME:
            nexthop_ipv6_ifname_add (rib, &si->ipv6, si->ifname);
            break;
        }
        rib_queue_add (&zebrad, rn);
    }
    else
    {
        /* This is new static route. */
        rib = XCALLOC (MTYPE_RIB, sizeof (struct rib));
        rib->type = ZEBRA_ROUTE_STATIC;
        rib->distance = si->distance;
        rib->metric = 0;
        rib->nexthop_num = 0;

        switch (si->type)
        {
        case STATIC_IPV6_GATEWAY:
            nexthop_ipv6_add (rib, &si->ipv6);
            break;
        case STATIC_IPV6_IFNAME:
            nexthop_ifname_add (rib, si->ifname);
            break;
        case STATIC_IPV6_GATEWAY_IFNAME:
            nexthop_ipv6_ifname_add (rib, &si->ipv6, si->ifname);
            break;
        }

        /* Save the flags of this static routes (reject, blackhole) */
        rib->flags = si->flags;

        /* Link this rib to the tree. */
        rib_addnode (rn, rib);
    }

    return 0;
}

static int static_uninstall_ipv4_4over6 (struct prefix *p, struct static_ipv6 *si)
{
    struct route_node *rn;
    struct rib *rib;
    struct nexthop *nexthop;
    struct route_table *table;

    /* Lookup table.  */
    table = vrf_table (AFI_IP, SAFI_4OVER6, 0);
    if (!table)
        return -1;

    /* Lookup existing route with type and distance. */
    rn = route_node_lookup (table, p);
    if (!rn)
        return -1;

    for (rib = rn->info; rib; rib = rib->next)
    {
        if (CHECK_FLAG (rib->status, RIB_ENTRY_REMOVED))
            continue;

        if (rib->type == ZEBRA_ROUTE_STATIC && rib->distance == si->distance)
            break;
    }

    if (!rib)
    {
        route_unlock_node (rn);
        return -1;
    }

    /* Lookup nexthop. */
    for (nexthop = rib->nexthop; nexthop; nexthop = nexthop->next)
    {
        if (static_ipv6_nexthop_same (nexthop, si))
            break;
    }

    /* Can't find nexthop. */
    if (!nexthop)
    {
        route_unlock_node (rn);
        return -1;
    }

    /* Check nexthop. */
    if (rib->nexthop_num == 1)
        rib_delnode (rn, rib);
    else
    {
        if (CHECK_FLAG (nexthop->flags, NEXTHOP_FLAG_FIB))
            rib_uninstall (rn, rib);
        nexthop_delete (rib, nexthop);
        nexthop_free (nexthop);
        rib_queue_add (&zebrad, rn);
    }
    /* Unlock node. */
    route_unlock_node (rn);

    return 0;
}

int static_delete_ipv4_4over6 (struct prefix *p, u_char type, struct in_addr *gate, const char *ifname, u_char distance, u_int32_t vrf_id)
{
    struct route_node *rn;
    struct static_ipv6 *si;
    struct route_table *stable;

    /* Lookup table.  */
    stable = vrf_static_table (AFI_IP, SAFI_4OVER6, vrf_id);
    if (!stable)
        return -1;

    /* Lookup static route prefix. */
    rn = route_node_lookup (stable, p);
    if (!rn)
        return 0;

    /* Find same static route is the tree */
    for (si = rn->info; si; si = si->next)
    {
        if (distance == si->distance && type == si->type && (!gate || IPV6_ADDR_SAME (gate, &si->ipv6)) && (!ifname || strcmp (ifname, si->ifname) == 0))
            break;
    }

    /* Can't find static route. */
    if (!si)
    {
        route_unlock_node (rn);
        return 0;
    }

    /* Install into rib. */
    static_uninstall_ipv4_4over6 (p, si);

    /* Unlink static route from linked list. */
    if (si->prev)
        si->prev->next = si->next;
    else
        rn->info = si->next;
    if (si->next)
        si->next->prev = si->prev;
    route_unlock_node (rn);

    /* Free static route configuration. */
    if (ifname)
        XFREE (0, si->ifname);
    XFREE (MTYPE_STATIC_IPV6, si);

    route_unlock_node (rn);

    return 1;
}

/* Add static route into static route configuration. */
int static_add_ipv4_4over6 (struct prefix *p, u_char type, struct in6_addr *gate, const char *ifname, u_char flags, u_char distance, u_int32_t vrf_id)
{
    struct route_node *rn;
    struct static_ipv6 *si;
    struct static_ipv6 *pp;
    struct static_ipv6 *cp;
    struct static_ipv6 *update = NULL;
    struct route_table *stable;

    /* Lookup table.  */
    stable = vrf_static_table (AFI_IP, SAFI_4OVER6, vrf_id);
    if (!stable)
        return -1;

    if (!gate && (type == STATIC_IPV6_GATEWAY || type == STATIC_IPV6_GATEWAY_IFNAME))
        return -1;

    if (!ifname && (type == STATIC_IPV6_GATEWAY_IFNAME || type == STATIC_IPV6_IFNAME))
        return -1;

    /* Lookup static route prefix. */
    rn = route_node_get (stable, p);

    /* Do nothing if there is a same static route.  */
    for (si = rn->info; si; si = si->next)
    {
        if (type == si->type && (!gate || IPV6_ADDR_SAME (gate, &si->ipv6)) && (!ifname || strcmp (ifname, si->ifname) == 0))
        {
            if (distance == si->distance)
            {
                route_unlock_node (rn);
                return 0;
            }
            else
                update = si;
        }
    }

    /* Distance changed.  */
    if (update)
        static_delete_ipv4_4over6 (p, type, gate, ifname, update->distance, vrf_id);

    /* Make new static route structure. */
    si = XCALLOC (MTYPE_STATIC_IPV6, sizeof (struct static_ipv6));
    si->type = type;
    si->distance = distance;
    si->flags = flags;

    switch (type)
    {
    case STATIC_IPV6_GATEWAY:
        si->ipv6 = *gate;
        break;
    case STATIC_IPV6_IFNAME:
        si->ifname = XSTRDUP (0, ifname);
        break;
    case STATIC_IPV6_GATEWAY_IFNAME:
        si->ipv6 = *gate;
        si->ifname = XSTRDUP (0, ifname);
        break;
    }

    /* Add new static route information to the tree with sort by distance value and gateway address. */
    for (pp = NULL, cp = rn->info; cp; pp = cp, cp = cp->next)
    {
        if (si->distance < cp->distance)
            break;
        if (si->distance > cp->distance)
            continue;
    }

    /* Make linked list. */
    if (pp)
        pp->next = si;
    else
        rn->info = si;
    if (cp)
        cp->prev = si;
    si->prev = pp;
    si->next = cp;

    /* Install into rib. */
    static_install_ipv4_4over6 (p, si);

    return 1;
}
/* RIB update function. */
void rib_update (void)
{
    struct route_node *rn;
    struct route_table *table;

    table = vrf_table (AFI_IP, SAFI_UNICAST, 0);
    if (table)
        for (rn = route_top (table); rn; rn = route_next (rn))
            if (rn->info)
                rib_queue_add (&zebrad, rn);

    table = vrf_table (AFI_IP6, SAFI_UNICAST, 0);
    if (table)
        for (rn = route_top (table); rn; rn = route_next (rn))
            if (rn->info)
                rib_queue_add (&zebrad, rn);
}
/* Remove all routes which comes from non main table.  */
static void rib_weed_table (struct route_table *table)
{
    struct route_node *rn;
    struct rib *rib;
    struct rib *next;

    if (table)
        for (rn = route_top (table); rn; rn = route_next (rn))
            for (rib = rn->info; rib; rib = next)
            {
                next = rib->next;

                if (CHECK_FLAG (rib->status, RIB_ENTRY_REMOVED))
                    continue;

                if (rib->table != zebrad.rtm_table_default && rib->table != RT_TABLE_MAIN)
                    rib_delnode (rn, rib);
            }
}

/* Delete all routes from non main table. */
void rib_weed_tables (void)
{
    rib_weed_table (vrf_table (AFI_IP, SAFI_UNICAST, 0));
    rib_weed_table (vrf_table (AFI_IP6, SAFI_UNICAST, 0));
}
/* Delete self installed routes after zebra is relaunched.  */
static void rib_sweep_table (struct route_table *table)
{
    struct route_node *rn;
    struct rib *rib;
    struct rib *next;
    int ret = 0;

    if (table)
        for (rn = route_top (table); rn; rn = route_next (rn))
            for (rib = rn->info; rib; rib = next)
            {
                next = rib->next;

                if (CHECK_FLAG (rib->status, RIB_ENTRY_REMOVED))
                    continue;

                if (rib->type == ZEBRA_ROUTE_KERNEL && CHECK_FLAG (rib->flags, ZEBRA_FLAG_SELFROUTE))
                {
                    ret = rib_uninstall_kernel (rn, rib);
                    if (!ret)
                        rib_delnode (rn, rib);
                }
            }
}

/* Sweep all RIB tables.  */
void rib_sweep_route (void)
{
    rib_sweep_table (vrf_table (AFI_IP, SAFI_UNICAST, 0));
    rib_sweep_table (vrf_table (AFI_IP6, SAFI_UNICAST, 0));
}

/* Remove specific by protocol routes from 'table'. */
static unsigned long rib_score_proto_table (u_char proto, struct route_table *table)
{
    struct route_node *rn;
    struct rib *rib;
    struct rib *next;
    unsigned long n = 0;

    if (table)
        for (rn = route_top (table); rn; rn = route_next (rn))
            for (rib = rn->info; rib; rib = next)
            {
                next = rib->next;
                if (CHECK_FLAG (rib->status, RIB_ENTRY_REMOVED))
                    continue;
                if (rib->type == proto)
                {
                    rib_delnode (rn, rib);
                    n++;
                }
            }

    return n;
}

/* Remove specific by protocol routes. */
unsigned long rib_score_proto (u_char proto)
{
    return rib_score_proto_table (proto, vrf_table (AFI_IP, SAFI_UNICAST, 0)) + rib_score_proto_table (proto, vrf_table (AFI_IP6, SAFI_UNICAST, 0));
}

/* Close RIB and clean up kernel routes. */
static void rib_close_table (struct route_table *table)
{
    struct route_node *rn;
    struct rib *rib;

    if (table)
        for (rn = route_top (table); rn; rn = route_next (rn))
            for (rib = rn->info; rib; rib = rib->next)
            {
                if (!RIB_SYSTEM_ROUTE (rib) && CHECK_FLAG (rib->flags, ZEBRA_FLAG_SELECTED))
                    rib_uninstall_kernel (rn, rib);
            }
}

/* Close all RIB tables.  */
void rib_close (void)
{
    rib_close_table (vrf_table (AFI_IP, SAFI_UNICAST, 0));
    rib_close_table (vrf_table (AFI_IP6, SAFI_UNICAST, 0));
}
/* Routing information base initialize. */
void rib_init (void)
{
    rib_queue_init (&zebrad);
    /* VRF initialization.  */
    vrf_init ();
}
