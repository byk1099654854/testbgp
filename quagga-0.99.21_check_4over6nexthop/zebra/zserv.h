/* Zebra daemon server header.
 * Copyright (C) 1997, 98 Kunihiro Ishiguro
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

#ifndef _ZEBRA_ZSERV_H
#define _ZEBRA_ZSERV_H

#include "rib.h"
#include "if.h"
#include "workqueue.h"

/* Default port information. */
#define ZEBRA_VTY_PORT                2601
#define JUN_ADD //zhangqingjun


#ifdef JUN_ADD
#define ADD_OSPF6_ACL 36
#define DEL_OSPF6_ACL 37
#endif

#define g_debug 1
#define TEST_DEBUG(format,...) if(g_debug) { printf("%s %s @%d: "format, __FILE__, __func__, __LINE__, ##__VA_ARGS__);}

/* Default configuration filename. */
#define DEFAULT_CONFIG_FILE "zebra.conf"

/*add tdyth */
#if 1
#define IVI_INET_ADDRESS	"127.0.0.1"
#define IVI_INET_PORT		10032
struct ivi_message
{

    unsigned int type;
    unsigned int len;
    void *data;
};


#define  ospf_acl_message ivi_message
typedef union _ospf6_acl_addr
{
    unsigned char b_addr[16];
    unsigned short w_addr[8];
    unsigned int d_addr[4];
} ospf6_acl_addr;
struct ospf6_acl_message
{
    ospf6_acl_addr src_addr;
    ospf6_acl_addr dst_addr;
    unsigned int src_len;
    unsigned int dst_len;
    unsigned int fwd;
};
#define ROUT_DEBUG 1
#define   ROUT_CTRL_MSG   3
#define ARMY_TYPE 0x00
#define PEOPLE_TYPE 0x01
#define IN_AREA  1 << 1
#define OUT_AREA  0 << 1

/* Duplex, half or full. */
#define DUPLEX_UN       1<<1
#define DUPLEX_HALF     1<<2
#define DUPLEX_FULL     1<<3

#define SPEED_UN        1<<4
#define SPEED_10        1<<5
#define SPEED_100   1<<6
#define SPEED_1000      1<<7

#define _5U_DEVICE 0 //1 :5U 0:2u

/* Client structure. */
#define LOCAL_ADDRESS "127.0.0.1"
#define LOCAL_PORT 2016



struct dmesion2_ctrl_msg
{
    struct in6_addr src_prefix;
    unsigned char src_prefixlen;
    struct in6_addr dst_prefix;
    unsigned char dst_prefixlen;
    struct in6_addr next_hop;
    int ifindex;
};
struct tlv_flow
{
    unsigned char type;
    int length;
    char data[0];
};


struct msg_head
{
    char chrType;
    unsigned short len;
    char data[0];
} __attribute__((packed));

struct prefix_msg
{
    struct in6_addr prefix;
    unsigned char prefixlen;
};

#endif
/*add end*/
/* Client structure. */
struct zserv
{
    /* Client file descriptor. */
    int sock;

    /* Input/output buffer to the client. */
    struct stream *ibuf;
    struct stream *obuf;

    /* Buffer of data waiting to be written to client. */
    struct buffer *wb;

    /* Threads for read/write. */
    struct thread *t_read;
    struct thread *t_write;

    /* Thread for delayed close. */
    struct thread *t_suicide;

    /* default routing table this client munges */
    int rtm_table;

    /* This client's redistribute flag. */
    u_char redist[ZEBRA_ROUTE_MAX];

    /* Redistribute default route flag. */
    u_char redist_default;

    /* Interface information. */
    u_char ifinfo;

    /* Router-id information. */
    u_char ridinfo;
};
/*add by ccc for ivi*/
#define DPDK_SERVER_ADDRESS	"127.0.0.1"
#define DPDK_SERVER_PORT		10032
/*ivi_message type*/
#define ADD_IVI_PREFIX	1
#define DEL_IVI_PREFIX	2
#define ADD_IVI_POOL	3
#define DEL_IVI_POOL	4
#define ADD_TUNNEL		5
#define DEL_TUNNEL		6
#define ADD_TUNNEL_SRC	7
#define DEL_TUNNEL_SRC	8
#define ADD_TUNNEL_DST	9
#define DEL_TUNNEL_DEST	10
#define ADD_TUNNEL_IP	11
#define DEL_TUNNEL_IP	12
#define ADD_NAT64_POOL	13
#define DEL_NAT64_POOL	14
#define ADD_NAT64_PREFIX 15
#define DEL_NAT64_PREFIX 16
#define ADD_NAT64_TIMEOUT 17
#define DEL_NAT64_TIMEOUT 18
/*nat timeout */
#define NAT_TIMEOUT_TCP  19
#define NAT_TIMEOUT_UDP  20
#define NAT_TIMEOUT_ICMP 21
//sangmeng add
#define REQUEST_L3FWD_MIB 22
#define REQUEST_KNI_MIB 23
#define RESPONSE_L3FWD_MIB 24
#define RESPONSE_L3FWD_MIB_VPORT 43
#define RESPONSE_KNI_MIB 25


#define REQUEST_V4_ROUTE_TABLE 26
#define REQUEST_V6_ROUTE_TABLE 27
#define REQUEST_V4_ARP_TABLE 28
#define REQUEST_V6_ND_TABLE 29

#define RESPONSE_V4_ROUTE_TABLE 30
#define RESPONSE_V6_ROUTE_TABLE 31
#define RESPONSE_V4_ARP_TABLE 32
#define RESPONSE_V6_ND_TABLE 33

#define REQUEST_CLEAR_L3FWD_MIB 34
#define REQUEST_CLEAR_KNI_MIB 35

#define ADD_4OVER6_ROUTE 36
#define DEL_4OVER6_ROUTE 37
#define REQUEST_BGP_4OVER6_ROUTE 38
#define RESPONSE_BGP_4OVER6_ROUTE 39
#define RESPONSE_ADD_BGP_4OVER6_ROUTE 40
#define REQUEST_DEBUG  41
#define REQUEST_NODEBUG 42
#define ADD_CUSTOMIZE_IPV4_ROUTE  0x2B
#define ADD_CUSTOMIZE_IPV6_ROUTE  0x2C
#define REQUEST_CUSTOMIZE_ROUTE 0x2D

#define TRAFFIC_ENGINE_ADD      0x2E
#define TRAFFIC_ENGINE_DEL      0x2F
#define POLICY_BASED_ROUTE_ENGINE_ADD      0x30
#define POLICY_BASED_ROUTE_ENGINE_DEL      0x31

#define REAL_IPV6_SOURCE_ADDR_ADD      0x32
#define REAL_IPV6_SOURCE_ADDR_DEL      0x33


#define REQUEST_V6_ACL_TABLE 0x34

#define SOLDIER_PEOPLE_TRAFFIC_CONFIG_INFO 0x40
#define REQUSET_SOLDIER_PEOPLR_TRAFFIC_MIB 0x42
#define RESPONSE_SOLDIER_PEOPLR_TRAFFIC_MIB 0x43
#define REQUEST_CLEAR_SOLDIER_PEOPLR_TRAFFIC_MIB 0x44
#define RESPONSE_INTERFACE_STATUS 0x45
#define SHOW_ROUTE_FROM_LPM 0x46

#define MESSAGE_END 328
/*ivi_message flag*/
#define UBIT	1
#define NO_UBIT	2
struct comm_head
{
    unsigned int type;	//message type
    unsigned int len;
    char data[0];
} __attribute__((packed));

struct _ipv4overipv6_address_pool
{
    uint8_t used;
    uint32_t ipv4overipv6_address_prefix;
    uint16_t ipv4overipv6_address_len;
    uint8_t ipv4overipv6_tunnel_src_addr[16];
    uint8_t ipv4overipv6_tunnel_dst_addr[16];
    uint8_t gateway[16];
};


struct route_info
{
    int af;
    uint8_t forward;
    uint8_t tnl_num;
    union
    {
        u_int dstAddr;
        uint8_t dstAddr6[16];
    } u_dstAddr;

    int dstLen;
    union
    {
        u_int gateWay;
        uint8_t gateWay6[16];
    } u_gateway;
    char ifName[IF_NAMESIZE];

#define ipv4_route_dstaddr u_dstAddr.dstAddr
#define ipv6_route_dstaddr u_dstAddr.dstAddr6

#define ipv4_route_gateway u_gateway.gateWay
#define ipv6_route_gateway u_gateway.gateWay6

};


#define ETHER_ADDR_LEN 6
struct arp_info
{
    int af;
    union
    {
        u_int dstAddr;
        uint8_t dstAddr6[16];
    } u_dstAddr;
    unsigned char lladdr[ETHER_ADDR_LEN];
    //u_int if_out;
    char ifName[IF_NAMESIZE];
    time_t upTime;
#define ipv4_arp_dstaddr u_dstAddr.dstAddr
#define ipv6_nd_dstaddr u_dstAddr.dstAddr6

};



/*
*Structure of l3fwd port traffic
*/
struct l3fwd_interface_statistics
{

    uint8_t portid;
    uint64_t rx_packets;
    uint64_t tx_packets;
    //uint64_t dropped;
    uint64_t rx_dropped;
    uint64_t tx_dropped;

    uint64_t rx_packets_ipv4; //rx ipv4 packet
    uint64_t rx_packets_arp; //rx ipv4 packet
    uint64_t tx_packets_ipv4;//tx ipv4 packet
    uint64_t tx_packets_arp;//tx ipv4 packet
    uint64_t dropped_ipv4; //dropped ipv4 packet
    uint64_t rx_dropped_arp; //dropped ipv4 packet
    uint64_t tx_dropped_arp; //dropped ipv4 packet
    uint64_t rx_packets_ipv6; //rx ipv6 packet
    uint64_t tx_packets_ipv6;//tx ipv6 packet
    uint64_t dropped_ipv6;//dropped ipv6 packet

    uint64_t rx_packets_other;
    uint64_t tx_packets_other;
    uint64_t dropped_other;

    //octets
    uint64_t rx_packets_octets;
    uint64_t tx_packets_octets;
    uint64_t dropped_octets;


    uint64_t packets_no_mac_up; //can't find mac and up
    uint64_t packets_no_mac_dropped; //can't find mac and dropped
    uint64_t packets_no_route_dropped; //can't find dst port

    /*ivi*/
    uint64_t rx_packets_ivi4;
    uint64_t tx_packets_ivi4;
    uint64_t dropped_ivi4;

    uint64_t rx_packets_ivi6;
    uint64_t tx_packets_ivi6;
    uint64_t dropped_ivi6;

    /*4over6*/
    uint64_t rx_packets_4over6_encap;
    uint64_t tx_packets_4over6_encap;
    uint64_t dropped_4over6_encap;

    uint64_t rx_packets_4over6_decap;
    uint64_t tx_packets_4over6_decap;
    uint64_t dropped_4over6_decap;

    /*nat64*/
    uint64_t rx_packets_nat4;
    uint64_t tx_packets_nat4;
    uint64_t dropped_nat4;

    uint64_t rx_packets_nat6;
    uint64_t tx_packets_nat6;
    uint64_t dropped_nat6;

#if 1 //hbl add 20180907 /*ipv6 and ipv4 rx/tx  packet stats*/
    uint64_t rx_packets_octets_ipv4;
    uint64_t tx_packets_octets_ipv4;
    uint64_t rx_packets_octets_ipv6;
    uint64_t tx_packets_octets_ipv6;
#endif

};


struct l3fwd_interface_statistics l3fwd_stats[16];
struct l3fwd_interface_statistics vport_stats[20];

#if 0
struct veth_port_statistics
{
    uint8_t portid;
    char name[32];
    uint64_t fw_packets;
    uint64_t fw_packets_octets;
    uint64_t fw_packets_ipv4;
    uint64_t fw_packets_ipv6;
};
struct veth_port_statistics vport_stats[20];
#endif

/* Structure type for recording kni interface specific stats */
struct kni_interface_stats
{
    uint8_t portid;
    /* number of pkts received from NIC, and sent to KNI */
    uint64_t rx_packets;

    /* number of pkts received from NIC, but failed to send to KNI */
    uint64_t rx_dropped;

    /* number of pkts received from KNI, and sent to NIC */
    uint64_t tx_packets;

    /* number of pkts received from KNI, but failed to send to NIC */
    uint64_t tx_dropped;

    /* number of pkts received from NIC, and sent to KNI */
    uint64_t rx_packets_ipv4;

    /* number of pkts received from NIC, but failed to send to KNI */
    uint64_t rx_dropped_ipv4;

    /* number of pkts received from KNI, and sent to NIC */
    uint64_t tx_packets_ipv4;

    /* number of pkts received from KNI, but failed to send to NIC */
    uint64_t tx_dropped_ipv4;


    /* number of pkts received from NIC, and sent to KNI */
    uint64_t rx_packets_ipv6;

    /* number of pkts received from NIC, but failed to send to KNI */
    uint64_t rx_dropped_ipv6;

    /* number of pkts received from KNI, and sent to NIC */
    uint64_t tx_packets_ipv6;

    /* number of pkts received from KNI, but failed to send to NIC */
    uint64_t tx_dropped_ipv6;

    uint64_t rx_packets_arp;
    uint64_t rx_dropped_arp;

    uint64_t tx_packets_arp;
    uint64_t tx_dropped_arp;
    uint64_t rx_packets_other;
    uint64_t rx_dropped_other;

    uint64_t tx_packets_other;
    uint64_t tx_dropped_other;

    //octets
    uint64_t rx_packets_octets;
    uint64_t tx_packets_octets;
    uint64_t dropped_octets;

#if 1 //hbl add 20180907 /*ipv6 and ipv4 rx/tx  packet stats*/
    uint64_t rx_packets_octets_ipv4;
    uint64_t tx_packets_octets_ipv4;
    uint64_t rx_packets_octets_ipv6;
    uint64_t tx_packets_octets_ipv6;
#endif

};
/* kni device statistics array */
//struct kni_interface_stats kni_stats[16];
struct kni_interface_stats kni_stats[20];

typedef struct people_traffic
{
    uint8_t portid;
    uint64_t rx_packets;
    uint64_t rx_packets_octets;
    uint64_t rx_packets_tag;
    uint64_t rx_packets_drop;
    uint64_t tx_packets;
    uint64_t tx_packets_octets;
    uint64_t tx_packets_tag;
    uint64_t tx_packets_drop;
} people_traffic;
people_traffic people_traffic_statistics[20];

struct zebra_config_message
{
    unsigned int type;	//message type
    unsigned int len;	//messgae size
    void *data;		//message data
};
struct _bgp_4over6_route_message
{
    unsigned long ifindex;
    struct in6_addr local_ipv6_address;
    struct in6_addr remote_ipv6_address;
    struct prefix_ipv4 p;
};

struct ivi_prefix_message
{
    int flag;
    struct prefix_ipv6 prefix6;
};
struct ivi_pool_message
{
    struct prefix_ipv4 prefix4;
};
struct ivi_prefix_message *ivi_prefix_head;
struct ivi_pool_message *ivi_pool_head;
//for NAT64
struct nat_prefix_message
{
    int flag;
    struct prefix_ipv6 prefix6;
};
struct nat_pool_message
{
    struct prefix_ipv4 prefix4;
};
struct nat_timeout_message
{
    int nat_timeout;
    unsigned int nat_timeout_tcp;
    unsigned int nat_timeout_udp;
    unsigned int nat_timeout_icmp;
};
struct nat_prefix_message *nat_prefix_head;
struct nat_pool_message *nat_pool_head;
struct nat_timeout_message *nat_timeout_head;
//for tunnle
struct tunnel_info	//tunnel
{
    unsigned int tunnel_num;		//size 0-32
    //unsigned int used;
    struct in6_addr tunnel_source;	//tunnel_source address
    struct in6_addr tunnel_dest;	//tunnel_dest address
    struct prefix_ipv4 ip_prefix;	//ipv4_prefix

    struct tunnel_info * tunnel_next;
};
struct tunnel_info *tunnel_head;	//tunnel head

////add end/*add by  for ivi*/
//sangmeng add for openflow route info 20180705
#define NAMESIZE 32
struct ipv4_route_customize
{
    char type;
    char routetablename[NAMESIZE];
    struct prefix_ipv4 p;
    struct in_addr gate;
    unsigned int ifindex;
    char action;
};
struct ipv6_route_customize
{
    char type;
    char routetablename[NAMESIZE];
    struct prefix_ipv6 p;
    struct in6_addr gate;
    unsigned int ifindex;
    char action;
};

/*end add*/
/* Zebra instance */
struct zebra_t
{
    /* Thread master */
    struct thread_master *master;
    struct list *client_list;

    /* default table */
    int rtm_table_default;

    /* rib work queue */
    struct work_queue *ribq;
    struct meta_queue *mq;
};

//added for 4over6 20130305
//#define TUNNELNUMBER 4096
#define TUNNELNUMBER 32
#define ZEBRA_4OVER6_ENABLE		1
#define ZEBRA_4OVER6_DISABLE	0

//#define	IFNAMSIZ	16
struct zebra_4over6_tunnel_entry
{
    char name[IFNAMSIZ];	    /* name of tunnel device */
    struct prefix_ipv4 ip_prefix; //ipv4_prefix
    struct in6_addr source;	/* the source */
    struct in6_addr nexthop;	/* the nexthop	*/
    int num;
    int state;
    char tunnel_number;
    struct zebra_4over6_tunnel_entry *next;
};

//added for nat 20130507
#define	NATSIZE	20
#define	CMDSTR	200
#define	POOLSTR	200
#define NAT_ENABLE 1
#define NAT_DISABLE 0


struct nat_pool_entry
{
    char name[NATSIZE];
    char startaddr[NATSIZE];
    struct in_addr start_addr;
    char endaddr[NATSIZE];
    struct in_addr end_addr;
    char poolcmdstr[POOLSTR];

    struct nat_pool_entry *next;
};

struct nat_source_list
{
    char name[NATSIZE];
    char snet[NATSIZE];
    struct in_addr source_addr;
    int masklen;

    struct nat_source_list *next;
};

struct nat_source_list_pool_entry
{
    int pool_state;
    int list_state;

    struct nat_pool_entry pool;
    struct nat_source_list source;

    struct nat_source_list_pool_entry *next;
};


//add by wjh for flowengine
struct flowengine_info
{
    char flowenginename[20];
    unsigned char num;
    struct prefix prefix;
    int memory;
    int bandwidth;
    unsigned char type;
    char rtname[32];
    unsigned id;

};


//add by limingyuan 2013.8.16 for snmp
struct config_cmd_string
{
    char *config_string;
    struct config_cmd_string *next;
    struct config_cmd_string *tail;
};
extern void free_snmp_config_string();

/* Count prefix size from mask length */
#define PSIZE(a) (((a) + 7) / (8))

#if 1
//add by ccc for flow separation
#ifndef __FLOW_SEPARATION_BY_PEOPLE_AND_SOLDIER__
#define __FLOW_SEPARATION_BY_PEOPLE_AND_SOLDIER__
#define INTEGRATION 0
#define PEOPLE 1

#define FLOW_ADD 1
#define FLOW_DEL 2

struct inter_in_area
{
    char ifname[16];
    char area_value;
    struct inter_in_area *next;
};
#endif
#endif

/* Prototypes. */
extern void zebra_init (void);
extern void zebra_if_init (void);
extern void zebra_zserv_socket_init (char *path);
extern void openflow_zserv_socket_init (char *path);
extern void hostinfo_get (void);
extern void rib_init (void);
extern void interface_list (void);
extern void kernel_init (void);
extern void route_read (void);
extern void zebra_route_map_init (void);
extern void zebra_snmp_init (void);
extern void zebra_vty_init (void);

extern int zsend_interface_add (struct zserv *, struct interface *);
extern int zsend_interface_delete (struct zserv *, struct interface *);
extern int zsend_interface_address (int, struct zserv *, struct interface *,
                                    struct connected *);
extern int zsend_interface_update (int, struct zserv *, struct interface *);
extern int zsend_route_multipath (int, struct zserv *, struct prefix *,
                                  struct rib *);
extern int zsend_router_id_update(struct zserv *, struct prefix *);

extern pid_t pid;

int connect_dpdk_send_message (struct zebra_config_message *p_zebra_msg, int size);
#endif /* _ZEBRA_ZEBRA_H */
