/*
 * Copyright (C) 1999-2003 Yasuhiro Ohara
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

#ifndef OSPF6_MESSAGE_H
#define OSPF6_MESSAGE_H

#include "../zebra/zserv.h"
#include "ospf6_interface.h"
/******************************
*wlk define for statel lite
*******************************/
#define PORT "1949"
#define LOCALPORT "1950"
#define BUFSIZE 8192
#define IPV6_MAX 64
struct statellite_msg
{
    unsigned short stl_num;
    float start_time;
    float end_time;
    float connection_period;
} __attribute__((packed));
struct statellite_period
{
    unsigned short stl_num;
    float circle_period;
    char fe80[IPV6_MAX];
} __attribute__((packed));
/*********end wlk*********/
/******************************
*sangmeng define for statellite
*******************************/
#define DEBUG_M
#if defined(DEBUG_M)
#define DG(a, b...) printf("[%s][%s][%d]"a, __FILE__, __func__, __LINE__, ##b)
#else
#define DG(a, b...)
#endif

#define LOCAL_ADDRESS_OSPF  "127.0.0.1"
#define LOCAL_PORT_OSPF     2017
#define BACKLOG 10
//sangmeng define
//#define OSPF6_DEBUG

#define s_assert(x) { \
     if(!(x))  {err = -__LINE__;goto error;} \
}
#if 0
struct comm_head_tmp
{
    unsigned short len;
    char data[0];
};
struct msg_head
{
    char chrType;
    unsigned short len;
    char data[0];
};
#endif

struct statellite_msg_all
{
    unsigned short stl_num;
    struct in6_addr neighbor_ipv6_address; /**< neighbor ipv6 address */
    float start_time; /**< connection start time */
    float end_time;/**< connection edn time */
    float connection_period;/**< connection period */
    float circle_period;/**< circle period*/
};

typedef struct statellite_predict_list
{
    struct statellite_msg_all stl_msg_all;
    struct statellite_predict_list *next;
} stl_link_node, *stl_link_list;

extern stl_link_list stl_link_head;

/******sangmeng define end*****/

#define OSPF6_MESSAGE_BUFSIZ  4096

/* Debug option */
extern unsigned char conf_debug_ospf6_message[];
#define OSPF6_DEBUG_MESSAGE_SEND 0x01
#define OSPF6_DEBUG_MESSAGE_RECV 0x02
#define OSPF6_DEBUG_MESSAGE_ON(type, level) \
  (conf_debug_ospf6_message[type] |= (level))
#define OSPF6_DEBUG_MESSAGE_OFF(type, level) \
  (conf_debug_ospf6_message[type] &= ~(level))
#define IS_OSPF6_DEBUG_MESSAGE(t, e) \
  (conf_debug_ospf6_message[t] & OSPF6_DEBUG_MESSAGE_ ## e)

/* Type */
#define OSPF6_MESSAGE_TYPE_UNKNOWN  0x0
#define OSPF6_MESSAGE_TYPE_HELLO    0x1  /* Discover/maintain neighbors */
#define OSPF6_MESSAGE_TYPE_DBDESC   0x2  /* Summarize database contents */
#define OSPF6_MESSAGE_TYPE_LSREQ    0x3  /* Database download request */
#define OSPF6_MESSAGE_TYPE_LSUPDATE 0x4  /* Database update */
#define OSPF6_MESSAGE_TYPE_LSACK    0x5  /* Flooding acknowledgment */
#define OSPF6_MESSAGE_TYPE_ALL      0x6  /* For debug option */

/* OSPFv3 packet header */
#define OSPF6_HEADER_SIZE                     16U
struct ospf6_header
{
    u_char    version;
    u_char    type;
    u_int16_t length;
    u_int32_t router_id;
    u_int32_t area_id;
    u_int16_t checksum;
    u_char    instance_id;
    u_char    reserved;
};

#define OSPF6_MESSAGE_END(H) ((caddr_t) (H) + ntohs ((H)->length))

/* Hello */
#define OSPF6_HELLO_MIN_SIZE                  20U
struct ospf6_hello
{
    u_int32_t interface_id;
    u_char    priority;
    u_char    options[3];
    u_int16_t hello_interval;
    u_int16_t dead_interval;
    u_int32_t drouter;
    u_int32_t bdrouter;
    /* Followed by Router-IDs */
};

/* Database Description */
#define OSPF6_DB_DESC_MIN_SIZE                12U
struct ospf6_dbdesc
{
    u_char    reserved1;
    u_char    options[3];
    u_int16_t ifmtu;
    u_char    reserved2;
    u_char    bits;
    u_int32_t seqnum;
    /* Followed by LSA Headers */
};

#define OSPF6_DBDESC_MSBIT (0x01) /* master/slave bit */
#define OSPF6_DBDESC_MBIT  (0x02) /* more bit */
#define OSPF6_DBDESC_IBIT  (0x04) /* initial bit */

/* Link State Request */
#define OSPF6_LS_REQ_MIN_SIZE                  0U
/* It is just a sequence of entries below */
#define OSPF6_LSREQ_LSDESC_FIX_SIZE           12U
struct ospf6_lsreq_entry
{
    u_int16_t reserved;     /* Must Be Zero */
    u_int16_t type;         /* LS type */
    u_int32_t id;           /* Link State ID */
    u_int32_t adv_router;   /* Advertising Router */
};

/* Link State Update */
#define OSPF6_LS_UPD_MIN_SIZE                  4U
struct ospf6_lsupdate
{
    u_int32_t lsa_number;
    /* Followed by LSAs */
};

/* Link State Acknowledgement */
#define OSPF6_LS_ACK_MIN_SIZE                  0U
/* It is just a sequence of LSA Headers */

/* Function definition */
extern void ospf6_hello_print (struct ospf6_header *);
extern void ospf6_dbdesc_print (struct ospf6_header *);
extern void ospf6_lsreq_print (struct ospf6_header *);
extern void ospf6_lsupdate_print (struct ospf6_header *);
extern void ospf6_lsack_print (struct ospf6_header *);

extern int ospf6_iobuf_size (unsigned int size);
extern void ospf6_message_terminate (void);
extern int ospf6_receive (struct thread *thread);

extern int ospf6_hello_send (struct thread *thread);
extern int ospf6_dbdesc_send (struct thread *thread);
extern int ospf6_dbdesc_send_newone (struct thread *thread);
extern int ospf6_dbdesc_send_new_lsas_list(struct thread *thread);
extern int ospf6_lsreq_send (struct thread *thread);
extern int ospf6_lsupdate_send_interface (struct thread *thread);
extern int ospf6_lsupdate_send_neighbor (struct thread *thread);
extern int ospf6_lsack_send_interface (struct thread *thread);
extern int ospf6_lsack_send_neighbor (struct thread *thread);

extern int config_write_ospf6_debug_message (struct vty *);
extern void install_element_ospf6_debug_message (void);
//sangmeng OSPF+
extern int ospf6_check_lsa_maxage_prefix (struct ospf6_interface *oi, struct ospf6_lsa *lsa);
extern int ospf6_print_lsa_header_type(struct ospf6_lsa_header *lsah);

#endif /* OSPF6_MESSAGE_H */

