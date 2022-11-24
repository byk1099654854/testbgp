#ifndef _ZEBRA_FLOWENGINE_H
#define _ZEBRA_FLOWENGINE_H

#include "sockunion.h"
#include "prefix.h"
#include "table.h"
#include "if.h"
typedef uint8_t   u8_t;
struct sectionengine_node
{
    char sectionenginename[20];
    int prefixnum;
    struct prefix v6prefix[6];
    unsigned char isused;
};

struct sectionengine_table
{
    struct sectionengine_table *next;
    struct sectionengine_table *prev;
    struct sectionengine_node sectionengine;

};

extern struct sectionengine_table *sectionengine_table_head;

struct processing_engine_table_node
{
    char processingenginename[20];
    int memoryvalue;
    int bandwidthvalue;
    int type; // 1:ivi 2:nat64 3:4over6 4:FW
    char rt_name[20];
    unsigned char isused;
    struct route_table *routetable;

};
struct processing_engine_table
{
    struct processing_engine_table *next;
    struct processing_engine_table *prev;
    struct processing_engine_table_node processingengine;

};


extern struct processing_engine_table *processingengine_table_head;


struct flow_engine_table_node
{
    char flowenginename[20];
    //char processingenginename[20];
    struct processing_engine_table *processingenginename;
    //char sectionenginename[20];
    struct sectionengine_table *sectionenginename;
    unsigned char client_id;

};
struct flow_engine_table
{
    struct flow_engine_table *next;
    struct flow_engine_table *prev;
    struct flow_engine_table_node flowengine;

};


struct flow_engine_table *flowengine_table_head;

struct processingengine_info
{
    int memory;
    int bandwidth;
    unsigned char type;
    char rtname[32];
    unsigned char id;

};

//sangmeng mark here
struct acl_route_node
{
    uint8_t status;
    struct prefix s_prefix;
    struct prefix prefix;
    uint8_t gateway[16];
    struct interface *ifp;
};
struct acl_route_table
{
    struct acl_route_table *next;
    struct acl_route_table *prev;
    struct acl_route_node node;

};

struct acl_route_table *acl_route_table_head;

struct real_ipv6_source_address
{

    uint8_t typeOfprotocol;
    struct prefix source_addr_prefix;
    struct prefix destination_addr_prefix;
    char ifname[20];

    uint8_t type;//deny:0 permit:1

};

struct real_ipv6_source_address_link
{
    struct real_ipv6_source_address_link *prev;
    struct real_ipv6_source_address_link *next;
    struct real_ipv6_source_address node;

};

struct real_ipv6_source_address_link *real_ipv6_source_address_link_head;

extern unsigned char client_id[5];


struct header_compression_node
{

    struct prefix prefix;
};
struct header_compression_table
{
    struct header_compression_table *next;
    struct header_compression_table *prev;
    struct header_compression_node node;

};


struct header_compression_table *header_compression_table_head;



#endif /* _ZEBRA_FLOWENGINE_H */

