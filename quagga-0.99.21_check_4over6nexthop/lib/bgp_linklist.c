#include<stdio.h>
#include<errno.h>

typedef struct neighbor_node
{
    int reboot_flag;
    char *neighbor_str;
    struct neighbor_node *next;
} neighbor_node;

neighbor_node *neighbor_head_node = NULL;

void neighbor_linklist_create()
{
    if(!(neighbor_head_node = (neighbor_node *)malloc(sizeof(neighbor_node))))
        perror("malloc");
    neighbor_head_node->neighbor_str = NULL;
    neighbor_head_node->next = NULL;
}
void neighbor_linklist_insert(char *neighbor_str)
{
    zlog_debug("neighbor linklist_insert");
    neighbor_node *neighbor_node_pointer1 = neighbor_head_node->next;
    neighbor_node *neighbor_node_pointer2 = NULL;
    while(neighbor_node_pointer1)
    {
        if(!strcmp(neighbor_node_pointer1->neighbor_str,neighbor_str))
            return 1;

        neighbor_node_pointer1 = neighbor_node_pointer1->next;
    }
    if(!(neighbor_node_pointer2 = (neighbor_node *)malloc(sizeof(neighbor_node))))
        perror("malloc");
    neighbor_node_pointer2->reboot_flag = 1;

    if(!(neighbor_node_pointer2->neighbor_str = (neighbor_node *)malloc(strlen(neighbor_str) + 1)))
        perror("malloc");
    strncpy(neighbor_node_pointer2->neighbor_str,neighbor_str,strlen(neighbor_str) + 1);

    neighbor_node_pointer2->next = neighbor_head_node->next;
    neighbor_head_node->next = neighbor_node_pointer2;
}

int neighbor_linklist_search(char *neighbor_str)
{
    zlog_debug("neighbor_linklist_search");
    zlog_debug("nei is %s",neighbor_str);
    neighbor_node *neighbor_node_pointer = neighbor_head_node->next;

    while(neighbor_node_pointer)
    {
        if(!strcmp(neighbor_node_pointer->neighbor_str,neighbor_str)
                && neighbor_node_pointer->reboot_flag == 1)
            return 1;

        neighbor_node_pointer = neighbor_node_pointer->next;
    }
    return 0;
}

void neighbor_linklist_setflag(char *neighbor_str)
{
    neighbor_node *neighbor_node_pointer = neighbor_head_node->next;

    while(neighbor_node_pointer)
    {
        if(!strcmp(neighbor_node_pointer->neighbor_str,neighbor_str)
                && neighbor_node_pointer->reboot_flag == 1)
        {
            neighbor_node_pointer->reboot_flag = 0;
            return;
        }
        neighbor_node_pointer = neighbor_node_pointer->next;
    }
}
