typedef struct neighbor_node
{
    int reboot_flag;
    char *neighbor_str;
    struct neighbor_node *next;

} neighbor_node;

extern neighbor_node *neighbor_head_node;

extern void neighbor_linklist_create();
extern void neighbor_linklist_insert(char *neighbor_str);
extern void neighbor_linklist_search(char *neighbor_str);
extern void neighbor_linklist_setflag(char *neighbor_str);

