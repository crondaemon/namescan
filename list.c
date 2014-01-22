
#include <list.h>

#include <stdlib.h>
#include <log.h>

fragnode_t* fragnode_create(uint16_t ipid, size_t size)
{
	fragnode_t* elem;

	elem = (fragnode_t*)malloc(sizeof(fragnode_t));
	if (elem == NULL) {
		LOG_ERROR("Can't create fragnode");
		return NULL;
	}
	
	elem->ipid = ipid;
	elem->size = size;
	
	return elem;
}

void fragnode_delete(fragnode_t** head, fragnode_t* fragnode)
{
    fragnode_t* cur;
    fragnode_t* d;
    if (*head == fragnode) {
        cur = *head;
        *head = cur->next;
        free(cur);
        return;
    }
    
    cur = *head;
    while(cur->next != NULL) {
        if (cur->next->ipid == fragnode->ipid && cur->next->size == fragnode->size) {
            d = cur->next;
            cur->next = cur->next->next;
            free(d);
            return;
        }
    }
    
    // not found...
    LOG_ERROR("Element not found");       
}

fragnode_t* fragnode_update(fragnode_t** head, uint16_t ipid, size_t size)
{
    fragnode_t* cur;
    
    if (*head == NULL) {
        *head = fragnode_create(ipid, size);
        return *head;
    }
    
    cur = *head;
    while(cur != NULL) {
        if (cur->ipid == ipid) {
            // Found. Update the size and return
            cur->size += size;
            return cur;
        }
    }
    
    // Not found, add a new node
    cur = fragnode_create(ipid, size);
    cur->next = *head;
    *head = cur;
    return *head;
}
