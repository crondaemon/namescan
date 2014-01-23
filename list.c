
#include <list.h>

#include <stdlib.h>
#include <log.h>

void fragnode_print(fragnode_t* fragnode)
{
    printf("NODE: %p, %u %u %u %lu\n", fragnode, fragnode->ipid, fragnode->src.s_addr,
        fragnode->dst.s_addr, fragnode->size);
}

fragnode_t* fragnode_create(uint16_t ipid, struct in_addr src, struct in_addr dst, size_t size)
{
	fragnode_t* elem;

	elem = (fragnode_t*)malloc(sizeof(fragnode_t));
	if (elem == NULL) {
		LOG_ERROR("Can't create fragnode");
		return NULL;
	}

	elem->ipid = ipid;
	elem->src = src;
	elem->dst = dst;
	elem->size = size;
	elem->next = NULL;

	return elem;
}

static int fragnode_equal(fragnode_t* e1, fragnode_t* e2)
{
    if (e1->ipid == e2->ipid && e1->src.s_addr == e2->src.s_addr &&
            e1->dst.s_addr == e2->dst.s_addr && e1->size == e2->size)
        return 0;
    return 1;
}

void fragnode_unlink(fragnode_t** head, fragnode_t* fragnode)
{
    fragnode_t* cur;

    if (*head == fragnode) {
        *head = (*head)->next;
        return;
    }

    cur = *head;
    while(cur->next != NULL) {
        if (fragnode_equal(cur->next, fragnode)) {
            cur->next = cur->next->next;
            return;
        }
    }

    // not found...
    LOG_ERROR("Element not found");
}

fragnode_t* fragnode_update(fragnode_t* head, uint16_t ipid, struct in_addr src,
    struct in_addr dst, size_t size)
{
    fragnode_t* cur;

    cur = head;
    while(cur != NULL) {
        if (cur->ipid == ipid && cur->src.s_addr == src.s_addr && cur->dst.s_addr == dst.s_addr) {
            // Found. Update the size and return
            cur->size += size;
            return cur;
        }
    }

    LOG_ERROR("%s: Cant' find fragnode\n", __func__);
    return NULL;
}

fragnode_t* fragnode_add(fragnode_t** head, uint16_t ipid, struct in_addr src,
    struct in_addr dst, size_t size)
{
    fragnode_t* cur;
    cur = fragnode_create(ipid, src, dst, size);
    cur->next = *head;
    *head = cur;
    return *head;
}
