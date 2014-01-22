
#ifndef __LIST_H__
#define __LIST_H__

#include <stdint.h>
#include <unistd.h>
#include <stdbool.h>
#include <netinet/ip.h>

typedef struct fragnode {
	uint16_t ipid;
	struct in_addr src;
	struct in_addr dst;
	size_t size;
	struct fragnode* next;
} fragnode_t;

//! \brief Update a fragnode_t list
//! The updated element is returned.
//! If the datagram is complete, the value of complete is set to true and the element is deleted from the list
fragnode_t* fragnode_update(fragnode_t* head, uint16_t ipid, struct in_addr src, struct in_addr dst, size_t size);

fragnode_t* fragnode_add(fragnode_t** head, uint16_t ipid, struct in_addr src,
    struct in_addr dst, size_t size);

void fragnode_unlink(fragnode_t** head, fragnode_t* fragnode);

#endif
