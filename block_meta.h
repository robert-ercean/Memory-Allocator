/* SPDX-License-Identifier: BSD-3-Clause */

#pragma once

#define DIE(assertion, call_description)									\
	do {													\
		if (assertion) {										\
			fprintf(stderr, "(%s, %d): ", __FILE__, __LINE__);					\
			perror(call_description);								\
			exit(errno);										\
		}												\
	} while (0)

/* Structure to hold memory block metadata */
typedef struct block_meta {
	size_t size;
	int status;
	struct block_meta *prev;
	struct block_meta *next;
}block_meta;

/* Block metadata status values */
#define STATUS_FREE   0
#define STATUS_ALLOC  1
#define STATUS_MAPPED 2

