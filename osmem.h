/* SPDX-License-Identifier: BSD-3-Clause */

#pragma once

#include <stdlib.h>
#include "printf.h"
#include <errno.h>
#include <sys/mman.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>

void *os_malloc(size_t size);
void os_free(void *ptr);
void *os_calloc(size_t nmemb, size_t size);
void *os_realloc(void *ptr, size_t size);

#define METADATA_SIZE		(sizeof(struct block_meta))
#define MOCK_PREALLOC		(128 * 1024 - METADATA_SIZE - 8)
#define MMAP_THRESHOLD		(128 * 1024)
#define NUM_SZ_SM		11
#define NUM_SZ_MD		6
#define NUM_SZ_LG		4
#define MULT_KB			1024
#define HEAP_PREALLOC   131072

#define MAP_FAILED ((void *) -1)

#define ALIGNMENT 8
#define ALIGN(size) (((size) + (ALIGNMENT-1)) & ~(ALIGNMENT-1))
