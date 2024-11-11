// SPDX-License-Identifier: BSD-3-Clause

#include "osmem.h"
#include "block_meta.h"

block_meta * heap_head = NULL;

void heap_prealloc(void)
{
	heap_head = sbrk(HEAP_PREALLOC);
	DIE(heap_head == MAP_FAILED, "sbrk in prealloc failed\n");
	heap_head->prev = NULL;
	heap_head->next = NULL;
	heap_head->status = STATUS_FREE;
	heap_head->size = HEAP_PREALLOC - METADATA_SIZE;
}

block_meta *get_metablock_ptr(void *ptr)
{
	return (block_meta *)ptr - 1;
}

void *get_payload(block_meta *ptr)
{
	return (void *)(ptr + 1);
}

block_meta *get_heap_last_block(void)
{
	block_meta *iter = heap_head;

	while (iter->next)
		iter = iter->next;

	return iter;
}

void coalesce_blocks(void)
{
	block_meta *iter = heap_head;

	while (iter && iter->next) {
		if (iter->status == STATUS_FREE && iter->next->status == STATUS_FREE) {
			size_t coalesced_size = iter->size + iter->next->size + METADATA_SIZE;

			iter->size = coalesced_size;

			iter->next = iter->next->next;

			if (iter->next)
				iter->next->prev = iter;
		} else {
			iter = iter->next;
		}
	}
}

block_meta *get_free_block(size_t size)
{
	coalesce_blocks();

	block_meta *iter = heap_head;
	block_meta *best = NULL;

	while (iter) {
		if (iter->size >= size && iter->status == STATUS_FREE) {
			if (!best || iter->size < best->size)
				best = iter;
		}
		iter = iter->next;
	}
	return best;
}
void split_block(block_meta *old_block, size_t size)
{
	block_meta *new_free_block = (block_meta *)((char *)(old_block + 1) + size);

	new_free_block->size = old_block->size - size - METADATA_SIZE;
	new_free_block->status = STATUS_FREE;
	new_free_block->next = old_block->next;
	new_free_block->prev = old_block;

	if (old_block->next)
		old_block->next->prev = new_free_block;

	old_block->next = new_free_block;
	old_block->size = size;
	old_block->status = STATUS_ALLOC;
}
block_meta *expand_block(size_t size, block_meta *last)
{
	size_t expand_size = size - last->size;

	sbrk(expand_size);
	last->size += expand_size;
	last->status = STATUS_ALLOC;
	return last;
}

block_meta *increase_heap(size_t size)
{
	block_meta *last = get_heap_last_block();
	// Check requirements for expanding last block
	if (last->status == STATUS_FREE) {
		return expand_block(size, last);
	// If cannot expand last block, expand the heap with a new block altogether
	} else if (last->status == STATUS_ALLOC) {
		block_meta *new_block = sbrk(size + METADATA_SIZE);

		DIE(new_block == MAP_FAILED, "sbrk on new block failed\n");
		new_block->status = STATUS_ALLOC;
		new_block->size = size;
		new_block->prev = last;
		last->next = new_block;
		new_block->next = NULL;

		return new_block;
	}
	return NULL;
}
void *mmap_alloc(size_t size)
{
	block_meta *mmap_ptr = mmap(NULL, size + METADATA_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);

	DIE(mmap_ptr == MAP_FAILED, "mapping failed\n");
	mmap_ptr->status = STATUS_MAPPED;
	mmap_ptr->size = size;
	mmap_ptr->next = NULL;
	mmap_ptr->prev = NULL;
	return get_payload(mmap_ptr);
}
void *brk_alloc(size_t size)
{
	if (!heap_head)
		heap_prealloc();

	block_meta *curr = get_free_block(size);
	// Check if we have a corresponding free block to use
	if (curr) {
		// Check requirements for splitting the block
		if (curr->size >= size + METADATA_SIZE + 1) {
			split_block(curr, size);
			return get_payload(curr);
		// If we cant split the block, we just set the status to ALLOC
		} else {
			curr->status = STATUS_ALLOC;
			return get_payload(curr);
		}
	// If we find no corresponding free block, we increase the heap size
	} else {
		return get_payload(increase_heap(size));
	}
}

void *memset_to_zero(void *ptr)
{
	memset(ptr, 0, get_metablock_ptr(ptr)->size);
	return ptr;
}

void *realloc_mapped_block(block_meta *old_meta_ptr, size_t new_size)
{
	size_t old_size = old_meta_ptr->size;

	void *old_ptr = get_payload(old_meta_ptr);
	void *new_ptr = os_malloc(new_size);

	memmove(new_ptr, old_ptr, (new_size > old_size) ? old_size : new_size);
	os_free(old_ptr);

	return new_ptr;
}
void *smaller_size_realloc(block_meta *old_meta_block, size_t new_size)
{
	size_t old_size = old_meta_block->size;

	if (old_size >= new_size + METADATA_SIZE + 1) {
		split_block(old_meta_block, new_size);
		return get_payload(old_meta_block);
	}

	old_meta_block->size = new_size;
	printf("What do i do with the memory leaks here?\n");

	return get_payload(old_meta_block);
}
void realloc_coalesce(block_meta *old_meta_block, size_t new_size)
{
	block_meta *iter = old_meta_block;
	size_t total_size = old_meta_block->size;

	while (iter->next && iter->next->status == STATUS_FREE && total_size < new_size) {
		total_size += iter->next->size + METADATA_SIZE;
		iter->next = iter->next->next;
		if (iter->next)
			iter->next->prev = iter;
	}

	old_meta_block->status = STATUS_FREE;
	old_meta_block->size = total_size;
}
void *realloc_heap_block(block_meta *old_meta_block, size_t new_size)
{
	size_t old_size = old_meta_block->size;
	void *old_ptr = get_payload(old_meta_block);

	if (old_size > new_size)
		return smaller_size_realloc(old_meta_block, new_size);
	if (old_meta_block == get_heap_last_block())
		return get_payload(expand_block(new_size, old_meta_block));
	if (old_meta_block->next->status == STATUS_FREE) {
		realloc_coalesce(old_meta_block, new_size);
		if (old_meta_block->size >= new_size) {
			old_meta_block->status = STATUS_ALLOC;
			return get_payload(old_meta_block);
		}
	}

	void *new_payload = os_malloc(new_size);

	memmove(new_payload, get_payload(old_meta_block), old_size);
	os_free(old_ptr);

	return new_payload;
}

void *os_malloc(size_t size)
{
	// Align size to 8 bytes using the ALIGN macro
	size = ALIGN(size);

	if (size == 0)
		return NULL;
	if (size + METADATA_SIZE >= MMAP_THRESHOLD) {
		// MEM ALLOCATION WITH MMAP()
		return mmap_alloc(size);
	} else if (size + METADATA_SIZE < MMAP_THRESHOLD) {
		// MEM ALLOCATION WITH SBRK()
		return brk_alloc(size);
	}

	return NULL;
}

void os_free(void *ptr)
{
	if (ptr == NULL)
		return;

	block_meta *block_to_be_freed = get_metablock_ptr(ptr);

	if (block_to_be_freed->status == STATUS_ALLOC) {
		block_to_be_freed->status = STATUS_FREE;
	} else if (block_to_be_freed->status == STATUS_MAPPED) {
		int ret = munmap(block_to_be_freed, block_to_be_freed->size + METADATA_SIZE);

		DIE(ret == -1, "unmapping memory failed!\n");
	} else {
		printf("Something went wrong when freeing memory!\n");
	}
}

void *os_calloc(size_t nmemb, size_t size)
{
	size_t effective_size = nmemb * size;

	effective_size = ALIGN(effective_size);

	if (effective_size == 0)
		return NULL;
	if (effective_size + METADATA_SIZE >= (size_t) getpagesize())
		return memset_to_zero(mmap_alloc(effective_size));
	else if (effective_size + METADATA_SIZE < (size_t) getpagesize())
		return memset_to_zero(brk_alloc(effective_size));
	return NULL;
}

void *os_realloc(void *ptr, size_t size)
{
	size = ALIGN(size);

	if (!ptr)
		return os_malloc(size);
	if (!size) {
		os_free(ptr);
		return NULL;
	}

	block_meta *meta_ptr = get_metablock_ptr(ptr);

	if (meta_ptr->size == size)
		return ptr;
	switch (meta_ptr->status) {
	case STATUS_MAPPED:
			return realloc_mapped_block(meta_ptr, size);
	case STATUS_ALLOC:
			return realloc_heap_block(meta_ptr, size);
	case STATUS_FREE:
			return NULL;
	}
	return NULL;
}
