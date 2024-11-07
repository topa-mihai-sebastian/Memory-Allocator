// SPDX-License-Identifier: BSD-3-Clause

#include "osmem.h"
#include "block_meta.h"

#include <assert.h>
#include <stddef.h>
#include <sys/mman.h>
#include <unistd.h>
#include <string.h>

#define HEAP_SIZE (128 * 1024) // 128KB
#define META_SIZE sizeof(struct block_meta)
#define MMAP_THRESHOLD (128 * 1024) // Threshold for using mmap
#define ALIGNMENT 8 // must be a power of 2
#define ALIGN(size) (((size) + (ALIGNMENT - 1)) & ~(ALIGNMENT - 1))

int initialized;
static struct block_meta *heap_base;
static struct block_meta *heap_end;

void preallocate_heap(void)
{
    if (initialized == 0) {
        // Use mmap instead of sbrk
        heap_base = (struct block_meta *)mmap(NULL, HEAP_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        DIE(heap_base == MAP_FAILED, "mmap");

        // Set heap_end to the end of the allocated region
        heap_end = (struct block_meta *)((char *)heap_base + HEAP_SIZE);

        // Initialize the first block_meta
        heap_base->size = ALIGN(HEAP_SIZE - META_SIZE); // Ensure alignment
        heap_base->next = NULL;
        heap_base->prev = NULL;
        heap_base->status = STATUS_FREE;

        // Mark heap as initialized
        initialized = 1;
    }
}

void *find_free_block(struct block_meta **last, size_t size)
{
    struct block_meta *current = heap_base;

    struct block_meta *best_fit = NULL;

    // Inițializăm `best_fit` ca NULL și parcurgem toată lista de blocuri
    while (current)
	{
        // Verificăm dacă blocul este liber și are dimensiunea necesară
        if (current->status == STATUS_FREE && current->size >= size)
		{
            // Dacă este prima potrivire sau mai bună decât cea actuală, actualizăm `best_fit`
            if (!best_fit || current->size < best_fit->size)
                best_fit = current;
        }
        // Actualizăm `last` pentru a reține ultimul bloc parcurs
        *last = current;
        current = current->next;
    }

    return best_fit;
}

void split_block(struct block_meta *block, size_t size)
{
    size = ALIGN(size);
    size_t min_size = ALIGN(sizeof(struct block_meta) + 1);

	if(block->size >= size + META_SIZE + min_size)
	{
		struct block_meta *new_block = (struct block_meta *)((char *)block + sizeof(struct block_meta) + size);
		new_block->size = block->size - size - sizeof(struct block_meta);
		new_block->prev = block;
		new_block->next = block->next;
		new_block->status = STATUS_FREE;

		if(new_block->next)
			new_block->next->prev = new_block;
		
		block->size = size;
		block->next = new_block;
	}
}

struct block_meta *extend_heap(struct block_meta *last, size_t size)
{
    size = ALIGN(size); // Ensure aligned size
    struct block_meta *block = (struct block_meta *)sbrk(size + META_SIZE);
    DIE(block == (void *)-1, "sbrk");

    if (last)
        last->next = block;
    
	block->size = size;
    block->next = NULL;
    block->status = STATUS_ALLOC;
    
	return block;
}

void *os_malloc(size_t size)
{
    preallocate_heap();
    if (heap_base == NULL)
        return NULL;

    size = ALIGN(size);
    if (size <= 0)
        return NULL;

    if (size >= MMAP_THRESHOLD) {
        void *yoyo = mmap(NULL, size + META_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
        DIE(yoyo == MAP_FAILED, "mmap");
        struct block_meta *block = (struct block_meta *)yoyo;

        block->size = size;
        block->next = NULL;
        block->status = STATUS_ALLOC;
        return (block + 1);
    }

    struct block_meta *last = heap_base;
    struct block_meta *block = find_free_block(&last, size);

    if (!block) { // Failed to find free block
        block = extend_heap(last, size);
        if (!block)
            return NULL;
    } else { // Found free block
        // Split the block if it's too large
        if (block->size >= size + META_SIZE + ALIGNMENT)
            split_block(block, size);
        block->status = STATUS_ALLOC;
    }

    return (block + 1);
}

void os_free(void *ptr) {
    if (!ptr) {
        return;
    }

    struct block_meta *block = (struct block_meta *)ptr - 1;
    assert(block->status == STATUS_ALLOC);
    block->status = STATUS_FREE;

    // Use munmap for large allocations
    if (block->size + META_SIZE >= MMAP_THRESHOLD) {
        int result = munmap(block, block->size + META_SIZE);
        DIE(result == -1, "munmap");
    }
}

void *os_calloc(size_t nmemb, size_t size)
{
    size_t total_size = nmemb * size;

	total_size = ALIGN(total_size);
    void *ptr = os_malloc(total_size);
    
	if (ptr)
        memset(ptr, 0, total_size);
	return ptr;
}

void *os_realloc(void *ptr, size_t size)
{
	/* TODO: Implement os_realloc */
	return NULL;
}
