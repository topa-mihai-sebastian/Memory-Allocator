// SPDX-License-Identifier: BSD-3-Clause

#include "osmem.h"
#include "block_meta.h"

#include <assert.h>
#include <stddef.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define HEAP_SIZE (128 * 1024) // 128KB
#define META_SIZE sizeof(struct block_meta)
#define MMAP_THRESHOLD (128 * 1024) // Threshold for using mmap
#define ALIGNMENT 8                 // must be a power of 2
#define ALIGN(size) (((size) + (ALIGNMENT - 1)) & ~(ALIGNMENT - 1))

static int initialized;
static struct block_meta *heap_base;
static struct block_meta *heap_end;

void preallocate_heap(void)
{
	if (initialized) // Evită alocarea multiplă a heap-ului
		return;

	// Alocă spațiu pentru heap și verifică dacă s-a reușit alocarea
	heap_base = (struct block_meta *)sbrk(HEAP_SIZE);
	DIE(heap_base == (void *)-1, "sbrk failed");

	// Setează `heap_end` la adresa finală a heap-ului
	heap_end = (struct block_meta *)((char *)heap_base + HEAP_SIZE);

	// Configurarea blocului inițial de metadate
	heap_base->size =
	    ALIGN(HEAP_SIZE - META_SIZE); // Dimensiunea blocului, aliniată
	heap_base->next = NULL;
	heap_base->prev = NULL;
	heap_base->status = STATUS_FREE; // Marcat ca bloc liber

	// Marchez heap-ul ca fiind inițializat
	initialized = 1;
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
			// Dacă este prima potrivire sau mai bună decât cea actuală,
			// actualizăm `best_fit`
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
	if (block == NULL || size <= 0)
		return;
	size = ALIGN(size);
	size_t min_size = ALIGN(sizeof(struct block_meta) + 1);

	if (block->size >= size + META_SIZE + min_size)
	{
		struct block_meta *new_block =
		    (struct block_meta *)((char *)block + sizeof(struct block_meta) +
		                          size);
		new_block->size = block->size - size - META_SIZE;
		new_block->prev = block;
		new_block->next = block->next;
		new_block->status = STATUS_FREE;

		if (new_block->next)
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
	{
		last->next = block;
		block->prev = last;
	} else
	{
		block->prev = NULL;
		heap_base = block;
	}

	block->size = size;
	block->next = NULL;
	block->status = STATUS_ALLOC;

	return block;
}

void *os_malloc(size_t size)
{
	if (size <= 0)
		return NULL;

	// Aliniem dimensiunea cerută
	size = ALIGN(size);

	// Inițializăm heap-ul dacă nu este deja inițializat
	preallocate_heap();
	if (heap_base == NULL) // Verificare că heap-ul a fost alocat corect
		return NULL;

	// Alocăm cu mmap dacă dimensiunea este mai mare decât pragul specificat
	if (size >= MMAP_THRESHOLD)
	{
		void *mmap_ptr = mmap(NULL, size + META_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
		DIE(mmap_ptr == MAP_FAILED, "mmap");

		struct block_meta *block = (struct block_meta *)mmap_ptr;
		block->size = size;
		block->next = NULL;
		block->prev = NULL;
		block->status = STATUS_ALLOC;

		return (block + 1); // Returnăm adresa de după metadatele blocului
	}

	// Găsim un bloc liber în heap
	struct block_meta *last = heap_base;
	struct block_meta *block = find_free_block(&last, size);

	if (!block)
	{
		// Dacă nu s-a găsit un bloc liber, extindem heap-ul
		block = extend_heap(last, size);
		if (!block)
			return NULL;
	}
	else
	{
		// Dacă am găsit un bloc liber, îl divizăm dacă e prea mare
		if (block->size >= size + META_SIZE + ALIGNMENT)
			split_block(block, size);

		// Marcăm blocul ca alocat
		block->status = STATUS_ALLOC;
	}

	return (block + 1); // Returnăm adresa de după metadate
}

void os_free(void *ptr)
{
	if (!ptr)
		return;

	struct block_meta *block = (struct block_meta *)ptr - 1;

	assert(block->status == STATUS_ALLOC);
	block->status = STATUS_FREE;

	// Use munmap for large allocations
	if (block->size + META_SIZE >= MMAP_THRESHOLD)
	{
		int result = munmap(block, block->size + META_SIZE);
		DIE(result == -1, "munmap");
	}
}

void *os_calloc(size_t nmemb, size_t size)
{
	size_t total_size = nmemb * size;

	// total_size = ALIGN(total_size);
	void *ptr = os_malloc(total_size);

	if (ptr)
		memset(ptr, 0, total_size);
	return ptr;
}

void *os_realloc(void *ptr, size_t size)
{
	size = ALIGN(size);
	if (!ptr)
	{
		return os_malloc(size);
	}

	struct block_meta *block = (struct block_meta *)ptr - 1;

	// If the new size is smaller than the current size, we can simply return
	// the original pointer
	if (size <= block->size)
		return ptr;

	// If the next block is free and large enough, we can extend the current
	// block
	if (block->next && block->next->status == STATUS_FREE &&
	    block->size + block->next->size + META_SIZE >= size)
	{
		block->size += block->next->size + META_SIZE;
		block->next = block->next->next;
		if (block->next)
		{
			block->next->prev = block;
		}
		return ptr;
	}

	// Otherwise, we need to allocate a new block and copy the data
	void *new_ptr = os_malloc(size);
	if (!new_ptr)
	{
		return NULL;
	}
	memcpy(new_ptr, ptr, block->size);
	os_free(ptr);
	return new_ptr;
}
