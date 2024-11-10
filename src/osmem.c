// SPDX-License-Identifier: BSD-3-Clause

#include "osmem.h"
#include "block_meta.h"

#include <assert.h>
#include <stddef.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define HEAP_SIZE (128 * 1024) // 128KB
#define PAGE_SIZE (4 * 1024)   // 4kb
#define META_SIZE sizeof(struct block_meta)
#define MMAP_THRESHOLD (128 * 1024) // Threshold for using mmap
#define ALIGNMENT 8                 // must be a power of 2
#define ALIGN(size) (((size) + (ALIGNMENT - 1)) & ~(ALIGNMENT - 1))

static int initialized;
static struct block_meta *heap_base;

void preallocate_heap(void)
{
	if (initialized == 1) // Evită alocarea multiplă a heap-ului
		return;

	// Alocă spațiu pentru heap și verifică dacă s-a reușit alocarea
	heap_base = (struct block_meta *)sbrk(0);

	DIE(heap_base == (void *)-1, "sbrk failed");
	void *init_heap = sbrk(MMAP_THRESHOLD);

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
	struct block_meta *block_aux = heap_base;

	while (block_aux && block_aux->next)
	{
		if (block_aux->status == STATUS_FREE &&
		    block_aux->next->status == STATUS_FREE)
		{
			block_aux->size =
			    block_aux->size + META_SIZE + block_aux->next->size;
			block_aux->next = block_aux->next->next;
		}
		else
			block_aux = block_aux->next;
	}

	while (current)
	{
		if (current->status == STATUS_FREE && current->size >= size)
		{
			break;
		}
		*last = current;
		current = current->next;
	}
	return current;
}

void split_block(struct block_meta *block, size_t size)
{
	if (block == NULL || size <= 0)
		return;
	size = ALIGN(size);

	if (block->size >= size + META_SIZE + 8)
	{
		if (!block->next)
		{
			struct block_meta *new_block =
			    (struct block_meta *)((char *)block + META_SIZE + size);
			new_block->size = block->size - size - META_SIZE;
			new_block->prev = block;
			new_block->next = NULL;
			new_block->status = STATUS_FREE;

			block->size = size;
			block->next = new_block;
		}
		else
		{
			struct block_meta *new_block =
			    (struct block_meta *)((char *)block + META_SIZE + size);
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
	}
	else
		block->prev = NULL;

	block->size = size;
	block->next = NULL;
	block->status = STATUS_ALLOC;

	return block;
}

void *os_malloc(size_t size)
{
	if (size <= 0)
		return NULL;

	size = ALIGN(size);

	if (size + META_SIZE >= MMAP_THRESHOLD)
	{
		void *mmap_ptr = mmap(NULL, size + META_SIZE, PROT_READ | PROT_WRITE,
		                      MAP_PRIVATE | MAP_ANON, -1, 0);

		DIE(mmap_ptr == MAP_FAILED, "mmap");

		struct block_meta *block = (struct block_meta *)mmap_ptr;

		block->size = size;
		block->next = NULL;
		block->prev = NULL;
		block->status = STATUS_MAPPED;
		initialized = 1; // sigabrt

		return (block + 1);
	}

	preallocate_heap();
	if (heap_base == NULL)
		return NULL;

	struct block_meta *last = heap_base;
	struct block_meta *block = find_free_block(&last, size);

	if (!block)
	{
		struct block_meta *aux = heap_base;
		while (aux && aux->next)
			aux = aux->next;
		int do_not_extend = 0;
		if (aux->size < size && aux->status == STATUS_FREE)
		{
			size_t additional_size = size - aux->size;
			struct block_meta *new_block =
			    (struct block_meta *)sbrk(additional_size);

			DIE(new_block == (void *)-1, "sbrk");

			aux->size += additional_size;
			do_not_extend = 1;
		}
		if (!do_not_extend)
		{
			block = extend_heap(last, size);
			if (!block)
				return NULL;
		}
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

	if (block->status == STATUS_ALLOC)
		block->status = STATUS_FREE;
	else if (block->status == STATUS_MAPPED)
	{
		int result = munmap(block, block->size + META_SIZE);
		DIE(result == -1, "munmap");
	}
}

void *os_calloc(size_t nmemb, size_t size)
{
	if (nmemb == 0 || size == 0)
		return NULL;

	size_t total_size = nmemb * size;
	total_size = ALIGN(total_size);

	void *ptr;
	struct block_meta *block;

	if (total_size >= PAGE_SIZE)
	{
		ptr = mmap(NULL, total_size + META_SIZE, PROT_READ | PROT_WRITE,
		           MAP_PRIVATE | MAP_ANON, -1, 0);
		DIE(ptr == MAP_FAILED, "mmap");

		block = (struct block_meta *)ptr;
		block->size = total_size;
		block->next = NULL;
		block->prev = NULL;
		block->status = STATUS_MAPPED;
	}
	else
	{
		ptr = sbrk(total_size + META_SIZE);
		DIE(ptr == (void *)-1, "sbrk");

		block = (struct block_meta *)ptr;
		block->size = total_size;
		block->next = NULL;
		block->prev = NULL;
		block->status = STATUS_ALLOC;
	}

	ptr = (void *)(block + 1); // Point to the memory after the metadata
	if (ptr)
		memset(ptr, 0, total_size);
	return ptr;
}

void *os_realloc(void *ptr, size_t size)
{
	return NULL;
}
