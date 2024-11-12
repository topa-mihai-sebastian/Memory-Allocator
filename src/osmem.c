// SPDX-License-Identifier: BSD-3-Clause

#include "osmem.h"
#include <assert.h>
#include <stddef.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include "block_meta.h"

#define HEAP_SIZE (128 * 1024) // 128KB
#define PAGE_SIZE (4 * 1024)   // 4kb
#define META_SIZE sizeof(struct block_meta)
#define MMAP_THRESHOLD (128 * 1024)
#define ALIGNMENT 8
#define ALIGN(size) (((size) + (ALIGNMENT - 1)) & ~(ALIGNMENT - 1))

static int initialized;
static int calloc_mmap;
static struct block_meta *heap_base;

void preallocate_heap(void)
{
	if (initialized == 1)
		return;

	heap_base = (struct block_meta *)sbrk(0);

	DIE(heap_base == (void *)-1, "sbrk failed");
	void *init_heap = sbrk(MMAP_THRESHOLD);

	// configurare initiala
	heap_base->size = ALIGN(HEAP_SIZE - META_SIZE);
	heap_base->next = NULL;
	heap_base->prev = NULL;
	heap_base->status = STATUS_FREE;

	initialized = 1;
}

void *find_free_block(struct block_meta **last, size_t size)
{
	struct block_meta *current = heap_base;

	struct block_meta *block_aux = heap_base;

	// coalesce
	while (block_aux && block_aux->next) {
		if (block_aux->status == STATUS_FREE && block_aux->next->status == STATUS_FREE) {
			block_aux->size = block_aux->size + META_SIZE + block_aux->next->size;
			block_aux->next = block_aux->next->next;
			if (block_aux->next)
				block_aux->next->prev = block_aux;
		} else {
			block_aux = block_aux->next;
		}
	}
	// find a good free block
	while (current) {
		if (current->status == STATUS_FREE && current->size >= size)
			break;
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

	if (block->size >= size + META_SIZE + 8) {
		if (!block->next) {
			struct block_meta *new_block = (struct block_meta *)((char *)block + META_SIZE + size);

			new_block->size = block->size - size - META_SIZE;
			new_block->prev = block;
			// aici e singura diferenta
			new_block->next = NULL;
			new_block->status = STATUS_FREE;

			block->size = size;
			block->next = new_block;
		} else {
			struct block_meta *new_block = (struct block_meta *)((char *)block + META_SIZE + size);

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
	size = ALIGN(size);
	struct block_meta *block = (struct block_meta *)sbrk(size + META_SIZE);

	DIE(block == (void *)-1, "sbrk");

	if (last) {
		last->next = block;
		block->prev = last;
	} else {
		block->prev = NULL;
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

	size = ALIGN(size);
	// fac cu mmap daca se depaseste MMAP_THRESHOLD
	// sau daca se depaseste pagesize cu calloc
	if (size + META_SIZE >= MMAP_THRESHOLD || calloc_mmap == 1) {
		void *mmap_ptr = mmap(NULL, size + META_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);

		DIE(mmap_ptr == MAP_FAILED, "mmap");

		struct block_meta *block = (struct block_meta *)mmap_ptr;

		block->size = size;
		block->next = NULL;
		block->prev = NULL;
		block->status = STATUS_MAPPED;
		if (!initialized)
			initialized = 1; // sigabrt
		if (calloc_mmap == 1)
			calloc_mmap = 0;
		return (block + 1);
	}
	preallocate_heap();
	if (heap_base == NULL)
		return NULL;

	struct block_meta *last = heap_base;
	struct block_meta *block = find_free_block(&last, size);

	if (!block) {
		struct block_meta *aux = heap_base;

		while (aux && aux->next)
			aux = aux->next;
		int do_not_extend = 0;

		if (aux->size < size && aux->status == STATUS_FREE) {
			size_t additional_size = size - aux->size;
			void *degeaba = sbrk(additional_size);

			DIE(degeaba == (void *)-1, "sbrk");
			aux->size += additional_size;
			do_not_extend = 1;
		}
		if (!do_not_extend) {
			block = extend_heap(last, size);
			if (!block)
				return NULL;
		} else {
			block = aux;
		}
	} else {
		// daca am gasit un block si este prea mare ii dam split
		if (block->size >= size + META_SIZE + ALIGNMENT)
			split_block(block, size);

		// marchez ca alloc
		block->status = STATUS_ALLOC;
	}
	// adressa de dupa structura block-ului
	return (block + 1);
}

void os_free(void *ptr)
{
	if (!ptr)
		return;

	struct block_meta *block = (struct block_meta *)ptr - 1;

	if (block->status == STATUS_ALLOC) {
		block->status = STATUS_FREE;
	} else if (block->status == STATUS_MAPPED) {
		int result = munmap(block, block->size + META_SIZE);

		DIE(result == -1, "munmap");
	}
}

void *os_calloc(size_t nmemb, size_t size)
{
	if (nmemb == 0 || size == 0)
		return NULL;
	size_t total_size;

	if (nmemb == 1) {
		total_size = nmemb * ALIGN(size);
	} else {
		total_size = nmemb * size;
		total_size = ALIGN(total_size);
	}
	if (total_size + META_SIZE > PAGE_SIZE)
		calloc_mmap = 1;

	void *ptr = os_malloc(total_size);

	calloc_mmap = 0;
	if (ptr)
		memset(ptr, 0, total_size);
	return ptr;
}

void *os_realloc(void *ptr, size_t size)
{
	if (size == 0) {
		os_free(ptr);
		return NULL;
	}
	size = ALIGN(size);
	if (ptr == NULL)
		return os_malloc(size);

	struct block_meta *block = (struct block_meta *)ptr - 1;
	if (block->status == STATUS_FREE)
		return NULL;
	if (block->size == size)
		return ptr;
	struct block_meta *next = block->next;

	if (block->status == STATUS_MAPPED && size < PAGE_SIZE) {
		void *aux = os_malloc(size);

		if (aux)
			memcpy(aux, ptr, (block->size < size) ? block->size : size);
		int result = munmap(block, block->size + META_SIZE);

		DIE(result == -1, "munmap");
		return aux;
	}
	if (block->status == STATUS_MAPPED && size > PAGE_SIZE) {
		void *mmap_ptr = mmap(NULL, size + META_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);

		DIE(mmap_ptr == MAP_FAILED, "mmap");
		struct block_meta *new_block = (struct block_meta *)mmap_ptr;

		new_block->size = size;
		new_block->next = NULL;
		new_block->prev = NULL;
		new_block->status = STATUS_MAPPED;
		memcpy(new_block + 1, ptr, (block->size < size) ? block->size : size);
		initialized = 1;

		int result = munmap(block, block->size + META_SIZE);

		DIE(result == -1, "munmap");
		return (new_block + 1);
	}
	if (block->status == STATUS_FREE)
		return NULL;
	if (block->size >= size + META_SIZE + 8) {
		// truncate
		split_block(block, size);
		return ptr;
	}
	// else ->
	// incerc sa fac expend
	while (next && next->status == STATUS_FREE && block->size + META_SIZE + next->size < size) {
		block->size = block->size + META_SIZE + next->size;
		block->next = next->next;
		if (block->next)
			block->next->prev = block;
		next = block->next;
		// segfault aici :(
		if (next == NULL)
			break;
	}
	// daca s-a gasit fac alloc
	if (block->size >= size && block != NULL) {
		block->status = STATUS_ALLOC;
		return ptr;
	}
	// else ->
	// daca nu alloc in alta parte cu os_malloc
	void *new_ptr = os_malloc(size);

	if (new_ptr) {
		memcpy(new_ptr, ptr, (block->size < size) ? block->size : size);
		os_free(ptr);
	}
	return new_ptr;
}
