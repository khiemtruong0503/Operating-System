
#include "mem.h"
#include "stdlib.h"
#include "string.h"
#include <pthread.h>
#include <stdio.h>

static BYTE _ram[RAM_SIZE];

static struct
{
	uint32_t proc;				// ID of process currently uses this page
	int index;						// Index of the page in the list of pages allocated
												// to the process.
	int next;							// The next page in the list. -1 if it is the last
												// page.
} _mem_stat[NUM_PAGES]; // To track the status of physical pages

static pthread_mutex_t mem_lock;
static pthread_mutex_t ram_lock;

void init_mem(void)
{
	memset(_mem_stat, 0, sizeof(*_mem_stat) * NUM_PAGES);
	memset(_ram, 0, sizeof(BYTE) * RAM_SIZE);
	pthread_mutex_init(&mem_lock, NULL);
	pthread_mutex_init(&ram_lock, NULL);
}

/* get offset of the virtual address */
static addr_t get_offset(addr_t addr)
{
	return addr & ~((~0U) << OFFSET_LEN);
}

/* get the first layer index */
static addr_t get_first_lv(addr_t addr)
{
	return addr >> (OFFSET_LEN + PAGE_LEN);
}

/* get the second layer index */
static addr_t get_second_lv(addr_t addr)
{
	return (addr >> OFFSET_LEN) - (get_first_lv(addr) << PAGE_LEN);
}

/* Search for page table table from the a segment table */
static struct page_table_t *get_page_table(
		addr_t index, // Segment level index
		struct seg_table_t *seg_table)
{ // first level table

	/*
	 * TODO: Given the Segment index [index], you must go through each
	 * row of the segment table [seg_table] and check if the v_index
	 * field of the row is equal to the index
	 *
	 * */

	int i;
	for (i = 0; i < seg_table->size; i++)
	{
		// Enter your code here
		if (seg_table->table[i].v_index == index)
		{
			return seg_table->table[i].pages;
		}
	}
	return NULL;
}

/* Translate virtual address to physical address. If [virtual_addr] is valid,
 * return 1 and write its physical counterpart to [physical_addr].
 * Otherwise, return 0 */
static int translate(
		addr_t virtual_addr,	 // Given virtual address
		addr_t *physical_addr, // Physical address to be returned
		struct pcb_t *proc)
{ // Process uses given virtual address

	/* Offset of the virtual address */
	addr_t offset = get_offset(virtual_addr);
	/* The first layer index */
	addr_t first_lv = get_first_lv(virtual_addr);
	/* The second layer index */
	addr_t second_lv = get_second_lv(virtual_addr);

	/* Search in the first level */
	struct page_table_t *page_table = NULL;
	page_table = get_page_table(first_lv, proc->seg_table);
	if (page_table == NULL)
	{
		return 0;
	}

	int i;
	for (i = 0; i < page_table->size; i++)
	{
		if (page_table->table[i].v_index == second_lv)
		{
			/* TODO: Concatenate the offset of the virtual addess
			 * to [p_index] field of page_table->table[i] to
			 * produce the correct physical address and save it to
			 * [*physical_addr]  */
			*physical_addr = (page_table->table[i].p_index << OFFSET_LEN) | offset;
			return 1;
		}
	}
	return 0;
}

addr_t alloc_mem(uint32_t size, struct pcb_t *proc)
{
	pthread_mutex_lock(&mem_lock);
	addr_t ret_mem = 0;
	// /* TODO: Allocate [size] byte in the memory for the
	//  * process [proc] and save the address of the first
	//  * byte in the allocated memory region to [ret_mem].
	//  * */

	uint32_t num_pages = (size % PAGE_SIZE) ? size / PAGE_SIZE + 1 : 
					size / PAGE_SIZE; // Number of pages we will use
	int mem_avail = 0;	 // We could allocate new memory region or not?

	/* First we must check if the amount of free memory in
	 * virtual address space and physical address space is
	 * large enough to represent the amount of required
	 * memory. If so, set 1 to [mem_avail].
	 * Hint: check [proc] bit in each page of _mem_stat
	 * to know whether this page has been used by a process.
	 * For virtual memory space, check bp (break pointer).
	 * */
	uint32_t pages_avail = 0;
	int free_frame[num_pages];

	for (int i = 0, j = 0; 
				i < NUM_PAGES; 
				i++)
	{
		if (_mem_stat[i].proc == 0)
		{
			pages_avail++;
			free_frame[j] = i;
			j++;
			if (pages_avail == num_pages)
			{
				mem_avail = 1; // since number of free pages = number of pages
				break;
			}
		}
	}

	// check another condition if total size exceed size of ram
	if(proc->bp + num_pages * PAGE_SIZE > RAM_SIZE){
		mem_avail = 0;
	}

	if (mem_avail)
	{
		/* We could allocate new memory region to the process */
		ret_mem = proc->bp;
		proc->bp += num_pages * PAGE_SIZE;
		/* Update status of physical pages which will be allocated
		 * to [proc] in _mem_stat. Tasks to do:
		 * 	- Update [proc], [index], and [next] field
		 * 	- Add entries to segment table page tables of [proc]
		 * 	  to ensure accesses to allocated memory slot is
		 * 	  valid. */

		/* Physical
		 * Update index, proc, next  */
		for (int j = 0; j < num_pages; j++)
		{
			int frame_idx = free_frame[j];
			_mem_stat[frame_idx].proc = proc->pid;
			_mem_stat[frame_idx].index = j;

			if (j < num_pages - 1)
				_mem_stat[frame_idx].next = free_frame[j + 1];
			else 
				_mem_stat[frame_idx].next = -1;
		}
		

		/* Virtual
		 * Map to physical page */
		addr_t itr_mem = ret_mem;
		for (int j = 0; j < num_pages; j++)
		{
			addr_t seg_lv = get_first_lv(itr_mem);
			addr_t page_lv = get_second_lv(itr_mem);
			struct seg_table_t *seg_table = proc->seg_table;
			struct page_table_t *page_table = get_page_table(seg_lv, seg_table);

			/* Create a new entry */
			if (page_table == NULL)
			{
				int seg_sz = seg_table->size;
				seg_table->table[seg_sz].v_index = seg_lv;
				page_table = (struct page_table_t *)malloc(sizeof(struct page_table_t));
				seg_table->table[seg_sz].pages = page_table;
				page_table->size = 0;
				seg_table->size++;
			}

			/* Assign value */
			int page_sz = page_table->size;
			page_table->table[page_sz].v_index = page_lv;
			page_table->table[page_sz].p_index = free_frame[j];
			page_table->size++;

			itr_mem += PAGE_SIZE;
		}
	}
	pthread_mutex_unlock(&mem_lock);
	return ret_mem;
}

int free_mem(addr_t address, struct pcb_t *proc)
{
	/*TODO: Release memory region allocated by [proc]. The first byte of
	 * this region is indicated by [address]. Task to do:
	 * 	- Set flag [proc] of physical page use by the memory block
	 * 	  back to zero to indicate that it is free.
	 * 	- Remove unused entries in segment table and page tables of
	 * 	  the process [proc].
	 * 	- Remember to use lock to protect the memory from other
	 * 	  processes.  */
	pthread_mutex_lock(&mem_lock);

	// swap return values?
	addr_t p_addr;
	addr_t v_addr = address;

	if (translate(v_addr, &p_addr, proc) == 0)
		return 1; // not found the physical mem space from virtual mem space

	int freed_pages = 0;
	int p_idx = (p_addr >> OFFSET_LEN);

	// clear physical
	while (p_idx != -1)
	{
		_mem_stat[p_idx].proc = 0;
		freed_pages++;
		p_idx = _mem_stat[p_idx].next; // go to next page
	}

	v_addr += PAGE_SIZE * freed_pages;

	/**
	 * Preventing fragmentation:
	 */
	if (proc->bp != v_addr)
	{
		addr_t new_v_addr = address; // Address of next data chunk after
																 // dealloc this process
		addr_t old_v_addr = v_addr;	 // Address of current next data chunk

		/* move one page up at a time */
		while (proc->bp != old_v_addr)
		{
			/* Retrieve their first and second levels  */
			addr_t new_seg_lv = get_first_lv(new_v_addr);
			addr_t old_seg_lv = get_first_lv(old_v_addr);
			addr_t new_page_lv = get_second_lv(new_v_addr);
			addr_t old_page_lv = get_second_lv(old_v_addr);

			/**
			 * Locate the dest and src page based on levels
			 */
			struct seg_table_t *seg_table = proc->seg_table;
			struct page_table_t *new_page_table = get_page_table(new_seg_lv, seg_table);
			struct page_table_t *old_page_table = get_page_table(old_seg_lv, seg_table);
			if (new_page_table != NULL && old_page_table != NULL)
			{
				int new_page_idx;
				int old_page_idx;

				for (new_page_idx = 0; new_page_idx < new_page_table->size; new_page_idx++)
					if (new_page_table->table[new_page_idx].v_index == new_page_lv)
						break;
				for (old_page_idx = 0; old_page_idx < old_page_table->size; old_page_idx++)
					if (old_page_table->table[old_page_idx].v_index == old_page_lv)
						break;

				new_page_table->table[new_page_idx].p_index = old_page_table->table[old_page_idx].p_index;
				new_page_table->table[new_page_idx].v_index = new_page_lv;
			}

			/* Updatae registers that hold old addresses */
			for (int i = 0; i < 10; i++)
			{
				if (proc->regs[i] == old_v_addr)
				{
					proc->regs[i] = new_v_addr;
					break;
				}
			}

			new_v_addr += PAGE_SIZE;
			old_v_addr += PAGE_SIZE;
		}
	}

	/* decreases size and free page_table if emply after wards */
	int temp_fp = freed_pages;
	while (freed_pages > 0)
	{
		int seg_size = proc->seg_table->size;
		struct seg_table_t *seg_table = proc->seg_table;
		struct page_table_t *page_table = get_page_table(seg_size - 1, seg_table);
		if (page_table != NULL)
		{
			page_table->size--;
			if (page_table->size == 0)
			{
				free(page_table);
				seg_table->size--;
			}
		}
		freed_pages--;
	}

	/* Update bp */
	proc->bp -= temp_fp * PAGE_SIZE;

	pthread_mutex_unlock(&mem_lock);

	return 0;
}

int read_mem(addr_t address, struct pcb_t * proc, BYTE * data) {
	addr_t physical_addr;
	if (translate(address, &physical_addr, proc)) {
		pthread_mutex_lock(&ram_lock);
		*data = _ram[physical_addr];
		pthread_mutex_unlock(&ram_lock);
		return 0;
	}else{
		return 1;
	}
}

int write_mem(addr_t address, struct pcb_t * proc, BYTE data) {
	addr_t physical_addr;
	if (translate(address, &physical_addr, proc)) {
		pthread_mutex_lock(&ram_lock);
		_ram[physical_addr] = data;
		pthread_mutex_unlock(&ram_lock);
		return 0;
	}else{
		return 1;
	}
}

void dump(void) {
	int i;
	for (i = 0; i < NUM_PAGES; i++) {
		if (_mem_stat[i].proc != 0) {
			printf("%03d: ", i);
			printf("%05x-%05x - PID: %02d (idx %03d, nxt: %03d)\n",
				i << OFFSET_LEN,
				((i + 1) << OFFSET_LEN) - 1,
				_mem_stat[i].proc,
				_mem_stat[i].index,
				_mem_stat[i].next
			);
			int j;
			for ( j = i << OFFSET_LEN;
				j < ((i+1) << OFFSET_LEN) - 1;
				j++) {

				if (_ram[j] != 0) {
					printf("\t%05x: %02x\n", j, _ram[j]);
				}

			}
		}
	}
}
