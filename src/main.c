/*
 * LiME - Linux Memory Extractor
 * Copyright (c) 2011-2013 Joe Sylve - 504ENSICS Labs
 *
 *
 * Author:
 * Joe Sylve       - joe.sylve@gmail.com, @jtsylve
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at
 * your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details. 
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA 
 */

#include "lime.h"

// This file
static int write_lime_header(struct resource *);
static int write_padding(size_t);
// static int write_range(struct resource *);
static int write_vaddr(void *, size_t);
static int setup(void);
static void cleanup(void);
static int init(void);
static void search_process(pid_t);

// External
extern int write_vaddr_tcp(void *, size_t);
extern int setup_tcp(void);
extern void cleanup_tcp(void);

extern int write_vaddr_disk(void *, size_t);
extern int setup_disk(void);
extern void cleanup_disk(void);

static char * format = 0;
static int mode = 0;
static int method = 0;
static char zero_page[PAGE_SIZE];

char * path = 0;
// char * package = 0;
int dio = 1;
int port = 0;
pid_t pid = 0;

// extern struct resource iomem_resource;

// module_param type: bool invbool charp int long short uint ulong ushort

/**  permission
#define S_IRWXUGO       (S_IRWXU|S_IRWXG|S_IRWXO)
#define S_IALLUGO       (S_ISUID|S_ISGID|S_ISVTX|S_IRWXUGO)
#define S_IRUGO         (S_IRUSR|S_IRGRP|S_IROTH)
#define S_IWUGO         (S_IWUSR|S_IWGRP|S_IWOTH)
#define S_IXUGO         (S_IXUSR|S_IXGRP|S_IXOTH)
*/

module_param(path, charp, S_IRUGO);
module_param(dio, bool, S_IRUGO);
module_param(format, charp, S_IRUGO);
module_param(pid, uint, S_IRUGO);
//module_param(package, charp, S_IRUGO);

int init_module (void)
{
	if(!path) {
		DBG("No path parameter specified");
		return -EINVAL;
	}

	if(!format) {
		DBG("No format parameter specified");
		return -EINVAL;
	}

	if(!pid) {
		DBG("No pid parameter specified");
		return -EINVAL;
	}

	DBG("Parameters");
	DBG("  PATH: %s", path);
	DBG("  DIO: %u", dio);
	DBG("  FORMAT: %s", format);
	// DBG("  PACKAGE: %s", package);
	DBG("  pid: %d", pid);

	memset(zero_page, 0, sizeof(zero_page));

	if (!strcmp(format, "raw")) mode = LIME_MODE_RAW;
	else if (!strcmp(format, "lime")) mode = LIME_MODE_LIME;
	else if (!strcmp(format, "padded")) mode = LIME_MODE_PADDED;
	else {
		DBG("Invalid format parameter specified.");
		return -EINVAL;
	}

	method = (sscanf(path, "tcp:%d", &port) == 1) ? LIME_METHOD_TCP : LIME_METHOD_DISK;
	return init();
}

static int init() {
	/*
	struct resource *p;
	int err = 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,18)
	resource_size_t p_last = -1;
#else
	__PTRDIFF_TYPE__ p_last = -1;
#endif
*/
	int err = 0;

	DBG("Initilizing Dump...");

	if((err = setup())) {
		DBG("Setup Error");
		cleanup();
		return err;
	}



	/*
	for (p = iomem_resource.child; p ; p = p->sibling) {
		if (strncmp(p->name, LIME_RAMSTR, sizeof(LIME_RAMSTR)))
			continue;

		if (mode == LIME_MODE_LIME && (err = write_lime_header(p))) {
			DBG("Error writing header 0x%lx - 0x%lx", (long) p->start, (long) p->end);
			break;
		} else if (mode == LIME_MODE_PADDED && (err = write_padding((size_t) ((p->start - 1) - p_last)))) {
			DBG("Error writing padding 0x%lx - 0x%lx", (long) p_last, (long) p->start - 1);
			break;
		}

		if ((err = write_range(p))) {
			DBG("Error writing range 0x%lx - 0x%lx", (long) p->start, (long) p->end);
			break;
		}

		p_last = p->end;
	}
	*/

	search_process(pid);

	cleanup();
	
	return err;
}

static void search_process(pid_t pid) {
	// list_entry(ptr,type,member);
	//   struct task_struct *task = &init_task;
	
	struct task_struct *task = NULL;
	struct mm_struct *mm = NULL;
	struct vm_area_struct *mmap = NULL;
	struct page *tmp_page = NULL;
	// char header[9] = {0};
	void *p = NULL;
	char *odex = "\x64\x65\x79\x0A\x30\x33\x36\x00";
	int size = 0;
	int i = 0;
	int s = 0;

	// in case some process disapears when traversing processes
	rcu_read_lock();
	for_each_process(task) {
		// printk("%s --> %d\n", task->comm, task_tgid_vnr(task));
		// printk("%s --> %d\n", task->comm, task->pid);
		if(pid == task->pid) {
			DBG("%s --> %d\n", task->comm, task->pid);
			mm = task->mm;
			if(mm){
				DBG("maps_count: %d, total_vm: %ld\n",mm->map_count, mm->total_vm);
				mmap = mm->mmap;
				do {
					// char *name = 0;
					if(! mmap->vm_file) {
						if(mmap->vm_flags == 0x100075) { // r-xp
							DBG("vm_start: %lX, vm_end: %lX, prot: %lX\n",mmap->vm_start, mmap->vm_end, mmap->vm_flags);
							
							// virt_to_page() works only for kernel virtual addresses
							//copy_from_user(header, (void const *)(mmap->vm_start), 8); device & application

							down_read(&(mm->mmap_sem));
							get_user_pages(task, mm, mmap->vm_start, 1, 0, 0, &tmp_page, NULL);
							up_read(&(mm->mmap_sem));

							p = kmap(tmp_page);

							if(memcmp(p, odex, 7) == 0) {
								kunmap(p);

								/*
								write_vaddr(p, (size_t) PAGE_SIZE);
								memcpy(header, p, 8);
								printk("Header: %s\n", header);
								memset(header, 0, 9);
								kunmap(p);
								break;
								*/
								
								size = (mmap->vm_end - mmap->vm_start) / PAGE_SIZE;

								for(i=0; i<size; i++) {
									down_read(&(mm->mmap_sem));
									get_user_pages(task, mm, (mmap->vm_start) + i * PAGE_SIZE , 1, 0, 0, &tmp_page, NULL);
									up_read(&(mm->mmap_sem));

									p = kmap(tmp_page);
									s = write_vaddr(p, (size_t) PAGE_SIZE);
									kunmap(p);
									
									if (s != (size_t) PAGE_SIZE) {
										DBG("Error sending page %d", s);
									}
								}
								
								break;

							} else {
								kunmap(p);
							}
						}		
					}
					/* 
					else {
						name = mmap->vm_file->f_path.dentry->d_name.name;
						printk("vm_start: %lX, vm_end: %lX, vm_file: %s\n",mmap->vm_start, mmap->vm_end, name);	
					}
					*/
					
				} while((mmap = mmap->vm_next));
			} else {
				DBG("mm null");
			}
		}
    }
    rcu_read_unlock();
    printk("search_process done\n");
}

/*
static void search_process2(void) {
      struct task_struct *pos;
      struct list_head *current_head;
      int count=0;

      printk("Traversal module is working..\n");
      current_head=&(current->tasks);
      list_for_each_entry(pos,current_head,tasks)
      {
             count++;
             printk("[process %d]: %s\'s pid is %d\n",count,pos->comm,pos->pid);
      }
      printk(KERN_ALERT"The number of process is:%d\n",count);
}

static void read_maps(pid_t pid){
	mm_segment_t old_fs;
	char *buf[250] = {0};
	ssize_t ret;
	struct file *file=NULL;
	char name[30] = {0};
	int n = sprintf(name, "%s%d%s", "/proc/", pid, "/maps");
	name[n] = '\0';

	printk("%s",name); 

	file = filp_open(name,O_RDWR,0);
	if(IS_ERR(file))
		goto out;
	old_fs = get_fs();
	// set_fs(get_ds());
	set_fs(KERNEL_DS);

	//ret = file->f_op->write(file,buf,sizeof(buf),&file->f_pos);
	while(ret = file->f_op->read(file,buf,sizeof(buf),&file->f_pos)) {
		buf[ret] = '\0';
		printk("%s",buf); 	
	}
	
	set_fs(old_fs);
out:
	filp_close(file,NULL);
}
*/

static int write_lime_header(struct resource * res) {
	long s;

	lime_mem_range_header header;

	memset(&header, 0, sizeof(lime_mem_range_header));
	header.magic = LIME_MAGIC;
	header.version = 1;
	header.s_addr = res->start;
	header.e_addr = res->end;
	
	s = write_vaddr(&header, sizeof(lime_mem_range_header));
	
	if (s != sizeof(lime_mem_range_header)) {
		DBG("Error sending header %ld", s);
		return (int) s;
	}				

	return 0;
}

static int write_padding(size_t s) {
	size_t i = 0;
	int r;

	while(s -= i) {

		i = min((size_t) PAGE_SIZE, s);
		r = write_vaddr(zero_page, i);

		if (r != i) {
			DBG("Error sending zero page: %d", r);
			return r;
		}
	}

	return 0;
}

/*
static int write_range(struct resource * res) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,18)
	resource_size_t i, is;
#else
	__PTRDIFF_TYPE__ i, is;
#endif
	struct page * p;
	void * v;
	
	int s;

	for (i = res->start; i <= res->end; i += PAGE_SIZE) {

		p = pfn_to_page((i) >> PAGE_SHIFT);
        
        is = min((size_t) PAGE_SIZE, (size_t) (res->end - i + 1));

		v = kmap(p);
		s = write_vaddr(v, is);
		kunmap(p);

		if (s != is) {
			DBG("Error sending page %d", s);
			return (int) s;
		}				
	}

	return 0;
}
*/

static int write_vaddr(void * v, size_t is) {
	return (method == LIME_METHOD_TCP) ? write_vaddr_tcp(v, is) : write_vaddr_disk(v, is);
}

static int setup(void) {
	return (method == LIME_METHOD_TCP) ? setup_tcp() : setup_disk();
}

static void cleanup(void) {
	return (method == LIME_METHOD_TCP) ? cleanup_tcp() : cleanup_disk();
}

void cleanup_module(void)
{
	
}

MODULE_AUTHOR ("Joe T. Sylve joe@digitalforensicssolutions.com, Tim Xia xialiangzhao@baidu.com");
//MODULE_DESCRIPTION ("Perform physical memory dump on Linux and Android devices.");
MODULE_DESCRIPTION ("Dump BangBang Loaded ODEX File");
MODULE_LICENSE("GPL");
