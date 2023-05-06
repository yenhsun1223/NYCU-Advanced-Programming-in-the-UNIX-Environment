/*
 * Lab problem set for UNIX programming course
 * by Chun-Ying Huang <chuang@cs.nctu.edu.tw>
 * License: GPLv2
 */
#include <linux/module.h>	// included for all kernel modules
#include <linux/kernel.h>	// included for KERN_INFO
#include <linux/init.h>		// included for __init and __exit macros
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/errno.h>
#include <linux/sched.h>	// task_struct requried for current_uid()
#include <linux/cred.h>		// for current_uid();
#include <linux/slab.h>		// for kmalloc/kfree
#include <linux/uaccess.h>	// copy_to_user
#include <linux/string.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/mman.h>
#include <linux/vmalloc.h>
#include <asm/io.h>
//#include <sys/ioctl.h>
#include "kshram.h"

#ifndef PAGE_SHIFT
#define PAGE_SHIFT 12
#endif

struct kshram_data {
    char *data;
    int size;
};

static struct kshram_data kshram_data[8];
static dev_t devnum;
static struct cdev c_dev;
static struct cdev cdev[8];
static struct class *kshram_class;
//static char *kshram_data[8];
static int KSHRAM_SIZE = 4096;

static int hellomod_dev_open(struct inode *i, struct file *f) {
	//printk(KERN_INFO "kshram: device opened.\n");
	//int id = MINOR(f->f_inode->i_rdev);
	//long mem_size = ioctl(f, KSHRAM_GETSIZE);
    struct kshram_data *data = kzalloc(sizeof(struct kshram_data), GFP_KERNEL);
	//printk(KERN_INFO "kshram/mmap: idx %d size %d\n", id, kshram_data[id].size);    
    if (!data) {
        return -ENOMEM;
    }
    // store the pointer to the allocated data structure in the file's private_data field
    f->private_data = data;	    
	return 0;
}

static int hellomod_dev_close(struct inode *i, struct file *f) {
	//printk(KERN_INFO "kshram: device closed.\n");
    struct kshram_data *data = f->private_data;
    if (data) {
        kfree(data->data);
        kfree(data);
        // set the file's private_data field to NULL after freeing the data structure
        f->private_data = NULL;
    }	
	return 0;
}

static ssize_t hellomod_dev_read(struct file *f, char __user *buf, size_t len, loff_t *off) {
	//printk(KERN_INFO "kshram: read %zu bytes @ %llu.\n", len, *off);
	return len;
}

static ssize_t hellomod_dev_write(struct file *f, const char __user *buf, size_t len, loff_t *off) {
	//printk(KERN_INFO "kshram: write %zu bytes @ %llu.\n", len, *off);
	return len;
}

static long hellomod_dev_ioctl(struct file *fp, unsigned int cmd, unsigned long arg) {
	int id = MINOR(fp->f_inode->i_rdev);
    switch (cmd) 
    {
        case KSHRAM_GETSLOTS:
            return 8;
        case KSHRAM_GETSIZE:
            return PAGE_ALIGN(kshram_data[id].size);
        case KSHRAM_SETSIZE: {
        	void *mem = kshram_data[id].data;
        	unsigned long new_size = arg;
        	void *new_mem = krealloc(mem, new_size, GFP_KERNEL);
        	if (!new_mem) return -ENOMEM;
        	kshram_data[id].data = new_mem;
        	kshram_data[id].size = new_size;
            return 0;
		}
        default:
            return -ENOTTY;
    }	
	return 0;
}

static int kshram_mmap(struct file *filp, struct vm_area_struct *vma)
{
    unsigned long page;
    unsigned long size = vma->vm_end - vma->vm_start;
	int id = MINOR(filp->f_inode->i_rdev);
	printk(KERN_INFO "kshram/mmap: idx %d size %d\n", id, kshram_data[id].size); //////
	page = page_to_pfn(virt_to_page(kshram_data[id].data));
    if (remap_pfn_range(vma, vma->vm_start, page, size, vma->vm_page_prot)) {
        printk(KERN_ERR "kshram/mmap: error remapping memory\n");
        return -EAGAIN;
    }

    return 0;
}

static const struct file_operations hellomod_dev_fops = {
	.owner = THIS_MODULE,
	.open = hellomod_dev_open,
	.read = hellomod_dev_read,
	.write = hellomod_dev_write,
	.unlocked_ioctl = hellomod_dev_ioctl,
	.mmap = kshram_mmap,
	.release = hellomod_dev_close
};

static int hellomod_proc_read(struct seq_file *m, void *v) {
	//char buf[] = "`hello, world!` in /proc.\n";
	//seq_printf(m, buf);
    int i;
    for (i = 0; i < 8; i++) {
        seq_printf(m, "%02d: %d\n", i, kshram_data[i].size);  //////////
    }	
	return 0;
}

static int hellomod_proc_open(struct inode *inode, struct file *file) {
	return single_open(file, hellomod_proc_read, NULL);
}

static const struct proc_ops hellomod_proc_fops = {
	.proc_open = hellomod_proc_open,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

static char *hellomod_devnode(const struct device *dev, umode_t *mode) {
	if(mode == NULL) return NULL;
	*mode = 0666;
	return NULL;
}

static int __init hellomod_init(void)
{
	int i;
	struct device *ret;
	// Register character device
	if(alloc_chrdev_region(&devnum, 0, 8, "kshram") < 0)  // 向系統申請一個主設備號
	{
	    printk(KERN_ERR "kshram: Failed to register device number\n");
	    return -1;
	}
		
		
		
	// Create device class	
	kshram_class = class_create(THIS_MODULE, "kshram");
	if(kshram_class == NULL)  // 建立一個設備類別 class
	{
	    unregister_chrdev_region(devnum, 8);
	    return -1;
	    //goto release_region;
	}
		
		
	kshram_class->devnode = hellomod_devnode; // class 的 devnode 欄位設置為 hellomod_devnode 函式的位址


    // Initialize devices
    for (i = 0; i < 8; i++) {
        // Allocate memory using kzalloc
        kshram_data[i].size = KSHRAM_SIZE;
        kshram_data[i].data = kzalloc(kshram_data[i].size, GFP_KERNEL);
        if (!kshram_data[i].data) {
            printk(KERN_ERR "kshram: Failed to allocate memory\n");
            for (i--; i >= 0; i--) {
				struct page *page = virt_to_page(kshram_data[i].data);
				SetPageReserved(page);            
                kfree(kshram_data[i].data);
                device_destroy(kshram_class, MKDEV(MAJOR(devnum), i));
            }
            class_destroy(kshram_class);
            unregister_chrdev_region(devnum, 8);
            return -ENOMEM;
        }

        // Create device file
        ret = device_create(kshram_class, NULL, MKDEV(MAJOR(devnum), i), NULL, "kshram%d", i);
        
        if (IS_ERR(ret)) {
            printk(KERN_ERR "kshram: Failed to create device file\n");
            for (i--; i >= 0; i--) {
				struct page *page = virt_to_page(kshram_data[i].data);
				SetPageReserved(page);             
                kfree(kshram_data[i].data);
                device_destroy(kshram_class, MKDEV(MAJOR(devnum), i));
            }
            class_destroy(kshram_class);
            unregister_chrdev_region(devnum, 8);
            return PTR_ERR(ret);
        }
		cdev_init(&cdev[i], &hellomod_dev_fops);
		if (cdev_add(&cdev[i], MKDEV(MAJOR(devnum), i), 1) == -1) {
		    printk(KERN_ERR "kshram: Failed to add cdev %d\n", i);
		    device_destroy(kshram_class, MKDEV(MAJOR(devnum), i));
		    kfree(kshram_data[i].data);
		    for (i--; i >= 0; i--) {
				struct page *page = virt_to_page(kshram_data[i].data);
				SetPageReserved(page); 		    
		        cdev_del(&cdev[i]);
		        device_destroy(kshram_class, MKDEV(MAJOR(devnum), i));
		        kfree(kshram_data[i].data);
		    }
		    class_destroy(kshram_class);
		    unregister_chrdev_region(devnum, 8);
		    return -1;
		}        
    }

	
	//if(device_create(kshram_class, NULL, devnum, NULL, "kzalloc_dev") == NULL)
	//	goto release_class;
		
	cdev_init(&c_dev, &hellomod_dev_fops);  // 初始化字符設備 c_dev，將其操作方法設置為 hellomod_dev_fops
	if(cdev_add(&c_dev, devnum, 1) == -1)
	{
		printk(KERN_ERR "kshram: Failed to add cdev\n");
		for (i = 0; i < 8; i++) {
			struct page *page = virt_to_page(kshram_data[i].data);
			SetPageReserved(page); 		
		    cdev_del(&cdev[i]);
		    device_destroy(kshram_class, MKDEV(MAJOR(devnum), i));
		    kfree(kshram_data[i].data);
		}
		class_destroy(kshram_class);
		unregister_chrdev_region(devnum, 8);
		return -1;	
	}
		//goto release_device; // 向系統註冊字符設備

	// create proc
	proc_create("kshram", 0, NULL, &hellomod_proc_fops);


	for (i = 0; i < 8; i++) {
		printk(KERN_INFO "kshram%d: %lu bytes allocated @ %px\n", i, (unsigned long)kshram_data[i].size, kshram_data[i].data);
	}

	printk(KERN_INFO "kshram: initialized.\n");
	return 0;    // Non-zero return means that the module couldn't be loaded.

//release_device:
//	device_destroy(kshram_class, devnum);
//release_class:
//	class_destroy(kshram_class);
//release_region:  // 釋放申請的主設備號
//	unregister_chrdev_region(devnum, 8);
//	return -1;
}

static void __exit hellomod_cleanup(void)
{
	int i;
	remove_proc_entry("kshram", NULL);

	cdev_del(&c_dev);
    for (i = 0; i < 8; i++) {
        device_destroy(kshram_class, MKDEV(MAJOR(devnum), i));
        kfree(kshram_data[i].data);
    }	
	//device_destroy(kshram_class, devnum);
	class_destroy(kshram_class);
	unregister_chrdev_region(devnum, 8);

	printk(KERN_INFO "kshram: cleaned up.\n");
}

module_init(hellomod_init);
module_exit(hellomod_cleanup);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Yen-Hsun Chu");
MODULE_DESCRIPTION("The unix programming course demo kernel module.");
