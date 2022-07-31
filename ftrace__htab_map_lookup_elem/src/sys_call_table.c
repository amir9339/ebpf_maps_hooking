#include <linux/sched.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/dirent.h>
#include <linux/slab.h>
#include <linux/version.h> 

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 13, 0)
#include <asm/uaccess.h>
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
#include <linux/proc_ns.h>
#else
#include <linux/proc_fs.h>
#endif

unsigned long *
get_syscall_table_bf(void) 
{
	unsigned long *syscall_table;
	
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 4, 0)
#ifdef KPROBE_LOOKUP
	typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
	kallsyms_lookup_name_t kallsyms_lookup_name;
	register_kprobe(&kp);
	kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
	unregister_kprobe(&kp);
#endif
	syscall_table = (unsigned long*)kallsyms_lookup_name("sys_call_table");
	return syscall_table;
#else
	unsigned long int i;

	for (i = (unsigned long int)sys_close; i < ULONG_MAX;
			i += sizeof(void *)) {
		syscall_table = (unsigned long *)i;

		if (syscall_table[__NR_close] == (unsigned long)sys_close)
			return syscall_table;
	}
	return NULL;
#endif
}

// My code begins here
#include <asm-generic/unistd.h>

int test_fake_table(unsigned long *fake_table, unsigned long *orig_table){
	/* 
	This is a testing fucntion. 
	This function checks that the creation of the fake table was successful.
	To do so, it compares between the values of the __NR_kill entry of 
		the original table and the new - fake table.
	*/

	unsigned long orig_kill = (unsigned long) orig_table[__NR_kill];
	unsigned long fake_kill = (unsigned long) fake_table[__NR_kill];

	if (orig_kill == fake_kill){
		return 1; // Table creation completed successfully
	}
	return 0;
}

unsigned long * create_fake_sys_call_table(void){
    /* This function allocates a fake table and returns it's address. */

	// Get a pointer to the original syscall table
    unsigned long *orig_syscall_table;
    orig_syscall_table = get_syscall_table_bf();

	// Allocate memory for the fake table
    unsigned long sys_ni_syscall(void); // Define syscall entry
    int sys_call_table_size = (sizeof(sys_ni_syscall) * 4) * __NR_syscalls; // Calculate size of fake table
    unsigned long *fake_sys_call_table_addr = (unsigned long *) vmalloc(sys_call_table_size * __NR_syscalls * 4); // Allocate mem for fake table
    
	// Check that the allocation succeeded
	if (fake_sys_call_table_addr == NULL) {
		printk("Could not allocate mem for fake table\n");
		return 0;
	}

	memcpy(fake_sys_call_table_addr, orig_syscall_table, sys_call_table_size);

	if (test_fake_table(fake_sys_call_table_addr, orig_syscall_table) == 0){
		pr_info("Fake table creation failed :( \n");
		return 0;
	}
	
	return fake_sys_call_table_addr;
}
