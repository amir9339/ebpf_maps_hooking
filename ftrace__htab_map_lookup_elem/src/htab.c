#include <linux/module.h>

#include "sys_call_table.c"
#include "hooks.h"
#include "htab.h"

int hooks_installed = 0;

static int __init htab_init(void)
{
    pr_info("Inserted htab\n");
 
    // Create the fake syscall table
    fake_sys_call_table_addr = create_fake_sys_call_table();
    if (fake_sys_call_table_addr){
        pr_info("Fake table addr: %p\n", fake_sys_call_table_addr);
    }

    int err;
    err = register_hooks();
    if (err) {
        pr_err("htab: failed registering hooks (error code %d)\n", err);
    }
    
    hooks_installed = 1;
    return 0;
}

static void __exit htab_exit(void)
{
    if (hooks_installed)
        unregister_hooks();
    pr_info("Removed htab\n");
}

module_init(htab_init)
module_exit(htab_exit)
MODULE_LICENSE("GPL");
