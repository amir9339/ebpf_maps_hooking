## Hiding from Tracee
 
This repo contains a simple POC of a binary intended to hook the communication between [Tracee](https://github.com/aquasecurity/tracee) userspace program and eBPF.

<br>

### Some first thoughts:

There are two components in Tracees's architecture:
- **tracee-ebpf** - Linux Tracing and Forensics using eBPF
- **tracee-rules** - Runtime Security Detection Engine

When running tracee using the official docker image we can see that the two components are running separately as two different processes.


``` bash
$ pstree
docker-init───containerd-shim─┬─entrypoint.sh─┬─tracee-ebpf───15*[{tracee-ebpf}]
                              │               └─tracee-rules───10*[{tracee-rules}]
                              └─10*[{containerd-shim}]
```

tracee-ebpf is the process that communicates with eBPF while tracee-rules is in charge of the Rules engine.

The two communicate using a custom protocol via the file /tmp/tracee/pipe which is defined in the file [tracee/builder/entrypoint.sh](https://github.com/aquasecurity/tracee/blob/144179185b0b2c86c9ba79cd8f4d0021d4b95a77/builder/entrypoint.sh) as an environment variable named `TRACEE_PIPE`.

<br>

### Next research

To hide my rootkit from Tracee, I want to hook the communication between `tracee-ebpf` and eBPF. I think it will be possible to hook some of the pipes it uses. 

To list them we can run the command `sudo ls -l /proc/$(pidof tracee-ebpf)/fd`

> Note that this output only shows unique types of files (There are many anon_inode:bpf-prog and perf_events)
``` bash
lr-x------ 1 root root 64 Jul  5 09:53 0 -> /dev/null
lrwx------ 1 root root 64 Jul  5 09:53 1 -> /dev/pts/0
lrwx------ 1 root root 64 Jul  5 09:53 10 -> anon_inode:bpf-map
lrwx------ 1 root root 64 Jul  5 09:53 100 -> anon_inode:bpf-prog
lr-x------ 1 root root 64 Jul  5 09:53 122 -> anon_inode:bpf-raw-tracepoint
lrwx------ 1 root root 64 Jul  5 09:53 123 -> 'anon_inode:[perf_event]'
lrwx------ 1 root root 64 Jul  5 09:53 143 -> 'anon_inode:[eventpoll]'
l-wx------ 1 root root 64 Jul  5 09:53 158 -> /tmp/tracee/pipe
lrwx------ 1 root root 64 Jul  5 09:53 159 -> 'socket:[587880]'
lr-x------ 1 root root 64 Jul  5 09:53 3 -> anon_inode:btf
lr-x------ 1 root root 64 Jul  5 09:53 5 -> 'pipe:[584520]'
```

___
# Remove this
### Quick explanation about each of the anonymous inode (`anon_inode`) types shown in the output above
All of these files are related to the eBPF program and to the communication mechanism between the eBPF programs and the user-space program `tracee-ebpf`. It uses anonymous inodes because those files are not being stored on disk but only in memory.

- anon_inode:**bpf-map** -
- anon_inode:**bpf-prog** -
- anon_inode:**bpf-raw-tracepoint** -
- anon_inode:**[perf_event]** - 
- anon_inode:**[eventpoll]** - 
- anon_inode:**btf** - 
___

<br>

### How to bypass Tracee’s “Syscall Hooking Detection” mechanism?
#### A high level overlook

To detect Syscall hooking, Tracee iterates over the syscalls addresses in the syscall table and checks if the address points to kernel memory. This way, Tracee can detect malformed entries in the syscall table.

[This sample](https://github.com/aquasecurity/tracee/blob/afc4094c172398749325d9a01230d4d2b3884f67/pkg/ebpf/c/tracee.bpf.c#L2922) from Tracee’s code performs this task:

``` c
/* invoke_print_syscall_table_event submit to the buff the syscalls function handlers address from
 * the syscall table. the syscalls are strode in map which is syscalls_to_check_map and the
 * syscall-table address is stored in the kernel_symbols map.
 */
static __always_inline void invoke_print_syscall_table_event(event_data_t *data)
{
    int key = 0;
    u64 *table_ptr = bpf_map_lookup_elem(&syscalls_to_check_map, (void *) &key);
    if (table_ptr == NULL) {
        return;
    }

    char syscall_table[15] = "sys_call_table";
    unsigned long *syscall_table_addr = (unsigned long *) get_symbol_addr(syscall_table);
    u64 idx;
    u64 *syscall_num_p; // pointer to syscall_number
    u64 syscall_num;
    unsigned long syscall_addr = 0;
    int monitored_syscalls_amount = 0;
#if defined(bpf_target_x86)
    monitored_syscalls_amount = NUMBER_OF_SYSCALLS_TO_CHECK_X86;
    u64 syscall_address[NUMBER_OF_SYSCALLS_TO_CHECK_X86];
#elif defined(bpf_target_arm64)
    monitored_syscalls_amount = NUMBER_OF_SYSCALLS_TO_CHECK_ARM;
    u64 syscall_address[NUMBER_OF_SYSCALLS_TO_CHECK_ARM];
#else

    return
#endif

    __builtin_memset(syscall_address, 0, sizeof(syscall_address));
// the map should look like [syscall number 1][syscall number 2][syscall number 3]...
#pragma unroll
    for (int i = 0; i < monitored_syscalls_amount; i++) {
        idx = i;
        syscall_num_p = bpf_map_lookup_elem(&syscalls_to_check_map, (void *) &idx);
        if (syscall_num_p == NULL) {
            continue;
        }
        syscall_num = (u64) *syscall_num_p;
        syscall_addr = READ_KERN(syscall_table_addr[syscall_num]);
        if (syscall_addr == 0) {
            return;
        }
        syscall_address[i] = syscall_addr;
    }
    save_u64_arr_to_buf(data, (const u64 *) syscall_address, monitored_syscalls_amount, 0);
    events_perf_submit(data, PRINT_SYSCALL_TABLE, 0);
}
```

As you can see, in order to detect the changes, Tracee gets the syscall table address using the function `get_symbol_addr` which is a wrapper around the BPF helper  `bpf_map_lookup_elem()`. Tracee then iterates over the syscall table. For each entry, it checks whether the address is in the Kernel address range (Note that the comparison between the address and the address range is made in the user-mode process).

In order to bypass Tracee’s detection we'll need to hook and alter the function `get_symbol_addr()` and replace the return value of the call to `get_symbol_addr(syscall_table)` with a pointer to a “proper table” (a table without the changes made by our rootkit). 

With this hook, Tracee will not be able to detect changes in the syscall table because it will point to a “proper table” each time it tries to detect changes in the Syscall Table.

<br>

### How do we hook and alter `get_symbol_addr()`?

Because this is a wrapper around `bpf_map_lookup_elem()` we'll need to deep dive into this function kernel code and find a good point to place a kprobe.

