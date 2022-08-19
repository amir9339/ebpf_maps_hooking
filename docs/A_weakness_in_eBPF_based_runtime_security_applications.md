## A weakness in eBPF-based runtime security applications
### By Amir Sheffer
<br>

### Abstract
This paper presents a weak point in the architecture of eBPF-based security applications that are heavily based on eBPF maps. In this paper I will be discussing Tracee, a runtime security application built by Aqua Security as an example of a security product based only on eBPF. I will demonstrate a POC I developed to bypass one detection method of Tracee.

<br>

### 1. Introduction
During the last BSides TLV event, two Security Researchers from Aqua Security, got on stage and gave a great talk [1]. They presented a new detection mechanism added to Tracee [2], an open-source Runtime Security and Forensics tool.

The researchers demonstrated how Tracee could detect “Syscall Table Hooking,” generally used by rootkits, and showed Diamorphine (an open-source Rootkit used in the wild by Team TNT) as an example. With this new mechanism, Tracee can now detect hooks even after the malware is already loaded to the Kernel.

At the end of the talk, an idea came to me: to attack eBPF Maps, one of eBPF’s main components, which just so happens to be heavily used in Tracee.
This paper will spotlight a weak point in eBPF-based security products. I will explain a feature that I added to Diamorphine’s code to evade one detection method used by Tracee. 

It is important to note that while this article will show how to evade Tracee, it is only an example of one security product subject to this kind of attack, and any security product that relies only on eBPF can be evaded using similar techniques.

But before I can show the attack itself, it is necessary to introduce some basic concepts and subjects:

- **eBPF Maps**
- **Tracee’s Architecture**
- **Why Diamorphine?**
- **Tracee’s detection method**

and in the second part (starting in section 6) of this paper, I’ll talk about:

- **The method I used to evade Tracee**
- **How to detect the method I used**
- **An advanced, better method**

### 2. eBPF Maps

A detailed introduction to eBPF is beyond this paper's scope. But for those of you who don't know, eBPF is a new technology embedded in the Linux Kernel. eBPF allows running sandboxed programs in a privileged context safely and efficiently.

eBPF Maps [3] is the mechanism that allows storing and retrieving data between different eBPF programs and between eBPF programs and applications in the user space.

Basically, eBPF Maps store a key/value using an arbitrary structure. 
The following diagram is taken from the official documentation of eBPF [4]. 
It presents how eBPF Maps can be used to pass and retrieve data between a user space application (the left process), another eBPF program that hooks a Syscall, and an eBPF program that hooks the TCP/IP Stack (on the right).

<img src="https://ebpf.io/static/map_architecture-6b0f37504ff7d44559b740bab0012d02.png" alt="eBPF maps arch" width="60%"/>

Interacting with Maps can be done from either user space or kernel space, using some **lookup/update/delete** primitives [5]. The common helper functions are almost identical in user mode and the Kernel.

The kernel helper functions are defined as follows:
``` C
void bpf_map_lookup_elem(map, void *key. ...);
void bpf_map_update_elem(map, void *key, ..., __u64 flags);
void bpf_map_delete_elem(map, void *key);
```

While the user space helpers look like this:
``` C
int bpf_map_lookup_elem(int fd, void *key, void *value);
int bpf_map_update_elem(int fd, void *key, void *value, __u64 flags);
int bpf_map_delete_elem(int fd, void *key);
```

As you can see, in order to access a map you need the map’s object and a key that holds some data.

Later in this paper, we’ll dig deeper into the kernel functions that perform map operations and play around with them while exploiting some of their weaknesses.

### 3. How does Tracee work?
Tracee is an awesome tool. It gives a researcher the capability to dig into a working Kernel and trace some of its important events. Many tools give you the ability to do such things (Like Ftrace’s TraceFS), but Tracee is very convenient and has layers of abstraction that let you stay focused on the events you're searching for.

Tracee is composed of two sub-projects:
- Tracee-eBPF - A tracing and forensics tool which massively uses eBPF
- Tracee-Rules - A runtime Security Detection Engine

In this paper, we’ll focus on Tracee-eBPF, which itself consists of two parts: a user space program written in Go and some eBPF programs.

```
┌───────────────┐
│  tracee-ebpf  │
└▲─────────────┬┘
─┼─Kernel──────┼─
┌┴─────────────▼┐
│   eBPF Maps   │
└▲─────────────┬┘
┌┴─────────────▼┐
│ eBPF programs │
└───────────────┘
```

More precisely, we’ll focus on the “pipe” that is used to move data between the user mode application and the eBPF program: eBPF Maps.

Basically, Tracee places hooks in different parts of the Kernel code using tracing mechanisms like Kprobes and Tracepoints (which, sadly, we won’t get into). When those hooks trigger events, they are sent to the user space program.

As well as sending events from eBPF programs up to the user space, Tracee uses custom hooks to send commands from the user space down to the eBPF programs. Using this method, Tracee sends a request to the eBPF program to look for malicious Syscall Hooks.

### Why Diamorphine?	

Diamorphine [10] is a simple LKM Rootkit that the researchers from Aqua used as an example. They chose it because of its simplicity, use in the wild (by Team TNT), and open-source code base.

The malware can hide from the kernel’s modules list, hide any process, file or directory, and give “root” permissions to any given user.

Diamorphine achieves part of its abilities by hooking the Syscall Table. It hooks three Syscalls: *getdents & getdents64* to hide files and *kill*, to be controlled from user space using custom signals.


``` C
/* Diamorphine changes the entries in the sys_call_table to point to its functions */
__sys_call_table[__NR_getdents] = (unsigned long) hacked_getdents;
__sys_call_table[__NR_getdents64] = (unsigned long) hacked_getdents64;
__sys_call_table[__NR_kill] = (unsigned long) hacked_kill;
```

Later in the paper, I’ll present the code I added to Diamorphine to bypass Tracee’s detection.

### 5. Tracee’s detection method in a nutshell
Because I didn’t attack the detection logic but rather another part of Tracee’s design, I’m not going to go into Tracee’s detection mechanism. The Team at Aqua published a great post [6] on their blog about it, so I invite you to check it out.

In a nutshell: the original functions in the kernel are stored in a specific memory map region called *core_text*. When a new kernel module is loaded to the kernel, its functions are written in another memory region, different from *core_text*. Tracee iterates over the Syscall Table and searches for functions whose code is not stored in the *core_text* memory region.

Because Diamorphione edits the Syscall Table, the entries of *getdents, getdents64*, and *kill* are pointed to Diamorphine’s memory region, and Tracee can easily detect those hooks.

```
/*
┌─Syscall Table─┐      ┌─Kernel mem─┐
│               ├──────►            │
│ sys_read      │    ┌─► core_text  │
├───────────────┤    │ ┌────────────┤
│ sys_write     ├────┘ │            │
├───────────────┤      └────────────┤
│ hacked_kill   ├──────► Diamorphie │
└───────────────┘      └────────────┘
 /*
```

The flow of this program is very simple:
- The user space program sends the eBPF program the Syscall Table address and the Syscalls names it needs to check using eBPF Maps
- The user space program sends an IOCTL Syscall to the eBPF program, and asks it to check the Syscall Table
- The eBPF program iterates over the Syscall Table, obtaining the Syscalls addresses and sends it over to the user space program
- The user space program checks if the addresses are not pointing to the core_text memory region and prints the output to the user

```
User space                   │  Kernel space
                             │
┌────────────────────────┐   │           ┌────────────────┐
│ Execute Tracee with    ◄───┼──┐        │ Syscalls Table │
│ detect_hooked_syscalls │   │  │        └──────────────▲─┘
└─┬──────────────────────┘   │  │                       │
  │                          │  │                       │
  │                          │  │                       │
┌─▼──────────────────────┐   │  ├───────────────────────┴─┐
│ Syscalls Table Address │      │ Catch the call &        │
│ eBPF Map: ksymbols_map │IOCTL─► fetch the Syscall Table │
└────────────────────────┘      └─────────────────────────┘
```

The code snippet below is taken from *tracee/pkg/ebpf/c/tracee.bpf.c*. It shows a part of the eBPF function that iterates over the Syscall Table from the eBPF side:

``` C
/* invoke_print_syscall_table_event submit to the buff the syscalls function handlers address from
 * the syscall table. The syscalls are stored in a map which is syscalls_to_check_map, and the
 * syscall-table address is stored in the kernel_symbols map.
 */
static void invoke_print_syscall_table_event(event_data_t *data){
    int key = 0;
    u64 *table_ptr = bpf_map_lookup_elem(&syscalls_to_check_map, (void *) &key);

    char syscall_table[15] = "sys_call_table";
    unsigned long *syscall_table_addr = (unsigned long *) get_symbol_addr(syscall_table);
    /*
        The code has been reduced for readability
    */
}
```

The important line from the code snippet above is the one that uses `get_symbol_addr`: This line uses an internal wrapper around the eBPF helper `bpf_map_lookup_elem()`, all it does is copying the value of symbol_name (which in this case, is the symbol *sys_call_table*) to a buffer, while under the hood, it accesses the map *ksymbols_map*, which is an eBPF map that Tracee uses to pass addresses of some symbols between the userspace and the eBPF programs.


## 6. Part 2 - Hook the eBPF map and evade the detection

Now that we understand Tracee’s architecture, its detection mechanism, and how it passes data between the user space and the eBPF programs, we can start talking about the weak part of its design.

We assume that we’re already running as an LKM and have full privileges on the machine.

If we had a way to hook the `bpf_map_lookup_elem()` helper function that is used within the eBPF programs, we could inject other data into the maps Tracee is looking for and alter the program’s data. Of course, because we’re running on a Linux machine, there is always a good way to hook kernel functions. 

Many tracing systems are built into the kernel, which allows us to play with kernel functions. For the purposes of this paper, we’ll use Ftrace to perform this task (later, we’ll see exactly how and why).

> It is worth mentioning that if we’re already using Ftrace for other kernel function hooking, we can use it to hook those Syscalls and evade Tracee’s detection. By hooking eBPF Maps, we can completely change Tracee's flow and bypass other detections and other eBPF-based security products.

We need to hook the lookup call to the map *“ksymbols_map”* with the key “sys_call_table,” which holds the Syscall Table address, and replace it with another address to a fake proper Syscall Table we’ve created earlier. This way, when Tracee iterates over the Syscall Table and searches for function hooks, it will iterate over the fake Syscall Table we gave and show no detections.

Let’s open the kernel code and look for the function call chain that is called from the kernel  when the function `bpf_map_lookup_elem()` is used.

It all starts in the file *kernel/bpf/helpers.c* in [this line](https://elixir.bootlin.com/linux/latest/source/kernel/bpf/helpers.c#L33):
``` C
BPF_CALL_2(bpf_map_lookup_elem, struct bpf_map *, map, void *, key)
{
	WARN_ON_ONCE(!rcu_read_lock_held() && !rcu_read_lock_bh_held());
	return (unsigned long) map->ops->map_lookup_elem(map, key);
}
```

Further down the call chain, the function `__htab_map_lookup_elem()` from [*kernel/bpf/hashtab.c*](https://elixir.bootlin.com/linux/latest/source/kernel/bpf/hashtab.c#L642) will be called and will perform the lookup on the hash table associated with the eBPF Map. This function gets a map and a key (like buried treasure) as arguments and returns a pointer to the value saved under the key. I placed a Ftrace hook on this function, and after a quick check that compares the map and the key names to the ones we’re looking for, it returns the address of the fake Syscall Table instead of the real address from the eBPF map. The code I used for this is:
``` C
static void *hook_htab_map_lookup_elem(struct bpf_map *map, void *key)
{
    /*
        This function hooks the kernel function `__htab_map_lookup_elem`.
        It searches for a lookup to a specific map: `ksymbols_map`
            and a specific key in it: `sys_call_table`.
        If it hooks this call, it returns an address to a fake Syscalls table,
        else, it continues to the original function and performs a normal lookup.
    */

    char* key_name = (char *)key;
    char map_name[BPF_OBJ_NAME_LEN];
    strncpy(map_name, map->name, BPF_OBJ_NAME_LEN);

    // Check if the hooked map is the one we're looking for
    if ( strncmp(key_name, "sys_call_table", sizeof("sys_call_table")) == 0
        && strncmp(map_name, "ksymbols_map", sizeof("ksymbols_map")) == 0 )
        {
            extern unsigned long *fake_sys_call_table_addr;
            pr_info("The original syscall_table_addr from map is: %p But %p returned\n", *syscall_table_addr, *fake_sys_call_table_addr);
            return *fake_sys_call_table_addr;
        }
    return orig_htab_map_lookup_elem(map, key);
}
```

To perform the actual hook, first I tried to use Kprobes because I had previous experience with it but encountered a problem. The specific code I’m trying to hook in Tracee’s eBPF component is running under the context of an eBPF program defined as such:

``` C
SEC("kprobe/security_file_ioctl")
int BPF_KPROBE(trace_tracee_trigger_event)
```

The function is of type BPF_KPROBE and therefore, the code that is run under its context and all the calls it performs can’t be hooked using a Kprobe. Luckily, Ftrace uses a different mechanism and can hook this specific function.

### 7. Diamorphine extension

As mentioned above, I extended Diamorphine with the ability to evade Tracee’s detection using Ftrace [7]. I used a small library for Ftrace hooks created by [Harvey Phillips](https://github.com/xcellerator) [8] and added the function explained previously.

Now, when running Diamorphine with our changes, while Tracee is running on the machine, Tracee won’t detect the Syscall Table Hooking and will return nothing when running this command:
``` bash
$ sudo ./dist/tracee-ebpf -t e=hooked_syscalls
TIME             UID    COMM             PID     TID     RET            EVENT                ARGS
```

### 8. Detection

As a security researcher, the first question I had was: how do you protect from such attacks, and on top of that - how do you detect them?

Tracee will still be able to watch for module loading, but if Diamorphine is already running on the machine, there are some other ways to detect it. When looking at a live machine, the hook I made will be present in the file: `/sys/kernel/debug/tracing/enabled_functions` exported by the DebugFS. This method is specific to hooks using Ftrace though, so a different method cannot be detected this way.

At the BlackHat 2021 conference, Andrew Case and Golden G. Richard III from the contributors' team of the Volatility project published a great paper called “Fixing a Memory Forensics Blind Spot: Linux Kernel Tracing” [9]. They presented a few Volatility plugins, and one of them, named “linux_ftrace,” can detect the hooks made by Ftrace, so it should be able to catch the hook I made. 

The plugin relies on the LKMs list, so it won’t be able to find the name of the LKM (because Diamorphine hides from it) but still prints the function name used by Diamorphine. The other plugins they created can detect different hooking methods. Also, some of Volatility’s existing plugins can detect other types of hooks.  

The output above is what the plugin should return after it analyzes a memory sample of a victim machine:

``` bash
$ python vol.py -f victim.lime --profile=LinuxRKDevx64 linux_ftrace
Volatility Foundation Volatility Framework 2.6
Offset             Function           Symbol                        Traces
------------------ ------------------ ----------------------------- ----------------------
0xffffffffc05c2160 0xffffffffc05c0000 fh_ftrace_thunk [ftrace_hook] __htab_map_lookup_elem
```

It’s also possible to add a watchdog to the application design, its sole purpose is to watch for Ftrace hooks or even hooks on the Ftrace framework code itself. This watchdog can be an additional LKM and be protected from Ftrace hooks using a method such as the one presented in [this article](https://www.codeproject.com/Articles/1275114/Hooking-Linux-Kernel-Functions-Part-2-How-to-Hook#Protecting%20a%20Linux%20kernel%20module%20from%20ftrace%20hooks).

### 9. Advanced evasion technique

After finishing this paper, I received a message from a friend who sent me [this project](https://github.com/carloslack/KoviD) [11], an amazing rootkit written by carloslack. One of this rootkit's many features is hiding from detection tools like Tracee that search for Syscall Table Hooking. Its method is better than the one shown in this paper because it searches for the address of the Syscall Table in every lookup call to an eBPF Map and replaces it.

Additionally, it is more generic and can hide from other tools and not just from Tracee. While Carloslack’s method is better than the one presented in this paper, the method used here still shows the fundamental weakness of eBPF-based security products and gives a different and straightforward approach to eBPF maps hooking.

### Conclusion

In this paper, I spotlighted a major weakness in the security of some “runtime security” products that use eBPF as the only tracing component. I used Tracee as an example of such a product, and I presented the extension I added to the Diamorphine code to evade one detection method of Tracee. 

I want to thank Ofek Shaked [13] for his support in writing this paper and Assaf Reich for reviewing this paper.

You can find the source code of the forked Diamorphine and other projects of mine in my own GitHub profile [12].

Thank you very much for reading, and I hope you’ll always find the map and the key!

### References

1. [**Hunting kernel**](https://www.youtube.com/watch?v=Z41WJtFsuGc&ab_channel=BSidesTLV) rootkits with eBPF by Asaf Eitani & Itamar Maouda Kochavi - YouTube
2. [**Tracee**](https://github.com/aquasecurity/tracee) - GitHub, [**Tracee**](https://aquasecurity.github.io/tracee/dev/) - Official website
3. [**eBPF Maps**](https://prototype-kernel.readthedocs.io/en/latest/bpf/ebpf_maps.html) - Kernel documentation
4. [**eBPF Official documentation**](https://ebpf.io/what-is-ebpf#maps)
5. [**BPF Source Code**](https://elixir.bootlin.com/linux/latest/source/kernel/bpf), [**man BPF(2)**](https://man7.org/linux/man-pages/man2/bpf.2.html)
6. [**Hunting Rootkits with eBPF: Detecting Linux Syscall Hooking Using Tracee**](https://blog-aquasec-com.cdn.ampproject.org/c/s/blog.aquasec.com/linux-syscall-hooking-using-tracee?hs_amp=true) - Itamar Maouda
7. [**Ftrace Documentation**](https://www.kernel.org/doc/Documentation/trace/ftrace.txt)
8. [**ftrace_helper**](https://gist.github.com/xcellerator/ac2c039a6bbd7782106218298f5e5ac1#file-ftrace_helper-h) - Github Gist
9. [**Fixing a Memory Forensics Blind Spot: Linux Kernel Tracing**](https://i.blackhat.com/USA21/Wednesday-Handouts/us-21-Fixing-A-Memory-Forensics-Blind-Spot-Linux-Kernel-Tracing-wp.pdf) - Andrew Case and Golden G. Richard III
10. [**Diamorphine**](https://github.com/m0nad/Diamorphine) - GitHub
11. [**KoviD**](https://github.com/carloslack/KoviD) - GitHub
12. [**amir9339**](https://github.com/amir9339/) - GitHub
13. [**oshaked1**](https://github.com/oshaked1/) - GitHub