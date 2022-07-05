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