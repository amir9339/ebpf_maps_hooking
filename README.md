## 🙈 Hiding from Tracee

This repository contains the POC developed while writing [the paper](docs/A_weakness_in_eBPF_based_runtime_security_applications.md): “A weakness in eBPF-based runtime security applications”.

The paper presents a weak point in the architecture of eBPF-based security applications that are heavily based on eBPF maps. In the paper, I discussed [Tracee](https://github.com/aquasecurity/tracee), a runtime security application built by Aqua Security as an example of a security product based only on eBPF. The POC was developed to bypass one detection method of Tracee.

### 📁 The repository includes four directories:
```
├── docs                           includes the paper in Markdown format
├── extended_diamorphin            The full POC
├──  ftrace__htab_map_lookup_elem  The code for the hook
└── setup_env                      environment setup scripts
```

> ### ⚠️ It is necessary to note that
> The code here relies on static [kernel code](https://elixir.bootlin.com/linux/latest/source/kernel/bpf) (*extended_diamrphine/src/bpf/* *) and was tested only on Ubuntu 18.04 / 20.04 with Kernel version 5.4.0 
> It will probably **not run** on other kernel versions!
    
>If you want to run on a different kernel, there is a script called `get_bpf_dir.sh` that update the static code

### 🏃‍♀️ Run and test 
Few step are required before running the POC. 

First, **setup** the development environment:
``` bash
# Setup dev environment
cd setup_env/
./setup_env.sh

# Compile Diamorphine and load to the kernel
cd Diamorphine/
make
sudo insmod diamorphine.ko

# Compile Tracee from source
cd tracee
make

## Compile the program
cd ../../extended_diamorphine
make
```

**Run**:
``` bash
sudo insmod diamorphine.ko
```

**Unload**:
``` bash
# Uninstall Diamorphine
kill -63 0 && sudo rmmod diamorphine
sudo rmmod htab
```

### 🧪 Example output
``` bash
$ cd setup_env/tracee/
$ sudo ./dist/tracee-ebpf -t e=hooked_syscalls
TIME             UID    COMM             PID     TID     RET              EVENT                ARGS
```

``` bash
$ sudo dmesg | tail

# Fake table allocated successfully
[4.874517] Fake table addr: 00000000198b1f93 
# The hook succeeded!
[5.172042] The original syscall_table_addr from map: 000000000a0fb5da But 00000000827549d2 returned 
```

