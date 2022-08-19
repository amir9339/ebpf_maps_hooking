### ftrace__htab_map_lookup_elem

This directory includes the program that only hooks the function `__htab_map_lookup_elem`.

> This POC was tested only on Ubuntu 18.04 / 20.04 with kernel version 5.4.0. It relies on files (*ftrace__htab_map_lookup_elem/src/bpf/* *) taken from the kernel source code and needs some tweaks if you want to run it on a different kernel.

### Setup:

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
cd ../../ftrace__htab_map_lookup_elem
make
```

### And run:
``` bash
sudo insmod htab.ko
```

### Run Tracee and test
``` bash
cd setup_env/tracee/
sudo ./dist/tracee-ebpf -t e=hooked_syscalls
```
If the loaded successfully, and Diamorphine is running in the background the output will return nothing.

### Unload
``` bash
# Uninstall Diamorphine
kill -63 0 && sudo rmmod diamorphine
sudo rmmod htab
```