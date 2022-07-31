# Install docker dependencies
sudo apt-get update
sudo apt-get install ca-certificates curl gnupg lsb-release

# Add Docker's GPG key
sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg

echo \
    "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
    $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# Install docker
sudo apt-get install docker-ce docker-ce-cli containerd.io docker-compose-plugin

# Pull Tracee's image in advanced
sudo docker pull aquasec/tracee:full
sudo docker pull aquasec/tracee:latest

# Install build-essential for diamorphine compilation
sudo apt-get install build-essential

# Install kmod for insmod command
sudo apt-get install kmod

# Install linux-headers
sudo apt-get install -y linux-headers-$(uname -r)

# Install bcc
sudo apt-get install -y bpfcc-tools

# Install go for Tracee's compilation
sudo apt install golang-go

# Tracee uses libelf-dev
sudo apt-get install -y libelf-dev

# Mount debugfs for better eBPF debugging
sudo mount -t debugfs debugfs /sys/kernel/debug
sudo mount -t tracefs nodev /sys/kernel/debug/tracing

# Clone Tracee's files
git clone https://github.com/aquasecurity/tracee.git

# Finally, Run Tracee
sudo docker run \
  --name tracee --rm -it \
  --pid=host --cgroupns=host --privileged \
  -v /etc/os-release:/etc/os-release-host:ro \
  -e LIBBPFGO_OSRELEASE_FILE=/etc/os-release-host \
  aquasec/tracee:latest

# Run Tracee for Sycalls Table hooking detection only
sudo ./dist/tracee-ebpf -t e=hooked_syscalls \
  -o format:json | ./dist/tracee-rules \
  --input-tracee file:stdin --input-tracee format:json
