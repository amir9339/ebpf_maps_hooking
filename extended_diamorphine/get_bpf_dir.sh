# Download LInux 5.4 from git for htab_elem definition
VERSION_TAG=v5.4

cd extended_diamorphin
git clone https://github.com/torvalds/linux.git

cd linux
git checkout tags/$VERSION_TAG
cp -R kernel/bpf/ ../src/bpf