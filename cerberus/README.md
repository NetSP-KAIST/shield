# cerberus-reproduce
You need [Intel P4 Studio](https://www.intel.com/content/www/us/en/products/details/network-io/intelligent-fabric-processors/p4-studio.html) or [Open P4 studio](https://github.com/p4lang/open-p4studio) to use bf-sde.

> [!NOTE]
> This artifact requires strict hardware and software constraints. 

> [!NOTE]
> We assume your username of switch as `edgecore`.



## Compile p4 program

```
$ cd bf-sde-XXX
$ . ../tools/set_sde.sh

$ pwd
/home/edgecore/shield/cerberus
$ /home/edgecore/tools/p4_build.sh /home/edgecore/shield/cerberus/data-plane/cerberus-c2.p4

# For run python control plane, else goto control plane build
$ ./run_switchd.sh -p cerberus-c2

# run below on bfshell if you wnat to run python version of Cerberus
ucli
port-add 11/- 100G RS
port-add 12/- 100G RS
port-enb 11/-
port-enb 12/-
port-add 33/- 10G NONE
an-set 33/- NONE
port-enb 33/-
pm show
```

## Build and run contorl plane
### Python version
```
sudo -E $SDE_INSTALL/bin/python3.10 ./control-plane/run_cp_scapy.py
```

### DPDK version
We use `vfio-pci` for dpdk, so check if IOMMU setting in switch BIOS is enabled.
```
git clone https://github.com/DPDK/dpdk.git
cd dpdk
git checkout v24.11
meson setup build
sudo ninja -C build install
sudo ldconfig

export DPDK_SRC=~/dpdk
export DPDK_BUILD=~/dpdk/build

cd ./control-plane/dpdk
mkdir build
cd build
cmake ..
make
cd ../

sudo dpdk-devbind.py -u 0000:04:00.0
sudo dpdk-devbind.py --bind=vfio-pci 0000:04:00.0
sudo dpdk-devbind.py --status

./run_cp.sh
```