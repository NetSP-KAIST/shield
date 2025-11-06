# Shield
Shield: Shared Hierarchical Registers for Layered Decay

> [!NOTE]
> This artifact requires strict hardware and software constraints. 

## Compile p4 program

```
$ cd bf-sde-XXX
$ . ../tools/set_sde.sh
$ pwd
/home/edgecore/shield
$ /home/edgecore/tools/p4_build.sh /home/edgecore/shield/shield-sketch/shield.p4
```

## Run p4 program and control plane

Run P4 program
```
$ ./run_switchd.sh -p shield

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

Run control plane
```
sudo -E $SDE_INSTALL/bin/python3.10 run_cp_scapy.py
```