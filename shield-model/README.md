# Files and Directories

- layered_cms.p4: Implementation of Shield sketch data plane
- setup.py: Sets tables of data plane
- ptf-tests: Directory containing PTF tests
- run_cp_scapy.py: Implementation of Shield sketch control plane (not run with PTF tests)
- cms.py, co_monitor.py, crc.py, send_packets.py: Implementation of CMS, co-monitoring, CRC, and packet sending utility
- generate_management_packets.py: Generate management packet pcap used in control plane (management_packets_16.pcap, management_packets_17.pcap)

# PTF Tests

PTF test is composed as follows:
- overflow.py
  - SendToLayer1: Send packets affecting layer 1
  - SendToLayer2: Send packets affecting layer 1 and 2
  - SendToLayer3: Send packets affecting layer 1, 2, and 3
  - SendToControlPlane: Send packets affecting layer 1, 2, 3, and control plane - commented out since software is to slow to get this test passed
- decay.py
  - DecayLayer2: Send packets affecting layer 1 and 2, and see whether the value on layer 2 is well decayed - prone to failure than other test cases, because software processing speed is slow
  - DecayLayer3: Send packets affecting layer 1, 2, and 3, and see whether the value on layer 3 is well decayed - commented out since software is to slow to get this test passed

# Running PTF Tests

Suppose tools directory is $TOOLS and this directory is located at $CURDIR.   
You can find tools for Tofino on [P4ica](https://github.com/P4ica/tools) and SDE on [Open P4 Studio](https://github.com/p4lang/open-p4studio).
After downloading and installing tools and SDE, please set up the manifest file and link `p4c` to `bf-p4c`.
```
cd $SDE_INSTALL/bin
ln -s p4c bf-p4c
cd $SDE
echo "-DP4C=$SDE_INSTALL/bin/p4c" > ./bf-sde-open-p4studio.manifest
```

Below compiles Shield sketch data plane.
```
$TOOLS/p4_build.sh $CURDIR/layered_cms.p4
```

First, run the following at a terminal. This starts Shield sketch inside the model.
```
sde; ./run_tofino_model.sh -p layered_cms -f '$CURDIR/ptf-tests/ports_model.json'
```

Then, type the following in another terminal. This runs the driver.
```
sde; ./run_switchd.sh -p layered_cms
```

Next, type the following in yet another terminal. This runs the PTF tests.
```
sde; ./run_p4_tests.sh -p layered_cms -f $CURDIR/ptf-tests/ports_model.json -t $CURDIR/ptf-tests
```
