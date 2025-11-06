# Shield 
This is a repository for the paper "On the Security Risks of Memory Adaptation and Augmentation in Data-plane DoS Mitigation".

## Heracles attack
> [!NOTE]
> This part requires strict hardware and software constraints. 

In the `cerberus` directory, we provide a `README` for running both Python and DPDK versions of the reproduced version of Cerberus [SP'24].
Note that running the `cerberus-c2` requires a Tofino ASIC-powered programmable switch and a server with two 40Gbps NIC ports (connected with QSFP28 cables to the programmable switch). 

It is possible to compile and run `cerberus-c2` with the Tofino model; however, due to its packet-processing performance limitations, it is impossible to evaluate DoS defense performance with the Tofino model.

## Shield: Shared Hierarchical Registers for Layered Decay

### Shield (Model)
In the `shield-model` directory, we provide a `README` for running PTF tests to emulate shield functionality with the Tofino model.

To test functionality of `Shield`, we provide minimum implementation for the PTF test. 
This layered_cms implementation includes Shield's hierarchical register design with layered decay.

### Shield (ASIC)
> [!NOTE]
> Below requires strict hardware and software constraints.

In the `shield-sketch` directory, we provide a `README` for running the full shield-sketch implementation. 
Note that evaluating the full performance of `Shield` requires a Tofino ASIC-powered programmable switch and a server with two 40Gbps NIC ports (connected with QSFP28 cables to the programmable switch). 