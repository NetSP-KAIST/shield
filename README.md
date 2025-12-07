# Shield
[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.17490769.svg)](https://doi.org/10.5281/zenodo.17490769)

## On the Security Risks of Memory Adaptation and Augmentation in Data-plane DoS Mitigation

This is a repository for NDSS'26 paper [[DOI]](https://dx.doi.org/10.14722/ndss.2026.241857):
> __*On the Security Risks of Memory Adaptation and Augmentation in Data-plane DoS Mitigation*__

Please refer our paper for more details.

### Overview
Data-plane programmability in commodity switches is reshaping the landscape of denial-of-service (DoS) defense by enabling adaptive, line-rate mitigation strategies. Recent systems like Cerberus [[SP'24]](https://ieeexplore.ieee.org/document/10646662) augment limited switch memory with control-plane support to rapidly respond to evolving attacks. In this paper, we reveal a subtle yet critical vulnerability in this model; that is, the very mechanisms that enable the defense system’s agility and scalability can be subverted by a new class of coordinated DoS attacks. We present Heracles, the first attack to exploit hardware-level constraints in programmable switches to orchestrate precise resource contention across data-plane and control-plane memory. By leveraging side-channel timing signals, Heracles triggers synchronized augmentation, memory squeezing, and time-window exploitation, which are three orthogonal contention strategies that significantly degrade or even completely disable the DoS mitigation capabilities. We implement and test Heracles against real Tofino hardware and show that it can reliably disrupt DoS defenses across diverse DoS attack profiles, even when using loosely (1–2 second) time-synchronized attack sources. To mitigate this threat, we propose Shield, a multi-layered DoS mitigation sketch architecture that decouples memory operations across control- and dataplane layers, effectively mitigating the Heracles attack while preserving both line-rate performance and detection accuracy.

Our artifact contains several proof-of-concept implementations of DPDK-enabled Cerberus (Cerberus++) and Shield that demonstrate the functionality of the techniques described in the
paper. For the simple test, we provide the Packet Testing Framework (PTF), a Python-based dataplane test framework, for Shield.

#### Hardware and other requirements
> Evaluating the functionality of our artifact only requires software dependencies. This only requires the Tofino model (Tofino ASIC emulator). This work can be done with a common desktop (x86_64) with native Linux installed (Ubuntu 22.04). Initial setup may take more than 2 hours, depending on hardware performance. _**However**, evaluating the full performance of 'Shield' requires a Tofino ASIC-powered programmable switch and a server with two 40Gbps NIC ports (connected with QSFP28 cables to the programmable switch)._


## Heracles attack
> [!WARNING]
> This part requires strict hardware and software constraints. 

In the `cerberus` directory, we provide a `README` for running both Python and DPDK versions of the reproduced version of Cerberus.
Note that running the `cerberus-c2` requires a Tofino ASIC-powered programmable switch and a server with two 40Gbps NIC ports (connected with QSFP28 cables to the programmable switch). 

It is possible to compile and run `cerberus-c2` with the Tofino model; however, due to its packet-processing performance limitations, it is impossible to evaluate DoS defense performance with the Tofino model.
Note that evaluating the full performance of `cerberus` requires a Tofino ASIC-powered programmable switch and a server with NIC (with two 40Gbps ports wired via QSFP28 cables to the programmable switch). 

## Shield: Shared Hierarchical Registers for Layered Decay

### Shield (Model)
> [!NOTE]
> If you don't have a programmable switch (Tofino ASICs), you can test this part only.
In the `shield-model` directory, we provide a `README` for running PTF tests to emulate shield functionality with the Tofino model.
Note that the [Open P4 Studio](https://github.com/p4lang/open-p4studio) only supports the x86_64 architecture.

To test the functionality of `Shield`, we provide a minimum implementation for the PTF test. 
This layered_cms implementation includes Shield's hierarchical register design with layered decay.
**Please refer artifact appendix in our paper.**

### Shield (ASIC)
> [!WARNING]
> Below requires strict hardware and software constraints.

In the `shield-sketch` directory, we provide a `README` for running the full shield-sketch implementation. 
It is possible to compile and run `shield-sketch` with the Tofino model; however, due to its packet-processing performance limitations, it is impossible to evaluate DoS defense performance with the Tofino model.
Note that evaluating the full performance of `Shield` requires a Tofino ASIC-powered programmable switch and a server with NIC (with two 40Gbps ports wired via QSFP28 cables to the programmable switch). 

---
### Citation
```
@inproceedings{nam2026security,
  title = {{On the Security Risks of Memory Adaptation and Augmentation in Data-plane DoS Mitigation}},
  author = {Nam, Hocheol and Lim, Daehyun and Zhou, Huancheng and Gu, Guofei and Kang, Min Suk},
  booktitle = {Proceedings of the 2026 Network and Distributed System Security Symposium (NDSS'26)},
  pages = {1-20},
  year = {2026},
}
```

