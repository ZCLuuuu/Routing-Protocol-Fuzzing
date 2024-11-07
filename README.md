
# Routing Protocol Fuzzing Project

This project is designed for fuzz testing BGP protocols. It includes setup scripts and instructions for configuring a GNS3 environment, Python virtual environment, and necessary dependencies for fuzzing network protocols.


## Ubuntu GNS3 Environment Setup

To set up GNS3 on Ubuntu with a Python virtual environment (`gns3venv`), follow these steps using the `setup_gns3_env.sh` script:

    1) Ensure you are in Routing-Protocol-Fuzzing directory.
    
    2) Run './setup_gns3_env.sh'.
    
    3) Activate venv with 'source GNS3-Ubuntu-Setup/venv4gns3/bin/activate'.
    
    4) Run 'gns3' in this venv to start the application.


**Note**:
- The script automatically deletes and recreates the `venv` at `GNS3-Ubuntu-Setup/venv4gns3` if it already exists.
- Download the GNS3 VM from [GNS3’s official site](https://gns3.com/software/download-vm) if it’s not installed. It’s recommended to use VMware Workstation Pro instead of VirtualBox to avoid compatibility issues.



## Fuzzing BGP Protocols

This project includes a baseline fuzzer implemented in `fuzz_baseline.ipynb` for fuzz testing BGP protocols.

### 1. Importing Network Topology

1. Import the network topology located in subdirectory `BGP_Basic_Topology`.
2. Use the `ubuntugns3` project file for Ubuntu compatibility.
3. Ensure that the **C7200-XB12 router IOS** is pre-imported into GNS3.
4. Start the GNS3 project and ensure all nodes are running.

### 2. Setting up the Fuzzing Development Environment

To set up the development environment, you can either run the setup script or manually install dependencies.

- **Automatic Setup**:
   Run the following commands to execute the setup script:

   ```bash
   cd Fuzz-Material
   ./set_env.sh
   ```

- **Manual Setup**:
   Alternatively, you can manually install the necessary packages by downloading `fuzzingbook` and `pygraphviz`.

### 3. Running the Baseline Fuzzer

The `fuzz_baseline.ipynb` notebook provides the baseline fuzzer for BGP fuzzing. To use it:

1. **Open `fuzz_baseline.ipynb` in Jupyter Notebook**:
   Use the `gns3venv` as the interpreter and kernel.

2. **Start the GNS3 Project**:
   Ensure that the GNS3 project is open and all nodes are started in the GNS3 GUI before running the notebook.

3. **Execute the Notebook**:
   Follow the instructions in the notebook to begin fuzzing the BGP protocol.



## System Requirements

- **Operating System**: Linux Kernel 6.8.0-47-generic
- **Python Version**: Python 3 with the following dependencies:
  - `fuzzingbook`
  - `pygraphviz`
- **Additional System Packages**:
  - `python3`, `python3-pip`, `pipx`, `python3-pyqt5`, `python3-pyqt5.qtwebsockets`, `python3-pyqt5.qtsvg`
  - `qemu-kvm`, `qemu-utils`, `libvirt-clients`, `libvirt-daemon-system`, `virtinst`, `dynamips`
  - `software-properties-common`, `ca-certificates`, `curl`, `gnupg2`

**Installing System Dependencies**:

If any dependencies are missing, you can install them using:

```bash
sudo apt install python3 python3-pip pipx python3-pyqt5 python3-pyqt5.qtwebsockets python3-pyqt5.qtsvg qemu-kvm qemu-utils libvirt-clients libvirt-daemon-system virtinst dynamips software-properties-common ca-certificates curl gnupg2
```


## Contact

For questions, suggestions, or further assistance, please reach out to the author:

**Email**: [zhanglv0413@163.com](mailto:zhanglv0413@163.com)
```

This README includes all relevant information for setting up the environment, configuring GNS3, running the fuzzer, and meeting system requirements. It is organized into sections for easy navigation. Let me know if you need further adjustments!