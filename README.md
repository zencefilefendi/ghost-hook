# Ghost-Hook 👻🪝
**Operation "Entropy Zero" - Ephemeral, Polymorphic, and Self-Aware eBPF Defense Architecture**

[![Rust](https://img.shields.io/badge/rust-%23000000.svg?style=for-the-badge&logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![eBPF](https://img.shields.io/badge/ebpf-O-black?style=for-the-badge)](https://ebpf.io/)
[![Linux](https://img.shields.io/badge/Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)](https://www.kernel.org/)
[![License: Proprietary](https://img.shields.io/badge/License-Zencefil_Efendi-red.svg?style=for-the-badge)](LICENSE)

> *"Görünmez olanı vuramazsın. Statik olanı aşarsın ama değişeni asla."*

Ghost-Hook is an advanced proof-of-concept for a **Zero-Persistence** cyber defense doctrine. Unlike traditional EDRs or XDRs that rely on static, bloated agents constantly running in the background (which makes them prime targets for BYOVD and evasion attacks), Ghost-Hook operates on the principle of **Ephemeral Defense**. It materializes in the Linux Kernel only during an active threat, neutralizes it with zero-latency, and immediately vanishes without a forensic trace.

## ⚔️ Core Capabilities

* **Zero-Persistence Doctrine:** The system does not linger in the kernel. The user-space Rust application deploys the eBPF hook dynamically upon detecting heuristic triggers (e.g., syscall spikes) and self-destructs (detaches) within milliseconds after neutralizing the threat.
* **Polymorphic Bytecode Weaver:** To evade signature-based detection and memory dumps, the Rust loader mutates the BPF bytecode before every deployment. By seamlessly swapping `r9=r9` instruction padding with randomized equivalents (`r8=r8`, `r7=r7`), the ELF hash is constantly altered in memory.
* **Anti-Debugging & Self-Awareness:** The eBPF kernel datapath aggressively monitors the `task->ptrace` flag. If it detects that the system or process is under analysis via debuggers (gdb, strace) or heuristic telemetry, it triggers a "Silent Exit" to maintain absolute stealth.
* **In-Memory Diskless Execution:** The Rust loader utilizes `memfd_create` and reflective execution concepts. It severs its `/proc/self/exe` linkage from the physical disk, running entirely from volatile memory.
* **Process Obfuscation:** The loader masks its process name via `PR_SET_NAME` to masquerade as a standard system worker thread (`[kworker/u4:2]`), avoiding suspicion during manual or automated process enumeration.
* **Secure Slab Wiping (Zeroing-Out):** Before self-destruction, a final Kill-Switch signal (`prctl(0xDEADBEEF)`) instructs the kernel to overwrite the `BPF_MAP_TYPE_HASH` threat tables with junk bytes, preventing forensic reconstruction of the system's logic from kernel memory dumps.
* **Zero-Latency Judgment:** Neutralizes threats (like malicious `sys_ptrace` attachments) synchronously using `bpf_send_signal(SIGKILL)`, executing the kill command instantly before the context switch returns to user-space.

## 🏗️ Architecture

### 1. eBPF Datapath (`ghost_hook.bpf.c`)
- Hooks into `tracepoint/syscalls/sys_enter_ptrace` for stable ABI.
- Manages the `live_threats` map dynamically without user-space roundtrips.
- Implements the polymorphic junk-code sleds.
- Handles the `kprobe/sys_prctl` for Secure Memory Wiping.

### 2. User-Space Control Plane (`main.rs`)
- Built with the `Aya` framework for eBPF deployment without `libbpf` C-dependencies.
- Contains the JSON-to-BPF Dynamic Decision Engine.
- Executes the Polymorphic Weaver on raw ELF bytes before loading.
- Manages the ephemeral lifecycle and SIGINT/Kill-Switch triggers.

## 🚀 Usage

*Disclaimer: This is a sophisticated architectural skeleton intended for cybersecurity research, academic study, and defensive engineering. Do not deploy in production without full hardware-trigger (PMC) implementations and extensive verifications.*

```bash
# Clone the repository
git clone https://github.com/zencefilefendi/ghost-hook.git
cd ghost-hook

# Build the project
cargo build --release

# Run with elevated privileges (Required for eBPF and memfd operations)
sudo ./target/release/ghost_hook
```

## 📜 License
**Proprietary & Confidential**

Copyright (c) 2026 Zencefil Efendi. All rights reserved.
This project is proprietary. Any copying, modification, or distribution is strictly prohibited without explicit permission. See the [LICENSE](LICENSE) file for more details.
