#include "dpdk_sniffer.hpp"

#include "co_monitor.hpp"
#include "bfrt_control.hpp"
#include "crc.hpp"

#include <iostream>
#include <fstream>
#include <atomic>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <net/ethernet.h>
#include <unordered_set>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_ring.h>

namespace cerberus {

constexpr int BURST_SIZE = 128;
constexpr int NUM_MBUFS = 8192;
// constexpr int NUM_MBUFS = 16384;
// constexpr int NUM_MBUFS = 32768;
constexpr int MBUF_CACHE_SIZE = 250;
constexpr int RX_RING_SIZE = 2048;
// constexpr int RX_RING_SIZE = 4096;
// constexpr int RX_RING_SIZE = 8192;
constexpr int TX_RING_SIZE = 1024;
constexpr int RING_SIZE = 8192;
// constexpr int RING_SIZE = 16384;

constexpr int THRESHOLDS[4] = {3000, 2050, 2150, 3500};

std::shared_ptr<CoMonitor> co_monitor = nullptr;
static struct rte_mempool *mbuf_pool = nullptr;
static struct rte_ring *worker_ring = nullptr;

int nfiltered = 0;

struct IpPairHash {
    size_t operator()(const std::pair<uint32_t, uint32_t>& p) const {
        return std::hash<uint64_t>()(((uint64_t)p.first << 32) | p.second);
    }
};

std::unordered_set<std::pair<uint32_t, uint32_t>, IpPairHash> blocked_ip_pairs;

std::atomic<uint64_t> total_processed_count = 0;

uint16_t extract_identifier(struct iphdr* iph) {
    return ntohs(iph->id);
}

uint32_t ip_to_uint(const std::string& ip_str) {
    struct in_addr addr;
    inet_pton(AF_INET, ip_str.c_str(), &addr);
    return ntohl(addr.s_addr);
}

int rx_loop(void*) {
    constexpr int MAX_BURST_ITERATIONS = 4;
    uint16_t port_id = 0;
    rte_mbuf* pkts_burst[BURST_SIZE];
    
    uint64_t prev_ipackets = 0, prev_ierrors = 0, prev_imissed = 0;
    auto last_log_time = std::chrono::steady_clock::now();

    while (true) {
        int total_rx = 0;
        for (int i = 0; i < MAX_BURST_ITERATIONS; ++i) {
            uint16_t nb_rx = rte_eth_rx_burst(port_id, 0, pkts_burst, BURST_SIZE);
            if (nb_rx == 0)
                break;

            unsigned enq = rte_ring_enqueue_burst(worker_ring, (void**)pkts_burst, nb_rx, nullptr);
            if (enq < nb_rx) {
                for (uint16_t j = enq; j < nb_rx; ++j)
                    rte_pktmbuf_free(pkts_burst[j]);
            }

            total_rx += nb_rx;
        }

        auto now = std::chrono::steady_clock::now();
        if (std::chrono::duration_cast<std::chrono::milliseconds>(now - last_log_time).count() >= 100) {
            struct rte_eth_stats stats;
            if (rte_eth_stats_get(port_id, &stats) == 0) {
                uint64_t delta_ipackets = stats.ipackets - prev_ipackets;
                uint64_t delta_ierrors = stats.ierrors - prev_ierrors;
                uint64_t delta_imissed = stats.imissed - prev_imissed;

                prev_ipackets = stats.ipackets;
                prev_ierrors = stats.ierrors;
                prev_imissed = stats.imissed;

                uint64_t timestamp_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count();

                uint64_t processed_now = total_processed_count.exchange(0);
                log_file << timestamp_ms << "," << processed_now << "," << delta_ipackets << ","
                         << delta_ierrors << "," << delta_imissed << "\n";
                log_file.flush();
            }
            last_log_time = now;
        }
    }
    return 0;
}

int worker_loop(void* arg) {
    constexpr unsigned BATCH_SIZE = 32;
    rte_mbuf* mbufs[BATCH_SIZE];
    WorkerArgs* args = static_cast<WorkerArgs*>(arg);
    auto& co_monitor = args->monitor;
    auto& slice_dict = *(args->slice_dict);

    while (true) {
        unsigned nb = rte_ring_dequeue_burst(worker_ring, (void**)mbufs, BATCH_SIZE, nullptr);
        if (nb == 0)
            continue;

        for (unsigned i = 0; i < nb; ++i) {
            rte_mbuf* mbuf = mbufs[i];
            uint8_t* pkt_data = rte_pktmbuf_mtod(mbuf, uint8_t*);
            size_t pkt_len = rte_pktmbuf_pkt_len(mbuf);

            if (pkt_len < sizeof(struct ethhdr) + sizeof(struct iphdr)) {
                rte_pktmbuf_free(mbuf);
                continue;
            }

            struct ethhdr* eth = (struct ethhdr*)pkt_data;
            if (ntohs(eth->h_proto) != ETH_P_IP) {
                rte_pktmbuf_free(mbuf);
                continue;
            }

            struct iphdr* iph = (struct iphdr*)(pkt_data + sizeof(struct ethhdr));
            std::string src_ip = inet_ntoa(*(in_addr*)&iph->saddr);
            std::string dst_ip = inet_ntoa(*(in_addr*)&iph->daddr);

            uint16_t src_port = 0, dst_port = 0;
            uint8_t proto = iph->protocol;

            if (proto == IPPROTO_TCP) {
                struct tcphdr* tcph = (tcphdr*)((uint8_t*)iph + iph->ihl * 4);
                src_port = ntohs(tcph->source);
                dst_port = ntohs(tcph->dest);
            } else if (proto == IPPROTO_UDP) {
                struct udphdr* udph = (udphdr*)((uint8_t*)iph + iph->ihl * 4);
                src_port = ntohs(udph->source);
                dst_port = ntohs(udph->dest);
            } else if (proto != IPPROTO_ICMP) {
                rte_pktmbuf_free(mbuf);
                continue;
            }

            total_processed_count++;
            
            uint16_t identifier = ntohs(iph->id);
            int current_window = (identifier >> 15) & 0x1;
            std::vector<std::vector<int>> overflow_flags(4, std::vector<int>(3));

            // Task 0
            overflow_flags[0][0] = (identifier >> 13) & 0x1;
            overflow_flags[0][1] = (identifier >> 8) & 0x1;
            overflow_flags[0][2] = (identifier >> 3) & 0x1;

            // Task 1
            overflow_flags[1][0] = (identifier >> 12) & 0x1;
            overflow_flags[1][1] = (identifier >> 7) & 0x1;
            overflow_flags[1][2] = (identifier >> 2) & 0x1;

            // Task 2
            overflow_flags[2][0] = (identifier >> 11) & 0x1;
            overflow_flags[2][1] = (identifier >> 6) & 0x1;
            overflow_flags[2][2] = (identifier >> 1) & 0x1;

            // Task 3
            overflow_flags[3][0] = (identifier >> 10) & 0x1;
            overflow_flags[3][1] = (identifier >> 5) & 0x1;
            overflow_flags[3][2] = (identifier >> 0) & 0x1;

            for (int task_id = 0; task_id < 4; ++task_id) {
                uint32_t read = co_monitor->update(task_id, src_ip, dst_ip, src_port, dst_port, proto,
                                                   overflow_flags[task_id], current_window);
                auto keys = TofinoCRC32::hash_keys(src_ip, dst_ip);
                uint32_t old_value = co_monitor->getPreviousValue(task_id, keys);
                int old_window = current_window ? 0 : 1;
                old_value = old_value << slice_dict[old_window][task_id];
                uint32_t new_read = read << slice_dict[current_window][task_id];
                uint32_t total = old_value + new_read;

                if (total > THRESHOLDS[task_id]) {
                    std::cout << "[Co-monitor] Task " << task_id << " - Blocking IP pair: "
                              << src_ip << " -> " << dst_ip << std::endl;
                    nfiltered++;
                    uint32_t src = ip_to_uint(src_ip);
                    uint32_t dst = ip_to_uint(dst_ip);
                    std::pair<uint32_t, uint32_t> ip_pair = {src, dst};
                    if (blocked_ip_pairs.find(ip_pair) == blocked_ip_pairs.end()) {
                        nfiltered++;
                        blocked_ip_pairs.insert(ip_pair);
                        addBlocklistEntry(src, dst);
                    }
                }
            }

            rte_pktmbuf_free(mbuf);
        }
    }

    return 0;
}


void packetSnifferLoop(std::shared_ptr<CoMonitor> monitor, std::vector<std::vector<int>>& slice_dict) {
    co_monitor = monitor;

    const char *argv[] = {
        "dpdk_sniffer", "-l", "0-4", "--huge-dir", "/dev/hugepages", "--socket-mem", "2048"
    };
    int argc = sizeof(argv) / sizeof(argv[0]);

    int ret = rte_eal_init(argc, const_cast<char**>(argv));
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "[DPDK] EAL init failed: %s\n", rte_strerror(rte_errno));

    uint16_t port_id = 0;
    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS, MBUF_CACHE_SIZE, 0,
                                        RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (!mbuf_pool)
        rte_exit(EXIT_FAILURE, "[DPDK] Failed to create mbuf pool: %s\n", rte_strerror(rte_errno));

    struct rte_eth_conf port_conf = {};
    ret = rte_eth_dev_configure(port_id, 1, 1, &port_conf);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "[DPDK] Failed to configure device: %s\n", rte_strerror(-ret));

    int socket_id = rte_eth_dev_socket_id(port_id);
    ret = rte_eth_rx_queue_setup(port_id, 0, RX_RING_SIZE, socket_id, nullptr, mbuf_pool);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "[DPDK] Failed to setup RX queue: %s\n", rte_strerror(-ret));

    ret = rte_eth_tx_queue_setup(port_id, 0, TX_RING_SIZE, socket_id, nullptr);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "[DPDK] Failed to setup TX queue: %s\n", rte_strerror(-ret));

    ret = rte_eth_dev_start(port_id);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "[DPDK] Failed to start device: %s\n", rte_strerror(-ret));

    rte_eth_promiscuous_enable(port_id);

    worker_ring = rte_ring_create("worker_ring", RING_SIZE, rte_socket_id(), 0);
    if (!worker_ring)
        rte_exit(EXIT_FAILURE, "[DPDK] Failed to create worker ring: %s\n", rte_strerror(rte_errno));

    static WorkerArgs worker_args;
    worker_args.monitor = monitor;
    worker_args.slice_dict = &slice_dict;

    // Core 0: RX loop
    unsigned rx_core = rte_get_next_lcore(-1, 1, 0);
    rte_eal_remote_launch(rx_loop, nullptr, rx_core);

    // Core else: Worker loops
    unsigned lcore_id;
    RTE_LCORE_FOREACH_WORKER(lcore_id) {
        if (lcore_id == rx_core) continue;  // prevent RX core from being a worker
        rte_eal_remote_launch(worker_loop, &worker_args, lcore_id);
    }

    rte_eal_mp_wait_lcore();
}


} // namespace cerberus
