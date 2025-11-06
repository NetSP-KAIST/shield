extern "C" {
    #include <bf_pm/bf_pm_intf.h>
    #include <bf_rt/bf_rt_common.h>
    #include <bf_switchd/bf_switchd.h>
    #include <traffic_mgr/traffic_mgr.h>
    #include <lld/bf_ts_if.h>
    #include <pkt_mgr/pkt_mgr_intf.h>
    #include <pipe_mgr/pipe_mgr_intf.h>
    #include <port_mgr/bf_port_if.h>
    #include <rte_eal.h>
    #include <rte_ethdev.h>
}

#include "dpdk_sniffer.hpp"
#include "co_monitor.hpp"
#include "bfrt_control.hpp"
#include "memory_slice_manager.hpp"

#include <bf_rt/bf_rt.hpp>
#include <thread>
#include <memory>
#include <vector>
#include <iostream>
#include <unistd.h>
#include <functional> 

#ifndef SDE
#error "Please add -DSDE=\"$SDE\" to CPPFLAGS"
#endif

#ifndef SDE_INSTALL
#error "Please add -DSDE_INSTALL=\"$SDE_INSTALL\" to CPPFLAGS"
#endif

bf_switchd_context_t *switchd_ctx = NULL;

void init_bf_switchd(std::string progname) {
    std::string conf_file{SDE_INSTALL "/share/p4/targets/tofino/" + progname + ".conf"};
    bf_status_t bf_status;

    switchd_ctx = (bf_switchd_context_t *)calloc(1, sizeof(bf_switchd_context_t));
    if (!switchd_ctx) {
        std::cerr << "Failed to allocate memory for switchd context\n";
        exit(1);
    }

    memset(switchd_ctx, 0, sizeof(bf_switchd_context_t));
    switchd_ctx->install_dir = strdup(SDE_INSTALL);
    switchd_ctx->conf_file = strdup(conf_file.c_str());
    switchd_ctx->skip_p4 = false;
    switchd_ctx->skip_port_add = false;
    switchd_ctx->running_in_background = true;
    switchd_ctx->dev_sts_thread = true;
    switchd_ctx->dev_sts_port = 7777;

    bf_status = bf_switchd_lib_init(switchd_ctx);
    std::cout << "Initialized bf_switchd, status = " << bf_status << std::endl;
    if (bf_status != BF_SUCCESS) {
        std::cerr << "Failed to initialize libbf_switchd (" << bf_err_str(bf_status) << ")\n";
        free(switchd_ctx);
        exit(1);
    }
}

int init_ports() {
    std::string port_setup_script = "/home/edgecore/cerberus-reproduce/control-plane/port_setup.bfsh";
    std::string command = "SDE=" + std::string(SDE) +
                          " SDE_INSTALL=" + std::string(SDE_INSTALL) +
                          " LD_LIBRARY_PATH=" + std::string(SDE_INSTALL) + "/lib/ " +
                          std::string(SDE_INSTALL) + "/bin/bfshell -f " + port_setup_script;

    std::cout << "Executing port setup: " << command << std::endl;
    int ret = system(command.c_str());
    if (ret != 0) {
        std::cerr << "Port setup script failed." << std::endl;
        return 1;
    }
    return 0;
}

int init_table() {
    std::string setup_script = "/home/edgecore/cerberus-reproduce/control-plane/dpdk/setup-c2.py";
    std::string python_path = std::string(SDE_INSTALL) + "/lib/python3.10/site-packages:" +
                              std::string(getenv("HOME")) + "/.local/lib/python3.10/site-packages";

    std::string command = "env SDE_INSTALL=" + std::string(SDE_INSTALL) + 
                            " SDE=" + std::string(SDE) + 
                            " PYTHONPATH=" + python_path +
                            " " + std::string(SDE)+ "/run_bfshell.sh -b " + setup_script;

    int ret = system(command.c_str());
    if (ret != 0) {
        std::cerr << "Initial table setup script failed." << std::endl;
        return 1;
    }
    return 0;
}

int main(int argc, char **argv) {
    if (geteuid() != 0) {
        std::cerr << "Need to run as root user! Exiting.\n";
        return 1;
    }

    // 1. Init Tofino switch
    std::string p4_name = "cerberus-c2";
    init_bf_switchd(p4_name);

    bf_rt_target_t dev_tgt{.dev_id = 0, .pipe_id = 0xFFFF}; // ALL_PIPES
    cerberus::initBFRT(dev_tgt, p4_name);

    // 2. Init P4 table
    sleep(2);
    if (init_table() != 0 || init_ports() != 0) {
        std::cerr << "Switch initialization failed." << std::endl;
        return 1;
    }

    // 3. Init CoMonitor
    std::shared_ptr<cerberus::CoMonitor> co_monitor = std::make_shared<cerberus::CoMonitor>(
        4,
        std::vector<int>{32, 32, 32, 32},
        std::vector<int>{16, 16, 16, 16},
        3,
        2
    );
    cerberus::co_monitor = co_monitor;

    cerberus::MemorySliceManager memory_manager(*co_monitor, 5.0);

    std::vector<std::vector<int>>& slice_dict = memory_manager.slice_dict_;

    std::thread sniffer_thread(cerberus::packetSnifferLoop, co_monitor, std::ref(slice_dict));

    memory_manager.start();
    sniffer_thread.join();
    memory_manager.stop();

    std::cout << "[Main] Shutdown complete." << std::endl;
    return 0;
}
