#include <gflags/gflags.h>
#include "common.hpp"
#include "metainfo_extract/feature_extractor.hpp"

using namespace Trinity;
using namespace std;

DEFINE_string(config, "./configuration/network_traffic.json",  "Configuration file location.");

int main(int argc, char* argv[]) {
    __START_FTIMMER__

    google::ParseCommandLineFlags(&argc, &argv, false);

    json config_j;
    try {
        ifstream fin(FLAGS_config, ios::in);
        fin >> config_j;
        // std::cout << config_j << std::endl;
    }
    catch (const exception& e) {
        FATAL_ERROR(e.what());
    }
    
    auto fe = make_shared<Parser>();
    fe->config_via_json(config_j);
    fe->start();

    __STOP_FTIMER__
    __PRINTF_EXE_TIME__
    return 0;
}