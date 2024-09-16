#pragma once
#ifndef FEATURE_EXTRACTOR_HPP
#define FEATURE_EXTRACTOR_HPP

#include "../packet_parse/pcap_parser.hpp"

using std::ofstream;
using std::string;
using std::flush;
using std::exception;
using std::logic_error;

namespace Trinity
{

class Parser {
private:
    json jin_main;
    string file_path;
    bool save_result_enable = false;
    string save_result_path;
    shared_ptr<vector<shared_ptr<BasicPacket>>> p_parse_result;  // 包解析数据    

public:
    void start();
    void config_via_json(const json&);
    void do_save(const string& save_path);
};

};

#endif