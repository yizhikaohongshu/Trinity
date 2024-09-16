#include "feature_extractor.hpp"

using namespace Trinity;


void Parser::start() 
{
    __START_FTIMMER__

    if (jin_main.count("packet_parse") && jin_main["packet_parse"].count("target_file_path"))
    {
        LOGF("Parse packet from file.");
        file_path = jin_main["packet_parse"]["target_file_path"];

        const auto p_packet_parser = make_shared<PcapParser>(file_path);
        LOGF("Parse packets");
        p_packet_parser->parse_raw_packet();
        p_packet_parser->parse_basic_packet_fast();
        p_parse_result = p_packet_parser->get_basic_packet_rep();
        p_packet_parser->type_statistic();
    }
    else 
    {
        LOGF("Pcap file not found.");
    }

    if (save_result_enable) {
        do_save(save_result_path);
    }

    __STOP_FTIMER__
    __PRINTF_EXE_TIME__
}

void Parser::config_via_json(const json& jin)
{
    try {
        if (jin.count("packet_parse") && jin.count("result_save")) {
            jin_main = jin;
        }
        else {
            throw logic_error("Incomplete json configuration.");
        }
        const auto j_save = jin["result_save"];
        if (j_save.count("save_result_enable")) {
            save_result_enable = static_cast<decltype(save_result_enable)>(j_save["save_result_enable"]);
        }
        if (j_save.count("save_result_path")) {
            save_result_path = static_cast<decltype(save_result_path)>(j_save["save_result_path"]);
        }
    }
    catch (const exception& e) {
        FATAL_ERROR(e.what());
    }
}

void Parser::do_save(const string& save_path) 
{
    __START_FTIMMER__

    ofstream _f(save_path);
    if (_f.is_open()) {
        try {
            for (auto i = 0; i < (*p_parse_result).size(); ++i) {
                _f << (*p_parse_result)[i]->get_pkt_str();
                if (i % 1000 == 0) {
                    _f << flush;
                }
            }
        }
        catch (const exception& e) {
            FATAL_ERROR(e.what());
        }
        _f.close();
    }
    else {
        FATAL_ERROR("File Error.");
    }

    __STOP_FTIMER__
    __PRINTF_EXE_TIME__
}