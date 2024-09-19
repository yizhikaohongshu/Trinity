#pragma once
#ifndef PCAP_PARSER_HPP
#define PCAP_PARSER_HPP

#include "../common.hpp"
#include "pcpp_common.hpp"
#include "packet_basic.hpp"
#include "packet_metainfo.hpp"


namespace Trinity
{

class PcapParser final 
{
private:
    const string file_path;
    // Number of packets received/dropped/dropped by interface
    shared_ptr<pcpp::IPcapDevice::PcapStats> p_parse_state;

    // typedef PointerVector<RawPacket> RawPacketVector;
    shared_ptr<pcpp::RawPacketVector> p_raw_packet;

    // PcapFileReaderDevice: A class for opening a pcap file in read-only mode. 
    // This class enable to open the file and read all packets, packet-by-packet
    shared_ptr<pcpp::PcapFileReaderDevice> p_pcpp_file_reader;
    shared_ptr<vector<shared_ptr<BasicPacket>>> p_parse_result;

public:
    auto parse_raw_packet(size_t num_to_parse = -1) -> decltype(p_raw_packet);
    auto parse_basic_packet_fast(size_t multiplex = 16) -> decltype(p_parse_result);
    void type_statistic() const;

    PcapParser(const PcapParser&) = delete;
    PcapParser& operator=(const PcapParser&) = delete;
    ~PcapParser() = default;

    explicit PcapParser(const string& s) : file_path(s)
    {
        p_pcpp_file_reader = make_shared<pcpp::PcapFileReaderDevice>(s.c_str());
        if (!p_pcpp_file_reader->open()) {
            FATAL_ERROR("Fail to read target pcap file.");
        }
        p_parse_result = nullptr;
        p_raw_packet = nullptr;
        p_parse_state = make_shared<pcpp::IPcapDevice::PcapStats>();
    }

    auto inline get_basic_packet_rep() const -> const decltype(p_parse_result) 
    {
        if (!p_parse_result) {
            WARN("Parse result is nullptr.");
            return nullptr;
        }
        return p_parse_result;
    }

    auto inline get_parse_state() const -> decltype(p_parse_state) {
        /**
         * Get statistics of packets read so far. 
         * In the PcapStats struct, only the packetsRecv member is relevant. The rest of the members will contain 0
         */
        p_pcpp_file_reader->getStatistics(*p_parse_state);
        return p_parse_state;
    }
};

};

#endif  // !PCAP_PARSER_HPP