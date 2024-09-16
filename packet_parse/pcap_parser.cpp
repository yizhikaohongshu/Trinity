#include "pcap_parser.hpp"

using namespace Trinity;
using std::pair;
using std::min;
using std::unique_ptr;
using std::make_unique;
using std::thread;

auto PcapParser::parse_raw_packet(size_t num_to_parse) -> decltype(p_raw_packet)
{
    __START_FTIMMER__
    if (p_raw_packet) {
        LOG("Parsing has been done, do it again.");
    }
    p_raw_packet = make_shared<pcpp::RawPacketVector>();
    if (!p_pcpp_file_reader->getNextPackets(*p_raw_packet, num_to_parse)) {
        FATAL_ERROR("Could not read the first packet in the file.");
    }
    else {
        LOGF("Read %ld raw packets from %s.", p_raw_packet->size(), file_path.c_str());
    }
    __STOP_FTIMER__
    __PRINTF_EXE_TIME__
    return p_raw_packet;
}

auto PcapParser::parse_basic_packet_fast(size_t multiplex) -> decltype(p_parse_result)
{
    __START_FTIMMER__
    if (p_parse_result) {
        WARN("Packets have been parsed, do it again.");
    }
    size_t bad_packet = 0;
    p_parse_result = make_shared<vector<shared_ptr<BasicPacket>>>(p_raw_packet->size());
    
    const u_int32_t part_size = ceil(static_cast<double>(p_raw_packet->size()) / static_cast<double>(multiplex));
    vector<pair<size_t, size_t>> _assign;
    for (size_t core = 0, idx = 0; core < multiplex; ++core, idx += part_size) {
        _assign.push_back({idx, min(idx + part_size, p_raw_packet->size())});
        // std::cout << idx << " " << min(idx + part_size, p_raw_packet->size()) << std::endl;
    }

    auto __f = [&] (const size_t _start, const size_t _end, decltype(p_raw_packet) _from, decltype(p_parse_result) _to) -> void {
        for (size_t i = _start; i < _end; ++i) {
            const auto& __p_raw_pk = (*_from).at(i);
            unique_ptr<pcpp::Packet> p_parsed_packet = make_unique<pcpp::Packet>(__p_raw_pk, false, pcpp::IP, pcpp::OsiModelNetworkLayer);

            pkt_addr4_t src_IPv4, dst_IPv4;
            pkt_addr6_t src_IPv6, dst_IPv6;
            shared_ptr<BasicPacket> ptr_pkt = nullptr;
            pkt_code_t packet_code = 0;
            pkt_ts_t packet_time = __p_raw_pk->getPacketTimeStamp();
            pkt_port_t src_port = 0, dst_port = 0;
            pkt_len_t packet_length = 0;
            
            // 运输层
            auto _f_parse_udp = [&p_parsed_packet, &src_port, &dst_port, &packet_code] () -> void {
                pcpp::UdpLayer* p_udp_layer = p_parsed_packet->getLayerOfType<pcpp::UdpLayer>();
                src_port = htons(p_udp_layer->getUdpHeader()->portSrc);
                dst_port = htons(p_udp_layer->getUdpHeader()->portDst);
                set_pkt_type_code(packet_code, pkt_type_t::UDP);
            };

            auto _f_parse_tcp = [&p_parsed_packet, &src_port, &dst_port, &packet_code] () -> void {
                pcpp::TcpLayer* p_tcp_layer = p_parsed_packet->getLayerOfType<pcpp::TcpLayer>();
                src_port = htons(p_tcp_layer->getTcpHeader()->portSrc);
                dst_port = htons(p_tcp_layer->getTcpHeader()->portDst);

                if (p_tcp_layer->getTcpHeader()->synFlag) {
                    set_pkt_type_code(packet_code, pkt_type_t::TCP_SYN);
                }
                if (p_tcp_layer->getTcpHeader()->finFlag) {
                    set_pkt_type_code(packet_code, pkt_type_t::TCP_FIN);
                }
                if (p_tcp_layer->getTcpHeader()->rstFlag) {
                    set_pkt_type_code(packet_code, pkt_type_t::TCP_RST);
                }
                if (p_tcp_layer->getTcpHeader()->ackFlag) {
                    set_pkt_type_code(packet_code, pkt_type_t::TCP_ACK);
                }
            };

            auto _f_load_ipv6_addr_type = [](const pcpp::IPv6Address& addr6) -> pkt_addr6_t {
                __pkt_addr6 __t;
                memcpy(__t.byte_rep, addr6.toBytes(), sizeof(__t));
                return __t.num_rep;
            };

            // 网际层
            // 解析网际层包的 meta information, e.g. srcIP, dstIP, length, protocol ...
            pcpp::ProtocolType type_next;
            if (p_parsed_packet->isPacketOfType(pcpp::IPv4)) {
                pcpp::IPv4Layer* p_IPv4_layer = p_parsed_packet->getLayerOfType<pcpp::IPv4Layer>();
                set_pkt_type_code(packet_code, pkt_type_t::IPv4);

                src_IPv4 = p_IPv4_layer->getSrcIPv4Address().toInt();
                dst_IPv4 = p_IPv4_layer->getDstIPv4Address().toInt();
                packet_length = htons(p_IPv4_layer->getIPv4Header()->totalLength);  
                p_IPv4_layer->parseNextLayer();
                if (p_IPv4_layer->getNextLayer() == nullptr) {
                    type_next = pcpp::UnknownProtocol;
                }
                else {
                    type_next = p_IPv4_layer->getNextLayer()->getProtocol();    // IPv4头部, 协议字段
                }
            }
            else if (p_parsed_packet->isPacketOfType(pcpp::IPv6)) {
                pcpp::IPv6Layer * p_IPv6_layer = p_parsed_packet->getLayerOfType<pcpp::IPv6Layer>();
                set_pkt_type_code(packet_code, pkt_type_t::IPv6);

                src_IPv6 = _f_load_ipv6_addr_type(p_IPv6_layer->getSrcIPv6Address());
                dst_IPv6 = _f_load_ipv6_addr_type(p_IPv6_layer->getDstIPv6Address());
                packet_length = htons(p_IPv6_layer->getIPv6Header()->payloadLength);
                p_IPv6_layer->parseNextLayer();
                if (p_IPv6_layer->getNextLayer() == nullptr) {
                    type_next = pcpp::UnknownProtocol;
                } else {
                    type_next = p_IPv6_layer->getNextLayer()->getProtocol();
                }
                
            }
            else {
                // bad packet
                ++bad_packet;
                (*_to)[i] = make_shared<BasicPacketBad>(packet_time);
                continue;
            }

            // 解析网际层上层协议(TCP, UDP, ICMP, IGMP, ...)
            switch (type_next)
            {
            case pcpp::TCP:
                _f_parse_tcp();
                break;
            case pcpp::UDP:
                _f_parse_udp();
                break;
            case pcpp::ICMP:
                set_pkt_type_code(packet_code, pkt_type_t::ICMP);
                break;
            case pcpp::IGMP:
                set_pkt_type_code(packet_code, pkt_type_t::IGMP);
                break;
            default:
                set_pkt_type_code(packet_code, pkt_type_t::UNKNOWN);
                break;
            }

            if (test_pkt_type_code(packet_code, pkt_type_t::IPv4)) {
                ptr_pkt = make_shared<BasicPacket4>(src_IPv4, dst_IPv4, src_port, dst_port, packet_time, packet_code, packet_length);
            }
            else if (test_pkt_type_code(packet_code, pkt_type_t::IPv6)) {
                ptr_pkt = make_shared<BasicPacket6>(src_IPv6, dst_IPv6, src_port, dst_port, packet_time, packet_code, packet_length);
            }
            else {
                assert(false);
            }

            (*_to)[i] = ptr_pkt;
            // std::cout << ptr_pkt->get_pkt_str();
        }
    };

    vector<thread> vthread;
    assert(multiplex > 0);
    for (size_t core = 0; core < multiplex; ++core) {
        vthread.emplace_back(__f, _assign[core].first, _assign[core].second, p_raw_packet, p_parse_result);
    }

    for (auto& t : vthread) {
        t.join();
    }

    LOGF("%ld packets representation was parsed, %ld bad packets.", p_parse_result->size(), bad_packet);

    __STOP_FTIMER__
    __PRINTF_EXE_TIME__
    return p_parse_result;
}

void PcapParser::type_statistic() const
{
    __START_FTIMMER__
    if (p_parse_result == nullptr) {
        FATAL_ERROR("Analyze packet statictis before parse packets.");
    }

    size_t bad_packet{ };
    vector<u_int32_t> __sat(pkt_type_t::UNKNOWN + 1);

    for (auto p_rep : *p_parse_result) {
        if (typeid(*p_rep) != typeid(BasicPacketBad)) {
            for (uint8_t i = 0; i < pkt_type_t::UNKNOWN + 1; ++i) {
                if (test_pkt_type_code(p_rep->tp, static_cast<pkt_type_t>(i))) {
                    ++__sat[i];
                }
            }
        }
        else {
            ++bad_packet;
        }
    }

    LOG("Display parsed packet type statistic");

    for (size_t i = 0; i <= pkt_type_t::UNKNOWN; i++) {
        printf("[%-8s]: %d\n", type2name[i], __sat[i]);
    }
    printf("[%-8s]: %ld\n", "ALL", __sat[pkt_type_t::IPv4] + __sat[pkt_type_t::IPv6] + bad_packet);
    printf("[%-8s]: %ld\n", "BAD", bad_packet);

    __STOP_FTIMER__
    __PRINTF_EXE_TIME__
}

