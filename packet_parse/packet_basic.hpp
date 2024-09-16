#pragma once
#ifndef PACKET_BASIC_HPP
#define PACKET_BASIC_HPP

#include "../common.hpp"
#include "packet_metainfo.hpp"
#include "pcpp_common.hpp"

using std::string;
using std::stringstream;

namespace Trinity
{

struct BasicPacket 
{
    pkt_ts_t ts;
    pkt_code_t tp;
    pkt_len_t len;
    BasicPacket() = default;
    explicit BasicPacket(const decltype(ts) ts, const decltype(tp) tp, const decltype(len) len) : ts(ts), tp(tp), len(len) { }
    virtual ~BasicPacket() { }

    virtual auto get_pkt_str(const int64_t align_time = 0) const -> string = 0;
};

struct BasicPacketBad : public BasicPacket 
{
    BasicPacketBad() = default;
    explicit BasicPacketBad(const decltype(ts) ts) : BasicPacket(ts, 0, 0) { }
    virtual ~BasicPacketBad() { }

    auto get_pkt_str(const int64_t align_time = 0) const -> string override
    {
        stringstream ss;
        ss << "bad" << ' ' << static_cast<int64_t>(GET_DOUBLE_TS(ts) * 1e6) - align_time
            << tp << ' '
            << len << '\n';
        return ss.str();
    }
};

struct BasicPacket4 final : public BasicPacket
{
    tuple4_conn4 flow_id;
    BasicPacket4() = default;

    explicit BasicPacket4(const pkt_addr4_t srcIP, const pkt_addr4_t dstIP, const pkt_port_t srcPort, const pkt_port_t dstPort,
                                const decltype(ts) ts, const decltype(tp) tp, const decltype(len) len) :
                                    flow_id(srcIP, dstIP, srcPort, dstPort), BasicPacket(ts, tp, len) { }
    explicit BasicPacket4(const decltype(flow_id) flow_id, const decltype(ts) ts, const decltype(tp) tp, 
                                const decltype(len) len) : 
                                    flow_id(flow_id), BasicPacket(ts, tp, len) { }

    virtual ~BasicPacket4() { }

    auto get_pkt_str(const int64_t align_time = 0) const -> string override
    {
        stringstream ss;
        ss << 4 << ' ' << pcpp::IPv4Address(tuple_get_src_addr(flow_id)).toString()
            << ' ' << pcpp::IPv4Address(tuple_get_dst_addr(flow_id)).toString()
            << ' ' << tuple_get_src_port(flow_id)
            << ' ' << tuple_get_dst_port(flow_id)
            << ' ' << static_cast<int64_t>(GET_DOUBLE_TS(ts) * 1e6) - align_time
            << ' ' << tp
            << ' ' << len << '\n';
        return ss.str();
    }
};

struct BasicPacket6 final : public BasicPacket 
{
    tuple4_conn6 flow_id;
    BasicPacket6() = default;

    explicit BasicPacket6(const pkt_addr6_t srcIP, const pkt_addr6_t dstIP, const pkt_port_t srcPort, const pkt_port_t dstPort,
                            const decltype(ts) ts, const decltype(tp) tp, const decltype(len) len) :
                                flow_id(srcIP, dstIP, srcPort, dstPort), BasicPacket(ts, tp, len) { }
    explicit BasicPacket6(const decltype(flow_id) flow_id, const decltype(ts) ts, const decltype(tp) tp, const decltype(len) len) :
                                flow_id(flow_id), BasicPacket(ts, tp, len) { }

    virtual ~BasicPacket6() { }

    auto get_pkt_str(const int64_t align_time = 0) const -> string override
    {
        stringstream ss;
        ss << 6 << ' ' << get_str_addr(tuple_get_src_addr(flow_id))
            << ' ' << get_str_addr(tuple_get_dst_addr(flow_id))
            << ' ' << tuple_get_src_port(flow_id)
            << ' ' << tuple_get_dst_port(flow_id)
            << ' ' << static_cast<int64_t>(GET_DOUBLE_TS(ts) * 1e6) - align_time
            << ' ' << tp
            << ' ' << len << '\n';
        return ss.str();
    }
};

};


#endif