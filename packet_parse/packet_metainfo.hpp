#pragma once
#ifndef PACKET_METAINFO_HPP
#define PACKET_METAINFO_HPP

#include "../common.hpp"
#include "pcpp_common.hpp"

using std::vector;
using std::tuple;
using std::get;
using std::string;

namespace Trinity 
{

union __pkt_addr6 {
    __uint128_t num_rep;
    uint8_t byte_rep[16];
};

using pkt_addr4_t   = u_int32_t;
using pkt_addr6_t   = __uint128_t;
using pkt_len_t     = u_int16_t;
using pkt_port_t    = u_int16_t;
using pkt_ts_t      = timespec;
using pkt_code_t    = u_int16_t;

enum pkt_type_t : u_int8_t {
    IPv4,
    IPv6,
    ICMP,
    IGMP,
    TCP_SYN,
    TCP_ACK,
    TCP_FIN,
    TCP_RST,
    UDP,
    UNKNOWN,
};

const vector<const char*> type2name = {
    "IPv4",
    "IPv6",
    "ICMP",
    "IGMP",
    "TCP_SYN",
    "TCP_ACK",
    "TCP_FIN",
    "TCP_RST",
    "UDP",
    "UNKNOWN"
};

inline void set_pkt_type_code(pkt_code_t& cd, const pkt_type_t t) {
    cd |= (1 << t);
}

inline auto test_pkt_type_code(const pkt_code_t cd, const pkt_type_t t) -> bool {
    return cd & (1 << t);
}

// using tuple2_conn4 = tuple<pkt_addr4_t, pkt_addr4_t>;
// using tuple2_conn6 = tuple<pkt_addr6_t, pkt_addr6_t>;
using tuple4_conn4 = tuple<pkt_addr4_t, pkt_addr4_t, pkt_port_t, pkt_port_t>;
using tuple4_conn6 = tuple<pkt_addr6_t, pkt_addr6_t, pkt_port_t, pkt_port_t>;

// inline auto tuple_get_src_addr(const tuple2_conn4& cn) -> pkt_addr4_t {
//     return get<0>(cn);
// }

inline auto tuple_get_src_addr(const tuple4_conn4& cn) -> pkt_addr4_t {
    return get<0>(cn);
}

inline auto tuple_get_dst_addr(const tuple4_conn4& cn) -> pkt_addr4_t {
    return get<1>(cn);
}

inline auto tuple_get_src_port(const tuple4_conn4& cn) -> pkt_port_t {
    return get<2>(cn);
}

inline auto tuple_get_dst_port(const tuple4_conn4& cn) -> pkt_port_t {
    return get<3>(cn);
}

inline auto get_str_addr(const pkt_addr6_t ad) -> string {
    __pkt_addr6 __t;
    __t.num_rep = ad;
    return pcpp::IPv6Address(__t.byte_rep).toString();
}

// todo
// IPv6
inline auto tuple_get_src_addr(const tuple4_conn6& cn) -> pkt_addr6_t { 
    return get<0>(cn);
}

inline auto tuple_get_dst_addr(const tuple4_conn6& cn) -> pkt_addr6_t {
    return get<1>(cn);
}


// template<typename TupleType>
// auto tuple_get_src_addr(const TupleType& tup) -> decltype(get<0>(tup))
// {
//     return get<0>(tup);
// }

// template<typename T>
// auto tuple_get_dst_addr(const T& tup)
// {
//     return get<1>(tup);
// }


};

#endif