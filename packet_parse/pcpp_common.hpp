#pragma once
#ifndef PCPP_COMMON_HPP
#define PCPP_COMMON_HPP

#include <netinet/in.h>
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/IPv6Layer.h>
#include <pcapplusplus/TcpLayer.h>
#include <pcapplusplus/UdpLayer.h>
#include <pcapplusplus/PcapFileDevice.h>


namespace Trinity 
{

using std::vector;
using std::tuple;
using std::get;
using std::string;
using std::pair;
using std::min;
using std::unique_ptr;
using std::make_unique;
using std::thread;
using std::stringstream;
using std::shared_ptr;
using std::make_shared;


};

#endif