# Trinity：网络数据包元数据提取器

## What is Trinity?

Trinity 用于提取网络数据包元数据，目前可以解析的协议包括：运输层协议（TCP、UDP），网际层协议（IPv4、IPv6、ICMP、IGMP）。可实现 **输入无关（Input Agnostic）**的包元数据提取。

## Building Trinity

```bash
sudo apt install cmake ninja-build

cd Trinity/

cd ./env/

./install_pcap.sh

./init.sh

cd build

./Trinity -config ../configuration/network_traffic.json
```

