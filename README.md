# Trinity：网络数据包元数据提取器

## What is Trinity?

Trinity 用于提取网络数据包元数据，目前可以解析的协议包括：运输层协议（TCP、UDP），网际层协议（IPv4、IPv6、ICMP、IGMP）。可实现__输入无关(Input Agnostic)__的包元数据提取。

## Building Trinity

### 0. 软件准备

0. __安装编译工具链.__	

​	Trinity 在 WSL2 Ubuntu 20.04 下完成编译。编译使用的工具有`cmake`+`ninja`+`g++`，使用`apt install`安装正确的编译工具链。

1. __安装LibPcap++.__

​	Trinity 使用 PcapPlusPlus 完成网络包的剖析。[LibPcap++安装](https://github.com/seladb/PcapPlusPlus/releases/download/v23.09/pcapplusplus-23.09-ubuntu-20.04-gcc-9.4.0-x86_64.tar.gz)。
   简化安装：
   ```bash
   ./env/install_all.sh
   ```

### 1. 编译

```bash
./init.sh
```

### 2. 运行

```bash
cd build

./Trinity -config ../configuration/network_traffic.json
```

### 3. 结果

<img src="./fig/result1.jpg" style="zoom:70%;" />

<img src="./fig/result2.jpg" style="zoom:50%;" />

## Ref.

```
C.Fu, Q. Li, M. Shen, and K. Xu. Realtime robust malicious traffic detection via frequency demain analysis, in Proc. ACM SIGSAC Conf. on Comput. Commun. Secur., pp. 3432-3446, 2021.

C. Fu, Q. Li, and K. Xu, Detecting unknown encrypted malicious traffic in real time via flow interaction graph analysis, in Proc. Netw. Distrib. Syst. Secur. Symp., pp. 1-18, 2023.
```

