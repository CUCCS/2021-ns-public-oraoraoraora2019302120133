# 基于 Scapy 编写端口扫描器

## 实验目的

- 掌握网络扫描之端口状态探测的基本原理

## 实验环境

- python3.7 + [scapy](https://scapy.net/)、
- pycharm2021.1.3

## 实验要求

- 禁止探测互联网上的 IP ，严格遵守网络安全相关法律法规
- 完成以下扫描技术的编程实现
  - TCP connect scan / TCP stealth scan
  - TCP Xmas scan / TCP fin scan / TCP null scan
  - UDP scan
- 上述每种扫描技术的实现测试均需要测试端口状态为：`开放`、`关闭` 和 `过滤` 状态时的程序执行结果
- 提供每一次扫描测试的抓包结果并分析与课本中的扫描方法原理是否相符？如果不同，试分析原因；
- 在实验报告中详细说明实验网络环境拓扑、被测试 IP 的端口状态是如何模拟的

## 实验过程

##### 网络拓扑

- 攻击者主机
  - 08:00:27:0e:34:8d / eth0
  - 10.0.2.5
  
- 受害者主机
  - 08:00:27:1d:6c:7e / eth0
  - 172.16.111.100
  
- 网关
  - 08:00:27:71:81:de / enp0s9
  - 172.16.111.1
  
  ### TCP connect scan

#### Kali端口命令

```c
#下载utf
sudo apt install ufw
#允许端口访问
sudo ufw enable && ufw allow portno/tcp(udp)
#停用端口访问
sudo ufw disable
#端口过滤
sudo ufw enable && sudo ufw deny 8888/tcp(udp)
## 使用iptables
# 允许端口访问
sudo iptables -A INPUT -p tcp --dport 8888 -j ACCEPT
# 端口过滤
sudo iptables -A INPUT -p tcp --dport 8888 -j DROP
```

<img src=".\img\connect\ufw.png" style="zoom: 80%;" />

<img src=".\img\connect\orders.png" style="zoom:80%;" />

安装dnsmasq

```c
sudo apt install dnsmasq
```

<img src=".\img\connect\dnsmasq.png" style="zoom:67%;" />

TCP的py代码

```python
 import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
dst_ip = "172.16.111.145"   # Victim-Kali
src_port = RandShort()
dst_port = 80

# 发送SYN+Port(n)
tcp_connect_scan_resp = sr1(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="S"),timeout=10)

# 无响应/其他拒绝反馈报文
if tcp_connect_scan_resp is None:
    print("Filtered")

elif(tcp_connect_scan_resp.haslayer(TCP)):

    # 回复SYN
    if(tcp_connect_scan_resp.getlayer(TCP).flags == 0x12):  #Flags: 0x012 (SYN, ACK)
        send_rst = sr(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="AR"),timeout=10)
        print("Open")

    # 回复RST
    elif (tcp_connect_scan_resp.getlayer(TCP).flags == 0x14):   #Flags: 0x014 (RST, ACK)
        print ("Closed")
```

进入桌面并打开<img src=".\img\connect\cd.png" style="zoom:80%;" />

<img src=".\img\connect\2.png" style="zoom: 50%;" />

![](.\img\connect\attack1.png)

开放端口

<img src=".\img\connect\apache.png" style="zoom:80%;" />

```
nmap -sT -p 80 172.16.111.100
```

![](.\img\connect\namp.png)

抓包

![](.\img\connect\zhuabao.png)

关闭端口

<img src=".\img\connect\close apache.png" style="zoom:80%;" />

抓

<img src=".\img\connect\catch.png" style="zoom: 80%;" />

端口过滤

```kali
SUDO su
ufw enable && ufw deny 80/tcp
```

![](.\img\connect\filter.png)

继续抓

![](.\img\connect\catch2.png)

### TCP stealth scan

靶机抓包

```
sudo tcpdump -i eth0 -enp -w tcpstealth.pcap
```

开放端口

<img src=".\img\stealth\kaifang1.png" style="zoom:67%;" />

![](.\img\stealth\catch.png)

攻击者执行代码

![](.\img\stealth\attack.png)

nmap复刻

```
nmap -sS -p 80 172.16.111.114
```

![](.\img\stealth\nmap1.png)

抓

![](.\img\stealth\catch1.png)

### TCP Xmas scan

- 端口开放

  ```
  systemctl start apache2
  systemctl status apache2
  ```

- 靶机抓包

  ```
  sudo tcpdump -i eth0 -enp -w tcpxmas.pcap
  ```

- 攻击者执行代码

  ```
  sudo python3 x.py
  ```

![](.\img\stealth\1.png)

nmap复刻

```
nmap -sS -p 80 172.16.111.114
```

![](.\img\stealth\nmap1.png)

- 端口关闭

  ```
  systemctl stop apache2
  systemctl status apache2
  ```

- 靶机抓包

  ```
  sudo tcpdump -i eth0 -enp -w tcpxmas2.pcap
  ```

- 攻击者执行代码

  ```
  sudo python3 tcpxmas.py
  ```

![](.\img\stealth\close che.png)

##### filter

- 端口过滤

  ```
  ufw enable && ufw deny 80/tcp
  ```

- 靶机抓包

  ```
  sudo tcpdump -i eth0 -enp -w tcpxmas3.pcap
  ```

- 攻击者执行代码

  ```
  sudo python3 tcpxmas.py
  ```

### TCP fin scan

##### open

- 端口开放

  ```
  systemctl start apache2
  systemctl status apache2
  ```

- 靶机抓包

  ```
  sudo tcpdump -i eth0 -enp -w tcpfin.pcap
  ```

- 攻击者执行代码

  ```
  sudo python3 fin.py
  ```

![](.\img\stealth\fin.png)

nmap复刻

```
nmap -sF -p 80 172.16.111.114
```

![](.\img\stealth\nmap1.png)

##### close

- 端口关闭

  ```
  systemctl stop apache2
  systemctl status apache2
  ```

- 靶机抓包

  ```
  sudo tcpdump -i eth0 -enp -w tcpfin2.pcap
  ```

- 攻击者执行代码

  ```
  sudo python3 fin.py
  ```

### TCP null scan





## 遇到的问题

1.ufw下载不下来，尝试更新后

```
sudo apt-get update
```

<img src=".\img\connect\update.png" style="zoom:80%;" />

后即可

<img src=".\img\connect\done.png" style="zoom:80%;" />

2.py文件打不开

打不开文件是因为编码格式有问题，在文件开头加上

```
# -*- coding: utf-8 -*
```

即可

3.显示没有scapy及无法识别

<img src=".\img\connect\1.png" style="zoom:80%;" />

##### 参考资料

[1](https://forums.linuxmint.com/viewtopic.php?t=202418)

[2](https://askubuntu-com.translate.goog/questions/913943/firewalld-does-not-start-at-boot?_x_tr_sl=en&_x_tr_tl=zh-CN&_x_tr_hl=zh-CN&_x_tr_pto=sc)

[3](https://blog.csdn.net/wy_bk/article/details/78680863)

[4](https://github.com/CUCCS/2021-ns-public-SagiSiuirs/blob/chap0x05/README.md)

[5](https://github.com/CUCCS/2021-ns-public-Tbc-tang/blob/chap0x05/0x05.md)

[6](https://github.com/CUCCS/2021-ns-public-akihi0718/blob/chap0x05/chap0x05/chap0x05.md)[6](https://github.com/CUCCS/2021-ns-public-Taaami/tree/chap0x05)

[7](https://zhuanlan.zhihu.com/p/36070979)