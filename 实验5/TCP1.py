# -*- coding: utf-8 -*# 导入模块
# from scapy.all import *
# # 查看包信息
# pkt = IP(dst="")
# ls(pkt)
# pkt.show()
# summary(pkt)
# # 发送数据包
# send(pkt)  # 发送第三层数据包，但不会受到返回的结果。
# sr(pkt)  # 发送第三层数据包，返回两个结果，分别是接收到响应的数据包和未收到响应的数据包。
# sr1(pkt)  # 发送第三层数据包，仅仅返回接收到响应的数据包。
# sendp(pkt)  # 发送第二层数据包。
# srp(pkt)  # 发送第二层数据包，并等待响应。
# srp1(pkt)  # 发送第二层数据包，并返回响应的数据包
# # 监听网卡
# sniff(iface="wlan1",count=100,filter="tcp")
# # 应用：简单的SYN端口扫描 （测试中）
# pkt = IP("...")/TCP(dport=[n for n in range(22, 3389)], flags="S")
# ans, uans = sr(pkt)
# ans.summary() # flag为SA表示开放，RA表示关闭        print ("Closed")