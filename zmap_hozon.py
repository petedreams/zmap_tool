#!/usr/bin/env python
# -*- coding: utf-8 -*-

#20140325
#zmap_tool.py
#pcapを読み込んで条件にあったパケットだけ出力
#使い方 ./zmap_hozon.py *.pcap


import os,sys,dpkt,socket,binascii,string,re, operator,socket,datetime,time

#宛先ポート変更はコレ
dstport = 53

def header(file):
#pcap読み込み

    global all_packet
    global tcp_packet
    global udp_packet

    f= open(file)
    pcap = dpkt.pcap.Reader(f)

    for ts,buf in pcap:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
        except:
            continue
        
        if type(eth.data) == dpkt.ip.IP:
            ip = eth.data
            src_addr=socket.inet_ntoa(ip.src)
            dst_addr=socket.inet_ntoa(ip.dst)
            
            if type(ip.data) == dpkt.udp.UDP:
            #UDPの検知
                udp = ip.data
                if (ip.id,ip.off,ip.len,udp.dport) == (54321,0,57,dstport):
                    a

if __name__ == '__main__':
    filename = sys.argv[1]
    header(sys.argv[1])
    print 'All ',all_packet
    print 'TCP ',tcp_packet
    print 'UDP ',udp_packet
    print 'tcphost ',len(host_tcp)
    print 'samehost ',len(host_tcp_cut)
    print
    if "/" in filename:
        print filename[filename.rindex('/')+1:]
    else :
        print filename
    sort(host_tcp,"tcp host")
    sort(host_udp,"udp host")
