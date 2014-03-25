#!/usr/bin/env python
# -*- coding: utf-8 -*-

#20140325
#zmap_tool.py
#pcapを読み込んで出力
#使い方 ./zmap_tool.py *.pcap


import os,sys,dpkt,socket,binascii,string,re, operator,socket,datetime,time

#送信元アドレス毎パケット数
host_tcp = {}
host_udp = {}

#パケットカウント
all_packet = 0
tcp_packet = 0
udp_packet = 0

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
            
            if type(ip.data) == dpkt.tcp.TCP:
            #TCPの検知
                tcp = ip.data
                if tcp.flags!=2:#synフラグ
                    continue
                if (ip.id,ip.off,tcp.win,ip.len)==(54321,0,65535,40):
                    if host_tcp.get(src_addr)==None:
                        host_tcp[src_addr] = 1
                    else:
                        host_tcp[src_addr] += 1
                    tcp_packet += 1

            elif type(ip.data) == dpkt.udp.UDP:
            #UDPの検知
                if ip.data.data == 'GET / HTTP/1.1\r\nHost: www\r\n\r\n':
                    if (ip.id,ip.off,ip.len) == (54321,0,57):
                        if host_udp.get(src_addr)==None:
                            host_udp[src_addr] = 1
                        else:
                            host_udp[src_addr] += 1
                        udp_packet += 1

            else:
                continue

            all_packet += 1


def sort(list_dict,name):
    #並び替えて表示

    print "\n====================== "+name+"sort =====================\n"
    for k,v in sorted(list_dict.items()):
        print k,v

if __name__ == '__main__':
    filename = sys.argv[1]
    if "/" in filename:
        print filename[filename.rindex('/')+1:]
    else :
        print filename

    header(sys.argv[1])
    print 'All packet = ',all_packet
    print 'TCP packet = ',tcp_packet
    print 'UDP packet = ',udp_packet
    sort(host_tcp,"tcp host")
    sort(host_udp,"udp host")
