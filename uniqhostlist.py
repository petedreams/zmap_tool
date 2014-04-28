#!/usr/bin/env python
# -*- coding: utf-8 -*-

#20140423
#uniq_host.py
#pcapを読み込んでユニークホスト数を表示
#使い方 ./uniqhost.py *.pcap


import os,sys,dpkt,socket,binascii,string,re, operator,socket,datetime,time

host={}

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
            if not host.get(src_addr):
                host[src_addr] = 1
            else :
                host[src_addr] += 1

if __name__ == '__main__':
    filename = sys.argv[1]
    if "/" in filename:
        infile =  filename[filename.rindex('/')+1:]
    else :
        infile = filename
    header(filename)
    x=0
    for k, v in sorted(host.items(), key=lambda x:x[1],reverse=True):
        print k,v

