#!/usr/bin/env python
# -*- coding: utf-8 -*-

#20140325
#zmap_tool.py
#pcapを読み込んで条件にあったパケットだけ出力
#使い方 ./zmap_hozon.py *.pcap


import ctypes,ipaddr,struct,os,sys,dpkt,socket,binascii,string,re, operator,socket,datetime,time,numpy


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
                tcp = ip.data
                #add= ipaddr.IPv4Interface(dst_addr)._ip^tcp.dport^tcp.seq
                #print 25337==numpy.array(add,dtype='H')
                addr_10 = int(binascii.b2a_hex(ip.dst),16)
                cal= addr_10^tcp.dport^tcp.seq
                print ctypes.c_ushort(cal).value==ip.id
                print ip.id


if __name__ == '__main__':
    filename = sys.argv[1]
    if "/" in filename:
        infile =  filename[filename.rindex('/')+1:]
    else :
        infile = filename
    header(filename)
