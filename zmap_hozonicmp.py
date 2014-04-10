#!/usr/bin/env python
# -*- coding: utf-8 -*-

#20140410
#zmap_hozonicmp.py
#pcapを読み込んで条件にあったパケットだけ出力
#使い方 ./zmap_hozonicmp.py *.pcap


import os,sys,dpkt,socket,binascii,string,re, operator,socket,datetime,time


def header(file,filename):
#pcap読み込み

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
            

            if type(ip.data) == dpkt.icmp.ICMP:
            #ICMPの検知
                icmp = ip.data
                if icmp.type == dpkt.icmp.ICMP_ECHO:
                    icmp_echo = icmp.data
                if (ip.id,ip.off,ip.len,icmp_echo.seq) == (54321,0,40,0):
                    outfile.writepkt(eth,ts)

if __name__ == '__main__':
    filename = sys.argv[1]
    if "/" in filename:
        infile =  filename[filename.rindex('/')+1:]
    else :
        infile = filename
    print "Reading",infile,"..."
    outfile = dpkt.pcap.Writer(open('sorted_icmp_'+infile,'wb'))
    header(filename,outfile)
