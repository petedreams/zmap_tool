#!/usr/bin/env python
# -*- coding: utf-8 -*-

#20140325
#zmap_tool.py
#pcapを読み込んで条件にあったパケットだけ出力
#使い方 ./zmap_hozon.py *.pcap


import os,sys,dpkt,socket,binascii,string,re, operator,socket,datetime,time

#宛先ポート変更はコレ

def header(file):
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

            if type(ip.data) == dpkt.udp.UDP:
            #UDPの検知
                udp = ip.data
                try:
                    ntp = dpkt.ntp.NTP(udp.data)
                except:
                    continue
                id = binascii.hexlify(ntp.id)
                print "flags = %x\nstratum = %s\ninterval = %s\nprecision = %s\ndelay = %s\ndispersion = %s\nid = %s\n" % (ntp.flags,ntp.stratum,ntp.interval,ntp.precision,ntp.delay,ntp.dispersion,id)
                
if __name__ == '__main__':
    filename = sys.argv[1]
    if "/" in filename:
        infile =  filename[filename.rindex('/')+1:]
    else :
        infile = filename
    header(filename)
