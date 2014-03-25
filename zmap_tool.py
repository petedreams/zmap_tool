#!/usr/bin/env python
# -*- coding: utf-8 -*-

#20140325
#zmap_tool.py
#pcapを読み込んで出力
#使い方 ./zmap_tool.py *.pcap


import os,sys,dpkt,socket,binascii,string,re, operator,socket,datetime,time

#シーケンス番号,IP ID保存用辞書 {"seq1":{"IP":count},"seq2":{"IP":count}・・・}
seq_list = {}
id_list = {}

def header(file):
#pcap読み込み
    
    #パケットカウント
    syn_packet = 0
    
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
                    print 'tcp detected'

            if type(ip.data) == dpkt.udp.UDP:
            #UDPの検知
                if ip.data.data == 'GET / HTTP/1.1\r\nHost: www\r\n\r\n':
                    if (ip.id,ip.off,ip.len) == (54321,0,57):
                        print "udp detected"


                """
            #TCPデータ
            if type(ip.data) == dpkt.tcp.TCP:
                tcp = ip.data
                if tcp.flags!=2:#synフラグ
                    continue
                time= datetime.datetime.fromtimestamp(ts)
                syn_packet += 1
                
                #シーケンス番号辞書追加
                if seq_list.get(tcp.seq)==None:
                    seq_list[tcp.seq] = {src_addr:1}
                else:
                    if seq_list.get(tcp.seq).get(src_addr)==None:
                        seq_list[tcp.seq][src_addr]=1
                    else:
                        seq_list[tcp.seq][src_addr] += 1
                
                #IP ID辞書追加
                if id_list.get(ip.id)==None:
                    id_list[ip.id] = {src_addr:1}
                else:
                    if id_list.get(ip.id).get(src_addr)==None:
                        id_list[ip.id][src_addr]=1
                    else:
                        id_list[ip.id][src_addr] +=1
                
                signature(ip,tcp,src_addr,dst_addr)
    
    f.close()
    return syn_packet
"""


def sort(list_dict,name):
    #並び替えて表示
    if name == "seq":
        max_value = SORT_SEQ_COUNT
    elif name == "id":
        max_value = SORT_ID_COUNT

    max_list = [] #seq or IDごとの最大のパケット数を持つアドレスとパケット数 [(seq,ip,packet),(),()・・・]
    print "\n====================== "+name+"sort =====================\n"
    for key,dic in list_dict.items():
        value_count = 0
        for value in dic.values():
            value_count += value
        if value_count >= max_value:
            max_key=max([(v,k) for k,v in dic.items()])[1]
            max_list.append((key,max_key,dic.get(max_key)))
            count = 0
    print "         Soruce IP Adrress : Packet\n"
    for key,ip,packet in sorted(max_list,key=lambda koujun: koujun[2], reverse=True):#3つめの要素をkeyにして降順に並べ替え
        print "*** ",name," ",key," ***"
        dic2 = list_dict.get(key)
        if name == "seq":
            if len(dic2)>=2:#送信ホストが2以上
                print "!!!!suspicious!!!!"
        count = 0
        for i,p in sorted(dic2.items(),key=lambda koujun2: koujun2[1],reverse=True):
            print "        ",i.rjust(15)," : ",str(p).rjust(7)
            count += p
        print "All Packet : ",count,"\n"

if __name__ == '__main__':
    filename = sys.argv[1]
    if "/" in filename:
        print filename[filename.rindex('/')+1:]
    else :
        print filename

    header(sys.argv[1])
