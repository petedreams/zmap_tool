#!/usr/bin/env python
# -*- coding: utf-8 -*-

#detect_tool.py
#pcapを読み込んでsynだけ取り出して出力
#使い方 ./detect_tool.py *.pcap


import os,sys,dpkt,socket,binascii,string,re, operator,socket,datetime,time

#表示する固定ヘッダを持つパケット数の下限
SORT_SEQ_COUNT = 15 #15?
SORT_ID_COUNT = 50 #50?

#マルウェア別送信ホストのリスト[1.1.1.1, 2.2.2.2, 3.3.3.3, .....]
host_morto2282 = []
host_morto1210 = []
host_morto1210_2 = []
host_morto2406 = []
host_srizbi = []
host_ms_dark1 = []
host_ss_dark1 = []
host_ss_dark2 = []
host_ss_dark3 = []
host_ss_dark4 = []
host_ss_dark5 = []

#シーケンス番号,IP ID保存用辞書 {"seq1":{"IP":count},"seq2":{"IP":count}・・・}
seq_list = {}
id_list = {}

hostlist = [host_morto2282,host_morto1210,host_morto1210_2,host_morto2406,host_srizbi,host_ms_dark1,host_ss_dark1,host_ss_dark2,host_ss_dark3,host_ss_dark4,host_ss_dark5]
signature_list=("SS_MORTODARK1","SS_MORTODARK2","SS_MORTODARK2_2","SS_MORTO","MS_SRIZBI","MS_DARK1","SS_DARK1","SS_DARK2","SS_DARK3","SS_DARK4","SS_DARK5")

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


def signature(ip,tcp,src_addr,dst_addr):
#シグネチャ参照

    #srizbi用
    srizbi_count = {}#カウント辞書,0?6
    init_seq = {}
    #ms_dark1用
    dark1_count = {}
    dark1_ttl = {}
    #ss_dark2用
    dark2_dport = (135,1433,3306)

#morto判定
    if tcp.dport == 3389:
        if (ip.id,tcp.seq,tcp.win)==(256,2284205602,512):#morto2282
            host_morto2282.append(src_addr)
        elif (ip.id,tcp.seq,tcp.win)==(256,12102533312,16384):#morto1210_1
            host_morto1210.append(src_addr)
        elif (ip.id,tcp.seq,tcp.win,tcp.sport)==(9496,2406000322,65535,4935):#morto2406
            host_morto2406.append(src_addr)
        elif (ip.id,tcp.seq,tcp.win,tcp.sport)==(256,12102533312,16384,6000):#morto1210_2
            host_morto1210_2.append(src_addr)
    
    #srizbi判定
    if tcp.dport == 4099:
        if dst_addr[:dst_addr.rindex(".")]== '208.72.169':
            if srizbi_count.get(src_addr) == None:#0
                init_seq[src_addr] = tcp.seq
                srizbi_count[src_addr] = 1
            elif 0 < srizbi_count.get(src_addr) and srizbi_count.get(src_addr) < 6:#1?5
                if tcp.seq != init_seq[src_addr]:
                    init_seq[src_addr] = tcp.seq
                    srizbi_count[src_addr] = 1
                else:
                    srizbi_count[src_addr] += 1
            elif srizbi_count[src_addr] == 6:#6
                if tcp.seq != init_seq[src_addr]:
                    init_seq[src_addr] = tcp.seq
                    srizbi_count[src_addr] = 1
                else:
                    for i in range(7):
                        host_srizbi.append(src_addr)
                        srizbi_count[src_addr]=None
    
    #MS_DARK1判定
    if tcp.seq == 0:
        if tcp.win == 0:
            if dark1_count.get(src_addr) == None:
                if ip.ttl == 1:
                    dark1_count[src_addr] = 1
                    dark1_ttl[src_addr] = 1
            elif 0 < dark1_count.get(src_addr) and dark1_count.get(src_addr) < 3:
                if ip.ttl == dark1_ttl[src_addr] + 1:
                    dark1_count[src_addr] += 1
                    dark1_ttl[src_addr] += 1
            elif dark1_count.get(src_addr) == 3:
                if ip.ttl == 4:
                    for i in range(4):
                        host_ms_dark1.append(src_addr)
                        dark1_count[src_addr]=None
    
    #SS_DARK1判定
    if (tcp.seq,ip.id,tcp.sport,tcp.dport,tcp.win)==(2018915346,65535,4445,135,65535):
        host_ss_dark1.append(src_addr)
    
    #SS_DARK2判定
    if (tcp.seq,tcp.win)==(520,16384):
        if tcp.dport in dark2_dport: #dportが135,1433,3066のどれかと一致
            host_ss_dark2.append(src_addr)

    #SS_DARK3判定
    if (tcp.seq,ip.id,tcp.sport,tcp.dport,tcp.win)==(2614384915,54321,32000,12345,1460):
        host_ss_dark3.append(src_addr)

    #SS_DARK4判定
    if (tcp.seq,tcp.sport,tcp.dport,tcp.win)==(886701323,27520,13663,65535):
        host_ss_dark4.append(src_addr)

    #SS_DARK5判定
    if (ip.id,tcp.sport,tcp.dport,tcp.win)==(256,6000,1433,16384):
        host_ss_dark5.append(src_addr)

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
    option = []
    """
        オプション
        -sig
        -seq
        -id
        無しはすべて実行
        """
    if len(sys.argv)>=3:
        for o in sys.argv:
            option.append(o)
    if len(sys.argv)==2:
        option.append("None")
    
    filename = sys.argv[1]
    if "/" in filename:
        print filename[filename.rindex('/')+1:]
    else :
        print filename

    syn_packet = header(sys.argv[1])
    print "All SYN Packet : ",syn_packet

    if "-sig" in option or "None" in option:#シグネチャ表示
        count = 0
        for i in hostlist:
            if i != []:
                print '--------* '+signature_list[count]+' *--------'
                host=[(x, i.count(x)) for x in set(i)]#マルウェア別host集計listからユニークカウントし、host[]に(host,count)
                print 'Source IP Address : Packet \n'
                for ip,packet in sorted(host,key=lambda koujun: koujun[1],reverse=True):
                    print ip.rjust(15),' : ',str(packet).rjust(5)
                print
            count +=1

    if "-seq" in option or "None" in option:
        sort(seq_list,"seq")
    if "-id" in option or "None" in option:
        sort(id_list,"id")

