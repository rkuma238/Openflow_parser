import pyparsing
import datetime,time
import os

from pip._vendor.pyparsing import Word, Combine, hexnums, Group, Optional, nums, alphanums

# print "Flows are ", flows

LBRACE = '('
RBRACE  = ')'
COMMA   = ','
COLON   = ':'
EQUAL = '='

in_port = packets = proto = tos = ttl = src = dst = op = Word(nums)
ipAddress = Combine(Word(nums) + ('.' + Word(nums)) * 3)
twohex = Word(hexnums, exact=2)
macAddress = Combine(twohex + (':' + twohex) * 5)
eth_type = Combine('0x' + Word(hexnums, exact=4))
frag = Word(alphanums)

eth = Group("eth" + LBRACE +
            "src" + EQUAL + macAddress("src") + COMMA +
            "dst" + EQUAL + macAddress("dst") +
            RBRACE)
arp = Group("arp" + LBRACE +
            "sip" + EQUAL + ipAddress("sip") + COMMA +
            "tip" + EQUAL + ipAddress("tip") + COMMA +
            "op" + EQUAL + op("op") + COMMA +
            "sha" + EQUAL + macAddress("sha") + COMMA +
            "tha" + EQUAL + macAddress("tha") +
            RBRACE)
ipv4 = Group("ipv4" + LBRACE + "src" + EQUAL + ipAddress("src") + COMMA +
             "dst" + EQUAL + ipAddress("dst") + COMMA +
             "proto" + EQUAL + proto("proto") + COMMA +
             "tos" + EQUAL + tos("tos") + COMMA +
             "ttl" + EQUAL + ttl("ttl") + COMMA +
             "frag" + EQUAL + frag("frag") +
             RBRACE)
# ipv4(src=193.170.192.143,dst=193.170.192.142,proto=6,tos=0,ttl=64,frag=no),tcp(src=45969,dst=5672), packets:1, bytes:87, used:4.040s, flags:P., actions:1
tcp = Group("tcp" + LBRACE +
            "src" + EQUAL + src("srcPkt") + COMMA +
            "dst" + EQUAL + dst("dstPkt") +
            RBRACE)
flowTcp = ("in_port" + LBRACE + in_port("in_port") + RBRACE + COMMA +
               eth("eth") + COMMA +
               Optional("eth_type" + LBRACE + eth_type("eth_type") + RBRACE + COMMA) +
               Optional(ipv4("ipv4") + COMMA) +
               Optional(tcp("tcp") + COMMA) +
               Optional(arp("arp") + COMMA) +

               "packets" + COLON + packets("packets"))

with open('parseopenflows') as f:
    lines = f.readlines()

flag_ipv4 = 0;
flag_arp = 0;
for line in lines:
    flowTcpValues = flowTcp.parseString(line)
    #print (flowTcpValues.dump())
    #print (flowTcpValues.packets)
    #print (flowTcpValues.eth.src)

    if flowTcpValues.arp:
        if (flag_arp == 0):
            print("\n\nDest_MAC           Source_MAC         Protocol       Packets ")
            print("-----------------------------------------------------------------")
            flag_arp = 1

        print ("%s  %s  ARP            %s"%(flowTcpValues.eth.src, flowTcpValues.eth.dst, flowTcpValues.packets   ))

for line in lines:
    flowTcpValues = flowTcp.parseString(line)


    if flowTcpValues.ipv4 :
        if (flag_ipv4 == 0):
            print("\n\nDest_MAC           Source_MAC         Protocol    Source_IP         Dest_IP       Packets")
            print("---------------------------------------------------------------------------------------------")
            flag_ipv4 = 1
        print("%s  %s  IPV4        %s   %s   %s" % (flowTcpValues.eth.src, flowTcpValues.eth.dst, flowTcpValues.ipv4.src, flowTcpValues.ipv4.dst, flowTcpValues.packets ))



