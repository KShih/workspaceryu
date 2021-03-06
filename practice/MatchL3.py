# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import time
import subprocess,sys
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ether
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import udp
from ryu import utils
from array import *


output_flag = [0 for n in range(0,60)]
pktin_count = [0 for n in range(0,60)]
count = 0
f = open('5SecPacketInLog.txt','w')
fall = open('PacketInLog.txt','w')


class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
    

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                     priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src
       

        minute = int(time.strftime("%M", time.localtime()))
        

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        #self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)


        #=============My Block Start====================#

            #>>>>>>>>>>>>>>> I P <<<<<<<<<<<<<<#
        pkt = packet.Packet(msg.data)
        
	if eth.ethertype == ether.ETH_TYPE_IP:
            #print 'Receive an ipv4 packet'
            ipv4_pkt = pkt.get_protocols(ipv4.ipv4)[0]
            print 'Src: %s, Dst: %s' % (ipv4_pkt.src, ipv4_pkt.dst)
           #fall.write(ipv4_pkt.src + '\n')
            fall.write('Src : ' + ipv4_pkt.src + '\n')
            fall.write('Dst : ' + ipv4_pkt.dst + '\n' + '\n')

        #arp_pkt = pkt.get_protocols(arp.arp)[0]
        #for p in pkt:
        #    print p
           # if(p.protocol_name == 'arp'):
               # _arp = pkt.get_protocols(arp.arp)[0]
               # f.write(_arp.src_ip + '\n')
               # fall.write(_arp.src_ip + '\n')
                #f.write(_arp.dst_ip + '\n')
                
        #    if(p.protocol_name == 'ipv4'):
        #        _ipv4 = pkt.get_protocols(ipv4.ipv4)[0]
        #        f.write(_ipv4.src + '\n')
        #        fall.write(_ipv4.src + '\n')
        #        f.write(_ipv4.dst + '\n' + '\n')
            #>>>>>>>>>>>>>>> I P <<<<<<<<<<<<<<#

        global fall
        global pktin_count
        a = int(time.strftime("%S", time.localtime()))
        pktin_count[a] += 1
        #print time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()) 
        if (output_flag[a-1]==0 and a>0):
            if(a % 5 == 0):
                f = open('5SecPacketInLog.txt','w')
            #f.close()
            #fall.close()
            fall = open('PacketInLog.txt','a')
            #f = open('5SecPacketInLog.txt','a')
            output_time = str( time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
            #f.write(output_time + ' --> ' + str(pktin_count[a-1]) + '\n')
            print "**********"
            print "PacketIn Count : ",
            print pktin_count[a-1]
            print "**********"
            output_flag[a-1] = 1

        if (output_flag[a-1]==0 and a==0):
            #f.close()
            #fall.close()
            fall = open('PacketInLog.txt','a')
            #f = open('5SecPacketInLog.txt','a')
            output_time = str( time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
            #f.write(output_time + ' --> ' + str(pktin_count[59]) + '\n')
            print "**********"
            print "PacketIn Count : ",
            print pktin_count[59]
            print "**********"
            output_flag[59] = 1
            pktin_count[59] = 0

        if(a==59):
            for i in range(0,58):
                pktin_count[i] = 0
                output_flag[i] = 0
        #============My Block End===================#
        

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        if (eth.ethertype == ether.ETH_TYPE_IP):
            print "###########  IPV4 flow  ###############"
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst,eth_type=0x0800, ipv4_src=ipv4_pkt.src)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)

        # install a flow to avoid packet_in next time
        elif out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath , buffer_id = msg.buffer_id,
                                  in_port=in_port , actions=actions,data=data)
        datapath.send_msg(out)

##      /* Print the details of each OFPacketIN */
        if msg.reason == ofproto.OFPR_NO_MATCH:
            reason = 'NO MATCH'
        elif msg.reason == ofproto.OFPR_ACTION:
            reason = 'ACTION'
        elif msg.reason == ofproto.OFPR_INVALID_TTL:
            reason = 'INVALID TTL'
        else:
            reason = 'unknown'
        self.logger.debug('OFPPacketIn received: '
                      'buffer_id=%x total_len=%d reason=%s '
                      'table_id=%d cookie=%d match=%s ',
                      msg.buffer_id, msg.total_len, reason,
                      msg.table_id, msg.cookie, msg.match)
# utils.hex_array(msg.data)
        print '..................'


