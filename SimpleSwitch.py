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
# =============================================================================================
#|| /\ \   /\  ___\           /\ \/ /    /\  ___\   /\ \_\ \   /\ \   /\ \_\ \   /\ \_\ \     ||
#|| \ \ \  \ \ \__ \    []    \ \  _"-.  \ \___  \  \ \  __ \  \ \ \  \ \  __ \  \ \  __ \    ||
#||  \ \_\  \ \_____\          \ \_\ \_\  \/\_____\  \ \_\ \_\  \ \_\  \ \_\ \_\  \ \_\ \_\   ||
#||   \/_/   \/_____/    []     \/_/\/_/   \/_____/   \/_/\/_/   \/_/   \/_/\/_/   \/_/\/_/ " ||
# =============================================================================================                             
import time
import subprocess,sys
import MySQLdb
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
from array import *
from entropy import entropy

output_flag = [0 for n in range(0,60)]
pktin_count = [0 for n in range(0,60)]
count = 0
close_flag = 0
blockip_flag = False


class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        fall = open('PacketInLog.txt','w')
        f = open('5SecPacketInLog.txt','w')
        f.close()
        fall.close()

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
        global blockip_flag
        
       
        if blockip_flag == False:
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        else:
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_CLEAR_ACTIONS, []) ]

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
    
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        #self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        f = open('5SecPacketInLog.txt','a')
	fall = open('PacketInLog.txt','a')
        #=============My Block Start====================#
        global close_flag
        a = int(time.strftime("%S", time.localtime()))
        pktin_count[a] += 1
        #print time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()) 
        if (output_flag[a-1]==0 and a>0):
            if(a % 5 == 0 and close_flag == 1):
                entropydb = entropy()
                
                #update the entropy count to sql
                
                db = MySQLdb.connect("120.113.173.84","root","ji3ul42; vul3j;6","ProjectSDN")
                cursor = db.cursor()
                sql = "UPDATE SDN SET Entropy = %f " % float(entropydb)
                try:
                    cursor.execute(sql)
                    db.commit()
                except:
                    db.rollback()
                db.close()
                #end of update to sql
                f.close()
                f = open('5SecPacketInLog.txt','w')
                close_flag = 0

            if(a % 6 ==0):
                close_flag = 1

            fall = open('PacketInLog.txt','a')
            print "**********"
            print "PacketIn Count : ",
            print pktin_count[a-1]
            print "**********"
            output_flag[a-1] = 1

        if (output_flag[a-1]==0 and a==0):
            entropy()
            fall = open('PacketInLog.txt','a')
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

            #>>>>>>>>>>>>>>> I P <<<<<<<<<<<<<<#
        pkt = packet.Packet(msg.data)
	if eth.ethertype == ether.ETH_TYPE_IP:
            ipv4_pkt = pkt.get_protocols(ipv4.ipv4)[0]
            print 'Src: %s, Dst: %s' % (ipv4_pkt.src, ipv4_pkt.dst)
            fall.write(ipv4_pkt.src + '\n')
            f.write(ipv4_pkt.src + '\n')
            #>>>>>>>>>>>>>>> I P <<<<<<<<<<<<<<#

        #============My Block End===================#
        

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]


        if (eth.ethertype == ether.ETH_TYPE_IP):
            print "############ IPV4 flow ##########"
            match = parser.OFPMatch(in_port=in_port, eth_type=0x0800, ipv4_src=ipv4_pkt.src, eth_dst=dst)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out

            #check ip
#            global blockip_flag
#
#            if ('216' in ipv4_pkt.src): #TARGET
#                blockip_flag = False
#            elif ('120.113' in ipv4_pkt.src):
#                blockip_flag = False
#            elif ('64.' in ipv4_pkt.src):
#                blockip_flag = False
#            elif ('74.' in ipv4_pkt.src):
#                blockip_flag = False
#            elif ('172.' in ipv4_pkt.src):
#                blockip_flag = False
#            elif ('10.' in ipv4_pkt.src): #self ip
#                blockip_flag = False
#            elif ('8.8.8.8' in ipv4_pkt.src): #DNS
#                blockip_flag = False
#            elif ('168.95' in ipv4_pkt.src): #DNS
#                blockip_flag = False
#            elif ('163.28' in ipv4_pkt.src): #DNS
#                blcokip_flag = False
#            elif ('140.130' in ipv4_pkt.src): #NCYU DNS
#                blockip_flag = False
#            else:
#                blockip_flag = True

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


