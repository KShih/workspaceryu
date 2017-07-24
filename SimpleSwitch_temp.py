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
import json
import threading
import subprocess , sys
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import udp
from array import *

count_pi = 0
count_last = 0
time_last = 0
time_now = 1
check_point = 0

pktin_flag = False

count_src = ''
count_dst = ''

class PacketInCount (threading.Thread,lock):
    while(True):
       lock.acquire()
       def run(self):
              testflag = 1
              f = open('PacketInLog.txt','w')
              while(1): 
                      globa l count_pi
                     global count_last
                     global count_src
                     global count_dst
                     output_time = str( time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()) )
                     output =str(count_pi - count_last)
                     print "**********"
                     print "PacketIn:", output ,"(Count/Sec)"

                     if(testflag == 0):
                       cmd = ' ryu-manager --observe-links --ofp-tcp-listen-port 5555 --verbose rest_firewall.py'
                       subprocess.call(cmd , shell=True)
                       print "High PacketIn Mode..."
                       testflag = 1
                     
                     global pktin_flag
                     if(count_pi - count_last ) > 150 :
                       pktin_flag = True

                     print "**********"
                     f.write(output_time + ' --> ' + output + '\n')
                     count_last = count_pi
                     time.sleep(1) 
       lock.release()

class SimpleSwitch13(threading.Thread,lock,app_manager.RyuApp):
  while(True):
    lock.acquire()
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
        print("************ Start of Pacet-in **************")
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


        #pkt = packet.Packet(array.array('B',msg.data))
        pkt = packet.Packet(msg.data)

        global count_src
        global count_dst
        ff = open('PacketInLog.txt','a')
        for p in pkt:
            #print p.protocol_name,p
            print p
            if(p.protocol_name == "arp"):
                _arp = pkt.get_protocols(arp.arp)[0]
                count_src = _arp.src_ip
                count_dst = _arp.dst_ip
                ff.write('Src IP : ' + _arp.src_ip + '\n')
                ff.write('Dst IP : ' + _arp.dst_ip + '\n')
                print('arp_src: '+ _arp.src_ip)
                print('arp_dst: '+ _arp.dst_ip)

            if(p.protocol_name == 'ipv4'):
                _ipv4 = pkt.get_protocols(ipv4.ipv4)[0]
                count_src = _ipv4.src
                count_dst = _ipv4.dst
                ff.write('Src IP : ' + _ipv4.src + '\n')
                ff.write('Src IP : ' + _ipv4.dst + '\n')
                print('ipv4_src: '+ _ipv4.src)
                print('ipv4_dst: '+ _ipv4.dst)

        #if eth.ethertype == ether_types.ETH_TYPE_LLDP:
        #    # ignore lldp packet
        #    return

        eth = pkt.get_protocols(ethernet.ethernet)[0]
        dst = eth.dst
        src = eth.src


        global pktin_flag
        if(pktin_flag == True):
          src = eth.dst

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        #self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)
        global count_pi
        count_pi += 1


        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
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

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

        print("********** END OF Pacet-IN ***********")
    lock.release()

if __name__ == "__main__":
        lock = thread.allocate_lock() 
        thread.start_new_thread(PacketInCount, (lock))
        thread.start_new_thread(SimpleSwitch13, (lock))
        while (True):
            pass
