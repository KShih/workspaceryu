# coding: utf-8
# In[ ]:

# 本實驗延續blockh3_with_tx.py
# 模擬：
#   假設 host3 為可疑的惡意來源，依據'流量時變量'，若每固定時間(monitor_time)之tx流量時變率>固定值，增加entry來block h3
# 測試：
#     mininet端輸入 h1 ping h3 -s 3000
# 以及mininet端輸入 h1 ping h3 -s 5000兩種情形
# 觀察：
#  1. mininet: 當被判定為可疑來源後 ping 即會失敗
#  2. ryu: 當被判定為可疑來源後，port1 的rx, tx 均不會再增加
#                              而port3 的rx 會持續增加（因為惡意攻擊還是送得進來）, 但tx則不會再增加
#  則表示我們成功block住host3了
# 方法：
#  透過list存取每個port之當下流量以及單位時間的流量變化量，其中取得變化量之演算法:
#   now = 當下總tx_byte
#   flow = now - last(即現在-上個時間點)
#   last = now (目前的總流量，會成為下個時間點的last)
#   list及其index關係，now[1]代表port1 的 now， flow[2]代表port 2的流量時變量，類推
# 未來：
#  流量時變量趨於穩定，更改entry，開通被block的host3
#
# Note:
#  list不可宣告在monitor內，會被不斷重複宣告，list內值便永遠為0
#  因list以global方式宣告，故需要透過call function的方式改值，偏麻煩，可嘗試改進

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from operator import attrgetter 
from ryu.lib import hub
from ryu.lib.packet import ether_types
import os


block3 = 0
monitor_time = 5
#monitor_time為單位時間，每過 X 秒，monitor就更新一次，並統計每個port在該秒跟五秒前的流量差異

last = [0 for n in range(0,30)]
flow = [0 for n in range(0,30)]
now  = [0 for r in range(0,30)]

class SimpleSwitch13(app_manager.RyuApp):
    
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)
        #============================monitor============================#

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if not datapath.id in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            global monitor_time
            hub.sleep(monitor_time)
# monitor每過monitor time秒，便更新一次，此monitor_time值設定在code最前面，以global方式宣告
	
    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body

        self.logger.info('datapath         '
                         'in-port  eth-dst           '
                         'out-port packets  bytes')
        self.logger.info('---------------- '
                         '-------- ----------------- '
                         '-------- -------- --------')
        for stat in sorted([flow for flow in body if flow.priority == 1],
                           key=lambda flow: (flow.match['in_port'],
                                             flow.match['eth_dst'])):
            self.logger.info('%016x %8x %17s %8x %8d %8d',
                             ev.msg.datapath.id,
                             stat.match['in_port'], stat.match['eth_dst'],
                             stat.instructions[0].actions[0].port,
                             stat.packet_count, stat.byte_count)
            
    
    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        body = ev.msg.body
        global monitor_time	
        self.logger.info('datapath         port     '
                         'rx-pkts  rx-bytes rx-error '
                         'tx-pkts  tx-bytes tx-error tx-flow/time')
        self.logger.info('---------------- -------- '
                         '-------- -------- -------- '
                         '-------- -------- -------- -----------')
        for stat in sorted(body, key=attrgetter('port_no')):
            num = 0
            if stat.port_no <= 2000:
                num = stat.port_no
            self.change_now(num,stat.tx_bytes)
            self.change_flow(num,now[num]-last[num])
            self.change_flow(num,flow[num]/monitor_time)
            self.change_last(num,now[num])
	    #now[num] = stat.tx_bytes	    
	    #flow[num] = now[num] - last[num]
	    #flow[num] = flow[num] / time
	    #last[num] = now[num]
            #flow[num]即為該port之流量時變量
            self.logger.info('%016x %8x %8d %8d %8d %8d %8d %8d %8d', 
                             ev.msg.datapath.id, stat.port_no,
                             stat.rx_packets, stat.rx_bytes, stat.rx_errors,
                             stat.tx_packets, stat.tx_bytes, stat.tx_errors, flow[num] )
            if (stat.port_no == 3) and (flow[stat.port_no] >= 5000):
                msg = ev.msg
                datapath = msg.datapath
                parser = datapath.ofproto_parser
                ofproto = datapath.ofproto

                instruction = [parser.OFPInstructionActions(ofproto.OFPIT_CLEAR_ACTIONS, []) ]
                self.logger.info("Blocked host 3's entry adding")
                match = parser.OFPMatch(eth_src = '00:00:00:00:00:03')
                blockflow = parser.OFPFlowMod(datapath,
                                              priority = 2,
                                              command = ofproto.OFPFC_ADD,
                                              match = match,
                                              instructions = instruction
                                              )
                self.logger.info("Block entry: %s" % str(blockflow));
                datapath.send_msg(blockflow)
                
                
    
    def change_now(self,num1,num2):
        global now
        now[num1] = num2
    def change_last(self,num1,num2):
        global last
        last[num1] = num2
    def change_flow(self,num1,num2):
        global flow
        flow[num1] = num2
        #============================monitor============================#

        #============================SWITCH============================#


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
        global block3
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

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD
        

        # Blocked host3 by setting output port to in_port
        
        actions = [parser.OFPActionOutput(out_port)]
        # install a flow to avoid packet_in next time
        
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            self.add_flow(datapath, 1, match, actions)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
                
        # Packet-out
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
        
