# coding: utf-8
# In[ ]:

# 本實驗延續blockh3_with_bdwith.py
# 模擬：
#   假設 host3 被判定為可疑來源並 增加entry來block h3 後，管理員願意在50個單位時間後，重新開放權限給host3來送資料
# 測試：
#     mininet端輸入 h1 ping h3 -s 3000
# 以及mininet端輸入 h1 ping h3 -s 5000兩種情形
# 觀察：
#  1. mininet: 當被Block住 ping 即會失敗，過了一段時間後h3又可以繼續送資料
#  2. ryu: 當被Block住後，port1 的rx, tx 均不會再增加
#                              而port3 的rx 會持續增加（因為惡意攻擊還是送得進來）, 但tx則不會再增加
#            （過了一段時間後)
#          解除Block ，port1 rx, tx, tx-flow/time 會重新開始增加
#                      port 3 的 tx, tx-flow/time 也會重新開始增加
#           則表示我們成功解除h3的Block了
#           （直到tx-flow/time超過5000，又會被block住 如此循環）
# 方法：
#   當Block entry被建立的同時，會將Block_flag set
#   系統即會進入計數的階段，
#   當一數到50則將舊的BlockEntry刪除，並會觸發一次新的Packet-In事件
# 未來：
#   OFPMatch()的判斷條件要再更彈性一點，即（不再單單只是監測host3，而是整個網路）
#   以限定流量大小，取代原有的直接Block住
# Note:
#  新增del_flow()這個函式去實踐刪除Entry的動作
#-----
# 07.02更新：加入物件導向編程, 新增class Host.py
#
import Host
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

monitor_time = 1
#monitor_time為單位時間，每過 X 秒，monitor就更新一次，並統計每個port在該秒跟五秒前的流量差異

host = [0 for n in range(0,100)]

for i in range (0,100):
    host[i] = Host.port_information(i)

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
                            key=lambda flow:(flow.match['in_port'],
                                        flow.match['eth_dst'])):
            self.logger.info('%016x %8x %17s %8x %8d %8d',
                             ev.msg.datapath.id,
                             stat.match['in_port'], stat.match['eth_dst'],
                             stat.instructions[0].actions[0].port,
                             stat.packet_count, stat.byte_count)
            
    
    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        body = ev.msg.body
        msg = ev.msg
        datapath = msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        global monitor_time
        self.logger.info('datapath         port     '
                         'rx-pkts  rx-bytes rx-error '
                         'tx-pkts  tx-bytes tx-error tx-flow/time')
        self.logger.info('---------------- -------- '
                         '-------- -------- -------- '
                         '-------- -------- -------- -----------')
        for stat in sorted(body, key=attrgetter('port_no')):
            num = 0
            if stat.port_no <= 10:
                num = stat.port_no
            host[num].set_now(stat.tx_bytes)
            host[num].set_flow(host[num].now - host[num].last)
            host[num].set_flow(host[num].flow / monitor_time)
            host[num].set_last(host[num].now)
            #self.change_now(num,stat.tx_bytes)
            #self.change_flow(num,now[num]-last[num])
            #self.change_flow(num,flow[num]/monitor_time)
            #self.change_last(num,now[num])
            self.logger.info('%016x %8x %8d %8d %8d %8d %8d %8d %8d', 
                             ev.msg.datapath.id, stat.port_no,
                             stat.rx_packets, stat.rx_bytes, stat.rx_errors,
                             stat.tx_packets, stat.tx_bytes, stat.tx_errors, host[num].flow )
            if (stat.port_no == 3) and (host[num].flow >= 5000):
                host[num].set_blocked_flag(True)
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
            if(host[num].blocked_flag):
                self.logger.info("Host%d's Block Timer: %d" % (num,host[num].blocked_timer));
                host[num].blocked_timer_add()
            if(host[num].blocked_timer == 50+monitor_time): #Re-Open the blocked host
                host[num].blocked_init()
                empty_match = parser.OFPMatch(eth_src = '00:00:00:00:00:03')
                instructions = []
                flow_mod = self.del_flow(datapath, empty_match,instructions)
                self.logger.info("Delete the Blocked entry(Re-Open Success!)")
            num = 0

        #============================monitor============================#

        #============================SWITCH============================#


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

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

    def del_flow(self, datapath, match,instructions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        mod = parser.OFPFlowMod(datapath=datapath,
                                command=ofproto.OFPFC_DELETE,
                                out_port=ofproto.OFPP_ANY,
                                out_group=ofproto.OFPG_ANY,
				instructions=instructions,
                                match=match)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
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
        
