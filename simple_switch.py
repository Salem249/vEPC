# Python Standard
import logging
import array
import thread
import struct
import host


#Ryu
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.topology import event
from ryu.lib import addrconv
from ryu.ofproto import ofproto_v1_2
from ryu.ofproto import ether
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import lldp
from ryu.lib.packet import dhcp
from ryu.lib.packet import ipv4
from ryu.lib.packet import udp


from protocol_handler import dhcp_handler
from protocol_handler import lldp_handler
from protocol_handler import arp_handler
from netmap import netmap


LOG = logging.getLogger(__name__)

class SimpleSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_2.OFP_VERSION]

    def add_flow(self, datapath, in_port, dst, src, out_port, actions):
        LOG.debug("--- Add FLow matching based on IPAddress")
        ofproto = datapath.ofproto

        match = datapath.ofproto_parser.OFPMatch(
            in_port=in_port,
            ipv4_dst=dst, ipv4_src=src, eth_type = 0x0800)
        instructions =[datapath.ofproto_parser.OFPInstructionActions(ofproto_v1_2.OFPIT_APPLY_ACTIONS, actions=actions)]

        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0, cookie_mask=0,
            command=ofproto.OFPFC_ADD, priority=3,idle_timeout=0, hard_timeout=0, out_port=out_port, flags=ofproto.OFPFF_SEND_FLOW_REM, instructions=instructions)
        datapath.send_msg(mod)            


    #def _execute_lldp(self, s):
    #    time.sleep(4)
    #    LOG.debug("--- Sending LLDP request")
    #    for  switch in self.networkMap.networkMap.neighbors("Control"):
    #        parser = switch.dp.ofproto_parser
    #        ofproto = switch.dp.ofproto
    #        for port in self.networkMap.networkMap.neighbors(switch):
    #            data = LLDPPacket.lldp_packet(switch.dp.id, 1, port.hw_addr, 1)
    #            actions = [parser.OFPActionOutput(port.port_no)]
    #            
    #            out = parser.OFPPacketOut(datapath=switch.dp,
    #                                buffer_id=ofproto_v1_2.OFP_NO_BUFFER,
    #                                actions=actions, in_port=ofproto_v1_2.OFPP_CONTROLLER,
    #                                data=data)
    #            switch.dp.send_msg(out)
    #    
    #    self.networkMap.report()
    #    self._execute_lldp(s)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _switch_features_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        actions = [parser.OFPActionOutput(port=ofproto.OFPP_CONTROLLER,
                                          max_len=ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(type_=ofproto.OFPIT_APPLY_ACTIONS,
                                             actions=actions)]
        mod = parser.OFPFlowMod(datapath=datapath,
                                priority=1,
                                match=parser.OFPMatch(),
                                instructions=inst)
        datapath.send_msg(mod)


    
    def __init__(self, *args, **kwargs):
        super(SimpleSwitch, self).__init__(*args, **kwargs)
        #Instance of the NetworkMap
        self.networkMap = netmap.netmap()
        #Instance of DHCP Handler
        self.dhcph = dhcp_handler.dhcp_handler(self.networkMap)
        #Instance of Arp Handler
        self.arph = arp_handler.arp_handler(self.networkMap)
        #Instance of LLDP Handler
        self.lldph = lldp_handler.lldp_handler(self.networkMap)
        #LLDP Deamon
        try:
            thread.start_new_thread(self.lldph._execute_lldp, (4,self._send_data))
        except:
            LOG.debug("--- LLDP Doesn't start")

    def _find_protocol(self, pkt, name):
        for p in pkt.protocols:
            if hasattr(p, 'protocol_name'):
                if p.protocol_name == name:
                    return p
        

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER) 
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        in_port = msg.match['in_port']
        pkt = packet.Packet(data=msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        dpid = datapath.id
        p_icmp = self._find_protocol(pkt, "icmp")
        p_ipv4 = self._find_protocol(pkt, "ipv4")
        toSend = None

        # The flow rules with test of icmp
        if p_ipv4 and p_icmp:

            #self.netMap.mac_to_port[dpid][eth.src] = in_port
            if self.networkMap.findActiveHostByMac(eth.dst):
                out_port = self.networkMap.findPortByHostMac(eth.dst).port_no

            else:
                out_port = ofproto.OFPP_FLOOD

            actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]

            # install a flow to avoid packet_in next time
            if out_port != ofproto.OFPP_FLOOD:
                self.add_flow(datapath, in_port, p_ipv4.dst, p_ipv4.src, out_port, actions)
            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data

            out = datapath.ofproto_parser.OFPPacketOut(
                datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
                actions=actions, data=data)
            datapath.send_msg(out)

        if self._find_protocol(pkt, "arp"):
            toSend = self.arph.handle(msg, self._send_packet)
        elif self._find_protocol(pkt, "lldp"):
            toSend = self.lldph.handle(msg, self._send_packet)
        elif pkt.get_protocols(dhcp.dhcp):
            toSend = self.dhcph._handle_dhcp(pkt)
        else:
            LOG.debug(" --- No Supported Protocol")
            for p in pkt.protocols:
                if hasattr(p, 'protocol_name'):
                    LOG.debug(p.protocol_name)
        if toSend:
                actions = [parser.OFPActionOutput(port=in_port)]
                self._send_packet(datapath, actions, toSend, ofproto.OFPP_CONTROLLER)
            

    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):
        if ev.switch is not None:
            switch = ev.switch
            self.networkMap.addSwitch(switch)


    def _send_packet(self, datapath, actions, pkt, in_port):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        #self.logger.info("packet-out %s" % (pkt,))
        pkt.serialize()
        data = pkt.data
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=in_port,
                                  actions=actions,
                                  data=data)
        datapath.send_msg(out)

    def _send_data(self, datapath, actions, data, in_port):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=in_port,
                                  actions=actions,
                                  data=data)
        datapath.send_msg(out)
