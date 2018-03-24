# Python Standard
import logging
import array
import netaddr
import thread
import time
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
from ryu.lib.packet import arp
from ryu.lib.packet import lldp
from ryu.lib.packet import dhcp
from ryu.lib.packet import ipv4
from ryu.lib.packet import udp
from ryu.topology.switches import LLDPPacket

from protocol_handler import dhcp_handler
from netmap import netmap



#Networkx
import networkx as nx

#Plotter
import matplotlib.pyplot as pl

LOG = logging.getLogger(__name__)

class SimpleSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_2.OFP_VERSION]

    def _execute_lldp(self, s):
        time.sleep(4000)
        LOG.debug("--- Sending LLDP request")
        for  switch in self.networkMap.neighbors(self.cDummy):
            parser = switch.dp.ofproto_parser
            ofproto = switch.dp.ofproto
            for port in self.networkMap.neighbors(switch):
                #LOG.debug("--- Sending From Port %s", port.hw_addr)
                data = LLDPPacket.lldp_packet(switch.dp.id, 1, port.hw_addr, 1)
                actions = [parser.OFPActionOutput(port.port_no)]
                
                out = parser.OFPPacketOut(datapath=switch.dp,
                                    buffer_id=ofproto_v1_2.OFP_NO_BUFFER,
                                    actions=actions, in_port=ofproto_v1_2.OFPP_CONTROLLER,
                                    data=data)
                switch.dp.send_msg(out)
        self._report()
        #nx.draw(self.networkMap, withLabel=True)
        #pl.show() 
        
        
        self._execute_lldp(s)

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
                                priority=0,
                                match=parser.OFPMatch(),
                                instructions=inst)
        datapath.send_msg(mod)



    def _report(self):
        return
   #     for switch in self.networkMap.neighbors(self.cDummy):
   #         LOG.debug("--- Switch %s", switch)
   #         for port in self.networkMap.neighbors(switch):
   #             LOG.debug("--- Port %s with addr %s", port.port_no, port.hw_addr)
   #             for p in self.networkMap.neighbors(port):
   #                 LOG.debug("--- Connected to %s", p)
    
    def __init__(self, *args, **kwargs):
        super(SimpleSwitch, self).__init__(*args, **kwargs)
        
        #Instance of DHCP Handler
        self.dhcp_h = dhcp_handler.dhcp_handler(self.networkMap)

        #LLDP Deamon
        try:
            thread.start_new_thread(self._execute_lldp, (4,))
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

        if self._find_protocol(pkt, "arp"):
            p_arp = self._find_protocol(pkt, "arp")
            LOG.debug("ARP %s", p_arp.opcode)
            if p_arp.opcode == arp.ARP_REQUEST:
                src_ip = str(netaddr.IPAddress(p_arp.src_ip))
                dst_ip = str(netaddr.IPAddress(p_arp.dst_ip))
                src_mac = str(p_arp.src_mac)
                dst_mac = str(p_arp.dst_mac)
                LOG.debug("--- ARP REQUEST found!: %s->%s\nMAC-Address src:%s\nMacAddress Dest:%s\n", src_ip, dst_ip, src_mac, dst_mac)
                #try to add src mac to network
                
                if not self._findMacByIP(src_ip):
                    self.networkMap.add_edge(self._findPortByPath(datapath.id, msg.match['in_port']), host.host(src_mac,src_ip))
            
                if self._findMacByIP(dst_ip):
                    LOG.debug("--- I can answer this. ")
                    dst_mac = self._findMacByIP(dst_ip)
                    e = ethernet.ethernet(src_mac, dst_mac, ether.ETH_TYPE_ARP)
                    a = arp.arp(hwtype=1, proto=ether.ETH_TYPE_IP, hlen=6, plen=4,
                    opcode=arp.ARP_REPLY, src_mac=dst_mac, src_ip=dst_ip,
                    dst_mac=src_mac, dst_ip=src_ip)
                    p = packet.Packet()
                    p.add_protocol(e)
                    p.add_protocol(a) 
                    p.serialize()
                    actions = [parser.OFPActionOutput(msg.match['in_port'])]
                    out = parser.OFPPacketOut(datapath=datapath,
                                        buffer_id=ofproto_v1_2.OFP_NO_BUFFER,
                                        actions=actions, in_port=ofproto_v1_2.OFPP_CONTROLLER,
                                        data=p)
                    datapath.send_msg(out)
                    
                else:
                    LOG.debug("--- Flood now")
                    actions = [parser.OFPActionOutput(ofproto_v1_2.OFPP_FLOOD)]
                    out = parser.OFPPacketOut(datapath=datapath,
                                      buffer_id=ofproto.OFP_NO_BUFFER,
                                      in_port=in_port, actions=actions,
                                      data=msg.data)
                    datapath.send_msg(out)

                    
               
            elif p_arp.opcode == arp.ARP_REPLY:
                port = self._findPortByHostMac(p_arp.dst_ip)
                if port:
                    actions = [parser.OFPActionOutput(port.port_no)]
                    out = parser.OFPPacketOut(datapath=port.dpid,
                                        buffer_id=ofproto_v1_2.OFP_NO_BUFFER,
                                        actions=actions, in_port=ofproto_v1_2.OFPP_CONTROLLER,
                                        data=msg.data)
                    switch.dp.send_msg(out)
                else:
                    LOG.debug("--- Flood Reply")
                    actions = [parser.OFPActionOutput(ofproto_v1_2.OFPP_FLOOD)]
                    out = parser.OFPPacketOut(datapath=datapath,
                                      buffer_id=ofproto.OFP_NO_BUFFER,
                                      in_port=in_port, actions=actions,
                                      data=msg.data)
                    datapath.send_msg(out)
        elif self._find_protocol(pkt, "lldp"):
            #LOG.debug("---LLDP Packet found")
            p_eth = self._find_protocol(pkt, "ethernet")
            #LOG.debug("from %s to %s", p_eth.src, datapath.id)
            if (self._findMac(p_eth.src) and self._findPortByPath(datapath.id, msg.match['in_port'])):
                #LOG.debug("AkA %s", self._findPortByPath(datapath.id, msg.match['in_port']))
                self.networkMap.add_edge(self._findMac(p_eth.src), self._findPortByPath(datapath.id, msg.match['in_port']))
            else:
                LOG.debug("%s konnte nicht gefunden werden", datapath.id)
        elif pkt.get_protocols(dhcp.dhcp):
            toSend = self.dhcp_h._handle_dhcp(pkt)
            if toSend:
                self._send_packet(datapath, in_port, toSend)
            
        else:
            LOG.debug(" --- No Supported Protocol")
            for p in pkt.protocols:
                if hasattr(p, 'protocol_name'):
                    LOG.debug(p.protocol_name)
            

    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):
        if ev.switch is not None:
            switch = ev.switch
            self._addSwitch(switch)
            pl.subplot(121)
            nx.draw(self.networkMap, withLabel=True)
            #pl.show()

    def _send_packet(self, datapath, port, pkt):
        print("Sending packet back")
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt.serialize()
        self.logger.info("packet-out %s" % (pkt,))
        data = pkt.data
        actions = [parser.OFPActionOutput(port=port)]
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=data)
        datapath.send_msg(out)
        
