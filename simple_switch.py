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
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.topology import event
from ryu.ofproto import ofproto_v1_2
from ryu.ofproto import ether
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import arp
from ryu.lib.packet import lldp
from ryu.topology.switches import LLDPPacket


#Networkx
import networkx as nx

#Plotter
import matplotlib.pyplot as pl

LOG = logging.getLogger(__name__)

class SimpleSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_2.OFP_VERSION]

    def _execute_lldp(self, s):
        time.sleep(4)
        LOG.debug("--- Sending LLDP request")
         #self._build_lldp()
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

    def _findMac(self, mac):
        for  switch in self.networkMap.neighbors(self.cDummy):
            for port in self.networkMap.neighbors(switch):
                if(port.hw_addr == mac):
                    return port
        return

    def _findPortByHostMac(self, mac):
        for  switch in self.networkMap.neighbors(self.cDummy):
            for port in self.networkMap.neighbors(switch):
                for thing in self.networkMap.neighbors(port):
                    if isinstance(thing, host.host):
                        if thing.mac == mac:
                            return port

    def _findMacByIP(self, ip):
        for  switch in self.networkMap.neighbors(self.cDummy):
            for port in self.networkMap.neighbors(switch):
                for thing in self.networkMap.neighbors(port):
                    LOG.debug("---This is a thing")
                    if isinstance(thing, host.host):
                        LOG.debug("---IP of thing: %s I look for %s",thing.ip, ip)
                        if thing.ip == ip:
                            return thing.mac
        
    
    def _findPortByPath(self, dp, port_no):
        for  switch in self.networkMap.neighbors(self.cDummy):
            if(switch.dp.id == dp):
                for port in self.networkMap.neighbors(switch):
                    if (port_no == port_no):
                        return port
        return

    def _report(self):
        return
        #for switch in self.networkMap.neighbors(self.cDummy):
            #LOG.debug("--- Switch %s", switch)
            #for port in self.networkMap.neighbors(switch):
                #LOG.debug("--- Port %s with addr %s", port.port_no, port.hw_addr)
                #for p in self.networkMap.neighbors(port):
                    #LOG.debug("--- Connected to %s", p)
    
    def __init__(self, *args, **kwargs):
        super(SimpleSwitch, self).__init__(*args, **kwargs)
        self.networkMap = nx.DiGraph()
        self.cDummy = "Control"
        try:
            thread.start_new_thread(self._execute_lldp, (4,))
        except:
            LOG.debug("--- LLDP Doesn't start")

    def _find_protocol(self, pkt, name):
        for p in pkt.protocols:
            if hasattr(p, 'protocol_name'):
                if p.protocol_name == name:
                    return p

    def _addSwitch(self, switch):
        LOG.debug("--- SWITCH Connected: ---\n%s", switch)
        LOG.debug("--- Adding %s to network ---\n", switch)
        self.networkMap.add_edge(self.cDummy, switch)
        LOG.debug("--- Adding Ports to network ---\n")
        for port in switch.ports:
            self.networkMap.add_edge(switch, port)
            LOG.debug("--- Port number %s", port.port_no)
            LOG.debug("--- Added %s ---\n", port.hw_addr)
        

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER) 
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        in_port = msg.match['in_port']
        
        pkt = packet.Packet(array.array('B', msg.data))

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
                src_ip = str(netaddr.IPAddress(p_arp.src_ip))
                dst_ip = str(netaddr.IPAddress(p_arp.dst_ip))
                src_mac = str(p_arp.src_mac)
                dst_mac = str(p_arp.dst_mac)
                if not self._findMacByIP(src_ip):
                    self.networkMap.add_edge(self._findPortByPath(datapath.id, msg.match['in_port']), host.host(src_mac,src_ip))
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
        else:
            LOG.debug(" --- No Supported Protocol")
            

    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):
        if ev.switch is not None:
            switch = ev.switch
            self._addSwitch(switch)
            pl.subplot(121)
            nx.draw(self.networkMap, withLabel=True)
            #pl.show()


"""
    def _build_lldp(self):
        e = ethernet.ethernet(lldp.LLDP_MAC_NEAREST_BRIDGE, 'DD:DD:DD:DD:DD:DD', ether.ETH_TYPE_LLDP)
        system = lldp.SystemName(system_name='test')

        #tlv_chassis = lldp.ChassisID(
        #                subtype=lldp.ChassisID.SUB_LOCALLY_ASSIGNED,
        #                chassis_id='13')
        #tlv_port_id = lldp.PortID(subtype=lldp.PortID.SUB_PORT_COMPONENT,
        #                          port_id=struct.pack('!I',12))
        #tlv_ttl = lldp.TTL(ttl=12)
        #tlv_end = lldp.End()
        #tlvs = (tlv_chassis, tlv_port_id, tlv_ttl, tlv_end)
        p = packet.Packet()
        tlvs = (system,)
        l = lldp.lldp(tlvs)
        LOG.debug("-----lldp output %s", l)
        p.add_protocol(l)
        p.add_protocol(e)
        LOG.debug("-----send LLDP with proto %s", p.protocols)
        p.serialize()
        LOG.debug("-----send LLDP with proto %s", p.protocols)
        return LLDPPacket.lldp_packet(dp.id, port_no, port_mac, 1)
"""
                    
