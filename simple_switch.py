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
                    if isinstance(thing, host.host):
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
   #     for switch in self.networkMap.neighbors(self.cDummy):
   #         LOG.debug("--- Switch %s", switch)
   #         for port in self.networkMap.neighbors(switch):
   #             LOG.debug("--- Port %s with addr %s", port.port_no, port.hw_addr)
   #             for p in self.networkMap.neighbors(port):
   #                 LOG.debug("--- Connected to %s", p)
    
    def __init__(self, *args, **kwargs):
        super(SimpleSwitch, self).__init__(*args, **kwargs)
        self.networkMap = nx.DiGraph()
        self.cDummy = "Control"

        # dhcp init
        self.hw_addr = '0a:e4:1c:d1:3e:44'
        self.dhcp_server = '192.168.1.1'
        self.netmask = '255.255.255.0'
        self.dns = '8.8.8.8'
        self.bin_dns = addrconv.ipv4.text_to_bin(self.dns)
        self.hostname = 'huehuehue'
        self.bin_netmask = addrconv.ipv4.text_to_bin(self.netmask)
        self.bin_server = addrconv.ipv4.text_to_bin(self.dhcp_server)
        self.ip_addr = '192.0.2.9'

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
            self._handle_dhcp(datapath, in_port, pkt)
            
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

    def assemble_ack(self, pkt):
        req_eth = pkt.get_protocol(ethernet.ethernet)
        req_ipv4 = pkt.get_protocol(ipv4.ipv4)
        req_udp = pkt.get_protocol(udp.udp)
        req = pkt.get_protocol(dhcp.dhcp)
        req.options.option_list.remove(
            next(opt for opt in req.options.option_list if opt.tag == 53))
        req.options.option_list.insert(0, dhcp.option(tag=51, value='8640'))
        req.options.option_list.insert(
            0, dhcp.option(tag=53, value='05'.decode('hex')))

        ack_pkt = packet.Packet()
        ack_pkt.add_protocol(ethernet.ethernet(
            ethertype=req_eth.ethertype, dst=req_eth.src, src=self.hw_addr))
        ack_pkt.add_protocol(
            ipv4.ipv4(dst=req_ipv4.dst, src=self.dhcp_server, proto=req_ipv4.proto))
        ack_pkt.add_protocol(udp.udp(src_port=67, dst_port=68))
        ack_pkt.add_protocol(dhcp.dhcp(op=2, chaddr=req_eth.src,
                                       siaddr=self.dhcp_server,
                                       boot_file=req.boot_file,
                                       yiaddr=self.ip_addr,
                                       xid=req.xid,
                                       options=req.options))
        LOG.debug("ASSEMBLED ACK: %s" % ack_pkt)
        return ack_pkt

    def assemble_offer(self, pkt):
        disc_eth = pkt.get_protocol(ethernet.ethernet)
        disc_ipv4 = pkt.get_protocol(ipv4.ipv4)
        disc_udp = pkt.get_protocol(udp.udp)
        disc = pkt.get_protocol(dhcp.dhcp)
        disc.options.option_list.remove(
            next(opt for opt in disc.options.option_list if opt.tag == 55))
        disc.options.option_list.remove(
            next(opt for opt in disc.options.option_list if opt.tag == 53))
        disc.options.option_list.remove(
            next(opt for opt in disc.options.option_list if opt.tag == 12))
        disc.options.option_list.insert(
            0, dhcp.option(tag=1, value=self.bin_netmask))
        disc.options.option_list.insert(
            0, dhcp.option(tag=3, value=self.bin_server))
        disc.options.option_list.insert(
            0, dhcp.option(tag=6, value=self.bin_dns))
        disc.options.option_list.insert(
            0, dhcp.option(tag=12, value=self.hostname))
        disc.options.option_list.insert(
            0, dhcp.option(tag=53, value='02'.decode('hex')))
        disc.options.option_list.insert(
            0, dhcp.option(tag=54, value=self.bin_server))

        offer_pkt = packet.Packet()
        offer_pkt.add_protocol(ethernet.ethernet(
            ethertype=disc_eth.ethertype, dst=disc_eth.src, src=self.hw_addr))
        offer_pkt.add_protocol(
            ipv4.ipv4(dst=disc_ipv4.dst, src=self.dhcp_server, proto=disc_ipv4.proto))
        offer_pkt.add_protocol(udp.udp(src_port=67, dst_port=68))
        offer_pkt.add_protocol(dhcp.dhcp(op=2, chaddr=disc_eth.src,
                                         siaddr=self.dhcp_server,
                                         boot_file=disc.boot_file,
                                         yiaddr=self.ip_addr,
                                         xid=disc.xid,
                                         options=disc.options))
        LOG.debug("ASSEMBLED OFFER: %s" % offer_pkt)
        return offer_pkt

    def get_state(self, pkt_dhcp):
        dhcp_state = ord(
            [opt for opt in pkt_dhcp.options.option_list if opt.tag == 53][0].value)
        if dhcp_state == 1:
            state = 'DHCPDISCOVER'
        elif dhcp_state == 2:
            state = 'DHCPOFFER'
        elif dhcp_state == 3:
            state = 'DHCPREQUEST'
        elif dhcp_state == 5:
            state = 'DHCPACK'
        return state

    def _handle_dhcp(self, datapath, port, pkt):

        pkt_dhcp = pkt.get_protocols(dhcp.dhcp)[0]
        dhcp_state = self.get_state(pkt_dhcp)
        LOG.debug("NEW DHCP %s PACKET RECEIVED: %s" %
                         (dhcp_state, pkt_dhcp))
        if dhcp_state == 'DHCPDISCOVER':
            self._send_packet(datapath, port, self.assemble_offer(pkt))
        elif dhcp_state == 'DHCPREQUEST':
            self._send_packet(datapath, port, self.assemble_ack(pkt))
        else:
            return

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
                    
