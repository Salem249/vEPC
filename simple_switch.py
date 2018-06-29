import networkx.algorithms as nx
# Python Standard
import logging
import array
import thread
import struct
import host


# Ryu
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
from ryu.lib.packet import ipv4
from ryu.lib.packet import udp
from ryu.lib.packet import dhcp
from ryu.topology.switches import Switch
from ryu.topology.switches import Port
from ryu.lib.packet import arp


from protocol_handler import dhcp_handler
from protocol_handler import lldp_handler
from protocol_handler import arp_handler
from protocol_handler import icmp_handler
from protocol_handler import nat_handler
from netmap import netmap


LOG = logging.getLogger(__name__)


class SimpleSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_2.OFP_VERSION]

    def add_flow(self, datapath, out_port, actions, match):
        LOG.debug("--- Add FLow matching based on IPAddress")
        ofproto = datapath.ofproto

        instructions = [datapath.ofproto_parser.OFPInstructionActions(
            ofproto_v1_2.OFPIT_APPLY_ACTIONS, actions=actions)]

        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0, cookie_mask=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0, out_port=out_port, flags=ofproto.OFPFF_SEND_FLOW_REM, instructions=instructions, priority=3)
        datapath.send_msg(mod)

    def del_flow(self, datapath, match, out_port, out_group):
        LOG.debug("--- delete FLow matching based on IPAddress")
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        for switch in self.networkMap.getAllSwitches():
            if isinstance(switch, Switch):
                datapath = switch.dp
                mod = parser.OFPFlowMod(
                    datapath=datapath, match=match, cookie=0,
                    command=ofproto.OFPFC_DELETE, out_port=out_port, out_group=out_group)
                datapath.send_msg(mod)

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

        self.movedHosts = {}
        # Instance of the NetworkMap
        self.networkMap = netmap.netmap()
        # Instance of DHCP Handler
        self.dhcph = dhcp_handler.dhcp_handler(self.networkMap)
        # Instance of icmp_handler
        self.icmp = icmp_handler.icmp_handler(self.networkMap)
        # Instance of nat_handler
        self.nat = nat_handler.nat_handler(self.networkMap)
        # Instance of Arp Handler
        self.arph = arp_handler.arp_handler(self.networkMap)
        # Instance of LLDP Handler
        self.lldph = lldp_handler.lldp_handler(self.networkMap)
        # LLDP Deamon

        try:
            thread.start_new_thread(
                self.lldph._execute_lldp, (10, self._send_data))
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
        pkt_tcp = self._find_protocol(pkt, "tcp")
        pkt_udp = self._find_protocol(pkt, "udp")
        p_ipv4 = self._find_protocol(pkt, "ipv4")
        p_icmp = self._find_protocol(pkt, "icmp")

        # The flow rules of NAT
        # if pkt_tcp and p_ipv4:
        #     print "@@@ Install TCP Flow Entry @@@"
        #     tcp_src = pkt_tcp.src_port
        #     tcp_dst = pkt_tcp.dst_port
        #     self.nat.tcp_handle(tcp_src, tcp_dst, p_ipv4, msg, in_port, eth, self.add_flow)
        # elif pkt_udp and p_ipv4 and not pkt.get_protocols(dhcp.dhcp):
        #     print "@@@ Install UDP Flow Entry @@@"
        #     udp_src = pkt_udp.src_port
        #     udp_dst = pkt_udp.dst_port
        #     self.nat.tcp_handle(udp_src, udp_dst, p_ipv4, msg, in_port, eth, self.add_flow)

        # The flow rules with test of icmp
        if p_ipv4 and p_icmp and p_ipv4.dst not in self.movedHosts:
            self.icmp.handle(p_ipv4, msg, in_port, eth, self.add_flow)
        elif self._find_protocol(pkt, "arp"):
            self.arph.handle(msg, self._send_packet)
        elif self._find_protocol(pkt, "lldp"):
            self.lldph.handle(msg, self._send_packet)
        elif pkt.get_protocols(dhcp.dhcp):
            self.dhcph._handle_dhcp(msg, datapath, self._send_packet)
        if p_ipv4:
            if p_ipv4.dst in self.movedHosts:
                print "p_ipv4.dst in self.movedHosts"
                print "eth.dst"
                print eth.dst
                print "eth.src"
                print eth.src

                datapath = msg.datapath
                ofproto = datapath.ofproto

                LOG.debug("--- moved host ipv4 Packet!: \nIP Address src:%s\nIP Address Dest:%s\n",
                          p_ipv4.src, p_ipv4.dst)

                # crafting fake arp
                src_mac = eth.src
                print "crafting fake arp"
                print src_mac
                print p_ipv4.src
                print p_ipv4.dst
                dst_mac = self.movedHosts.get(p_ipv4.dst, "none")
                e = ethernet.ethernet(
                    src_mac, dst_mac, ether.ETH_TYPE_ARP)
                a = arp.arp(hwtype=1, proto=ether.ETH_TYPE_IP, hlen=6, plen=4,
                            opcode=arp.ARP_REPLY, src_mac=dst_mac, src_ip=p_ipv4.dst,
                            dst_mac=src_mac, dst_ip=p_ipv4.src)
                p = packet.Packet()
                p.add_protocol(e)
                p.add_protocol(a)
                actions = [parser.OFPActionOutput(
                    port=msg.match['in_port'])]
                self._send_packet(datapath, actions, p,
                                  ofproto.OFPP_CONTROLLER)

                if self.networkMap.findActiveHostByMac(eth.dst):
                    LOG.debug("This adress has been found!")
                    if self.networkMap.isInactiveHost(eth.src):
                        LOG.debug("Activate Host...")
                        self.networkMap.addActiveHost(
                            datapath, msg.match['in_port'], host.host(eth.src, p_ipv4.src))
                    out_port = self.networkMap.findPortByHostMac(
                        eth.dst).port_no
                else:
                    out_port = ofproto.OFPP_FLOOD

                realIP = self.networkMap.findActiveHostByMac(eth.dst).ip
                actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]

                if out_port != ofproto.OFPP_FLOOD:
                    if (self.networkMap.findSwitchByDatapath(datapath) != self.networkMap.findSwitchByHostMac(eth.dst)):

                        LOG.debug("###More than one Switch detected###")

                        path1 = nx.shortest_path(self.networkMap.networkMap, self.networkMap.findSwitchByDatapath(
                            datapath), self.networkMap.findSwitchByHostMac(eth.dst))

                        for item in range(1, (len(path1) - 1)):
                            if isinstance(path1[item], Port) and isinstance(path1[item - 1], Switch):
                                datapath = path1[item - 1].dp
                                port_no = path1[item].port_no

                                match = datapath.ofproto_parser.OFPMatch(
                                    ipv4_src=p_ipv4.src, ipv4_dst=p_ipv4.dst, eth_type=0x0800)
                                actions = [
                                    datapath.ofproto_parser.OFPActionOutput(port_no)]

                                self.add_flow(datapath, port_no,
                                              actions, match)

                                port_no = self.networkMap.findPortByHostMac(
                                    eth.src).port_no
                                print "port_no = self.networkMap.findPortByHostMac("
                                print port_no
                                match = datapath.ofproto_parser.OFPMatch(
                                    ipv4_src=p_ipv4.dst, ipv4_dst=p_ipv4.src, eth_type=0x0800)
                                actions = [
                                    datapath.ofproto_parser.OFPActionOutput(port_no)]

                                self.add_flow(datapath, port_no,
                                              actions, match)

                        # fake flow impel
                        datapath2 = self.networkMap.findSwitchByHostMac(
                            eth.dst).dp
                        port_no = self.networkMap.findPortByHostMac(
                            eth.dst).port_no
                        match = datapath.ofproto_parser.OFPMatch(
                            ipv4_src=p_ipv4.src, ipv4_dst=p_ipv4.dst, eth_type=0x0800)
                        actions = [datapath.ofproto_parser.OFPActionSetField(ipv4_dst=realIP),
                                   datapath.ofproto_parser.OFPActionOutput(port_no)]

                        self.add_flow(datapath2, port_no,
                                      actions, match)

                        path2 = nx.shortest_path(self.networkMap.networkMap, self.networkMap.findSwitchByHostMac(eth.dst), self.networkMap.findSwitchByDatapath(
                            datapath))

                        for item in range(1, (len(path2) - 1)):
                            if isinstance(path2[item], Port) and isinstance(path2[item - 1], Switch):
                                datapath = path2[item - 1].dp
                                port_no2 = path2[item].port_no

                                match_back = datapath.ofproto_parser.OFPMatch(
                                    ipv4_src=realIP, ipv4_dst=p_ipv4.src, eth_type=0x0800)
                                actions = [datapath.ofproto_parser.OFPActionSetField(ipv4_src=p_ipv4.dst),
                                           datapath.ofproto_parser.OFPActionOutput(port_no2)]

                                self.add_flow(datapath, port_no2,
                                              actions, match_back)

                            else:
                                LOG.debug(
                                    "---- Error in establishing multiflow.")

                        LOG.debug("###TO BE IMPLEMENTED###")
                    else:
                        # TBC
                        match = datapath.ofproto_parser.OFPMatch(
                            in_port=in_port, ipv4_dst=p_ipv4.dst, ipv4_src=p_ipv4.src, eth_type=0x0800)

                        self.add_flow(datapath, out_port, actions, match)

                data = None

                if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                    data = msg.data

                # out = datapath.ofproto_parser.OFPPacketOut(
                #     datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
                #     actions=actions, data=data)
                # datapath.send_msg(out)
            else:
                return

        else:
            LOG.debug(" --- No Supported Protocol")
            for p in pkt.protocols:
                if hasattr(p, 'protocol_name'):
                    LOG.debug(p.protocol_name)

    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):
        if ev.switch is not None:
            switch = ev.switch
            self.networkMap.addSwitch(switch)

    @set_ev_cls(event.EventSwitchLeave)
    def remove_topology_data(self, ev):
        if ev.switch is not None:
            switch = ev.switch
            self.networkMap.delSwitch(switch)
            if len(self.networkMap.getAllSwitches()) == 0:
                self.networkMap.flushInactiveHosts()

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

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto
        reason = msg.reason
        port_no = msg.desc.port_no
        parser = datapath.ofproto_parser

        self.logger.info("slave state changed port: %d enabled: %s",)

        if reason == ofproto.OFPPR_ADD:
            self.logger.info("port added %s", port_no)
            self.logger.info("dpid %s", dpid)
            self.logger.info("dpid %s", msg.desc)
            self.networkMap.findSwitchByDatapath(datapath).add_port(msg.desc)
            self.networkMap.addPort(port_no, datapath)
        elif reason == ofproto.OFPPR_DELETE:
            host = self.networkMap.findHostByPort(port_no, datapath)
            if host is not None:
                self.networkMap.deleteHost(host)
                self.movedHosts[host.ip] = host.mac
                print "self.movedHosts"
                print self.movedHosts
                self.logger.info("port deleted %s", port_no)
                match = parser.OFPMatch(ipv4_src=host.ip, eth_type=0x0800)
                self.del_flow(
                    datapath, match, out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY)
                match = parser.OFPMatch(ipv4_dst=host.ip, eth_type=0x0800)
                self.del_flow(
                    datapath, match, out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY)
            else:
                LOG.debug("There was no Host found on the deleted port")
            switch = self.networkMap.findSwitchByDatapath(datapath)
            self.networkMap.delPort(
                self.networkMap.findPortByPath(datapath.id, port_no))
            switch.ports.remove(
                Port(switch.dp.id, switch.dp.ofproto, msg.desc))
        elif reason == ofproto.OFPPR_MODIFY:
            self.logger.info("port modified %s", port_no)
        else:
            self.logger.info("Illeagal port state %s %s", port_no, reason)
