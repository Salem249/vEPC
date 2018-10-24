import networkx.algorithms as nx
# Python Standard
import logging
import host

from ryu.lib.packet import packet
from ryu.lib.packet import arp
from ryu.ofproto import ofproto_v1_2
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.ofproto import ether
from ryu.topology.switches import Switch
from ryu.topology.switches import Port

import netaddr
import host


LOG = logging.getLogger(__name__)


class ip_mobility_handler:

    def __init__(self, networkMap):
        self.networkMap = networkMap

    def _find_protocol(self, pkt, name):
        for p in pkt.protocols:
            if hasattr(p, 'protocol_name'):
                if p.protocol_name == name:
                    return p

    def _send_packet(self, datapath, actions, pkt, in_port):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        # self.logger.info("packet-out %s" % (pkt,))
        pkt.serialize()
        data = pkt.data
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=in_port,
                                  actions=actions,
                                  data=data)
        datapath.send_msg(out)

    def handle(self, p_ipv4, msg, in_port, eth, dst_mac, callback):
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        LOG.debug("--- moved host ipv4 Packet!: \nIP Address src:%s\nIP Address Dest:%s\n",
                  p_ipv4.src, p_ipv4.dst)

        # crafting fake arp
        src_mac = eth.src
        LOG.debug("crafting a fake arp for moved host")
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
        if self.networkMap.findActiveHostByMac(eth.dst):
            dst_Real_IP = self.networkMap.findActiveHostByMac(eth.dst).ip
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
                            actions = [datapath.ofproto_parser.OFPActionSetField(ipv4_dst=dst_Real_IP),
                                       datapath.ofproto_parser.OFPActionOutput(port_no)]

                            callback(datapath, port_no,
                                     actions, match)

                            port_no = self.networkMap.findPortByHostMac(
                                eth.src).port_no
                            match_back = datapath.ofproto_parser.OFPMatch(
                                ipv4_src=dst_Real_IP, ipv4_dst=p_ipv4.src, eth_type=0x0800)
                            actions = [datapath.ofproto_parser.OFPActionSetField(ipv4_src=p_ipv4.dst),
                                       datapath.ofproto_parser.OFPActionOutput(port_no)]

                            callback(datapath, port_no,
                                     actions, match_back)

                    # fake flow impel for the switch that has the moved host
                    datapath2 = self.networkMap.findSwitchByHostMac(
                        eth.dst).dp
                    port_no = self.networkMap.findPortByHostMac(
                        eth.dst).port_no
                    match = datapath.ofproto_parser.OFPMatch(
                        ipv4_src=p_ipv4.src, ipv4_dst=dst_Real_IP, eth_type=0x0800)
                    actions = [
                        datapath.ofproto_parser.OFPActionOutput(port_no)]

                    callback(datapath2, port_no, actions, match)

                    path2 = nx.shortest_path(self.networkMap.networkMap, self.networkMap.findSwitchByHostMac(eth.dst), self.networkMap.findSwitchByDatapath(
                        datapath))

                    for item in range(1, (len(path2) - 1)):
                        if isinstance(path2[item], Port) and isinstance(path2[item - 1], Switch):
                            datapath = path2[item - 1].dp
                            port_no2 = path2[item].port_no

                            match_back = datapath.ofproto_parser.OFPMatch(
                                ipv4_src=dst_Real_IP, ipv4_dst=p_ipv4.src, eth_type=0x0800)
                            actions = [
                                datapath.ofproto_parser.OFPActionOutput(port_no2)]

                            callback(datapath, port_no2,
                                     actions, match_back)

                        else:
                            LOG.debug(
                                "---- Error in establishing multiflow.")

                    LOG.debug("###TO BE IMPLEMENTED###")
                else:
                    # TBC
                    return
                    # match = datapath.ofproto_parser.OFPMatch(
                    #     in_port=in_port, ipv4_dst=p_ipv4.dst, ipv4_src=p_ipv4.src, eth_type=0x0800)

                    # callback(datapath, out_port, actions, match)

            data = None

            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data

            # out = datapath.ofproto_parser.OFPPacketOut(
            #     datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
            #     actions=actions, data=data)
            # datapath.send_msg(out)
