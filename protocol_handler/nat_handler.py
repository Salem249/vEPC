# Python Standard
import logging

import host


# Ryu
from ryu.ofproto import ofproto_v1_2
from ryu.ofproto import inet


LOG = logging.getLogger(__name__)


class nat_handler:
    def __init__(self, networkMap):
        self.networkMap = networkMap

    def _find_protocol(self, pkt, name):
        for p in pkt.protocols:
            if hasattr(p, 'protocol_name'):
                if p.protocol_name == name:
                    return p

    def tcp_handle(self, tcp_src, tcp_dst, p_ipv4, msg, in_port, eth, callback):
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        if self.networkMap.findActiveHostByMac(eth.dst):
            out_port = self.networkMap.findPortByHostMac(eth.dst).port_no
        # else:
            #out_port = out_port
            print "else:"
            match = parser.OFPMatch(in_port=in_port,
                                    eth_type=0x0800,
                                    ip_proto=inet.IPPROTO_TCP,
                                    ipv4_src=p_ipv4.src,
                                    ipv4_dst=p_ipv4.dst,
                                    tcp_src=tcp_src,
                                    tcp_dst=tcp_dst)
            actions = [parser.OFPActionSetField(ipv4_src=p_ipv4.src),
                       parser.OFPActionSetField(tcp_src=tcp_src),
                       parser.OFPActionOutput(out_port)]

            callback(datapath, out_port, actions, match)

            match_back = parser.OFPMatch(eth_type=0x0800,
                                         ip_proto=inet.IPPROTO_TCP,
                                         ipv4_src=p_ipv4.dst,
                                         ipv4_dst=p_ipv4.src,
                                         tcp_src=tcp_dst,
                                         tcp_dst=tcp_src)
            actions_back = [parser.OFPActionSetField(ipv4_dst=p_ipv4.src),
                            parser.OFPActionSetField(tcp_dst=tcp_src),
                            parser.OFPActionOutput(in_port)]

            callback(datapath, out_port, actions_back, match_back)

    def udp_handle(self, udp_src, udp_dst, p_ipv4, msg, in_port, eth, callback):
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        if self.networkMap.findActiveHostByMac(eth.dst):
            out_port = self.networkMap.findPortByHostMac(eth.dst).port_no
        # else:
            #out_port = ofproto.OFPP_FLOOD

        match = parser.OFPMatch(in_port=in_port,
                                eth_type=0x0800,
                                ip_proto=inet.IPPROTO_UDP,
                                ipv4_src=p_ipv4.src,
                                ipv4_dst=p_ipv4.dst,
                                udp_src=udp_src,
                                udp_dst=udp_dst)

        actions = [parser.OFPActionSetField(ipv4_src=p_ipv4.src),
                   parser.OFPActionSetField(udp_src=udp_src),
                   parser.OFPActionOutput(out_port)]

        match_back = parser.OFPMatch(eth_type=0x0800,
                                     ip_proto=inet.IPPROTO_UDP,
                                     ipv4_src=p_ipv4.dst,
                                     ipv4_dst=p_ipv4.src,
                                     udp_src=udp_dst,
                                     udp_dst=udp_src)

        callback(datapath, out_port, actions, match)

        actions_back = [parser.OFPActionSetField(ipv4_dst=p_ipv4.src),
                        parser.OFPActionSetField(udp_dst=udp_src),
                        parser.OFPActionOutput(in_port)]

        callback(datapath, out_port, actions, match_back)
