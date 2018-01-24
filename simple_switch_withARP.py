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

"""
An OpenFlow 1.0 L2 learning switch implementation.
"""
import logging
import array
import netaddr

from ryu.base import app_manager
from ryu.controller import dpset
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.ofproto import ofproto_v1_2
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ether
from ryu.lib.mac import haddr_to_bin
from ryu.ofproto import inet
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ether_types
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp

LOG = logging.getLogger(__name__)


class SimpleSwitch(app_manager.RyuApp):
    _CONTEXTS = {'dpset': dpset.DPSet}
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    ZERO_MAC = '00:00:00:00:00:00'
    BROADCAST_MAC = 'ff:ff:ff:ff:ff:ff'
    RYU_MAC = 'fe:ee:ee:ee:ee:ef'
    RYU_IP = '10.0.0.100'
    ARP_TABLE = {}

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    def add_flow(self, datapath, in_port, dst, src, actions):
        ofproto = datapath.ofproto

        match = datapath.ofproto_parser.OFPMatch(
            in_port=in_port,
            dl_dst=haddr_to_bin(dst), dl_src=haddr_to_bin(src))

        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        datapath.send_msg(mod)

    def _send_msg(self, dp, data):
        LOG.debug("I am in _send_msg")
        buffer_id = 0xffffffff
        in_port = dp.ofproto.OFPP_LOCAL
        actions = [dp.ofproto_parser.OFPActionOutput(1, 0)]
        msg = dp.ofproto_parser.OFPPacketOut(
            dp, buffer_id, in_port, actions, data)
        LOG.debug(msg)
        dp.send_msg(msg)

    def _add_flow(self, dp, match, actions):
        inst = [dp.ofproto_parser.OFPInstructionActions(
            dp.ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = dp.ofproto_parser.OFPFlowMod(
            dp, cookie=0, cookie_mask=0, table_id=0,
            command=dp.ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=0xff, buffer_id=0xffffffff,
            out_port=dp.ofproto.OFPP_ANY, out_group=dp.ofproto.OFPG_ANY,
            flags=0, match=match, instructions=inst)
        dp.send_msg(mod)

    def _find_protocol(self, pkt, name):
        for p in pkt.protocols:
            if hasattr(p, 'protocol_name'):
                if p.protocol_name == name:
                    return p

    def _get_protocols(self, pkt):
        protocols = {}
        for p in pkt:
            if hasattr(p, 'protocol_name'):
                protocols[p.protocol_name] = p
            else:
                protocols['payload'] = p
        return protocols

    def _build_ether(self, ethertype, dst_mac, src_mac):
        e = ethernet.ethernet(dst_mac, src_mac, ethertype)
        return e

    def _build_arp(self, opcode, src_ip, src_mac, dst_ip, dst_mac):
        LOG.debug("I am in _build_arp")
        if opcode == arp.ARP_REQUEST:
            _eth_dst_mac = self.BROADCAST_MAC
            _arp_dst_mac = self.ZERO_MAC
            LOG.debug("I am in _build_arp in arp.ARP_REQUEST")
        elif opcode == arp.ARP_REPLY:
            _eth_dst_mac = dst_mac
            _arp_dst_mac = dst_mac
            LOG.debug("I am in _build_arp in arp.ARP_REPLY")

        e = self._build_ether(ether.ETH_TYPE_ARP, _eth_dst_mac, src_mac)
        a = arp.arp(hwtype=1, proto=ether.ETH_TYPE_IP, hlen=6, plen=4,
                    opcode=opcode, src_mac=src_mac, src_ip=src_ip,
                    dst_mac=_arp_dst_mac, dst_ip=dst_ip)
        LOG.debug("e")
        LOG.debug(e)
        LOG.debug("######")
        LOG.debug("a")
        LOG.debug(a)
        p = packet.Packet()
        p.add_protocol(e)
        p.add_protocol(a)
        p.serialize()

        return p

    def _build_echo(self, _type, echo, src_ip, dst_ip):
        LOG.debug("I am in _build_echo")
        e = self._build_ether(ether.ETH_TYPE_IP, src_ip, dst_ip)
        ip = ipv4.ipv4(version=4, header_length=5, tos=0, total_length=84,
                       identification=0, flags=0, offset=0, ttl=64,
                       proto=inet.IPPROTO_ICMP, csum=0,
                       src=src_ip, dst=dst_ip)
        ping = icmp.icmp(_type, code=0, csum=0, data=echo)

        print "I am in _build_echo"
        print e
        print ip
        print ping

        LOG.debug(e)
        LOG.debug(ip)
        LOG.debug(ping)

        p = packet.Packet()
        p.add_protocol(e)
        p.add_protocol(ip)
        p.add_protocol(ping)
        p.serialize()
        return p

    # def _garp(self):
    #     p = self._build_arp(arp.ARP_REQUEST, self.RYU_IP)
    #     return p.data

    def _arp_request(self, src_ip, src_mac, dst_ip, dst_mac):
        p = self._build_arp(arp.ARP_REQUEST, src_ip, src_mac, dst_ip, dst_mac)
        return p.data

    def _arp_reply(self, src_ip, src_mac, dst_ip, dst_mac):
        p = self._build_arp(arp.ARP_REPLY, src_ip, src_mac, dst_ip, dst_mac)
        return p.data

    def _echo_request(self, echo, src_ip, dst_ip):
        p = self._build_echo(icmp.ICMP_ECHO_REQUEST, echo, src_ip, dst_ip)
        return p.data

    def _echo_reply(self, echo, src_ip, dst_ip):
        p = self._build_echo(icmp.ICMP_ECHO_REPLY, echo, src_ip, dst_ip)
        return p.data

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ICMP_src_ip = 0
        ICMP_dst_ip = 0

        ofproto = dp.ofproto

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        dpid = dp.id
        self.mac_to_port.setdefault(dpid, {})

        # self.logger.info("packet in %s %s %s %s", dpid, eth.src, eth.dst, msg.in_port)

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return

        # arp from here
        pkt = packet.Packet(array.array('B', msg.data))
        p_arp = self._find_protocol(pkt, "arp")
        p_icmp = self._find_protocol(pkt, "icmp")
        p_ipv4 = self._find_protocol(pkt, "ipv4")
        # if p_arp:
        #     print "--- send Pkt: ARP_Reply #################"
        #     data = self._arp_reply(p_arp.src_ip, p_arp.src_mac, p_arp.dst_ip, p_arp.dst_mac)
        #     self._send_msg(dp, data)

        # IP - MAC mappings in  ryu
        if p_arp:
            src_ip = str(netaddr.IPAddress(p_arp.src_ip))
            ICMP_src_ip = src_ip
            src_mac = str(p_arp.src_mac)
            if str(netaddr.IPAddress(p_arp.src_ip)) not in self.ARP_TABLE:
                self.ARP_TABLE[str(src_ip)] = src_mac
                print "my ARP_TABLE1"
                print src_ip
                print src_mac
                print self.ARP_TABLE
                print "my ARP_TABLE1"
            else:
                old_mac = self.ARP_TABLE.get(src_ip, "none")
                if src_mac != old_mac:
                    self.ARP_TABLE[str(src_ip)] = src_mac
                    print "my ARP_TABLEold"
                    print src_ip
                    print src_mac
                    print self.ARP_TABLE
                    print "my ARP_TABLEold"

            dst_ip = str(netaddr.IPAddress(p_arp.dst_ip))
            ICMP_dst_ip = dst_ip

            dst_mac = str(p_arp.dst_mac)
            if dst_mac != self.ZERO_MAC and dst_mac != self.BROADCAST_MAC:
                if str(netaddr.IPAddress(p_arp.dst_ip)) not in self.ARP_TABLE:
                    self.ARP_TABLE[str(dst_ip)] = dst_mac
                    print "my ARP_TABLE2"
                    print dst_ip
                    print dst_mac
                    print self.ARP_TABLE
                    print "my ARP_TABLE2"

        if (p_arp and not self.ARP_TABLE.has_key(p_arp.dst_ip)) or p_icmp:
            print "Not in the table, flooding now"
            self.mac_to_port[dpid][eth.src] = msg.in_port

            if eth.dst in self.mac_to_port[dpid]:
                out_port = self.mac_to_port[dpid][eth.dst]
            else:
                out_port = ofproto.OFPP_FLOOD

            actions = [dp.ofproto_parser.OFPActionOutput(out_port)]

            # install a flow to avoid packet_in next time
            if out_port != ofproto.OFPP_FLOOD:
                self.add_flow(dp, msg.in_port, eth.dst, eth.src, actions)

            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data

            out = dp.ofproto_parser.OFPPacketOut(
                datapath=dp, buffer_id=msg.buffer_id, in_port=msg.in_port,
                actions=actions, data=data)
            dp.send_msg(out)

        elif p_arp and p_arp.opcode == arp.ARP_REQUEST and self.ARP_TABLE.has_key(p_arp.dst_ip):
            print "C0 will craft ARP_REPLY here"
            print "--- send Pkt: ARP_Reply #################"
            ARP_TABLE_dst_mac = self.ARP_TABLE.get(p_arp.dst_ip, "none")
            LOG.debug("ARP_TABLE_dst_mac")
            LOG.debug(ARP_TABLE_dst_mac)
            data = self._arp_reply(
                p_arp.dst_ip, ARP_TABLE_dst_mac, p_arp.src_ip, p_arp.src_mac)
            self._send_msg(dp, data)

        elif p_arp and p_arp.opcode == arp.ARP_REPLY:
            LOG.debug("--- PacketIn: ARP_Reply: %s->%s", src_ip, dst_ip)
            LOG.debug("--- send Pkt: Echo_RequestARP_REPLY")
            echo = icmp.echo(id_=66, seq=1)
            data = self._echo_request(echo, netaddr.IPAddress(p_arp.dst_ip), netaddr.IPAddress(p_arp.src_ip))
            self._send_msg(dp, data)

        # if p_icmp:
        #     print "i am in if p_icmp"
        #     src = str(netaddr.IPAddress(p_ipv4.src))
        #     dst = str(netaddr.IPAddress(p_ipv4.dst))
        #     if p_icmp.type == icmp.ICMP_ECHO_REQUEST:
        #         print "I am in if p_icmp.type == icmp.ICMP_ECHO_REQUEST:"
        #         LOG.debug("--- PacketIn: Echo_Request: %s->%s", src, dst)
        #         LOG.debug("--- send Pkt: Echo_Reply")
        #         echo = p_icmp.data
        #         echo.data = bytearray(echo.data)
        #         data = self._echo_reply(echo, netaddr.IPAddress(ICMP_dst_ip), netaddr.IPAddress(ICMP_src_ip))
        #         self._send_msg(dp, data)
        #     elif p_icmp.type == icmp.ICMP_ECHO_REPLY:
        #         LOG.debug("--- PacketIn: Echo_Reply: %s->%s", src, dst)

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status_handler(self, ev):
        msg = ev.msg
        reason = msg.reason
        port_no = msg.desc.port_no

        ofproto = msg.datapath.ofproto
        if reason == ofproto.OFPPR_ADD:
            self.logger.info("port added %s", port_no)
        elif reason == ofproto.OFPPR_DELETE:
            self.logger.info("port deleted %s", port_no)
        elif reason == ofproto.OFPPR_MODIFY:
            self.logger.info("port modified %s", port_no)
        else:
            self.logger.info("Illeagal port state %s %s", port_no, reason)

    # def handler_datapath(self, ev):
    #     if ev.enter:
    #         dp = ev.dp

    #         LOG.debug("--- send Pkt: Gratuitous ARP_Request")
            # data = self._garp()
            # self._send_msg(dp, data)
