# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2013 YAMAMOTO Takashi <yamamoto at valinux co jp>
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
#
#
# modified by Stefan Pawlowski

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import addrconv
from ryu.topology import event
from ryu.lib.packet import dhcp
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import packet
from ryu.lib.packet import udp
from ryu.ofproto import ofproto_v1_2
import host


class dhcp_handler:
    
    def __init__(self, network):
        # DHCP Config
        self.hw_addr = '0a:e4:1c:d1:3e:44'
        self.dhcp_server = '192.168.2.1'
        self.netmask = '255.255.255.0'
        self.dns = '8.8.8.8'
        self.hostname = 'VPEC Controller'
        self.ip_lowerbound = '192.168.2.1'
        self.ip_current = '192.168.2.1'
        self.ip_upperbound = '192.168.2.50'
        self.bin_netmask = addrconv.ipv4.text_to_bin(self.netmask)
        self.bin_server = addrconv.ipv4.text_to_bin(self.dhcp_server)
        self.bin_dns = addrconv.ipv4.text_to_bin(self.dns)
        self.networkMap = network
        


    def _getNextAddr(self):
        upper = self.ip_upperbound.split(".")
        current = self.ip_current.split(".")
        if int(upper[3]) > int(current[3]):
            self.ip_current = current[0]+"."+current[1]+"."+current[2]+"."+str(int(current[3])+1)
        elif int(upper[2]) > int(current[2]):
            self.ip_current = current[0]+"."+current[1]+"."+str(int(current[2])+1)+".0"
        elif int(upper[1]) > int(current[1]):
            self.ip_current = current[0]+"."+str(int(current[1])+1)+".0.0"
        elif int(upper[0]) > int(current[0]):
            self.ip_current = str(int(current[0])+1)+".0.0.0"
        else:
            return None
        return self.ip_current

    def _handle_dhcp(self, pkt):

        pkt_dhcp = pkt.get_protocols(dhcp.dhcp)[0]
        dhcp_state = self.get_state(pkt_dhcp)
        if dhcp_state == 'DHCPDISCOVER':
            known = self.networkMap.findActiveHostByMac(pkt.get_protocol(ethernet.ethernet).src)
            if known:
                ip = known.ip
            else:
                ip = self._getNextAddr()

            if ip:

                self.networkMap.addInactiveHost(host.host(pkt.get_protocol(ethernet.ethernet).src, ip))
                return self.assemble_offer(pkt,ip)
            else:
                return None
        elif dhcp_state == 'DHCPREQUEST':
            return self.assemble_ack(pkt)
        else:
            return None


    def assemble_ack(self, pkt):
        req_eth = pkt.get_protocol(ethernet.ethernet)
        req_ipv4 = pkt.get_protocol(ipv4.ipv4)
        req_udp = pkt.get_protocol(udp.udp)
        req = pkt.get_protocol(dhcp.dhcp)
        if not (self.networkMap.findInactiveHostByMac(req_eth.src)):
            return
        req.options.option_list.remove(
            next(opt for opt in req.options.option_list if opt.tag == 53))
        req.options.option_list.insert(0, dhcp.option(tag=51, value='8640'))
        req.options.option_list.insert(
            0, dhcp.option(tag=53, value='05'.decode('hex')))
        req.options.option_list.insert(
            0, dhcp.option(tag=1, value=self.bin_netmask))
        req.options.option_list.insert(
            0, dhcp.option(tag=3, value=self.bin_server))
        req.options.option_list.insert(
            0, dhcp.option(tag=6, value=self.bin_dns))

        ack_pkt = packet.Packet()
        ack_pkt.add_protocol(ethernet.ethernet(
            ethertype=req_eth.ethertype, dst=req_eth.src, src=self.hw_addr))
        ack_pkt.add_protocol(
            ipv4.ipv4(dst=req_ipv4.dst, src=self.dhcp_server, proto=req_ipv4.proto))
        ack_pkt.add_protocol(udp.udp(src_port=67, dst_port=68))
        ack_pkt.add_protocol(dhcp.dhcp(op=2, chaddr=req_eth.src,
                                       siaddr=self.dhcp_server,
                                       boot_file=req.boot_file,
                                       yiaddr=(self.networkMap.findInactiveHostByMac(req_eth.src).ip),
                                       xid=req.xid,
                                       options=req.options))
        ack_pkt.serialize()
        return ack_pkt

    def assemble_offer(self, pkt,ip):
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
                                         yiaddr=ip,
                                         xid=disc.xid,
                                         options=disc.options))
        offer_pkt.serialize()
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


