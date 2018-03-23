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
# (Re-)published by Andi Hill
#
# modified by Stefan Pawlowski


class dhcp_handler:
    
    def __init__(self, network):
    # DHCP Config
    self.hw_addr = '0a:e4:1c:d1:3e:44'
    self.dhcp_server = '192.168.1.1'
    self.netmask = '255.255.255.0'
    self.dns = '8.8.8.8'
    self.hostname = 'VPEC Controller'
    self.ip_lowerbound = '192.168.2.1'
    self.ip_current = self.ip_lowerbound
    self.ip_upperbound = '192.168.2.50'
    self.bin_netmask = addrconv.ipv4.text_to_bin(self.netmask)
    self.bin_server = addrconv.ipv4.text_to_bin(self.dhcp_server)
    self.bin_dns = addrconv.ipv4.text_to_bin(self.dns)


    def _getNextAddr(self):
        
        return;

    def _handle_dhcp(self, datapath, port, pkt):

        pkt_dhcp = pkt.get_protocols(dhcp.dhcp)[0]
        dhcp_state = self.get_state(pkt_dhcp)
        if dhcp_state == 'DHCPDISCOVER':
            self._send_packet(datapath, port, self.assemble_offer(pkt))
        elif dhcp_state == 'DHCPREQUEST':
            self._send_packet(datapath, port, self.assemble_ack(pkt))
        else:
            return


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



