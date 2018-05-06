import networkx.algorithms as nx
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
from ryu.lib.packet import ipv4
from ryu.lib.packet import udp
from ryu.lib.packet import dhcp
from ryu.topology.switches import Switch
from ryu.topology.switches import Port


from protocol_handler import dhcp_handler
from protocol_handler import lldp_handler
from protocol_handler import arp_handler
from netmap import netmap


LOG = logging.getLogger(__name__)

class SimpleSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_2.OFP_VERSION]

    
    def add_flow(self, datapath, out_port, actions, match):
        LOG.debug("--- Add FLow matching based on IPAddress")
        ofproto = datapath.ofproto

        instructions =[datapath.ofproto_parser.OFPInstructionActions(ofproto_v1_2.OFPIT_APPLY_ACTIONS, actions=actions)]

        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0, cookie_mask=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0, out_port=out_port, flags=ofproto.OFPFF_SEND_FLOW_REM, instructions=instructions, priority=3)
        datapath.send_msg(mod)


    def del_flow(self, datapath, match, out_port, out_group):
        LOG.debug("--- delete FLow matching based on IPAddress")
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
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
            thread.start_new_thread(self.lldph._execute_lldp, (10,self._send_data))
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
        pkt_tcp = self._find_protocol(pkt,"tcp")
        pkt_udp = self._find_protocol(pkt,"udp")

        # The flow rules of NAT
        if pkt_tcp and p_ipv4:
            print "@@@ Install TCP Flow Entry @@@"
            tcp_src = pkt_tcp.src_port
            tcp_dst = pkt_tcp.dst_port

            #self.mac_to_port[dpid][eth.src] = in_port
            if self.networkMap.findActiveHostByMac(eth.dst):
                out_port = self.networkMap.findPortByHostMac(eth.dst).port_no
            else:
                out_port = ofproto.OFPP_FLOOD

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

            match_back = parser.OFPMatch(eth_type=0x0800,
                                         ip_proto=inet.IPPROTO_TCP,
                                         ipv4_src=p_ipv4.dst,
                                         ipv4_dst=p_ipv4.src,
                                         tcp_src=tcp_dst,
                                         tcp_dst=tcp_src)

            actions_back = [parser.OFPActionSetField(ipv4_dst=p_ipv4.src),
                            parser.OFPActionSetField(tcp_dst=tcp_src),
                            parser.OFPActionOutput(in_port)]

            self.add_flow(datapath, out_port, match=match, actions=actions)
            self.add_flow(datapath, out_port, match=match_back, actions=actions_back)
        # elif pkt_udp and p_ipv4:
        #     print "@@@ Install UDP Flow Entry @@@"
        #     udp_src = pkt_udp.src_port
        #     udp_dst = pkt_udp.dst_port

        #     if self.networkMap.findActiveHostByMac(eth.dst):
        #         out_port = self.networkMap.findPortByHostMac(eth.dst).port_no
        #     else:
        #         out_port = ofproto.OFPP_FLOOD

        #     match = parser.OFPMatch(in_port=in_port,
        #                             eth_type=0x0800,
        #                             ip_proto=inet.IPPROTO_UDP,
        #                             ipv4_src=p_ipv4.src,
        #                             ipv4_dst=p_ipv4.dst,
        #                             udp_src=udp_src,
        #                             udp_dst=udp_dst)

        #     actions = [parser.OFPActionSetField(ipv4_src=p_ipv4.src),
        #                parser.OFPActionSetField(udp_src=udp_src),
        #                parser.OFPActionOutput(out_port)]

        #     match_back = parser.OFPMatch(eth_type=0x0800,
        #                                  ip_proto=inet.IPPROTO_UDP,
        #                                  ipv4_src=p_ipv4.dst,
        #                                  ipv4_dst=p_ipv4.src,
        #                                  udp_src=udp_dst,
        #                                  udp_dst=udp_src)

        #     actions_back = [parser.OFPActionSetField(ipv4_dst=p_ipv4.src),
        #                     parser.OFPActionSetField(udp_dst=udp_src),
        #                     parser.OFPActionOutput(in_port)]

        #     self.add_flow(datapath, out_port, match=match, actions=actions)
        #     self.add_flow(datapath, out_port, match=match_back, actions=actions_back)



        # The flow rules with test of icmp
        

        if p_ipv4 and p_icmp:
            LOG.debug("--- ICMP Packet!: \nIP Address src:%s\nIP Address Dest:%s\n", p_ipv4.src, p_ipv4.dst)
            #self.netMap.mac_to_port[dpid][eth.src] = in_port
            if self.networkMap.findActiveHostByMac(eth.dst):
                LOG.debug("This adress has been found!")
                if self.networkMap.isInactiveHost(eth.src):
                    LOG.debug("Activate Host...")
                    self.networkMap.addActiveHost(datapath, msg.match['in_port'], host.host(eth.src,p_ipv4.src))
                out_port = self.networkMap.findPortByHostMac(eth.dst).port_no
            else:
                 out_port = ofproto.OFPP_FLOOD

            actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
            LOG.debug("out_port to the destination host is ", out_port)
            # install a flow to avoid packet_in next time
            if out_port != ofproto.OFPP_FLOOD:
                if (self.networkMap.findSwitchByDatapath(datapath) != self.networkMap.findSwitchByHostMac(eth.dst)):


                    LOG.debug("###More than one Switch detected###")
                    path = nx.shortest_path(self.networkMap.networkMap,self.networkMap.findSwitchByDatapath(datapath),self.networkMap.findSwitchByHostMac(eth.dst))
                    print("---- Way to go ", str(path))
                    for item in range(1,(len(path)-1)):
                        if isinstance(path[item], Port) and isinstance(path[item-1], Switch):
                            datapath = path[item-1].dp
                            port_no = path[item].port_no
                            match = datapath.ofproto_parser.OFPMatch(in_port=in_port, ipv4_dst=p_ipv4.dst, ipv4_src=p_ipv4.src, eth_type = 0x0800)
                            actions = [datapath.ofproto_parser.OFPActionOutput(port_no)]
                            LOG.debug("out_port to the next hope is", port_no)
                            self.add_flow(datapath, port_no, actions, match)
                        else:
                            LOG.debug("---- Error in establishing multiflow.")
                            
                    LOG.debug("###TO BE IMPLEMENTED###")
                else:
                    match = datapath.ofproto_parser.OFPMatch(
            	    in_port=in_port, ipv4_dst=p_ipv4.dst, ipv4_src=p_ipv4.src, eth_type = 0x0800)
                    self.add_flow(datapath, out_port, actions, match)

            data = None

            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data

            out = datapath.ofproto_parser.OFPPacketOut(
                datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
                actions=actions, data=data)
            datapath.send_msg(out)

        elif self._find_protocol(pkt, "arp"):
            self.arph.handle(msg, self._send_packet)
        elif self._find_protocol(pkt, "lldp"):
            self.lldph.handle(msg, self._send_packet)
        elif pkt.get_protocols(dhcp.dhcp):
            self.dhcph._handle_dhcp(msg, self._send_packet)
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
            #host_ip = self.networkMap.findHostByPort(port_no, datapath).ip
            #host_mac = self.networkMap.findHostByPort(port_no, datapath).mac
            #if not self.networkMap.findActiveHostByIP(src_ip):
            #	print "addaddaddaddaddaddaddaddadd"
            #	self.networkMap.addActiveHost(datapath, port_no, host.host(host_mac,host_ip))
        elif reason == ofproto.OFPPR_DELETE:
        	host = self.networkMap.findHostByPort(port_no, datapath)
        	print "wwwwwwwwwwwHostwwwwwwwwwwwwww"
        	print host
        	print "wwwwwwwwwwwHostwwwwwwwwwwwwww"
        	self.networkMap.deactivateHost(host)
        	host_ip = host.ip
        	print "wwwwwwwwwwwHostwwwwwwwwwwwwww"
        	print host_ip
        	print "wwwwwwwwwwwHostwwwwwwwwwwwwww"
        	self.logger.info("port deleted %s", port_no)
        	match = parser.OFPMatch(ipv4_src=host_ip, eth_type=0x0800)
        	self.del_flow(datapath, match, out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY)
        	match = parser.OFPMatch(ipv4_dst=host_ip, eth_type = 0x0800)
        	self.del_flow(datapath, match, out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY)
        elif reason == ofproto.OFPPR_MODIFY:
            self.logger.info("port modified %s", port_no)
        else:
            self.logger.info("Illeagal port state %s %s", port_no, reason)
