import logging
import array
import netaddr
import thread
import time
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_2
from ryu.ofproto import ether
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import arp
from ryu.lib.packet import lldp

LOG = logging.getLogger(__name__)

class SimpleSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_2.OFP_VERSION]

    def _execute_lldp(self, s):
        LOG.debug("--- Sending LLDP request")
        time.sleep(4)
        data = self._build_lldp()
        
        
        actions = [parser.OFPActionOutput(ofproto_v1_2.OFPP_FLOOD)]
        out = parser.OFPPacketOut(buffer_id=ofproto.OFP_NO_BUFFER,
                                  actions=actions, data=data)
        datapath.send_msg(out)
        
        self._execute_lldp(s)
    
    def __init__(self, *args, **kwargs):
        super(SimpleSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        try:
            thread.start_new_thread(self._execute_lldp, (4,))
        except:
            LOG.debug("--- LLDP Doesn't start")

    def _find_protocol(self, pkt, name):
        for p in pkt.protocols:
            if hasattr(p, 'protocol_name'):
                if p.protocol_name == name:
                    return p

    def _build_lldp(self):
        l = lldp.lldp(())
        p = packet.Packet()
        p.add_protocol(l) 
        p.serialize()

        return p

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
                LOG.debug("--- ARP REQUEST found!!!: %s->%s\nMAC-Address src:%s\nMacAddress Dest:%s\n", src_ip, dst_ip, src_mac, dst_mac)
                LOG.debug("--- Flood now")

                actions = [parser.OFPActionOutput(ofproto_v1_2.OFPP_FLOOD)]
                out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=in_port, actions=actions,
                                  data=msg.data)
                datapath.send_msg(out)
               
            elif p_arp.opcode == arp.ARP_REPLY:
                LOG.debug("ARP_Reply, I don't have to care for this")
        elif self._find_protocol(pkt, "lldp"):
            LOG.debug("LLDP grab")
        else:
            LOG.debug("Not Supported")
            
                    
