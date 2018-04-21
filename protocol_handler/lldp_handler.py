from ryu.lib.packet import packet
from ryu.topology.switches import LLDPPacket
import time

class lldp_handler:

    def __init__(self, networkMap):
        self.networkMap = networkMap

    def _find_protocol(self, pkt, name):
        for p in pkt.protocols:
            if hasattr(p, 'protocol_name'):
                if p.protocol_name == name:
                    return p

    def handle(self, msg, callback):
        datapath = msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        pkt = packet.Packet(data=msg.data)
        p_eth = self._find_protocol(pkt, "ethernet")
        if (self.networkMap.findPortbyPortMac(p_eth.src) and self.networkMap.findPortByPath(datapath.id, msg.match['in_port'])):
            #Adds edge directly
            self.networkMap.networkMap.add_edge(self.networkMap.findPortbyPortMac(p_eth.src), self.networkMap.findPortByPath(datapath.id, msg.match['in_port']))
        else:
            #Drops invalid lldp
            print("%s konnte nicht gefunden werden", datapath.id)



    def _execute_lldp(self, s, callback):
        time.sleep(s)
        for switch in self.networkMap.networkMap.neighbors("Control"):
            parser = switch.dp.ofproto_parser
            ofproto = switch.dp.ofproto
            for port in self.networkMap.networkMap.neighbors(switch):
                pkt = LLDPPacket.lldp_packet(switch.dp.id, 1, port.hw_addr, 1)
                actions = [parser.OFPActionOutput(port=port.port_no)]
                callback(switch.dp, actions, pkt, ofproto.OFPP_CONTROLLER)
                #actions = [parser.OFPActionOutput(port.port_no)]
        
        self.networkMap.report()
