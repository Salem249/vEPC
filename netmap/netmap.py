import networkx as nx

from host import host
from copy import deepcopy
from ryu.topology.switches import Switch
from ryu.topology.switches import Port


class netmap:
    
    def __init__(self):
        self.dDummy = "Disconnected"
        self.networkMap = nx.Graph()
        self.networkMap.add_node(self.dDummy)

    def getAllSwitches(self):
        return [switch for switch in self.networkMap.nodes if isinstance(switch, Switch)]

    def getAllSwitchPorts(self, switch):
        for  thing in self.networkMap.nodes:
            if isinstance(thing, Switch) and thing == switch:
                return [port for port in self.networkMap.neighbors(switch) if isinstance(port, Port)]
        

    def findPortbyPortMac(self, mac):
        for  thing in self.networkMap.nodes:
            if isinstance(thing, Port) and thing.hw_addr == mac:
                return thing

    def findPortByHostMac(self, mac):
        for  thing in self.networkMap.nodes:
            if isinstance(thing, host) and thing.mac == mac:
                for port in self.networkMap.neighbors(thing):
                    if isinstance(port, Port):
                        return port

    def findSwitchByHostMac(self,mac):
        for  switch in self.networkMap.nodes:
            if isinstance(switch, Switch):
                for port in self.networkMap.neighbors(switch):
                    if isinstance(port, Port):
                        for thing in self.networkMap.neighbors(port):
                            if isinstance(thing, host):
                                if thing.mac == mac:
                                    return switch

    def findSwitchByDatapath(self,dp):
        for  switch in self.networkMap.nodes:
            if isinstance(switch, Switch):
                if switch.dp == dp:
                    return switch

    def findHostByPort(self, port_no, datapath):
        for  thing in self.networkMap.nodes:
            if isinstance(thing, Port) and thing.dpid == datapath.id:
                for obj in self.networkMap.neighbors(thing):
                            if isinstance(obj, host):
                                return obj

    def findActiveHostByIP(self, ip):
        for  thing in self.networkMap.nodes:
            if isinstance(thing, host) and thing.ip == ip:
                for port in self.networkMap.neighbors(thing):
                    if isinstance(port, Port):
                        return thing
   

    def findActiveHostByMac(self, mac):
        for  thing in self.networkMap.nodes:
            if isinstance(thing, host) and thing.mac == mac:
                for port in self.networkMap.neighbors(thing):
                    if isinstance(port, Port):
                        return thing


    def isInactiveHost(self, mac):
        for thing in self.networkMap.neighbors(self.dDummy):
            if isinstance(thing, host):
                if thing.mac == mac:
                    return True

    def findInactiveHostByMac(self, mac):
        for thing in self.networkMap.neighbors(self.dDummy):
            if isinstance(thing, host):
                if thing.mac == mac:
                    return thing
        return None

    def deactivateHost(self, searchHost):
        for  thing in self.networkMap.nodes:
            if isinstance(thing, host) and thing == searchHost:
                for port in self.networkMap.neighbors(thing):
                    if isinstance(port, Port):
                        self.networkMap.remove_node(thing)
                        self.networkMap.add_edge(self.dDummy, thing)
                        return

    def activateHost(self, host, datapath, port_no):
        for  switch in self.networkMap.nodes:
            if isinstance(switch, Switch) and switch.dp == datapath:
                for port in self.networkMap.neighbors(switch):
                    if isinstance(port, Port) and port.port_no == port_no:
                        self.networkMap.add_edge(port,host)
                        self.networkMap.remove_edge(self.dDummy, self.findInactiveHostByMac(host.mac))
                        return
                            
        
    def findPortByPath(self, dp, port_no):
        for switch in self.networkMap.nodes:
            if isinstance(switch, Switch) and (switch.dp.id == dp):
                for port in self.networkMap.neighbors(switch):
                    if isinstance(port, Port) and port.port_no == port_no:
                        return port

    def findDataPathById(self, dpid):
        for switch in self.networkMap.neighbors(self.cDummy):
            if(switch.dp.id == dpid):
                return swich.dp

    def addSwitch(self, switch):
        self.networkMap.add_node(switch)
        for port in switch.ports:
            self.networkMap.add_edge(switch, port)

    def addActiveHost(self, datapath, port, host):
        if not self.isInactiveHost(host.mac):
            self.networkMap.add_edge(self.findPortByPath(datapath.id, port), host)
        else:
            self.activateHost(host, datapath, port)
        
    
    def addInactiveHost(self, host):
        self.deactivateHost(host)
        if not self.findInactiveHostByMac(host.mac):
            self.networkMap.add_edge(self.dDummy, host)
            self.report()

    def report(self):
        for  switch in self.networkMap.nodes:
            if isinstance(switch, Switch):
                print("--- Switch ", str(switch))
                for port in self.networkMap.neighbors(switch):
                    if isinstance(port, Port):
                        print("--- Port ", port.port_no,"with addr ", port.hw_addr)
                        for p in self.networkMap.neighbors(port):
                            if not isinstance(p, Switch):
                                print("--- Connected to ", str(p))
        print("--- INACTIVE:---")
        for host in self.networkMap.neighbors(self.dDummy):
            print ("--- MAC ",host.mac, " IP ", host.ip, "----")
        
