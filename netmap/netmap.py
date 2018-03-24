import networkx as nx

class netmap:
    
    def __init__(self):
        controllerObject = "Control"
        DisconnectedObject = "Disconnected"
        self.networkMap = nx.DiGraph()

    def findMac(self, mac):
        for  switch in self.networkMap.neighbors(self.cDummy):
            for port in self.networkMap.neighbors(switch):
                if(port.hw_addr == mac):
                    return port

    def findPortByHostMac(self, mac):
        for  switch in self.networkMap.neighbors(self.cDummy):
            for port in self.networkMap.neighbors(switch):
                for thing in self.networkMap.neighbors(port):
                    if isinstance(thing, host.host):
                        if thing.mac == mac:
                            return port

    def findActiveHostByIP(self, ip):
        for  switch in self.networkMap.neighbors(self.cDummy):
            for port in self.networkMap.neighbors(switch):
                for thing in self.networkMap.neighbors(port):
                    if isinstance(thing, host.host):
                        if thing.ip == ip:
                            return thing

    def findActiveHostByMac(self, mac):
        for  switch in self.networkMap.neighbors("Control"):
            for port in self.networkMap.neighbors(switch):
                for thing in self.networkMap.neighbors(port):
                    if isinstance(thing, host.host):
                        if thing.mac == mac:
                            return thing

    def isInactiveHost(self, nac):
        for thing in self.networkMap.neighbors("Disconnected"):
            if isinstance(thing, host.host):
                if thing.mac == mac:
                    return thing

    def removeHost(host, datapath, port):
        return
        
    def findPortByPath(self, dp, port_no):
        for  switch in self.networkMap.neighbors(self.cDummy):
            if(switch.dp.id == dp):
                for port in self.networkMap.neighbors(switch):
                    if (port_no == port_no):
                        return port

    def addSwitch(self, switch):
        self.networkMap.add_edge(self.cDummy, switch)
        for port in switch.ports:
            self.networkMap.add_edge(switch, port)

    def addActiveHost(self, datapath, port, host):
        if not self._findActiveHostByMac(host.mac):
            self.networkMap.add_edge(self._findPortByPath(datapath.id, port), host)
        
    
    def addUndifinedHost(self, host):
        if not self._findInactiveHostByMac(host.mac):
            self.networkMap.add_edge(self._findPortByPath(datapath.id, port), host)
