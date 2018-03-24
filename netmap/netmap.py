import networkx as nx

class netmap:
    
    def __init__(self):
        controllerObject = "Control"
        DisconnectedObject = "Disconnected"
        self.networkMap = nx.DiGraph()

    def _findMac(self, mac):
        for  switch in self.networkMap.neighbors(self.cDummy):
            for port in self.networkMap.neighbors(switch):
                if(port.hw_addr == mac):
                    return port

    def _findPortByHostMac(self, mac):
        for  switch in self.networkMap.neighbors(self.cDummy):
            for port in self.networkMap.neighbors(switch):
                for thing in self.networkMap.neighbors(port):
                    if isinstance(thing, host.host):
                        if thing.mac == mac:
                            return port

    def _findMacByIP(self, ip):
        for  switch in self.networkMap.neighbors(self.cDummy):
            for port in self.networkMap.neighbors(switch):
                for thing in self.networkMap.neighbors(port):
                    if isinstance(thing, host.host):
                        if thing.ip == ip:
                            return thing.mac

    def _findIPByMac(self, mac):
        for  switch in self.networkMap.neighbors("Control"):
            for port in self.networkMap.neighbors(switch):
                for thing in self.networkMap.neighbors(port):
                    if isinstance(thing, host.host):
                        if thing.mac == mac:
                            return thing.ip
        
    
    def _findPortByPath(self, dp, port_no):
        for  switch in self.networkMap.neighbors(self.cDummy):
            if(switch.dp.id == dp):
                for port in self.networkMap.neighbors(switch):
                    if (port_no == port_no):
                        return port

    def _addSwitch(self, switch):
        LOG.debug("--- SWITCH Connected: ---\n%s", switch)
        LOG.debug("--- Adding %s to network ---\n", switch)
        self.networkMap.add_edge(self.cDummy, switch)
        LOG.debug("--- Adding Ports to network ---\n")
        for port in switch.ports:
            self.networkMap.add_edge(switch, port)
            LOG.debug("--- Port number %s", port.port_no)
            LOG.debug("--- Added %s ---\n", port.hw_addr)

    
    



