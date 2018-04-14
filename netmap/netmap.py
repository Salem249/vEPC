import networkx as nx
import host

class netmap:
    
    def __init__(self):
        self.cDummy = "Control"
        self.dDummy = "Disconnected"
        self.networkMap = nx.DiGraph()
        self.networkMap.add_node(self.cDummy)
        self.networkMap.add_node(self.dDummy)
        

    def findPortbyPortMac(self, mac):
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

    def findHostByPort(self, port_no, datapath):
        for  switch in self.networkMap.neighbors(self.cDummy):
            if(switch.dp.id == dp):
                for port in self.networkMap.neighbors(switch):
                    if port.port_no == port_no:
                        for thing in self.networkMap.neighbors(port):
                            if isinstance(thing, host.host):
                                return thing

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

    def isInactiveHost(self, mac):
        for thing in self.networkMap.neighbors(self.dDummy):
            if isinstance(thing, host.host):
                if thing.mac == mac:
                    return True

    def findInactiveHostByMac(self, mac):
        for thing in self.networkMap.neighbors(self.dDummy):
            if isinstance(thing, host.host):
                if thing.mac == mac:
                    print("Found")
                    return thing
        print("Notfound")
        return None

    def deactivateHost(self, searchHost):
        for  switch in self.networkMap.neighbors("Control"):
            for port in self.networkMap.neighbors(switch):
                for thing in self.networkMap.neighbors(port):
                    if isinstance(thing, host.host):
                        if thing == searchHost:
                            self.networkMap.remove_edge(host,thing)
                            self.networkMap.add_edge(self.dDummy, searchHost)

    def activateHost(self, host, datapath, port_no):
        for  switch in self.networkMap.neighbors("Control"):
            if switch.dp == datapath:
                for port in self.networkMap.neighbors(switch):
                    if port.port_no == port_no:
                        self.networkMap.add_edge(port,host)
                        self.networkMap.remove_edge(self.dDummy, self.findInactiveHostByMac(host.mac))
                            
        
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
        if not self.isInactiveHost(host.mac):
            self.networkMap.add_edge(self.findPortByPath(datapath.id, port), host)
        else:
            self.activateHost(host, datapath, port)
        
    
    def addInactiveHost(self, host):
        print("---------------------START METHOD")
        self.deactivateHost(host)
        print("-----------------------FIND MAC %s", host.mac)
        print(not self.findInactiveHostByMac(host.mac))
        if not self.findInactiveHostByMac(host.mac):
            print("ADDING HOST ----------------")
            self.networkMap.add_edge(self.dDummy, host)
            self.report()

    def report(self):
        for switch in self.networkMap.neighbors(self.cDummy):
            print("--- Switch %s", switch)
            for port in self.networkMap.neighbors(switch):
                 print("--- Port %s with addr %s", port.port_no, port.hw_addr)
                 for p in self.networkMap.neighbors(port):
                     print("--- Connected to %s", p)
        print("--- INACTIVE:---")
        for host in self.networkMap.neighbors(self.dDummy):
            print ("--- MAC %s IP %s ---", host.mac, host.ip)
        
