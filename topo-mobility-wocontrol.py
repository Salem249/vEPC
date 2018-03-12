from mininet.net import Mininet
from mininet.node import OVSSwitch
from mininet.node import RemoteController
from mininet.topo import LinearTopo
from mininet.log import info, output, warn, setLogLevel
from mininet.topo import Topo

class MobilitySwitch( OVSSwitch ):
    "Switch that can reattach and rename interfaces"

    def delIntf( self, intf ):
        "Remove (and detach) an interface"
        port = self.ports[ intf ]
        del self.ports[ intf ]
        del self.intfs[ port ]
        del self.nameToIntf[ intf.name ]

    def addIntf( self, intf, rename=False, **kwargs ):
        "Add (and reparent) an interface"
        OVSSwitch.addIntf( self, intf, **kwargs )
        intf.node = self
        if rename:
            self.renameIntf( intf )

    def attach( self, intf ):
        "Attach an interface and set its port"
        port = self.ports[ intf ]
        if port:
            if self.isOldOVS():
                self.cmd( 'ovs-vsctl add-port', self, intf )
            else:
                self.cmd( 'ovs-vsctl add-port', self, intf,
                          '-- set Interface', intf,
                          'ofport_request=%s' % port )
            self.validatePort( intf )

    def validatePort( self, intf ):
        "Validate intf's OF port number"
        ofport = int( self.cmd( 'ovs-vsctl get Interface', intf,
                                'ofport' ) )
        if ofport != self.ports[ intf ]:
            warn( 'WARNING: ofport for', intf, 'is actually', ofport,
                  '\n' )

    def renameIntf( self, intf, newname='' ):
        "Rename an interface (to its canonical name)"
        intf.ifconfig( 'down' )
        if not newname:
            newname = '%s-eth%d' % ( self.name, self.ports[ intf ] )
        intf.cmd( 'ip link set', intf, 'name', newname )
        del self.nameToIntf[ intf.name ]
        intf.name = newname
        self.nameToIntf[ intf.name ] = intf
        intf.ifconfig( 'up' )

    def moveIntf( self, intf, switch, port=None, rename=True ):
        "Move one of our interfaces to another switch"
        self.detach( intf )
        self.delIntf( intf )
        switch.addIntf( intf, port=port, rename=rename )
        switch.attach( intf )

    def plsMoveIt(self, host, old, new):
        h1, olds, news = net.get(host, old, new)
        hintf, sintf = moveHost(h1, olds, news, newPort=12)
        info( '*', hintf, 'is now connected to', sintf, '\n')



class MyTopo(Topo):

	def __init__( self ):
		Topo.__init__( self )
		hostA = self.addHost('ha', ip=None)
		hostB = self.addHost('hb', ip=None)
		hostC = self.addHost('hc', ip=None)
		swA = self.addSwitch('s1')
		swB = self.addSwitch('s2')
		swC = self.addSwitch('s3')

		self.addLink(hostA, swA)
		self.addLink(hostB, swA)
		self.addLink(hostC, swA)
		self.addLink(swB, swA)
		self.addLink(swB, swC)

		

topos = { 'mytopo': ( lambda: MyTopo() ) }

def startDHCPclient(host):
        info("Start dhcp client on", host)
        inf = host.defaultIntf()
        info(host.cmd('dhclient -v -d -r', inf))
        

def printConnections( switches ):
    "Compactly print connected nodes to each switch"
    for sw in switches:
        output( '%s: ' % sw )
        for intf in sw.intfList():
            link = intf.link
            if link:
                intf1, intf2 = link.intf1, link.intf2
                remote = intf1 if intf1.node != sw else intf2
                output( '%s(%s) ' % ( remote.node, sw.ports[ intf ] ) )
        output( '\n' )


def moveHost( host, oldSwitch, newSwitch, newPort=None ):
    "Move a host from old switch to new switch"
    hintf, sintf = host.connectionsTo( oldSwitch )[ 0 ]
    oldSwitch.moveIntf( sintf, newSwitch, port=newPort )
    return hintf, sintf

def mobilityTest():
    info( '* creating mobility Network\n' )
    global net
    info( '* Starting network:\n' )
    net = Mininet( topo=MyTopo(), switch=MobilitySwitch, controller=RemoteController)
    info( '* Get IP-Addresses for hosts..\n' )
    startDHCPclient(net.get("ha"))
    startDHCPclient(net.get("hb"))
    startDHCPclient(net.get("hc"))
    net.interact()

if __name__ == '__main__':
    setLogLevel( 'info' )
    mobilityTest()


