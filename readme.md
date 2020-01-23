# vEPC
A Software Defined Controller for mobile device and IP swap support based on ryu.

## Test it

There is a testcase based on mininet included. To run it follow this manual.

### Setup
1. Fire up a new Ubuntu VM ( or physical machine, but be aware that mininet and ryu making serious changes to your system settings.
2. Install Python 2, Mininet and Ryu
3. Clone this repository and navigate into the resulting folder.
4. Start the controller with the command `ryu-manager simple_switch.py`
5. Start the testnetwork by using `python topo-mobility-wocontrol`

### Important methods and hints
The shape of the network is:

 (h1)    
 |  
(s1)--(s2)--(s3)  
 |  
(h2)     

* Use the method `s1.moveHost(hostname, old_switch, new_switch)` to move a host from one switch to another
* With the method sh `ovs-ofctl dump-flows <switch>` you can have a look at the installed flows on each switch

## Enhance it
The architecture of the switch is built in a way, that you can easily exchange modules or create new modules for packets and protocols. Beginn with the simple_switch.py, to get a basic understanding of how the application works.

ProjectIcon By VistaICO.com (VistaICO Toolbar Icons) [CC BY 3.0 (http://creativecommons.org/licenses/by/3.0)], via Wikimedia Commons
