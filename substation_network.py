#!/usr/bin/env python3
from mininet.net import Mininet
from mininet.node import OVSBridge
from mininet.cli import CLI
from mininet.log import setLogLevel

def build_substation():
    # Initialize the Mininet network with NO controller, using a standard Layer 2 Bridge
    net = Mininet(switch=OVSBridge, controller=None)

    print("[*] Adding Substation Ethernet Switch (s1)...")
    s1 = net.addSwitch('s1')

    print("[*] Adding IEDs (Publisher, Subscriber, Adversary)...")
    h1 = net.addHost('h1', ip='10.0.0.1/24', mac='00:00:00:00:00:01') # Publisher
    h2 = net.addHost('h2', ip='10.0.0.2/24', mac='00:00:00:00:00:02') # Subscriber
    h3 = net.addHost('h3', ip='10.0.0.3/24', mac='00:00:00:00:00:03') # Adversary

    print("[*] Connecting IEDs to the Switch...")
    net.addLink(h1, s1)
    net.addLink(h2, s1)
    net.addLink(h3, s1)

    print("[*] Starting the Virtual Substation Network...")
    net.start()
    
    print("\n[*] ==========================================")
    print("[*] NETWORK LIVE. Opening Mininet CLI.")
    print("[*] Type 'xterm h1 h2' to open your terminals.")
    print("[*] Type 'exit' when you are done.")
    print("[*] ==========================================\n")
    
    # Drop the user into the Mininet command line
    CLI(net)

    print("[*] Shutting down network...")
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    build_substation()
