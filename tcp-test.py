from mininet.net import Mininet
from mininet.node import Node
from mininet.log import setLogLevel, info
from time import sleep
from mininet.net import Mininet
from mininet.node import Controller, Node
from mininet.link import TCLink
from mininet.log import setLogLevel, info

def basic_topology():
    net = Mininet(controller=Controller, link=TCLink)
    
    # Add controller
    info('*** Adding controller\n')
    net.addController('c0')

    # Add router
    info('*** Adding router\n')
    router = net.addHost('r1', ip='192.168.1.1/24')

    # Add hosts
    info('*** Adding hosts\n')
    h1 = net.addHost('h1', ip='192.168.1.2/24', defaultRoute='via 192.168.1.1')
    h2 = net.addHost('h2', ip='192.168.2.2/24', defaultRoute='via 192.168.2.1')

    # Add links
    info('*** Creating links\n')
    net.addLink(h1, router, intfName2='r1-eth0', params2={'ip': '192.168.1.1/24'})
    net.addLink(h2, router, intfName2='r1-eth1', params2={'ip': '192.168.2.1/24'})

    # Start the network
    info('*** Starting network\n')
    net.start()

    # Configure IP forwarding on the router
    info('*** Configuring router\n')
    router.cmd('sysctl -w net.ipv4.ip_forward=1')

    # Test connectivity
    #info('*** Testing connectivity\n')
    #net.pingAll()

    # Stop the network
    #info('*** Stopping network\n')
    #net.stop()

def tcp_test():
    # Connect to the existing Mininet network
    info('*** Connecting to the existing network\n')
    net = Mininet()
    h1 = net.get('h1')
    h2 = net.get('h2')

    # Start a TCP server on h2
    info('*** Starting TCP server on h2\n')
    h2.cmd('nc -l -p 12345 > /tmp/h2_received.txt &')

    sleep(1)  # Wait for the server to start

    # Send a TCP message from h1 to h2
    info('*** Sending TCP message from h1 to h2\n')
    h1.cmd('echo "Hello from h1!" | nc 192.168.2.2 12345')

    sleep(1)  # Wait for the message to be sent

    # Verify the message was received on h2
    result = h2.cmd('cat /tmp/h2_received.txt')
    if "Hello from h1!" in result:
        info('*** TCP communication successful!\n')
    else:
        info('*** TCP communication failed!\n')

    # Clean up
    h2.cmd('rm /tmp/h2_received.txt')

if __name__ == '__main__':
    setLogLevel('info')
    basic_topology()
    tcp_test()

