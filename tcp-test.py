from mininet.net import Mininet
from mininet.node import Node
from mininet.log import setLogLevel, info
from time import sleep

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
    tcp_test()
