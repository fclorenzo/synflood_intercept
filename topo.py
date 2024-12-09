from mininet.net import Mininet
from mininet.node import Controller, Node
from mininet.link import TCLink
from mininet.log import setLogLevel, info
from mininet.net import CLI


def basic_topology():
    net = Mininet(controller=Controller, link=TCLink)

    # Add controller
    info("*** Adding controller\n")
    net.addController("c0")

    # Add router
    info("*** Adding router\n")
    router = net.addHost("r1", ip="192.168.1.1/24")

    # Add hosts
    info("*** Adding hosts\n")
    h1 = net.addHost("h1", ip="192.168.1.2/24", defaultRoute="via 192.168.1.1")
    h2 = net.addHost("h2", ip="192.168.2.2/24", defaultRoute="via 192.168.2.1")

    # Add links
    info("*** Creating links\n")
    net.addLink(h1, router, intfName2="r1-eth0", params2={"ip": "192.168.1.1/24"})
    net.addLink(h2, router, intfName2="r1-eth1", params2={"ip": "192.168.2.1/24"})

    # Configure IP forwarding and disable reverse path filtering on the router
    info("*** Configuring router\n")
    router.cmd("sysctl -w net.ipv4.ip_forward=1")
    router.cmd("sysctl -w net.ipv4.conf.all.rp_filter=0")
    router.cmd("sysctl -w net.ipv4.conf.default.rp_filter=0")

    net.start()
    CLI(net)
    net.stop()


if __name__ == "__main__":
    setLogLevel("info")
    basic_topology()
