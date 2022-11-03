from pox.core import core
from pox.openflow import *
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.arp import arp
from pox.lib.packet.ipv4 import ipv4
from pox.lib.addresses import EthAddr, IPAddr
log = core.getLogger()
import time
import random
import json # addition to read configuration from file


class SimpleLoadBalancer(object):

    
    # initialize SimpleLoadBalancer class instance
    def __init__(self, lb_mac = None, service_ip = None, 
                 server_ips = [], user_ip_to_group = {}, server_ip_to_group = {}):
        
        # add the necessary openflow listeners
        core.openflow.addListeners(self) 

        # set class parameters
        self.lb_mac=lb_mac
        self.service_ip=service_ip
        self.server_ips=server_ips
        self.user_ip_to_group=user_ip_to_group
        self.server_ip_to_group=server_ip_to_group

    # respond to switch connection up event
    def _handle_ConnectionUp(self, event):
        self.connection = event.connection
        print("LB::OK! link between controller and switch inintialized lets send ARP to servers!!")
        for i in self.server_ips:
            self.send_proxied_arp_request(event.connection, i)


    # update the load balancing choice for a certain client
    def update_lb_mapping(self, client_ip):
        # write your code here!!!
        pass
    

    # send ARP reply "proxied" by the controller (on behalf of another machine in network)
    def send_proxied_arp_reply(self, packet, connection, outport, requested_mac):
        # write your code here!!!
        pass


    # send ARP request "proxied" by the controller (so that the controller learns about another machine in network)
    def send_proxied_arp_request(self, connection, ip):
    #send ARP req to find servers mac addr
        arp_req = arp_serv()
        arp_req.hwtype = arp_req.HW_TYPE_ETHERNET
        arp_req.prototype = arp_req.PROTO_TYPE_IP
        arp_req.hwlen = 6
        arp_req.protolen = arp_req.protolen
        arp_req.opcode = arp_req.REQUEST
        arp_req.hwdst = ETHER_BROADCAST
        arp_req.protodst = IPAddr(ip)
        arp_req.hwsrc = EthAddr("0A:00:00:00:00:01")
        arp_req.protosrc = IPAddr("10.1.2.3")
        e = ethernet(type=ethernet.ARP_TYPE, src=EthAddr("0A:00:00:00:00:01") , dst=ETHER_BROADCAST)
        e.set_payload(arp_req)
        msg = of.ofp_packet_out()
        msg.data = e.pack() #peossssssss aaaaaaa
        msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
        connection.send(msg)
        print("LB::Sended ARP reqs to servers.")

    
    # install flow rule from a certain client to a certain server
    def install_flow_rule_client_to_server(self, connection, outport, client_ip, server_ip, buffer_id=of.NO_BUFFER):
        # write your code here!!!
        pass


    # install flow rule from a certain server to a certain client
    def install_flow_rule_server_to_client(self, connection, outport, server_ip, client_ip, buffer_id=of.NO_BUFFER):
        # write your code here!!!
        pass


    # main packet-in handling routine
    def _handle_PacketIn(self, event):
        packet = event.parsed
        connection = event.connection
        inport = event.port

        if packet.type == packet.ARP_TYPE:
            if packet.payload.opcode == arp.REQUEST:
                """arp_reply = arp()
                arp_reply.hwsrc = <requested mac address>
                arp_reply.hwdst = packet.src
                arp_reply.opcode = arp.REPLY
                arp_reply.protosrc = <IP of requested mac-associated machine>
                arp_reply.protodst = packet.payload.protosrc
                ether = ethernet()
                ether.type = ethernet.ARP_TYPE
                ether.dst = packet.src
                ether.src = <requested mac address>
                ether.payload = arp_reply"""
                #send this packet to the switch
                #see section below on this topic
            elif packet.payload.opcode == arp.REPLY:
                print ("LB::Server replied. ") + str(packet.next.protosrc) 
            else:
                print "Some other ARP opcode, probably do something smart here" 
        elif packet.type == packet.IP_TYPE:
            # write your code here!!!
            pass
        else:
            log.info("Unknown Packet type: %s" % packet.type)
            return
        return


# extra function to read json files
def load_json_dict(json_file):
    json_dict = {}    
    with open(json_file, 'r') as f:
        json_dict = json.load(f)
    return json_dict


# main launch routine
def launch(configuration_json_file):
    log.info("Loading Simple Load Balancer module")
    
    # load the configuration from file    
    configuration_dict = load_json_dict(configuration_json_file)   

    # the service IP that is publicly visible from the users' side   
    service_ip = IPAddr(configuration_dict['service_ip'])

    # the load balancer MAC with which the switch responds to ARP requests from users/servers
    lb_mac = EthAddr(configuration_dict['lb_mac'])

    # the IPs of the servers
    server_ips = [IPAddr(x) for x in configuration_dict['server_ips']]    

    # map users (IPs) to service groups (e.g., 10.0.0.5 to 'red')    
    user_ip_to_group = {}
    for user_ip,group in configuration_dict['user_groups'].items():
        user_ip_to_group[IPAddr(user_ip)] = group

    # map servers (IPs) to service groups (e.g., 10.0.0.1 to 'blue')
    server_ip_to_group = {}
    for server_ip,group in configuration_dict['server_groups'].items():
        server_ip_to_group[IPAddr(server_ip)] = group

    # do the launch with the given parameters
    core.registerNew(SimpleLoadBalancer, lb_mac, service_ip, server_ips, user_ip_to_group, server_ip_to_group)
    log.info("Simple Load Balancer module loaded")
