from pox.core import core
from pox.openflow import *
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.arp import arp
from pox.lib.packet.ipv4 import ipv4
from pox.lib.addresses import EthAddr, IPAddr
from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST
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
        
        # our table for storing mac,port when servers reply to ARP req
        self.mac_ports = {}
        self.mac_portc= {}

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
        arp_reply = arp()
        arp_reply.hwsrc = requested_mac
        arp_reply.hwdst = packet.src
        arp_reply.opcode = arp.REPLY
        arp_reply.protosrc = packet.next.protodst
        arp_reply.protodst = packet.payload.protosrc
        ether = ethernet()
        ether.type = ethernet.ARP_TYPE
        ether.dst = packet.src
        ether.src = requested_mac
        ether.payload = arp_reply
        msg = of.ofp_packet_out()
        msg.data=ether.pack()
        msg.actions.append(of.ofp_action_output(port = outport))
        connection.send(msg)
        


    # send ARP request "proxied" by the controller (so that the controller learns about another machine in network)
    def send_proxied_arp_request(self, connection, ip):
    #send ARP req to find servers mac addr
        arp_req = arp()
        arp_req.hwtype = arp_req.HW_TYPE_ETHERNET
        arp_req.prototype = arp_req.PROTO_TYPE_IP
        arp_req.hwlen = 6
        arp_req.protolen = arp_req.protolen
        arp_req.opcode = arp_req.REQUEST
        arp_req.hwdst = ETHER_BROADCAST
        arp_req.protodst = IPAddr(ip)
        arp_req.hwsrc = EthAddr("0A:00:00:00:00:01") #src fake mac of switch
        arp_req.protosrc = IPAddr("10.1.2.3")#src fake ip of service
        e = ethernet(type=ethernet.ARP_TYPE, src=EthAddr("0A:00:00:00:00:01") , dst=ETHER_BROADCAST) #broadcast to find everyone
        e.set_payload(arp_req)
        msg = of.ofp_packet_out()
        msg.data = e.pack()
        msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))#flood to find everyone
        connection.send(msg)
        print("LB::Sended ARP reqs to servers.")

    
    # install flow rule from a certain client to a certain server
    def install_flow_rule_client_to_server(self, connection, outport, client_ip, server_ip, buffer_id=of.NO_BUFFER):
        msg = of.ofp_flow_mod()
        msg.priority = 42
        msg.match.dl_type = 0x800
        msg.match.nw_dst = IPAddr(self.service_ip) #match if dst is service ip
        msg.match.nw_src = client_ip #and if src is client ip
        msg.idle_timeout=15 #15 secs are fair enough i guess
        #now if above matches actions are; set ipdst=server_ip, macsrc=lb mac, macdst=servermac and port = outport 
        msg.actions.append(of.ofp_action_nw_addr.set_dst(server_ip))
        msg.actions.append(of.ofp_action_dl_addr.set_src(EthAddr(self.lb_mac)))
        msg.actions.append(of.ofp_action_dl_addr.set_dst(EthAddr(self.mac_ports[server_ip][0])))
        msg.actions.append(of.ofp_action_output(port = outport))

        self.connection.send(msg)


    # install flow rule from a certain server to a certain client
    def install_flow_rule_server_to_client(self, connection, outport, server_ip, client_ip, buffer_id=of.NO_BUFFER):
        msg = of.ofp_flow_mod()
        msg.priority = 42
        msg.match.dl_type = 0x800
        msg.match.nw_dst = IPAddr(client_ip) #match if dst is client ip
        msg.match.nw_src = server_ip #and if src is server ip
        msg.idle_timeout=15 #15 secs are fair enough i guess
        #now if above matches actions are: set ipdst=client_ip, macsrc=lb mac, macdst=clientmac and port = outport 
        msg.actions.append(of.ofp_action_nw_addr.set_dst(client_ip))
        msg.actions.append(of.ofp_action_dl_addr.set_src(EthAddr(self.lb_mac)))
        msg.actions.append(of.ofp_action_dl_addr.set_dst(EthAddr(self.mac_portc[client_ip][0])))
        msg.actions.append(of.ofp_action_output(port = outport))

        self.connection.send(msg)


    # main packet-in handling routine
    def _handle_PacketIn(self, event):
        packet = event.parsed
        connection = event.connection
        inport = event.port
        if packet.type == packet.ARP_TYPE:
            if packet.payload.opcode == arp.REQUEST:
                if packet.next.protosrc in self.server_ips and packet.next.protodst in self.mac_portc:
                    print ("LB::Detected server ARP request. ")+str(packet.next.protosrc)
                    self.send_proxied_arp_reply(packet, connection, inport, self.lb_mac)
                    print ("LB::Sended ARP reply to server in port. ")+str(inport)
                elif packet.next.protosrc not in self.server_ips and packet.next.protodst == self.service_ip:
                    print ("LB::Detected client ARP request. ")+str(packet.next.protosrc)
                    #adding to key(ip address of client) of table the coresponding mac,port
                    self.mac_portc[packet.next.protosrc] = (packet.src,inport)
                    print ("LB::Current mac_portc table:")
                    for key,value in self.mac_portc.items():
                        print(key,value)
                    self.send_proxied_arp_reply(packet, connection, inport, self.lb_mac)
                    print ("LB::Sended ARP reply to client in port. ")+str(inport)
                    #send this packet to the switch
                    #see section below on this topic
                else:
                    print ("LB::Detected false ARP request |OR| ARP destination not in ip,mac,port mapings.")
            elif packet.payload.opcode == arp.REPLY:
                print ("LB::Server replied. ") + str(packet.next.protosrc) 
                print ("LB::Adding server mac-port to mac_table.")
                #adding to key(ip address of server) of table the coresponding mac,port
                self.mac_ports[packet.next.protosrc] = (packet.src,inport)
                print ("LB::Current mac_ports table:")
                for key,value in self.mac_ports.items():
                    print(key,value)
            else:
                print ("LB::Error detected wrong ARP opcode.")
        elif packet.type == packet.IP_TYPE:
            if packet.payload.srcip in self.mac_portc and packet.payload.dstip==self.service_ip:
                print ("LB::Client IP packet without flow rule arrived installing a flow table entry for ClientToServer.")
                #hardcoded make flow rule and send packet to coresponding server by color
                if self.user_ip_to_group[packet.payload.srcip]== "red":
                    if random.randint(0, 1):
                        self.install_flow_rule_client_to_server(connection,5,packet.payload.srcip,IPAddr("10.0.0.5"))
                        packet.src=self.lb_mac
                        packet.payload.dstip=IPAddr("10.0.0.5")
                        packet.dst=self.mac_ports[IPAddr("10.0.0.5")][0]

                        icmp_req_packet=of.ofp_packet_out()
                        icmp_req_packet.data=packet
                        icmp_req_packet.actions.append(of.ofp_action_output(port=5))
                        connection.send(icmp_req_packet)
                    else:
                        self.install_flow_rule_client_to_server(connection,6,packet.payload.srcip,IPAddr("10.0.0.6"))
                        packet.src=self.lb_mac
                        packet.payload.dstip=IPAddr("10.0.0.6")
                        packet.dst=self.mac_ports[IPAddr("10.0.0.6")][0]

                        icmp_req_packet=of.ofp_packet_out()
                        icmp_req_packet.data=packet
                        icmp_req_packet.actions.append(of.ofp_action_output(port=6))
                        connection.send(icmp_req_packet)
                else:
                    if random.randint(0, 1):
                        self.install_flow_rule_client_to_server(connection,7,packet.payload.srcip,IPAddr("10.0.0.7"))
                        packet.src=self.lb_mac
                        packet.payload.dstip=IPAddr("10.0.0.7")
                        packet.dst=self.mac_ports[IPAddr("10.0.0.7")][0]

                        icmp_req_packet=of.ofp_packet_out()
                        icmp_req_packet.data=packet
                        icmp_req_packet.actions.append(of.ofp_action_output(port=7))
                        connection.send(icmp_req_packet)
                    else:
                        self.install_flow_rule_client_to_server(connection,8,packet.payload.srcip,IPAddr("10.0.0.8"))
                        packet.src=self.lb_mac
                        packet.payload.dstip=IPAddr("10.0.0.8")
                        packet.dst=self.mac_ports[IPAddr("10.0.0.8")][0]

                        icmp_req_packet=of.ofp_packet_out()
                        icmp_req_packet.data=packet
                        icmp_req_packet.actions.append(of.ofp_action_output(port=8))
                        connection.send(icmp_req_packet)
            elif packet.payload.srcip in self.mac_ports and packet.payload.dstip in self.mac_portc :
                #make flow rule and send packet to coresponding client by looking at packet 
                print ("LB::Server IP packet without flow rule arrived installing a flow table entry for ServerToClient.")
                self.install_flow_rule_server_to_client(connection,self.mac_portc[packet.payload.dstip][1],packet.payload.srcip,packet.payload.dstip)
                packet.src=self.lb_mac
                packet.payload.srcip=self.service_ip
                packet.dst=self.mac_portc[packet.payload.dstip][0]
                
                icmp_rep_packet=of.ofp_packet_out()
                icmp_rep_packet.data=packet
                icmp_rep_packet.actions.append(of.ofp_action_output(port=self.mac_portc[packet.payload.dstip][1]))
                connection.send(icmp_rep_packet)
            else:
                print ("LB::Error packet src IP not in <IP,MAC,PORT> tables.")

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
