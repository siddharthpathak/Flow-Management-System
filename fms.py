# Flow management system using RYU controller and OpenFlow Protocol
# Some of functions are used from: https://github.com/osrg/ryu/blob/v4.4/ryu/app/simple_switch_13.py

import os
import six
import array
from ryu.base import app_manager
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller import ofp_event
from ryu.controller.handler import set_ev_cls
from ryu.topology.switches import LLDPPacket
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import tcp
from ryu.lib.packet import ipv4
from ryu.lib.packet import vlan
from ryu.lib.packet import ether_types
from ryu.lib.packet.lldp import *
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto.ofproto_v1_2 import OFPG_ANY
from ryu import cfg


class MyController(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(MyController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if not datapath.id in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # remove existing flows before adding new ones
        [self.remove_flows(datapath, n) for n in [0]] # or just 0!

    def remove_flows(self, datapath, table_id):
        """Removing all flow entries."""
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        empty_match = parser.OFPMatch()
        instructions = []
        flow_mod = self.remove_table_flows(datapath, table_id,
                                        empty_match, instructions)
        print("deleting all flow entries in table {}".format(table_id))
        datapath.send_msg(flow_mod)

    def remove_table_flows(self, datapath, table_id, match, instructions):
        """Create OFP flow mod message to remove flows from table."""
        ofproto = datapath.ofproto
        flow_mod = datapath.ofproto_parser.OFPFlowMod(datapath, 0, 0, table_id,
                                                      ofproto.OFPFC_DELETE, 0, 0,
                                                      1,
                                                      ofproto.OFPCML_NO_BUFFER,
                                                      ofproto.OFPP_ANY,
                                                      OFPG_ANY, 0,
                                                      match, instructions)
        return flow_mod

    # helper method to install flows to a given datapath (switch)
    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # Store the interfaces
        interfaces = {143:141, 141:143, 142:144, 144:142} 
        in_port = msg.match['in_port']

        # get Datapath ID to identify connected switches.
        dpid = datapath.id

        # analyse the received packets using the packet library.
        pkt = packet.Packet(msg.data)

        # Ethernet packets 
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        dst = eth_pkt.dst
        src = eth_pkt.src
        
        # All traffic is tagged as VLAN in the current testing setup. 
        # Ethertype is present in VLAN header
        vlan_pkt = pkt.get_protocol(vlan.vlan)

        # Get the IP packet data
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
       
        # Get the TCP/UDP packet data
        pkt = packet.Packet(array.array('B', msg.data))
        for p in pkt:
            print (p.protocol_name, p)
            if p.protocol_name == "udp" or p.protocol_name == "tcp":
                dst_port = p.dst_port

        # out packet-in handler simply logs each packet arriving over the control channel
        self.logger.info("packet in  %s %s %s %x", src, dst, in_port, eth_pkt.ethertype)
        print ("")
        
        # if packet is ARP add a flow
        if vlan_pkt.ethertype == 0x0806:
            actions = [parser.OFPActionOutput(interfaces[in_port])]
            match = parser.OFPMatch(in_port=in_port, eth_type=0x0806)
            self.add_flow(datapath, 1, match, actions)
            return
        
        # if packet is IP and ICMP
        if vlan_pkt.ethertype == 0x0800 and ip_pkt.proto == 1:
            actions = [parser.OFPActionOutput(interfaces[in_port])]
            match = parser.OFPMatch(in_port=in_port, eth_type=0x0800, ip_proto=1)
            self.add_flow(datapath, 1, match, actions)
            return

        # if packet is ip and tcp and between destination port of 500 and 700 then drop
        if vlan_pkt.ethertype == 0x0800 and ip_pkt.proto == 6 and 500 <= dst_port <= 700:
            actions = []
            match = parser.OFPMatch(in_port=in_port, eth_type=0x0800, ip_proto=6, tcp_dst=dst_port)
            self.add_flow(datapath, 1, match, actions)
            return

        # if packet is ip and udp and between destination port of 1700 and 2000 then drop
        if vlan_pkt.ethertype == 0x0800 and ip_pkt.proto == 17 and 1700 <= dst_port <= 2000:
            actions = []
            match = parser.OFPMatch(in_port=in_port, eth_type=0x0800, ip_proto=17, udp_dst=dst_port)
            self.add_flow(datapath, 1, match, actions)
            return

        # if its a Mail request then we mark it with DSCP, so router can treat it specially
        if vlan_pkt.ethertype == 0x0800 and ip_pkt.proto == 17 and dst_port == 25:
            actions = [parser.OFPActionSetField(ip_dscp=26), parser.OFPActionOutput(141)]
            match = parser.OFPMatch(in_port=in_port, eth_type=0x0800, ip_proto=17, udp_dst=dst_port)
            self.add_flow(datapath, 2, match, actions)
            return

        # if packet is IP and TCP
        if vlan_pkt.ethertype == 0x0800 and ip_pkt.proto == 6:
            actions = [parser.OFPActionOutput(interfaces[in_port])]
            match = parser.OFPMatch(in_port=in_port, eth_type=0x0800, ip_proto=6, tcp_dst=dst_port)
            self.add_flow(datapath, 1, match, actions)
            return

        # if packet is IP and UDP
        if vlan_pkt.ethertype == 0x0800 and ip_pkt.proto == 17:
            actions = [parser.OFPActionOutput(interfaces[in_port])]
            match = parser.OFPMatch(in_port=in_port, eth_type=0x0800, ip_proto=17, udp_dst=dst_port)
            self.add_flow(datapath, 1, match, actions)
            return
