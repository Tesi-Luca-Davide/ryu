#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import logging
import struct

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, \
    HANDSHAKE_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.topology import event

LOG = logging.getLogger('app.openstate.loadbalancing_new')

SWITCH_PORTS = 4

#questa e' una classe ereditata da app_manager.RyuApp
#con super si chiama una funzione della classe madre....init e' della classe madre
class OSLoadBalancing(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        LOG.info("OpenState Load Balancing sample app initialized")
       # LOG.info("Supporting MAX %d ports per switch" % SWITCH_PORTS)
        super(OSLoadBalancing, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto

        # install table-miss flow entry (if no rule matching, send it to
        # controller)

        self.send_features_request(datapath)
        self.send_group_mod(datapath)
        self.send_table_mod(datapath)

        self.send_key_lookup(datapath)
        self.send_key_update(datapath)

        # self.add_flow(datapath, True)

        self.add_flow(datapath, False)
        

# port considere in_port and state=metadata: matching headers are in_port
# + metadata
    def add_flow(self, datapath, table_miss=False):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        LOG.info("Configuring flow table for switch %d" % datapath.id)

        # ARP packets flooding
        match = datapath.ofproto_parser.OFPMatch(eth_type=0x0806)
        actions = [
            datapath.ofproto_parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        inst = [datapath.ofproto_parser.OFPInstructionActions(
            datapath.ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, cookie=0, cookie_mask=0, table_id=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=32768, buffer_id=ofproto.OFP_NO_BUFFER,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            flags=0, match=match, instructions=inst)
        datapath.send_msg(mod)

        
        # Reverse path flow
        for in_port in range(2, SWITCH_PORTS + 1):
            src_ip="10.0.0.2"
            match = datapath.ofproto_parser.OFPMatch(in_port=in_port, eth_type=0x800, ip_proto=6)
            actions = [parser.OFPActionSetField(ipv4_src=src_ip),
                parser.OFPActionSetField(eth_src="00:00:00:00:00:02"),
                parser.OFPActionSetField(tcp_src=80),
                datapath.ofproto_parser.OFPActionOutput(1,0)]
            inst = [datapath.ofproto_parser.OFPInstructionActions(
                datapath.ofproto.OFPIT_APPLY_ACTIONS, actions)]
            mod = datapath.ofproto_parser.OFPFlowMod(
                datapath=datapath, cookie=0, cookie_mask=0, table_id=0,
                command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
                priority=32767, buffer_id=ofproto.OFP_NO_BUFFER,
                out_port=ofproto.OFPP_ANY,
                out_group=ofproto.OFPG_ANY,
                flags=0, match=match, instructions=inst)
            datapath.send_msg(mod)
        

        if table_miss:
            LOG.debug("Installing table miss...")
            actions = [parser.OFPActionOutput(
                ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
            match = datapath.ofproto_parser.OFPMatch()
            inst = [datapath.ofproto_parser.OFPInstructionActions(
                datapath.ofproto.OFPIT_APPLY_ACTIONS, actions)]
            mod = datapath.ofproto_parser.OFPFlowMod(
                datapath=datapath, cookie=0, cookie_mask=0, table_id=0,
                command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
                priority=0, buffer_id=ofproto.OFP_NO_BUFFER,
                out_port=ofproto.OFPP_ANY,
                out_group=ofproto.OFPG_ANY,
                flags=0, match=match, instructions=inst)

            datapath.send_msg(mod)

        else:
            in_port = 1
            #for in_port in range(1, SWITCH_PORTS + 1):
            LOG.info("Installing flow rule for port %d..." % in_port)
            #la in_port avra' 4 flow entry (3 per le porte di uscita ed 1 per la default port)
            for state in range(SWITCH_PORTS):
                if state == 0:
                    #se sono nello stato di DEFAULT mando alla group table con id=1
                    actions = [
                            datapath.ofproto_parser.OFPActionGroup(1)]
                    match = datapath.ofproto_parser.OFPMatch(
                            in_port=in_port, metadata=state, eth_type=0x800, ip_proto=6)
                else:
                    #stato 0 = default, stato x = porta di uscita x+1
                    dest_ip="10.0.0."+str(state+1)
                    dest_eth="00:00:00:00:00:0"+str(state+1)
                    dest_tcp=(state+1)*100
                    actions = [
                        parser.OFPActionSetField(ipv4_dst=dest_ip),
                        parser.OFPActionSetField(eth_dst=dest_eth),
                        parser.OFPActionSetField(tcp_dst=dest_tcp),
                        parser.OFPActionOutput(state+1, 0),
                        parser.OFPActionSetState(state, 0)]
                    match = datapath.ofproto_parser.OFPMatch(
                        in_port=in_port, metadata=state, eth_type=0x800, ip_proto=6)
                inst = [
                    datapath.ofproto_parser.OFPInstructionActions(
                        datapath.ofproto.OFPIT_APPLY_ACTIONS, actions)]
                mod = datapath.ofproto_parser.OFPFlowMod(
                    datapath=datapath, cookie=0, cookie_mask=0, table_id=0,
                    command=ofproto.OFPFC_ADD, idle_timeout=0,
                    hard_timeout=0, priority=32767,
                    buffer_id=ofproto.OFP_NO_BUFFER,
                    out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,
                    flags=0, match=match, instructions=inst)
                datapath.send_msg(mod)

    def send_group_mod(self, datapath):
            ofp = datapath.ofproto
            ofp_parser = datapath.ofproto_parser
            buckets = []
            # Action Bucket: <PWD port_i , SetState(i-1)
            for port in range(2,SWITCH_PORTS+1):
                max_len = 2000
                dest_ip="10.0.0."+str(port)
                dest_eth="00:00:00:00:00:0"+str(port)
                dest_tcp=(port)*100
                actions = [ofp_parser.OFPActionSetField(ipv4_dst=dest_ip),
                    ofp_parser.OFPActionSetField(eth_dst=dest_eth),
                    ofp_parser.OFPActionSetField(tcp_dst=dest_tcp),
                    ofp_parser.OFPActionOutput(port, max_len),
                    ofp_parser.OFPActionSetState(port-1, 0)]
                weight = 0
                watch_port = 0
                watch_group = 0
                buckets.append(ofp_parser.OFPBucket(weight, watch_port, watch_group,actions))
                #buckets.append(ofp_parser.OFPBucket(actions))

            group_id = 1
            req = ofp_parser.OFPGroupMod(datapath, ofp.OFPGC_ADD,
                                         ofp.OFPGT_RANDOM, group_id, buckets)
            datapath.send_msg(req)

    def send_table_mod(self, datapath):
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        req = ofp_parser.OFPTableMod(datapath, 0, ofp.OFPTC_TABLE_STATEFULL)
        datapath.send_msg(req)
    '''
    def add_state_entry(self, datapath):
            ofproto = datapath.ofproto
            state = datapath.ofproto_parser.OFPStateEntry(
            datapath, ofproto.OFPSC_ADD_FLOW_STATE, 3, 1, [1, 2, 3],
            cookie=0, cookie_mask=0, table_id=0)
    '''
    def send_features_request(self, datapath):
        ofp_parser = datapath.ofproto_parser

        req = ofp_parser.OFPFeaturesRequest(datapath)
        datapath.send_msg(req)

    def send_key_lookup(self, datapath):
        ofp = datapath.ofproto
        key_lookup_extractor = datapath.ofproto_parser.OFPKeyExtract(datapath, ofp.OFPSC_SET_L_EXTRACTOR, 1, [ofp.OXM_OF_TCP_SRC])
        #key_lookup_extractor = datapath.ofproto_parser.OFPKeyExtract(datapath, ofp.OFPSC_SET_L_EXTRACTOR, 4, [ofp.OXM_OF_IPV4_DST,ofp.OXM_OF_IPV4_SRC,ofp.OXM_OF_TCP_DST,ofp.OXM_OF_TCP_SRC])
        datapath.send_msg(key_lookup_extractor)

    def send_key_update(self, datapath):
        ofp = datapath.ofproto

        key_update_extractor = datapath.ofproto_parser.OFPKeyExtract(datapath, ofp.OFPSC_SET_U_EXTRACTOR,  1, [ofp.OXM_OF_TCP_SRC])
        #key_update_extractor = datapath.ofproto_parser.OFPKeyExtract(datapath, ofp.OFPSC_SET_U_EXTRACTOR,  4, [ofp.OXM_OF_IPV4_DST,ofp.OXM_OF_IPV4_SRC,ofp.OXM_OF_TCP_DST,ofp.OXM_OF_TCP_SRC])
        datapath.send_msg(key_update_extractor)