
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
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, HANDSHAKE_DISPATCHER
from ryu.controller.handler import set_ev_cls
import ryu.ofproto.ofproto_v1_3 as ofp
import ryu.ofproto.ofproto_v1_3_parser as ofparser
import ryu.ofproto.openstate_v1_0 as osp
import ryu.ofproto.openstate_v1_0_parser as osparser
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.topology import event
import time

LOG = logging.getLogger('app.openstate.masked_match')


class OSLinkProtection(app_manager.RyuApp):
    OFP_VERSIONS = [ofp.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(OSLinkProtection, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        
        self.send_features_request(datapath)
        self.add_flow(datapath)

        '''
        #After 10 seconds h1 will be able to ping h3
        self.send_reset_flag_mod(datapath)
        time.sleep(10)
        flags_string="1*00*1101"
        self.send_modify_flag_mod(datapath,flags_string)
        '''


    def add_flow(self, datapath, table_miss=False):
        match = ofparser.OFPMatch(in_port=1,eth_type=0x800,flags=osparser.maskedflags("0"))
        actions = [
            ofparser.OFPActionOutput(2,0)]
        inst = [ofparser.OFPInstructionActions(
            ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod = ofparser.OFPFlowMod(
            datapath=datapath, cookie=0, cookie_mask=0, table_id=0,
            command=ofp.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=32760, buffer_id=ofp.OFP_NO_BUFFER,
            out_port=ofp.OFPP_ANY,
            out_group=ofp.OFPG_ANY,
            flags=0, match=match, instructions=inst)
        datapath.send_msg(mod)
        
        match = ofparser.OFPMatch(in_port=1,eth_type=0x800,flags=osparser.maskedflags("1"))
        actions = [
            ofparser.OFPActionOutput(3,0)]
        inst = [ofparser.OFPInstructionActions(
            ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod = ofparser.OFPFlowMod(
            datapath=datapath, cookie=0, cookie_mask=0, table_id=0,
            command=ofp.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=32760, buffer_id=ofp.OFP_NO_BUFFER,
            out_port=ofp.OFPP_ANY,
            out_group=ofp.OFPG_ANY,
            flags=0, match=match, instructions=inst)
        datapath.send_msg(mod)
        
        match = ofparser.OFPMatch(in_port=2,eth_type=0x0800,ip_proto=6, tcp_dst=33333)
        (flag, flag_mask) = osparser.maskedflags("1")
        actions = [
            osparser.OFPExpActionSetFlag(flag, flag_mask)]
        inst = [ofparser.OFPInstructionActions(
            ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod = ofparser.OFPFlowMod(
            datapath=datapath, cookie=0, cookie_mask=0, table_id=0,
            command=ofp.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=32760, buffer_id=ofp.OFP_NO_BUFFER,
            out_port=ofp.OFPP_ANY,
            out_group=ofp.OFPG_ANY,
            flags=0, match=match, instructions=inst)
        datapath.send_msg(mod)

        match = ofparser.OFPMatch(in_port=3,eth_type=0x0800,ip_proto=6, tcp_dst=22222)
        (flag, flag_mask) = osparser.maskedflags("0")
        actions = [
            osparser.OFPExpActionSetFlag(flag, flag_mask)]
        inst = [ofparser.OFPInstructionActions(
            ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod = ofparser.OFPFlowMod(
            datapath=datapath, cookie=0, cookie_mask=0, table_id=0,
            command=ofp.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=32760, buffer_id=ofp.OFP_NO_BUFFER,
            out_port=ofp.OFPP_ANY,
            out_group=ofp.OFPG_ANY,
            flags=0, match=match, instructions=inst)
        datapath.send_msg(mod)

        match = ofparser.OFPMatch(in_port=2,eth_type=0x800)
        actions = [
            ofparser.OFPActionOutput(1,0)]
        inst = [ofparser.OFPInstructionActions(
            ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod = ofparser.OFPFlowMod(
            datapath=datapath, cookie=0, cookie_mask=0, table_id=0,
            command=ofp.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=32760, buffer_id=ofp.OFP_NO_BUFFER,
            out_port=ofp.OFPP_ANY,
            out_group=ofp.OFPG_ANY,
            flags=0, match=match, instructions=inst)
        datapath.send_msg(mod)

        match = ofparser.OFPMatch(in_port=3,eth_type=0x800)
        actions = [
            ofparser.OFPActionOutput(1,0)]
        inst = [ofparser.OFPInstructionActions(
            ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod = ofparser.OFPFlowMod(
            datapath=datapath, cookie=0, cookie_mask=0, table_id=0,
            command=ofp.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=32760, buffer_id=ofp.OFP_NO_BUFFER,
            out_port=ofp.OFPP_ANY,
            out_group=ofp.OFPG_ANY,
            flags=0, match=match, instructions=inst)
        datapath.send_msg(mod)

    def send_features_request(self, datapath):
        req = ofparser.OFPFeaturesRequest(datapath)
        datapath.send_msg(req)

    def send_reset_flag_mod(self, datapath):
        msg = osparser.OFPExpSetGlobalState(
            datapath, ofp.OFPSC_RESET_FLAGS)
        datapath.send_msg(msg)

    def send_modify_flag_mod(self, datapath, flags_string, offset_value=0):
        (flag, flag_mask) = osparser.maskedflags(flags_string,offset_value)
        msg = osparser.OFPExpSetGlobalState(
            datapath, flag, flag_mask)
        datapath.send_msg(msg)
