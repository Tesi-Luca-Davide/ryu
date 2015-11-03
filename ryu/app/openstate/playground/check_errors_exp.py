# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
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

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
import ryu.ofproto.ofproto_v1_3 as ofp
import ryu.ofproto.ofproto_v1_3_parser as ofparser
import ryu.ofproto.openstate_v1_0 as osp
import ryu.ofproto.openstate_v1_0_parser as osparser


class SimpleSwitch13(app_manager.RyuApp):

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath

        ''' [FLOW STATES] '''

        # [TEST 0] Setting the extractor on a stateless stage should be impossible
        self.test0(datapath)

        # [TEST 1] Set state action must be performed onto a stateful stage (run-time check => no error is returned!)
        # mininet> h1 ping -c5 h2
        # ping should fail, but rules are correctly installed
        #self.test1(datapath)

        # [TEST 2] Set state action must be performed onto a stage with table_id less or equal than the number of pipeline's tables (install-time check)
        #self.test2(datapath)

        # [TEST 3]  OFPExpMsgKeyExtract: I should provide a number of fields >0 and <MAX_FIELD_COUNT
        #self.test3(datapath)

        # [TEST 4] OFPExpMsgSetFlowState: I should provide a key of size >0 and <MAX_KEY_LEN
        #self.test4(datapath)

        # [TEST 5] OFPExpMsgSetFlowState: I should provide a key of size consistent with the number of fields of the update-scope
        #self.test5(datapath)

        # [TEST 6] OFPExpMsgDelFlowState: I should provide a key of size consistent with the number of fields of the update-scope
        #self.test6(datapath)

        # [TEST 7] OFPExpMsgKeyExtract: lookup-scope and update-scope must provide same length keys
        #self.test7(datapath)
        #self.test7b(datapath)

        # [TEST 8] OFPExpMsgSetFlowState: must be executed onto a stage with table_id<=64 (number of pipeline's tables)
        #self.test8(datapath)

        ####################################################################################################################

        ''' [GLOBAL STATES] '''

        # [TEST 9] exact match on global_state
        # mininet> h5 ping -c5 h6
        #self.test9(datapath)

        # [TEST 10] masked match on global_state
        # mininet> h5 ping -c5 h6
        #self.test10(datapath)

        # [TEST 11] exact match on global_state
        # mininet> h5 ping -c5 h6
        # the first ping should fail
        #self.test11(datapath)

        # [TEST 12] masked match on global_state
        # mininet> h5 ping -c5 h6
        # the first ping should fail
        #self.test12(datapath)

    def add_flow(self, datapath, priority, match, actions):

        inst = [ofparser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = ofparser.OFPFlowMod(
                datapath=datapath, cookie=0, cookie_mask=0, table_id=0,
                command=ofp.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
                priority=priority, buffer_id=ofp.OFP_NO_BUFFER,
                out_port=ofp.OFPP_ANY,
                out_group=ofp.OFPG_ANY,
                flags=0, match=match, instructions=inst)
        datapath.send_msg(mod)

    def send_table_mod(self, datapath):
        req = osparser.OFPExpMsgConfigureStatefulTable(datapath=datapath, table_id=0, stateful=1)
        datapath.send_msg(req)

    def send_key_lookup(self, datapath):
        key_lookup_extractor = osparser.OFPExpMsgKeyExtract(datapath=datapath, command=osp.OFPSC_EXP_SET_L_EXTRACTOR, fields=[ofp.OXM_OF_ETH_SRC,ofp.OXM_OF_ETH_DST], table_id=0)
        datapath.send_msg(key_lookup_extractor)

    def send_key_update(self, datapath):
        key_update_extractor = osparser.OFPExpMsgKeyExtract(datapath=datapath, command=osp.OFPSC_EXP_SET_U_EXTRACTOR, fields=[ofp.OXM_OF_ETH_SRC,ofp.OXM_OF_ETH_DST], table_id=0)
        datapath.send_msg(key_update_extractor)

    def test0(self,datapath):
        self.send_key_lookup(datapath)
        self.send_key_update(datapath)
        

    def test1(self,datapath):
        self.send_table_mod(datapath)
        self.send_key_lookup(datapath)
        self.send_key_update(datapath)
        actions = [ofparser.OFPActionOutput(2,0)]
        match = ofparser.OFPMatch(in_port=1,state=6)
        self.add_flow(datapath, 150, match, actions)

        actions = [osparser.OFPExpActionSetState(state=6,table_id=10)]
        match = ofparser.OFPMatch(in_port=1)
        self.add_flow(datapath, 100, match, actions)

        actions = [ofparser.OFPActionOutput(1,0)]
        match = ofparser.OFPMatch(in_port=2)
        self.add_flow(datapath, 200, match, actions)

    def test2(self,datapath):
        self.send_table_mod(datapath)
        self.send_key_lookup(datapath)
        self.send_key_update(datapath)
        actions = [ofparser.OFPActionOutput(2,0)]
        match = ofparser.OFPMatch(in_port=1,state=6)
        self.add_flow(datapath, 150, match, actions)

        actions = [osparser.OFPExpActionSetState(state=6,table_id=200)]
        match = ofparser.OFPMatch(in_port=1)
        self.add_flow(datapath, 100, match, actions)

        actions = [ofparser.OFPActionOutput(1,0)]
        match = ofparser.OFPMatch(in_port=2)
        self.add_flow(datapath, 200, match, actions)

    def test3(self,datapath):
        self.send_table_mod(datapath)

        # I provide zero fields => I cannot set an empty extractor!
        key_lookup_extractor = osparser.OFPExpMsgKeyExtract(datapath=datapath, command=osp.OFPSC_EXP_SET_L_EXTRACTOR, fields=[], table_id=0)
        datapath.send_msg(key_lookup_extractor)
        # I provide more fields than allowed
        key_lookup_extractor = osparser.OFPExpMsgKeyExtract(datapath=datapath, command=osp.OFPSC_EXP_SET_L_EXTRACTOR, fields=[ofp.OXM_OF_ETH_SRC,ofp.OXM_OF_ETH_DST,ofp.OXM_OF_IPV4_DST,ofp.OXM_OF_TCP_SRC,ofp.OXM_OF_TCP_DST,ofp.OXM_OF_UDP_SRC,ofp.OXM_OF_UDP_DST], table_id=0)
        datapath.send_msg(key_lookup_extractor)

    def test4(self,datapath):
        self.send_table_mod(datapath)
        self.send_key_lookup(datapath)
        self.send_key_update(datapath)
        # I provide zero keys => I cannot access the state table with an empty key!
        state = osparser.OFPExpMsgSetFlowState(datapath=datapath, state=88, keys=[], table_id=0)
        datapath.send_msg(state)
        # I provide more keys than allowed
        state = osparser.OFPExpMsgSetFlowState(datapath=datapath, state=88, keys=[0,0,0,0,0,2,0,0,0,0,0,4,0,0,0,0,0,2,0,0,0,0,0,4,0,0,0,0,0,2,0,0,0,0,0,4,0,0,0,0,0,2,0,0,0,0,0,4,5], table_id=0)
        datapath.send_msg(state)

    def test5(self,datapath):
        self.send_table_mod(datapath)
        key_lookup_extractor = osparser.OFPExpMsgKeyExtract(datapath=datapath, command=osp.OFPSC_EXP_SET_L_EXTRACTOR, fields=[ofp.OXM_OF_ETH_SRC], table_id=0)
        datapath.send_msg(key_lookup_extractor)
        key_update_extractor = osparser.OFPExpMsgKeyExtract(datapath=datapath, command=osp.OFPSC_EXP_SET_U_EXTRACTOR, fields=[ofp.OXM_OF_ETH_SRC], table_id=0)
        datapath.send_msg(key_update_extractor)
        state = osparser.OFPExpMsgSetFlowState(datapath=datapath, state=88, keys=[10,0,0,5], table_id=0)
        datapath.send_msg(state)

    def test6(self,datapath):
        self.send_table_mod(datapath)
        key_lookup_extractor = osparser.OFPExpMsgKeyExtract(datapath=datapath, command=osp.OFPSC_EXP_SET_L_EXTRACTOR, fields=[ofp.OXM_OF_ETH_SRC], table_id=0)
        datapath.send_msg(key_lookup_extractor)
        key_update_extractor = osparser.OFPExpMsgKeyExtract(datapath=datapath, command=osp.OFPSC_EXP_SET_U_EXTRACTOR, fields=[ofp.OXM_OF_ETH_SRC], table_id=0)
        datapath.send_msg(key_update_extractor)
        state = osparser.OFPExpMsgDelFlowState(datapath=datapath, keys=[10,0,0,5], table_id=0)
        datapath.send_msg(state)

    def test7(self,datapath):
        self.send_table_mod(datapath)
        key_lookup_extractor = osparser.OFPExpMsgKeyExtract(datapath=datapath, command=osp.OFPSC_EXP_SET_L_EXTRACTOR, fields=[ofp.OXM_OF_ETH_SRC,ofp.OXM_OF_ETH_DST], table_id=0)
        datapath.send_msg(key_lookup_extractor)
        key_update_extractor = osparser.OFPExpMsgKeyExtract(datapath=datapath, command=osp.OFPSC_EXP_SET_U_EXTRACTOR, fields=[ofp.OXM_OF_ETH_SRC], table_id=0)
        datapath.send_msg(key_update_extractor)

    def test7b(self,datapath):
        self.send_table_mod(datapath)
        key_update_extractor = osparser.OFPExpMsgKeyExtract(datapath=datapath, command=osp.OFPSC_EXP_SET_U_EXTRACTOR, fields=[ofp.OXM_OF_ETH_SRC], table_id=0)
        datapath.send_msg(key_update_extractor)
        key_lookup_extractor = osparser.OFPExpMsgKeyExtract(datapath=datapath, command=osp.OFPSC_EXP_SET_L_EXTRACTOR, fields=[ofp.OXM_OF_ETH_SRC,ofp.OXM_OF_ETH_DST], table_id=0)
        datapath.send_msg(key_lookup_extractor)

    def test8(self,datapath):
        self.send_table_mod(datapath)
        self.send_key_lookup(datapath)
        self.send_key_update(datapath)
        state = osparser.OFPExpMsgSetFlowState(datapath=datapath, state=88, keys=[0,0,0,0,0,2,0,0,0,0,0,4], table_id=200)
        datapath.send_msg(state)

    def test9(self,datapath):
        self.send_table_mod(datapath)
        actions = [ofparser.OFPActionOutput(6,0)]
        match = ofparser.OFPMatch(in_port=5,ip_proto=1,eth_type=0x800,global_state=2863311530)
        self.add_flow(datapath, 150, match, actions)

        msg = osparser.OFPExpSetGlobalState(datapath=datapath, global_state=2863311530, global_state_mask=0xffffffff)
        datapath.send_msg(msg)

        actions = [ofparser.OFPActionOutput(5,0)]
        match = ofparser.OFPMatch(in_port=6,ip_proto=1,eth_type=0x800)
        self.add_flow(datapath, 150, match, actions)

    def test10(self,datapath):
        self.send_table_mod(datapath)
        (global_state, global_state_mask) = osparser.masked_global_state_from_str("1*1*1*1*1*1*1*1*0*0*1*1*1*1*1*1*")
        actions = [ofparser.OFPActionOutput(6,0)]
        match = ofparser.OFPMatch(in_port=5,eth_type=0x800,ip_proto=1,global_state=osparser.masked_global_state_from_str("1*1*1*1*1*1*1*1*0*0*1*1*1*1*1*1*"))
        self.add_flow(datapath, 150, match, actions)

        msg = osparser.OFPExpSetGlobalState(datapath=datapath, global_state=global_state, global_state_mask=global_state_mask)
        datapath.send_msg(msg)

        actions = [ofparser.OFPActionOutput(5,0)]
        match = ofparser.OFPMatch(in_port=6,ip_proto=1,eth_type=0x800)
        self.add_flow(datapath, 200, match, actions)

    def test11(self,datapath):
        self.send_table_mod(datapath)
        actions = [ofparser.OFPActionOutput(6,0)]
        match = ofparser.OFPMatch(in_port=5,ip_proto=1,eth_type=0x800,global_state=1492)
        self.add_flow(datapath, 200, match, actions)

        actions = [osparser.OFPExpActionSetGlobalState(global_state=1492)]
        match = ofparser.OFPMatch(in_port=5,eth_type=0x800,ip_proto=1)
        self.add_flow(datapath, 100, match, actions)

        actions = [ofparser.OFPActionOutput(5,0)]
        match = ofparser.OFPMatch(in_port=6,eth_type=0x800,ip_proto=1)
        self.add_flow(datapath, 200, match, actions)

    def test12(self,datapath):
        self.send_table_mod(datapath)
        (global_state, global_state_mask) = osparser.masked_global_state_from_str("*1*1*1*1*0*0*1*1*1*1*1*1*")
        actions = [ofparser.OFPActionOutput(6,0)]
        match = ofparser.OFPMatch(in_port=5,eth_type=0x800,ip_proto=1,global_state=osparser.masked_global_state_from_str("*1*1*1*1*0*0*1*1*1*1*1*1*"))
        self.add_flow(datapath, 200, match, actions)

        actions = [osparser.OFPExpActionSetGlobalState(global_state=global_state, global_state_mask=global_state_mask)]
        match = ofparser.OFPMatch(in_port=5,eth_type=0x800,ip_proto=1)
        self.add_flow(datapath, 100, match, actions)

        actions = [ofparser.OFPActionOutput(5,0)]
        match = ofparser.OFPMatch(in_port=6,eth_type=0x800,ip_proto=1)
        self.add_flow(datapath, 200, match, actions)