import logging
import struct

from ryu.base import app_manager
from ryu.lib.hub import StreamServer
from ryu.lib import hub
from ryu.controller import ofp_event
from ryu.controller.handler import set_ev_cls
from ryu.controller import mac_to_port
from ryu.ofproto import ofproto_v1_3
from ryu.lib import mac
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
import os, exceptions, time
import socket, struct
import cmd
import random

from datetime import datetime

PRIORITY_DEFAULT = 500
PRIORITY_MAX = 65535
PRIORITY_MIN = 0

LOOP_COUNT = 0

SOCKET_RECV_LEN = 1024
CLI_SERVER_PORT = 2505
MAX_VLAN_ID = 4094

datapaths = []
dpids = []
dpports = []

start_time = None
end_time = None
flag_locking =  False


LOG = logging.getLogger(__name__)

def micros(dt):
    mics=(dt.days*24*60*60 + dt.seconds)* 1000000 + dt.microseconds
    return mics

def millis(dt):
    ms=(dt.days*24*60*60 + dt.seconds)* 1000 + dt.microseconds/1000.0
    return ms

def second(dt):
    s = (dt.days*24*60*60 + dt.seconds) + dt.microseconds/1000000.0
    return s
        

class RyuCli(cmd.Cmd):
    prompt = "Ryu>"
    use_rawinput = False

    def do_show(self, args):
        args = args.split()
        if len(args)>0:
            if args[0] == 'dpid':
                self.stdout.write("%s\n" % self.list_datapaths())
            elif args[0] == 'ports':
                self.stdout.write("%s\n" % self.list_ports(int(args[1])))                
            else:
                self.show_help()

    def do_test(self, args):
        args = args.split()
        if len(args)>3:
            if args[0] == 'tablesize' and args[1] == 'mac_dst':
                self.test_tablesize_mac(args[2], int(args[3]), args[4])
            elif args[0] == 'tablesize' and args[1] == 'ip':
                self.test_tablesize_ip(args[2], int(args[3]), args[4])
            else:
                self.test_help()
        else:
            self.test_help()
    
    def do_flowstat(self,args):
        print "Got flowstats"
        args = args.split()
        #import pdb; pdb.set_trace()
	if args[0] == 'datapath':
	    self.get_flowstat(int(args[1]), int(args[2]), int(args[3]))
	else:
	    self.flowstat_help()

    def list_datapaths(self):
        return [d.id for d in datapaths if not d.id is None]

    def list_ports(self, dpid):
	dpidports = list()
	for d in datapaths:
	    if not d.id is None and d.id == dpid:
		dpidports.extend(d.ports)
	return dpidports
 
    
    def show_help(self):
        self.stdout.write('show <dpid | ports [dpid]>\n')

    def test_help(self):
        self.stdout.write('test tablesize vlan|mac_dst|ip same_priority| ascending_priority | descending_priority [size]\n')

    def flowstat_help(self):
        self.stdout.write('flowstat datapath [dpid] [loop] [query mode(0~19,33)]\n')

    def get_flowstat(self, datapath, number, netmask):
        global starttime,LOOP_COUNT,REP_COUNT
        flag = 0
	for dp in datapaths:
	    if dp.id == datapath:
	        flag = 1
		break
	if flag == 0:
	    self.stdout.write('no such datapath!\n')
	    return
	
	ofp = dp.ofproto
	ofp_parser = dp.ofproto_parser

	cookie = cookie_mask = 0
	#import pdb; pdb.set_trace()
        #match = ofp_parser.OFPMatch()

	# Query with different prefix
	if netmask == 0:
	    ipv4_dst=(0,'255.255.255.255')
	elif netmask == 1:
            ipv4_dst=(0,'255.255.255.254')
	elif netmask == 2:
            ipv4_dst=(0,'255.255.255.252')
	elif netmask == 3:
            ipv4_dst=(0,'255.255.255.248')
	elif netmask == 4:
            ipv4_dst=(0,'255.255.255.240')
	elif netmask == 5:
            ipv4_dst=(0,'255.255.255.224')
	elif netmask == 6:
            ipv4_dst=(0,'255.255.255.192')
	elif netmask == 7:
            ipv4_dst=(0,'255.255.255.128')
	elif netmask == 8:
            ipv4_dst=(0,'255.255.255.0')
	elif netmask == 9:
            ipv4_dst=(0,'255.255.254.0')
	elif netmask == 10:
            ipv4_dst=(0,'255.255.252.0')
	elif netmask == 11:
            ipv4_dst=(0,'255.255.248.0')
	elif netmask == 12:
            ipv4_dst=(0,'255.255.240.0')
	elif netmask == 13:
            ipv4_dst=(0,'255.255.224.0')
	elif netmask == 14:
            ipv4_dst=(0,'255.255.192.0')
	elif netmask == 15:
            ipv4_dst=(0,'255.255.128.0')
	elif netmask == 16:
            ipv4_dst=(0,'255.255.0.0')
	elif netmask == 17:
            ipv4_dst=(0,'255.254.0.0')
	elif netmask == 18:
            ipv4_dst=(0,'255.252.0.0')
	elif netmask == 19:
            ipv4_dst=(0,'255.248.0.0')

        starttime = datetime.now()
        LOOP_COUNT = number
        REP_COUNT = 0

	for i in range(number):
	    #import pdb; pdb.set_trace()

	    # Query the whole table
	    if netmask == 33:
	        #match = ofp_parser.OFPMatch(in_port = 1)
	        match = ofp_parser.OFPMatch(eth_type=0x0800)
	    else:
	        match = ofp_parser.OFPMatch(ipv4_dst=ipv4_dst, eth_type=0x0800)

	    #time.sleep(20)
            req = ofp_parser.OFPFlowStatsRequest(dp, 0, ofp.OFPTT_ALL, ofp.OFPP_ANY, ofp.OFPG_ANY, cookie, cookie_mask, match)
	    dp.send_msg(req)
    
    def set_init_priority (self, mode):
        if mode == 'same_priority':
            p = PRIORITY_DEFAULT
        elif mode == 'ascending_priority':
            p = PRIORITY_MIN
        elif mode == 'descending_priority':
            p = PRIORITY_MAX
        elif mode == 'random':
            p = random.choice(range(65536))
	else:
	    p = -1
        return p

    def adjust_priority (self, p, mode):
       #import pdb; pdb.set_trace()
       if mode == 'ascending_priority':
           p = p+1
       elif mode == 'descending_priority':
           p = p-1
       elif mode == 'same_priority':
           p = p
       else:
           p = random.choice(range(65536))
       
       return p
       
            
    def int_to_haddr(self, int_value):
        """convert int value into internal representation, for example, 1024->'\x00\x00\x00\x00\x04\x00'"""
        encoded = format(int_value, 'x')
        encoded = encoded.zfill(12)
        return encoded.decode('hex')  
        
    def test_tablesize_mac(self, mode, size, pmode):
        j = 0
	priority = self.set_init_priority(pmode)
        global starttime,endtime
        starttime = datetime.now()
        for i in range(1, size+1):
            mac_haddr = self.int_to_haddr(i)
            if mode=='outport_single':
                out_port = 48
            elif mode=='outport_multiple':
                out_port = (j % 48) + 1
                j = j+1
            else:
                self.test_help()
                return
             
            self.mod_flows('ADD', dl_dst=mac_haddr, out_port=out_port, priority=priority)
	    priority = self.adjust_priority(priority,pmode)

        self.stdout.write("added %d flows.\n" % size)
        endtime = datetime.now()
        self.stdout.write("duration: %f\n" % second(endtime-starttime))


    def test_tablesize_ip(self, mode, size, pmode):
        j = 0
	#import pdb; pdb.set_trace()
	priority = self.set_init_priority(pmode)
        global starttime,endtime
        starttime = datetime.now()
        for i in range (size):
            if mode == 'outport_single':
                out_port = 48
            elif mode == 'outport_multiple':
                out_port = (j % 48) + 1
                j = j+1
            else:
                self.test_help()
                return
            self.mod_flows('ADD', dl_type=0x0800, nw_dst=i, out_port=out_port, priority=priority)
	    priority = self.adjust_priority(priority,pmode)
	    if priority < 0:
	        priority=65535
	    elif priority > 65535:
	        priority=0

        self.stdout.write("added %d flows.\n" % size)
        endtime = datetime.now()
        self.stdout.write("duration: %f\n" % second(endtime-starttime))

    def mod_flows(self, command='ADD', priority=PRIORITY_DEFAULT, in_port=None, dl_type=None, nw_proto=None, 
                        nw_dst=None, nw_src=None, set_dl_src=None, set_dl_dst=None, 
                        out_port=None, vlan_id=None, dl_dst=None, 
                        nw_dst_mask=32, nw_src_mask=32): 
        """generate OF flow_mod (add) message, all arguments are integers."""
        if len(datapaths) > 0:
            dp = datapaths[0]
	    #self.stdout.write('add to datapath %s\n' % dp.id)
            ofproto = datapaths[0].ofproto
            
	    match = dp.ofproto_parser.OFPMatch(eth_type=0x0800, ipv4_dst=nw_dst)
            actions = []
	 
            if out_port is None:
                self.out_port = 0
            else:
                self.out_port = out_port
                actions.append(dp.ofproto_parser.OFPActionOutput(self.out_port))
            
	    instructions = [dp.ofproto_parser.OFPInstructionActions(dp.ofproto.OFPIT_APPLY_ACTIONS, actions)]
            self.priority = priority
	    table_id = (nw_dst-1)/1000000 + 1

            if command == 'ADD':
                mod = dp.ofproto_parser.OFPFlowMod(
                      datapath = dp, match=match, cookie=0, table_id=table_id, 
                      command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
                      priority=self.priority,
                      flags=ofproto.OFPFF_SEND_FLOW_REM, instructions=instructions)
		#self.stdout.write('flow serial number: %d --> table %d\n' % (nw_dst, table_id)) 
            elif command == 'MOD':
                mod = dp.ofproto_parser.OFPFlowMod(
                      datapath = dp, match=match, cookie=0, 
                      command=ofproto.OFPFC_MODIFY, idle_timeout=0, hard_timeout=0,
                      priority=self.priority,
                      flags=ofproto.OFPFF_SEND_FLOW_REM, instructions=instructions)
            elif command == 'DELETE':
                mod = dp.ofproto_parser.OFPFlowMod(
                      datapath = dp, match=match, cookie=0, 
                      command=ofproto.OFPFC_DELETE, idle_timeout=0, hard_timeout=0,
                      priority=self.priority,
                      flags=ofproto.OFPFF_SEND_FLOW_REM, instructions=instructions)

            dp.send_msg(mod)

    
    def do_exit(self, args):
        return True

    
def cli_client_factory(socket, address):
    f = socket.makefile("rb")
    try:
        RyuCli(stdin=f, stdout=f).cmdloop()
    except:
        pass

class CliController(object):
    """CLI server helper"""

    def __init__(self):
        print "cliserver.init"
        super(CliController, self).__init__()

    def __call__(self):
        print "cliserver socket listening on port: %d" % CLI_SERVER_PORT
        server=StreamServer(('0.0.0.0', CLI_SERVER_PORT), cli_client_factory)
        server.serve_forever()


class Cli(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Cli, self).__init__(*args, **kwargs)
        cliserver = CliController()
        self.mac_to_port = {}
        hub.spawn(cliserver)
      
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        #self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            self.add_flow(datapath, 1, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPEchoRequest, MAIN_DISPATCHER)
    def _echo_request_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath

        #add the datapath into datapath list if not already there
        if datapaths.count(datapath) == 0:
            datapaths.insert(0, datapath)

        # add the dpid into dpid list if not already there
        dpid = datapath.id
        if dpids.count(dpid) == 0:
            dpids.insert(0,dpid)
        
        #self.logger.info("cli module: echo request %s %s", datapath, dpid)

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removed_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        
        #delete the datapath if in the list
        if datapaths.count(datapath) > 0:
           datapaths.remove(datapath)
        dpid = datapath.id
        if dpids.count(dpid) > 0:
            dpids.remove(dpid)

        self.logger.info("cli module: 1 flow removed %s %s", datapath, datapath.id)
    
    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status_handler(self, ev):
        msg = ev.msg
        reason = msg.reason
        port_no = msg.desc.port_no
        datapath = msg.datapath
        print "get message from datapath: ", datapath

        ofproto = msg.datapath.ofproto
        if reason == ofproto.OFPPR_ADD:
            print "datapath port add: ", port_no
            dpports.append(int(port_no))
            dpports.sort()
        elif reason == ofproto.OFPPR_DELETE:
            print "port deleted: ", port_no
            dpports.remove(int(port_no))
        elif reason == ofproto.OFPPR_MODIFY:
            print "port modified: ", port_no
        else:
            print "Illeagal port state: ", (port_no, reason)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def stats_reply_handler_flow(self, ev):
        global LOOP_COUNT,REP_COUNT
        REP_COUNT = REP_COUNT + 1
        #import pdb; pdb.set_trace()
        body = ev.msg.body
        self.flow_stats_reply_handler(body)
        if REP_COUNT == LOOP_COUNT:
            endtime = datetime.now()
            self.logger.info("duration: %f\n" % second(endtime-starttime))

    def flow_stats_reply_handler(self, body):
        flows = []

        for stat in body:
            flows.append('%s\n' % stat)

        self.logger.info('FlowStats: %d' % len(flows))
        #self.logger.info('%s' % flows)


