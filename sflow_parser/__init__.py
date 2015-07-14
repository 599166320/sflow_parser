# -*- coding: utf-8 -*-

import logging
from socket import socket, AF_INET, SOCK_DGRAM, ntohl
from xdrlib import Unpacker


FORMAT_FLOW_SAMPLE = 1
FORMAT_COUNTER_SAMPLE = 2

FORMAT_COUNTER_RECORD_GENERIC = 1
FORMAT_COUNTER_RECORD_ETHERNET = 2
FORMAT_COUNTER_RECORD_TOKENRING = 3
FORMAT_COUNTER_RECORD_100BASEVG = 4
FORMAT_COUNTER_RECORD_VLAN = 5
FORMAT_COUNTER_RECORD_PROCESS = 1001


class SFlowPacket(object):

    def __init__(self):
        self.version = None
        self.agent_ip_version = None
        self.agent_ip_address = None
        self.sub_agent_id = None
        self.datagram_sequence_num = None
        self.switch_uptime = None # unit in ms
        self.sample_amount = None

        self.flow_samples = []
        self.counter_samples = []


class Record(object):

    def __init__(self, sample_data):
        self.format = None


class FlowRecord(Record):

    def __init__(self, sample_data):
        super(FlowRecord, self).__init__(sample_data)
        # TODO


class CounterRecord(Record):

    def __init__(self, sample_data):
        super(CounterRecord, self).__init__(sample_data)
        self.format = sample_data.unpack_uint()
        record_data = Unpacker(sample_data.unpack_opaque())

        if self.format == FORMAT_COUNTER_RECORD_GENERIC:
            self._parse_generic(record_data)
        elif self.format == FORMAT_COUNTER_RECORD_ETHERNET:
            self._parse_ethernet(record_data)
        elif self.format == FORMAT_COUNTER_RECORD_TOKENRING:
            self._parse_tokenring(record_data)
        elif self.format == FORMAT_COUNTER_RECORD_100BASEVG:
            self._parse_100basevg(record_data)
        elif self.format == FORMAT_COUNTER_RECORD_VLAN:
            self._parse_vlan(record_data)
        elif self.format == FORMAT_COUNTER_RECORD_PROCESS:
            self._parse_process(record_data)

    def _parse_generic(self, record_data):
        self.index = record_data.unpack_uint()
        self.if_type = record_data.unpack_uint()
        self.speed = record_data.unpack_uhyper()
        self.direction = record_data.unpack_uint()
        self.status = record_data.unpack_uint()
        self.in_octets = record_data.unpack_uhyper()
        self.in_ucasts = record_data.unpack_uint()
        self.in_mcasts = record_data.unpack_uint()
        self.in_bcasts = record_data.unpack_uint()
        self.in_discards = record_data.unpack_uint()
        self.in_errors = record_data.unpack_uint()
        self.in_unknown_protos = record_data.unpack_uint()
        self.out_octets = record_data.unpack_uhyper()
        self.out_ucasts = record_data.unpack_uint()
        self.out_mcasts = record_data.unpack_uint()
        self.out_bcasts = record_data.unpack_uint()
        self.out_discards = record_data.unpack_uint()
        self.out_errors = record_data.unpack_uint()
        self.promiscuous_mode = record_data.unpack_uint()

    def _parse_ethernet(self, record_data):
        self.dot3StatsAlignmentErrors = record_data.unpack_uint()
        self.dot3StatsFCSErrors = record_data.unpack_uint()
        self.dot3StatsSingleCollisionFrames = record_data.unpack_uint()
        self.dot3StatsMultipleCollisionFrames = record_data.unpack_uint()
        self.dot3StatsSQETestErrors = record_data.unpack_uint()
        self.dot3StatsDeferredTransmissions = record_data.unpack_uint()
        self.dot3StatsLateCollisions = record_data.unpack_uint()
        self.dot3StatsExcessiveCollisions = record_data.unpack_uint()
        self.dot3StatsInternalMacTransmitErrors = record_data.unpack_uint()
        self.dot3StatsCarrierSenseErrors = record_data.unpack_uint()
        self.dot3StatsFrameTooLongs = record_data.unpack_uint()
        self.dot3StatsInternalMacReceiveErrors = record_data.unpack_uint()
        self.dot3StatsSymbolErrors = record_data.unpack_uint()

    def _parse_tokenring(self, record_data):
        self.dot5StatsLineErrors = record_data.unpack_uint()
        self.dot5StatsBurstErrors = record_data.unpack_uint()
        self.dot5StatsACErrors = record_data.unpack_uint()
        self.dot5StatsAbortTransErrors = record_data.unpack_uint()
        self.dot5StatsInternalErrors = record_data.unpack_uint()
        self.dot5StatsLostFrameErrors = record_data.unpack_uint()
        self.dot5StatsReceiveCongestions = record_data.unpack_uint()
        self.dot5StatsFrameCopiedErrors = record_data.unpack_uint()
        self.dot5StatsTokenErrors = record_data.unpack_uint()
        self.dot5StatsSoftErrors = record_data.unpack_uint()
        self.dot5StatsHardErrors = record_data.unpack_uint()
        self.dot5StatsSignalLoss = record_data.unpack_uint()
        self.dot5StatsTransmitBeacons = record_data.unpack_uint()
        self.dot5StatsRecoverys = record_data.unpack_uint()
        self.dot5StatsLobeWires = record_data.unpack_uint()
        self.dot5StatsRemoves = record_data.unpack_uint()
        self.dot5StatsSingles = record_data.unpack_uint()
        self.dot5StatsFreqErrors = record_data.unpack_uint()

    def _parse_100basevg(self, record_data):
        self.dot12InHighPriorityFrames = record_data.unpack_uint()
        self.dot12InHighPriorityOctets = record_data.unpack_uhyper()
        self.dot12InNormPriorityFrames = record_data.unpack_uint()
        self.dot12InNormPriorityOctets = record_data.unpack_uhyper()
        self.dot12InIPMErrors = record_data.unpack_uint()
        self.dot12InOversizeFrameErrors = record_data.unpack_uint()
        self.dot12InDataErrors = record_data.unpack_uint()
        self.dot12InNullAddressedFrames = record_data.unpack_uint()
        self.dot12OutHighPriorityFrames = record_data.unpack_uint()
        self.dot12OutHighPriorityOctets = record_data.unpack_uhyper()
        self.dot12TransitionIntoTrainings = record_data.unpack_uint()
        self.dot12HCInHighPriorityOctets = record_data.unpack_uhyper()
        self.dot12HCInNormPriorityOctets = record_data.unpack_uhyper()
        self.dot12HCOutHighPriorityOctets = record_data.unpack_uhyper()

    def _parse_vlan(self, record_data):
        self.vlan_id = record_data.unpack_uint()
        self.octets = record_data.unpack_uhyper()
        self.ucastPkts = record_data.unpack_uint()
        self.multicastPkts = record_data.unpack_uint()
        self.broadcastPkts = record_data.unpack_uint()
        self.discards = record_data.unpack_uint()

    def _parse_process(self, record_data):
        self.cpu_percentage_in_5s = record_data.unpack_uint()
        self.cpu_percentage_in_1m = record_data.unpack_uint()
        self.cpu_percentage_in_5m = record_data.unpack_uint()
        self.total_memory = record_data.unpack_hyper()
        self.free_memory = record_data.unpack_hyper()


class Sample(object):

    def __init__(self, packet, data):
        self.enterprise = 0
        self.format = None


class FlowSample(Sample):

    def __init__(self, packet, data):
        super(FlowSample, self).__init__(packet, data)
        self.format = FORMAT_FLOW_SAMPLE

        self.sequence_number = None
        self.source_id = None
        self.sampling_rate = None
        self.sample_pool = None
        self.drops = None
        self.input_if = None
        self.output_if = None

        sample_data = Unpacker(data.unpack_opaque())
        self._parse(packet, sample_data)

    def _parse(self, packet, sample_data):
        # sample sequence number
        self.sequence_number = sample_data.unpack_uint()
        # source id
        self.source_id = sample_data.unpack_uint()
        # sampling rate
        self.sampling_rate = sample_data.unpack_uint()
        # sample pool (total number of packets that could have been sampled)
        self.sample_pool = sample_data.unpack_uint()
        # drops (packets dropped due to a lack of resources)
        self.drops = sample_data.unpack_uint()
        # input (SNMP ifIndex of input interface, 0 if not known)
        self.input_if = sample_data.unpack_uint()
        # output (SNMP ifIndex of output interface, 0 if not known)
        # broadcast or multicast are handled as follows: the
        # first bit indicates multiple destinations, the
        # lower order bits number of interfaces
        self.output_if = sample_data.unpack_uint()

        self.record_amount = sample_data.unpack_uint()
        for _ in range(0, self.record_amount):
            self.records.append(FlowRecord(sample_data))


class CounterSample(Sample):

    def __init__(self, packet, data):
        super(CounterSample, self).__init__(packet, data)
        self.format = FORMAT_COUNTER_SAMPLE

        self.sequence_num = None
        self.source_id = None
        self.record_amount = None
        self.records = []

        sample_data = Unpacker(data.unpack_opaque())
        self._parse(packet, sample_data)

    def _parse(self, packet, sample_data):
        # sample sequence number
        self.sequence_num = sample_data.unpack_uint()
        # source id
        self.source_id = sample_data.unpack_uint()

        self.record_amount = sample_data.unpack_uint()
        for _ in range(0, self.record_amount):
            self.records.append(CounterRecord(sample_data))


class SPManager(object):

    def __init__(self):
        pass

    def parse(self, raw_data):
        packet = SFlowPacket()
        data = Unpacker(raw_data)

        # sFlow version (2|4|5)
        packet.version = data.unpack_uint()
        if packet.version != 5:
            logging.error("Only support version 5.")
            raise RuntimeError("Only support version 5.")
        logging.debug("Get version {0}".format(packet.version))

        # IP version of the Agent/Switch (1=v4|2=v6)
        packet.agent_ip_version = data.unpack_uint()
        if packet.agent_ip_version != 1:
            logging.error("Only support IPv4.")
            raise RuntimeError("Only support IPv4.")

        # Agent IP address (v4=4byte|v6=16byte)
        packet.agent_ip_address = ntohl(data.unpack_uint())

        # sub agent id
        packet.sub_agent_id = data.unpack_uint()

        # datagram sequence number
        packet.datagram_sequence_num = data.unpack_uint()

        # switch uptime in ms
        packet.switch_uptime = data.unpack_uint()

        # how many samples in datagram
        packet.sample_amount = data.unpack_uint()

        self._parse_samples(packet, data)

        return packet

    def _parse_samples(self, packet, data):
        for _ in range(0, packet.sample_amount):
            # data format sample data (20 bit enterprise & 12 bit format)
            # (standard enterprise 0, formats 1,2,3,4)
            format_ = data.unpack_uint()
            if format_ == FORMAT_FLOW_SAMPLE:
                packet.flow_samples.append(FlowSample(packet, data))
            elif format_ == FORMAT_COUNTER_SAMPLE:
                packet.counter_samples.append(CounterSample(packet, data))
            else:
                logging.error("Sample format {0} is not support now.".format(
                    format_
                ))
                raise RuntimeError("Sample format {0} is not "
                                   "support now.".format(format_))


if __name__ == "__main__":
    logging.basicConfig()
    listen_addr = ("0.0.0.0", 6343)
    sock = socket(AF_INET, SOCK_DGRAM)
    sock.bind(listen_addr)
    m = SPManager()
    while True:
        data, addr = sock.recvfrom(65535)
        print m.parse(data)
