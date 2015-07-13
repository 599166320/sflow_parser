# -*- coding: utf-8 -*-

import logging
from socket import ntohl
from xdrlib import Unpacker


FORMAT_FLOW_SAMPLE = 1
FORMAT_COUNTER_SAMPLE = 2


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
        super(self, FlowRecord).__init__(sample_data)
        # TODO


class CounterRecord(Record):

    def __init__(self, sample_data):
        super(self, CounterRecord).__init__(sample_data)
        # TODO


class Sample(object):

    def __init__(self, packet, data):
        self.enterprise = 0
        self.format = None


class FlowSample(Sample):

    def __init__(self, packet, data):
        super(self, FlowSample).__init__(packet, data)
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
        super(self, CounterSample).__init__(packet, data)
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

