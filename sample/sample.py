import logging
from socket import socket, AF_INET, SOCK_DGRAM, ntohl

from sflow_parser import (SPManager,
                          FORMAT_FLOW_RECORD_RAW_PACKET,
                          ETHER_TYPE_ARP)

if __name__ == "__main__":
    logging.basicConfig()
    listen_addr = ("0.0.0.0", 6343)
    sock = socket(AF_INET, SOCK_DGRAM)
    sock.bind(listen_addr)
    m = SPManager()
    while True:
        data, addr = sock.recvfrom(65535)
        packet = m.parse(data)

        for sample in packet.flow_samples:
            for record in sample.records:
                if (record.format == FORMAT_FLOW_RECORD_RAW_PACKET and
                        record.ether_type == ETHER_TYPE_ARP):
                    print ("GET ARP SAMPLE RECORD.")
                    print ("ARP_OP: {0}".format(
                        ["", "ARP", "ARP RESP", "RARP", "RARP RESP"]
                        [record.arp_header.arp_op]
                    ))
                    print ("ARP_SHA: {0}".format(record.arp_header.arp_sha))
                    print ("ARP_SPA: {0}".format(record.arp_header.arp_spa))
                    print ("ARP_THA: {0}".format(record.arp_header.arp_tha))
                    print ("ARP_TPA: {0}".format(record.arp_header.arp_tpa))
                    print ("")
