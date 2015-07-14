# sFlow Parser

项目参考了https://github.com/kok/pyflow的实现。

sFlow Parser是一个用于解析sFlow v5版本数据包的Python库。用法如下：

```python
import logging
from socket import socket, AF_INET, SOCK_DGRAM

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

```

输出如下：

```
GET ARP SAMPLE RECORD.
ARP_OP: ARP
ARP_SHA: 5E:97:D1:8D:A6:00
ARP_SPA: 10.8.8.9
ARP_THA: 00:00:00:00:00:00
ARP_TPA: 10.8.8.100

GET ARP SAMPLE RECORD.
ARP_OP: ARP
ARP_SHA: 5E:97:D1:8D:A6:00
ARP_SPA: 10.8.8.9
ARP_THA: 00:00:00:00:00:00
ARP_TPA: 10.8.8.100

GET ARP SAMPLE RECORD.
ARP_OP: ARP RESP
ARP_SHA: 5E:97:D1:8D:A6:00
ARP_SPA: 10.8.8.9
ARP_THA: 7A:2F:94:5B:87:6A
ARP_TPA: 10.8.8.8

GET ARP SAMPLE RECORD.
ARP_OP: ARP
ARP_SHA: 5E:97:D1:8D:A6:00
ARP_SPA: 10.8.8.9
ARP_THA: 00:00:00:00:00:00
ARP_TPA: 10.8.8.101

GET ARP SAMPLE RECORD.
ARP_OP: ARP
ARP_SHA: 5E:97:D1:8D:A6:00
ARP_SPA: 10.8.8.9
ARP_THA: 00:00:00:00:00:00
ARP_TPA: 10.8.8.101
```
