import scapy
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, IPOption_Router_Alert
from scapy.sendrecv import sendp
from scapy.contrib.igmp import IGMP
from scapy.contrib.igmpv3 import IGMPv3, IGMPv3mr, IGMPv3mq

from enum import Enum
import configuration


class IGMPMessageType(Enum):
    MEMBERSHIP_QUERY = 0x11
    V1_MEMBERSHIP_REPORT = 0x12
    V2_MEMBERSHIP_REPORT = 0x16
    LEAVE_GROUP = 0x17
    V3_MEMBERSHIP_REPORT = 0x22


def send_igmp_v2_membership_query(
        source_ip="2.0.0.1",
        router_alert_option=True,
        mrcode=100,
        gaddr="0.0.0.0"):
    a = Ether(src="00:11:22:33:44:55")
    b = IP(src=source_ip, dst="224.0.0.1")
    if router_alert_option:
        b.options = [IPOption_Router_Alert()]
    c = IGMP(
            type=IGMPMessageType.MEMBERSHIP_QUERY.value,
            mrcode=mrcode,
            gaddr=gaddr
        )
    packet = a/b/c
    sendp(packet, iface=configuration.IFACE)


def send_igmp_v3_membership_query(
        source_ip="2.0.0.1",
        router_alert_option=True,
        mrcode=100,
        gaddr="0.0.0.0"):
    a = Ether(src="00:11:22:33:44:55")
    b = IP(src=source_ip, dst="224.0.0.1")
    if router_alert_option:
        b.options = [IPOption_Router_Alert()]
    c = IGMPv3(
            type=IGMPMessageType.MEMBERSHIP_QUERY.value,
            mrcode=mrcode,
        )
    # mrcode >= 128: floating-point value
    c.encode_maxrespcode()
    d = IGMPv3mq()
    d.gaddr = gaddr
    if gaddr != '0.0.0.0':
        if isinstance(gaddr, list):
            c.srcaddrs = gaddr
        else:
            c.srcaddrs = [gaddr]
    packet = a/b/c/d
    sendp(packet, iface=configuration.IFACE)


def get_igmp_v2_packets(capture, type):
    packets = []
    for pkt in scapy.utils.PcapReader(capture):
        if pkt.haslayer(IGMP):
            ip_data = pkt[IP]
            igmp_data = pkt[IGMP]
            if igmp_data.type == type.value:
                packets.append({
                    "src": ip_data.src,
                    "dst": ip_data.dst,
                    "gaddr": igmp_data.gaddr,
                    "time": pkt.time,
                    "mrcode": igmp_data.mrcode
                    })
    return packets


def get_v2_membership_queries(capture):
    return get_igmp_v2_packets(capture, IGMPMessageType.MEMBERSHIP_QUERY)


def get_v2_membership_reports(capture):
    return get_igmp_v2_packets(capture, IGMPMessageType.V2_MEMBERSHIP_REPORT)


def get_v2_leaves(capture):
    return get_igmp_v2_packets(capture, IGMPMessageType.LEAVE_GROUP)


def get_v3_membership_queries(capture):
    packets = []
    for pkt in scapy.utils.PcapReader(capture):
        if pkt.haslayer(IGMPv3mq):
            ip_data = pkt[IP]
            igmp_data = pkt[IGMPv3]
            igmp_mq_data = pkt[IGMPv3mq]
            assert igmp_data.resv == 0, 'The reserved field should be set to 0'
            packets.append({
                "src": ip_data.src,
                "dst": ip_data.dst,
                "time": pkt.time,
                "srcaddrs": igmp_mq_data.srcaddrs,
                "mrcode": igmp_data.mrcode
                })
    return packets


def get_v3_membership_reports(capture):
    packets = []
    for pkt in scapy.utils.PcapReader(capture):
        if pkt.haslayer(IGMPv3mr):
            ip_data = pkt[IP]
            igmp_data = pkt[IGMPv3mr]
            packets.append({
                "src": ip_data.src,
                "dst": ip_data.dst,
                "time": pkt.time,
                "records": igmp_data.records
                })
    return packets
