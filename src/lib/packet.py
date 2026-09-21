import scapy
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, IPOption_Router_Alert
from scapy.packet import bind_bottom_up, split_bottom_up
from scapy.sendrecv import sendp
from scapy.contrib.igmp import IGMP
from scapy.contrib.igmpv3 import IGMPv3, IGMPv3mr, IGMPv3mq

from enum import Enum
import configuration

# By default scapy only dissects IP payloads as IGMP when ttl == 1, because that
# is what a conformant implementation sends (RFC 2236 section 2). A DUT that gets
# the ttl wrong is exactly what this test suite has to be able to detect, but such
# packets would dissect as Raw and be invisible to the getters below, silently
# turning a conformance failure into a pass. Rebind the dissection direction
# without the ttl condition so every IGMP packet is parsed and can be checked
# explicitly. The build direction is left untouched, so packets we send still get
# ttl = 1 automatically.
split_bottom_up(IP, IGMP, frag=0, proto=2, ttl=1)
bind_bottom_up(IP, IGMP, frag=0, proto=2)
split_bottom_up(IP, IGMPv3, frag=0, proto=2, ttl=1)
bind_bottom_up(IP, IGMPv3, frag=0, proto=2)


class IGMPMessageType(Enum):
    MEMBERSHIP_QUERY = 0x11
    V1_MEMBERSHIP_REPORT = 0x12
    V2_MEMBERSHIP_REPORT = 0x16
    LEAVE_GROUP = 0x17
    V3_MEMBERSHIP_REPORT = 0x22


def decode_maxrespcode(mrcode):
    """Decode an IGMPv3 Max Resp Code byte to the maximum response time in seconds.

    This is for IGMPv3 only. IGMPv2 carries the field as a literal value over its
    whole range (RFC 2236 section 2.2), so decoding a v2 query with this function
    would inflate every value of 128 and above.

    Below 128 the code is a literal value in units of 1/10 second. From 128 up it
    is a floating point value, as specified in RFC 3376 section 4.1.1:

        Max Resp Time = (mant | 0x10) << (exp + 3)

    also in units of 1/10 second, hence the division by 10 in both branches.
    """
    if mrcode < 128:
        return mrcode / 10
    exp = (mrcode & 0x70) >> 4  # 0x70 = b'0111 0000'
    mant = mrcode & 0x0F  # 0x0F = b'0000 1111'
    return ((mant | 0x10) << (exp + 3)) / 10


def encoded_max_response_time(mrcode):
    """Return the maximum response time in seconds that an IGMPv3 query built with
    this mrcode actually carries on the wire.

    The Max Resp Code field is a single byte, so not every mrcode survives the trip.
    Values from 128 up are quantised to the nearest representable floating point
    value and anything above 31743 is clamped to 255, so asking for 300 seconds
    (mrcode 3000) really transmits 294.4 seconds. A test that waits for the value it
    asked for rather than the value it sent would accept a response that arrived
    after the window the DUT was actually given.
    """
    query = IGMPv3(type=IGMPMessageType.MEMBERSHIP_QUERY.value, mrcode=mrcode)
    query.encode_maxrespcode()
    return decode_maxrespcode(query.mrcode)


def query_destination(gaddr):
    """Return the IP destination for a membership query.

    A general query goes to the all-systems address, a group specific query to the
    group itself (RFC 2236 section 2.1 and RFC 3376 section 4.1.12). Addressing a
    group specific query to 224.0.0.1 instead lets a DUT that correctly filters
    queries by destination drop it, which would be reported as a DUT failure.
    """
    if gaddr == "0.0.0.0":
        return "224.0.0.1"
    return gaddr


def send_igmp_v2_membership_query(
        source_ip="2.0.0.1",
        router_alert_option=True,
        mrcode=100,
        gaddr="0.0.0.0"):
    a = Ether(src="00:11:22:33:44:55")
    b = IP(src=source_ip, dst=query_destination(gaddr))
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
    b = IP(src=source_ip, dst=query_destination(gaddr))
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
    # No source addresses are set: a group specific query carries an empty source
    # list (RFC 3376 section 4.1.8). Earlier code assigned srcaddrs here, but it set
    # the attribute on the IGMPv3 header, which has no such field, so it never
    # reached the wire and the query already carried an empty list.
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
                    "ttl": ip_data.ttl,
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
        if pkt.haslayer(IGMPv3) and pkt.haslayer(IGMPv3mq):
            ip_data = pkt[IP]
            igmp_data = pkt[IGMPv3]
            if igmp_data.type != IGMPMessageType.MEMBERSHIP_QUERY.value:
                continue
            igmp_mq_data = pkt[IGMPv3mq]
            packets.append({
                "src": ip_data.src,
                "dst": ip_data.dst,
                "time": pkt.time,
                "resv": igmp_mq_data.resv,
                "srcaddrs": igmp_mq_data.srcaddrs,
                "mrcode": igmp_data.mrcode
                })
    return packets


def get_v3_membership_reports(capture):
    packets = []
    for pkt in scapy.utils.PcapReader(capture):
        if pkt.haslayer(IGMPv3) and pkt.haslayer(IGMPv3mr):
            ip_data = pkt[IP]
            igmp_data = pkt[IGMPv3]
            if igmp_data.type != IGMPMessageType.V3_MEMBERSHIP_REPORT.value:
                continue
            igmp_data = pkt[IGMPv3mr]
            packets.append({
                "src": ip_data.src,
                "dst": ip_data.dst,
                "time": pkt.time,
                "ttl": ip_data.ttl,
                "records": igmp_data.records
                })
    return packets
