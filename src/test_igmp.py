"""IGMPv2 Test suite
The tests in this test suite are automatic tests focussed on the IGMPv2 behavior
of devices that want to receive multicast data.
"""
from time import sleep
import pytest
import warnings
import lib.packet as packet
from lib.capture import start_capture, stop_capture
from lib.utils import check_interface_up, validate_igmpv2_reports, validate_igmpv2_packet_spacing
from configuration import IFACE, MGROUP_1


def validate_membership_reports(
        pcap_file,
        source_ip="2.0.0.1",
        router_alert_option=True,
        gaddr="0.0.0.0"):
    """Transmit query and validate membership reports
    This is a helper function where a V2 membership query is transmitted and
    the received membership reports are validated.
    """
    print(f"Detect link up on interface {IFACE}")
    check_interface_up()

    print(f"Start capture on interface {IFACE} to file {pcap_file}")
    start_capture(IFACE, pcap_file)

    max_response_time = 1  # seconds
    mrcode = max_response_time * 10
    print("Send IGMPv2 membership query")
    packet.send_igmp_v2_membership_query(
            source_ip=source_ip,
            router_alert_option=router_alert_option,
            mrcode=mrcode,
            gaddr=gaddr)

    print("Wait membership response timeout + a little margin")
    sleep(max_response_time + 1)

    print("Stop capture")
    stop_capture(pcap_file)

    validate_igmpv2_reports(pcap_file, gaddr)


def test_v2_general_query_response():
    """Verify that the device responds to a IGMPv2 general membership query
    This is a basic tests where it is validated that the Device Under Test (DUT)
    responds to an IGMPv2 general membership query. The query contents are based on the
    'scapy' IGMP implementation and is considered a 'good' query.
    The output capture of this test can also be used to discover which multicast groups
    the DUT would like to receive and configure the MGROUP_1 variable
    in the test configuration accordingly.
    """
    pcap_file = "output/v2_general_query_response.pcap"
    validate_membership_reports(pcap_file)


def test_v2_general_query_response_no_router_alert_option():
    """Report how the device handels a IGMPv2 general membership query without router alert option
    Failing this test is not a big deal since the router alert option is mandatory
    according to the IGMPv2 specification, but it is still recommended to also
    respond to membership requests that don't have this option set, since it is
    known that not all queriers have this option set.
    """
    pcap_file = "output/v2_general_query_response_no_router_alert_option.pcap"
    validate_membership_reports(pcap_file, router_alert_option=False)


def test_v2_general_query_response_other_querier_ip_same_net():
    """Verify that the device responds to a membership query when using a different Querier IP within the same subnet
    It is possible that the querier IP changes over time, for example due to configuration changes.
    The DUT should respond to a membership query, even if the source IP of the query is different
    compared to previous query packets.
    """
    pcap_file = "output/v2_general_query_response_other_querier_ip_same_net.pcap"
    validate_membership_reports(pcap_file, source_ip="2.0.0.2")


def test_v2_general_query_response_other_querier_ip():
    """Verify that the device responds to a membership query when using a different Querier IP
    Some devices are known to only accept IGMP membership query packets where the source IP is in the same subnet
    as their own IP address. This test uses a source IP from a different subnet to validate that the DUT
    responds to a query, even if the source IP is in a different range.
    """
    pcap_file = "output/v2_general_query_response_other_querier_ip.pcap"
    validate_membership_reports(pcap_file, source_ip="10.0.0.1")


def test_v2_general_query_response_zeroes_querier_ip():
    """Verify that the device responds to a membership query when using an all-zero querier IP
    The all zeroes '0.0.0.0' is a special but valid source IP address. Devices shall respond to this query packet.
    """
    pcap_file = "output/v2_general_query_response_zeroes_querier_ip.pcap"
    validate_membership_reports(pcap_file, source_ip="0.0.0.0")


def test_v2_specific_query_response():
    """Verify that the DUT responds to a specific membership request
    This test assumes that the DUT is configured to receive multicast from MGROUP_1.
    Change the test configuration so that MGROUP_1 corresponds to a multicast address on which the DUT
    is registering.
    """
    pcap_file = "output/v2_specific_query_response.pcap"
    validate_membership_reports(pcap_file, gaddr=MGROUP_1)


def test_unsolicited_membership_reports():
    """Verify that the device does not send unsolicited IGMPv2 messages
    Some devices have a 'dumb' IGMP implementation and just transmit membership reports at a fixed
    interval. This is not how the IGMP implementation intended the protocol to be used, therefore
    this test validates that the DUT does not transmit any membership reports when no membership query
    packets are transmitted.
    """
    print(f"Detect link up on interface {IFACE}")
    check_interface_up()

    pcap_file = "output/unsolicited_membership_reports.pcap"
    print(f"Start capture on interface {IFACE} to file {pcap_file}")
    start_capture(IFACE, pcap_file)

    print("Wait default query interval + a little margin")
    sleep(125 + 5)

    print("Stop capture")
    stop_capture(pcap_file)

    print("Check capture for V2 membership report")
    v2_membership_reports = packet.get_v2_membership_reports(pcap_file)
    v3_membership_reports = packet.get_v3_membership_reports(pcap_file)
    print(v2_membership_reports)
    print(v3_membership_reports)
    assert len(v2_membership_reports) == 0, f"Found {len(v2_membership_reports)} IGMPv2 membership " \
                                            f"reports, none were exepcted"
    assert len(v3_membership_reports) == 0, f"Found {len(v3_membership_reports)} IGMPv3 membership " \
                                            f"reports, none were exepcted"

    assert True


def test_maximum_response_time():
    """Verify that the DUT is using a random response time and respects the maximum response time
    A DUT has to respond to a membership query within the maximum response time as indicated in the query packets.
    Additionally, the response time has to be a random value between 0 and the maximum response time.
    This is needed so that in big networks, not all devices transmit their membership reports at the same time,
    resulting in overloading the IGMP querier.
    This test transmits multiple membership queries with increasing maximum response times and validates that the
    DUT responds in time. Additionally, it is validated that there is sufficient variance on the response times in
    an attempt to detect if the DUT is using a random timer value.
    """
    from statistics import variance
    print(f"Detect link up on interface {IFACE}")
    check_interface_up()

    max_response_times = [1, 3, 5, 10, 20]
    response_times = []
    for response_time in max_response_times:
        pcap_file = f"output/maximum_response_time_{response_time}_sec.pcap"
        print(f"Start capture on interface {IFACE} to file {pcap_file}")
        start_capture(IFACE, pcap_file)

        mrcode = response_time * 10
        print("Send IGMPv2 membership query")
        packet.send_igmp_v2_membership_query(mrcode=mrcode)

        print("Wait for the maximum response time")
        sleep(response_time + 2)

        print("Stop capture")
        stop_capture(pcap_file)

        response_times.append(validate_igmpv2_packet_spacing(pcap_file))

    var = variance(response_times)
    print(response_times)
    assert var > 0.2, f"It looks like the membership response times aren't randomly distributed " \
                      f"Variance is {var}"

    assert True
