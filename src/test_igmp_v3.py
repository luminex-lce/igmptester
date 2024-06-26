"""IGMPv3 Test suite
The tests in this test suite are automatic tests focussed on the IGMPv3 behavior
of devices that want to receive multicast data.
IGMPv3 is defined in RFC 3376 (https://datatracker.ietf.org/doc/html/rfc3376)
The tests in this suite can be skipped by configuring the IGMPv3_SUPPORT parameter
"""
import pytest
from time import sleep
import lib.packet as packet
from lib.capture import start_capture, stop_capture
from lib.utils import check_interface_up, validate_igmpv3_reports, validate_igmpv3_packet_spacing
from configuration import IFACE, MGROUP_1, IGMPV3_SUPPORT  # noqa: F401


def validate_membership_reports(
        pcap_file,
        source_ip="2.0.0.1",
        router_alert_option=True,
        gaddr="0.0.0.0"):
    """Transmit query and validate membership reports
    This is a helper function where a V3 membership query is transmitted and
    the received membership reports are validated.
    """
    print(f"Detect link up on interface {IFACE}")
    check_interface_up()

    print(f"Start capture on interface {IFACE} to file {pcap_file}")
    start_capture(IFACE, pcap_file)

    max_response_time = 1  # seconds
    mrcode = max_response_time * 10
    print("Send IGMPv3 membership query")
    packet.send_igmp_v3_membership_query(
            source_ip=source_ip,
            router_alert_option=router_alert_option,
            mrcode=mrcode,
            gaddr=gaddr)

    print("Wait membership response timeout + a little margin")
    sleep(max_response_time + 1)

    print("Stop capture")
    stop_capture(pcap_file)

    print("Check capture for membership report")
    validate_igmpv3_reports(pcap_file, gaddr)


@pytest.mark.skipif("not IGMPV3_SUPPORT")
def test_v3_general_query_response():
    """Verify that the device responds to a IGMPv3 general membership query
    """
    pcap_file = "output/v3_general_query_response.pcap"
    validate_membership_reports(pcap_file)


@pytest.mark.skipif("not IGMPV3_SUPPORT")
def test_v3_general_query_response_no_router_alert_option():
    """Report how the device handels a IGMPv3 general membership query without router alert option
    Failing this test is not a big deal since the router alert option is mandatory
    according to the IGMPv3 specification, but it is still recommended to also
    respond to membership requests that don't have this option set, since it is
    known that not all queriers have this option set.
    """
    pcap_file = "output/v3_general_query_response_no_router_alert_option.pcap"
    validate_membership_reports(pcap_file, router_alert_option=False)


@pytest.mark.skipif("not IGMPV3_SUPPORT")
def test_v3_general_query_response_other_querier_ip():
    """Verify that the device responds to a membership query when using a different Querier IP
    """
    pcap_file = "output/v3_general_query_response_other_querier_ip.pcap"
    validate_membership_reports(pcap_file, source_ip="10.0.0.1")


@pytest.mark.skipif("not IGMPV3_SUPPORT")
def test_v3_specific_query_response():
    """Verify that the DUT responds to a specific membership request
    This test assumes that the DUT is configured to receive multicast from MGROUP_1.
    Change the test configuration so that MGROUP_1 corresponds to a multicast address on which the DUT
    is registering.
    """
    pcap_file = "output/v3_specific_query_response.pcap"
    validate_membership_reports(pcap_file, gaddr=MGROUP_1)


@pytest.mark.skipif("not IGMPV3_SUPPORT")
def test_maximum_response_time():
    """Verify that the DUT is using a random response time and respects the maximum response time
    A DUT has to respond to a membership query within the maximum response time as indicated in the query packets.
    Additionally, the response time has to be a random value between 0 and the maximum response time.
    This is needed so that in big networks, not all devices transmit their membership reports at the same time,
    resulting in overloading the IGMP querier.
    This test transmits multiple membership queries with increasing maximum response times and validates that the
    DUT responds in time. Additionally, it is validated that there is sufficient variance on the response times in
    an attempt to detect if the DUT is using a random timer value.

    Note that in IGMPv3, the maximum response time has an exponential range as described in section 4.1.1 of RFC 3376.
    If the value of the max resp code is above 128 (12.8 seconds), it represents a floating point value.
    """
    from statistics import variance
    print(f"Detect link up on interface {IFACE}")
    check_interface_up()

    max_response_times = [1, 3, 5, 10, 20, 300]
    response_times = []
    for max_response_time in max_response_times:
        pcap_file = f"output/v3_maximum_response_time_{max_response_time}_sec.pcap"
        print(f"Start capture on interface {IFACE} to file {pcap_file}")
        start_capture(IFACE, pcap_file)

        mrcode = max_response_time * 10
        print("Send IGMPv3 membership query")
        packet.send_igmp_v3_membership_query(mrcode=mrcode)

        print("Wait for the maximum response time")
        sleep(max_response_time + 2)

        print("Stop capture")
        stop_capture(pcap_file)

        response_times.append(validate_igmpv3_packet_spacing(pcap_file))

    var = variance(response_times)
    print(response_times)
    assert var > 0.2, f"It looks like the membership response times aren't randomly distributed " \
                      f"Variance is {var}"

    assert True
