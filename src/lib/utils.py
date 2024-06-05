from configuration import IFACE, MGROUP_1, IGMP_MEMBERSHIP_REPORT_THRESHOLD
import lib.packet as packet
import psutil
import socket
import os
import warnings
from statistics import median


def check_interface_up(expected=True):
    if os.environ.get('RUNNING_IN_DOCKER', False):
        # When running inside a Docker container, the interface is always up.
        return
    interface_addrs = psutil.net_if_addrs().get(IFACE) or []
    up = socket.AF_INET in [snicaddr.family for snicaddr in interface_addrs]
    assert up == expected, f'Interface {IFACE} is not in the expected link state (up = {expected})'


def validate_igmpv2_reports(
        pcap_file,
        gaddr="0.0.0.0"):
    print("Check capture for V2 membership report")
    membership_reports = packet.get_v2_membership_reports(pcap_file)
    assert len(membership_reports) > 0, f"Found {len(membership_reports)} IGMPv2 membership " \
                                        f"reports, expected at least 1"
    print(membership_reports)

    print("Check that for each membership report, the IP destination address is equal to the group address")
    gaddrs = []
    source_ips = {}
    for report in membership_reports:
        src = report['src']
        dst = report['dst']
        rcv_gaddr = report['gaddr']
        assert dst == rcv_gaddr, f"Received membership report from {src} where destination " \
                                 f"address {dst} is not equal to the group address {rcv_gaddr}"
        assert rcv_gaddr not in gaddrs, f"Received duplicate membership report for {rcv_gaddr}"
        gaddrs.append(rcv_gaddr)
        if src in source_ips.keys():
            source_ips[src] += 1
        else:
            source_ips[src] = 1

    if gaddr != "0.0.0.0":
        assert gaddr in gaddrs, f"No membership report for {gaddr} received"
        assert len(gaddrs) == 1, f"Received membership report for multiple " \
                                 f"addresses as a response to the specific " \
                                 f"query for {gaddr}: {gaddrs}"

    for src, count in source_ips.items():
        assert count <= IGMP_MEMBERSHIP_REPORT_THRESHOLD, \
            f"Received {count} membership reports from {src}. " \
            f"There is a limit to the amount of membership reports network equipment can handle. " \
            f"Verify that all these multicast addresses are necessary for your application."

        if count > 100:
            warnings.warn(UserWarning(f"INFO: Received {count} membership reports from {src}. "
                                      "This is allowed, but make sure that all of them are necessary."))

    assert True


def validate_igmpv3_reports(pcap_file, gaddr="0.0.0.0"):
    """Validate IGMPv3 reports
    This is a helper function to validate if a pcap file contains IGMPv2 or IGMPv3
    membership reports.
    """
    v2_membership_reports = packet.get_v2_membership_reports(pcap_file)
    v3_membership_reports = packet.get_v3_membership_reports(pcap_file)
    assert len(v3_membership_reports) > 0 or len(v2_membership_reports) > 0, \
        "Found no IGMP membership " \
        "reports, expected at least 1"
    print(v2_membership_reports)
    print(v3_membership_reports)

    if len(v3_membership_reports) == 0:
        warnings.warn(UserWarning("INFO: DUT responded with V2 membership reports to V3 query"))

    print(f"Check that a v3 membership report is received for {MGROUP_1}")

    found_mgroup_1_join = False
    for report in v2_membership_reports:
        if report["gaddr"] == MGROUP_1:
            found_mgroup_1_join = True
            assert report["gaddr"] == report["dst"], "Membership reports should use the same multicast destination " \
                                                     "address as the address present in the IGMP payload"
    for report in v3_membership_reports:
        assert report["dst"] == "224.0.0.22", "IGMPv3 packets should be addressed to 224.0.0.22"
        if gaddr != '0.0.0.0':
            assert len(report["records"]) == 1, 'Specific membership reports are expected to have 1 group record'
        for record in report["records"]:
            if record.maddr == MGROUP_1:
                found_mgroup_1_join = True

    assert found_mgroup_1_join, f"Expected to get an IGMP membership report for multicast group {MGROUP_1}"

    return v2_membership_reports + v3_membership_reports


def validate_reports(query_time, max_response_time, membership_reports):
    print("Verify for each membership report that it arrived in time")
    # Add a small tolerance to the maximum response time to take into account
    # network transit time and timestamp inaccuracy
    max_resp = max_response_time + 0.1
    last_resp = query_time
    elapsed_list = []
    response_time = None
    for report in membership_reports:
        # Calculate that the elapsed time since the query packet is within tolerance
        elapsed = report["time"] - query_time
        print(f"Got response in {elapsed} seconds. Max is {max_response_time} seconds")
        assert elapsed < max_resp, f"Membership report received after {elapsed} seconds, " \
                                   f"but the maximum is {max_response_time} seconds"
        # Only track first response for statistic calculations.
        # Some devices may have lots of responses, this may disturb the result of the statistics
        if response_time is None:
            response_time = elapsed

        # Calculate the elapsed time since the previous membership report and verify
        # That these are not transmitted in a burst
        elapsed = report["time"] - last_resp
        last_resp = report["time"]
        elapsed_list.append(elapsed)

    median_inter_response_time = median(elapsed_list)
    assert median_inter_response_time > 0.001, \
        f"The median time between membership responses is {median_inter_response_time}. " \
        f"This might indicate that responses are transmitted in burst instead of randomly " \
        f"delaying each and every response. Tranmsitting a lot of IGMP responses in burst may " \
        f"overload the IGMP querier and cause responses to be dropped, leading to the multicast " \
        f"registrations being dropped as well."

    assert len(elapsed_list) <= IGMP_MEMBERSHIP_REPORT_THRESHOLD, \
        f"Received {len(elapsed_list)} membership reports. " \
        f"There is a limit to the amount of membership reports network equipment can handle. " \
        f"Verify that all these multicast addresses are necessary for your application."

    return response_time


def validate_igmpv2_packet_spacing(pcap_file):
    print("Check capture for V2 membership report")
    membership_reports = packet.get_v2_membership_reports(pcap_file)
    print(membership_reports)
    assert len(membership_reports) != 0, f"Found {len(membership_reports)} IGMPv2 membership " \
                                         f"reports, expected at least 1"

    print("Get membership query timestamp")
    membership_query = packet.get_v2_membership_queries(pcap_file)
    print(membership_query)
    assert len(membership_query) == 1, f"Found {len(membership_reports)} IGMPv2 membership " \
                                       f"queries, expected exactly 1"

    query_time = membership_query[0]["time"]
    mrcode = membership_query[0]["mrcode"]
    max_response_time = mrcode / 10
    return validate_reports(query_time, max_response_time, membership_reports)


def validate_igmpv3_packet_spacing(pcap_file):
    print("Check capture for V3 membership report")
    membership_reports = validate_igmpv3_reports(pcap_file)

    print("Get membership query timestamp")
    membership_query = packet.get_v3_membership_queries(pcap_file)
    print(membership_query)
    assert len(membership_query) == 1, f"Found {len(membership_reports)} IGMPv3 membership " \
                                       f"queries, expected exactly 1"

    print("Verify for each membership report that it arrived in time")
    query_time = membership_query[0]["time"]
    mrcode = membership_query[0]["mrcode"]
    if mrcode < 128:
        max_response_time = mrcode / 10
    else:
        exp = (mrcode & 0x70) > 4  # 0x70 = b'0111 0000'
        mant = mrcode & 0xF  # 0xF = b'0000 1111'
        max_response_time = (mant | 0x10) << (exp + 3)
    return validate_reports(query_time, max_response_time, membership_reports)
