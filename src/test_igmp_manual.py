"""Test IGMP manual
This test suite contains tests where manual interaction is required from the test operator.
It is possible to skip these tests by configuring the 'SKIP_MANUAL' variable in the test
configuration
"""
import pytest
from time import sleep
import lib.packet as packet
from lib.capture import start_capture, stop_capture
from lib.utils import check_interface_up
from configuration import IFACE, MGROUP_1, MGROUP_2, SKIP_MANUAL


@pytest.fixture(scope="module")
def user_input(pytestconfig):
    class suspend_guard:
        def __init__(self):
            self.capmanager = pytestconfig.pluginmanager.getplugin('capturemanager')

        def __enter__(self):
            self.capmanager.suspend_global_capture(in_=True)

        def __exit__(self, _1, _2, _3):
            self.capmanager.resume_global_capture()

    yield suspend_guard()

@pytest.mark.skipif("sys.platform.startswith('linux') or SKIP_MANUAL")
def test_report_on_link(user_input):
    """Verify that the device send IGMP membership report on link up
    Although not required by the specification, it can be a good idea to transmit unsolicited
    membership reports on a link up event. This will speed up multicast registrations since now
    the DUT doesn't have to wait on the next query interval.

    This is already an automatic test when the host operating system is a Linux system.
    """
    pcap_file = "output/report_on_link.pcap"

    print(f"Start capture on interface {IFACE} to file {pcap_file}")
    start_capture(IFACE, pcap_file)

    print(f"Toggle link on interface {IFACE}")

    with user_input:
        input('\nDisconnect the network cable between the DUT and the test computer. Afterwards press enter')

    sleep(3)
    check_interface_up(expected=False)

    with user_input:
        input('\nReconnect the network cable between the DUT and the test computer. Afterwards press enter')

    sleep(3)
    check_interface_up()

    print("Stop capture")
    stop_capture(pcap_file)

    v2_membership_reports = packet.get_v2_membership_reports(pcap_file)
    v3_membership_reports = packet.get_v3_membership_reports(pcap_file)

    assert len(v2_membership_reports) > 0 or len(v3_membership_reports) > 0, "Received no IGMP membership reports"

    found_mgroup_1_join = False
    for report in v2_membership_reports:
        if report["gaddr"] == MGROUP_1:
            found_mgroup_1_join = True
            assert report["gaddr"] == report["dst"], "Membership reports should use the same multicast destination " \
                                                     "address as the address present in the IGMP payload"
    for report in v3_membership_reports:
        assert report["dst"] == "224.0.0.22", "IGMPv3 packets should be addressed to 224.0.0.22"
        for record in report["records"]:
            if record.maddr == MGROUP_1:
                found_mgroup_1_join = True

    assert found_mgroup_1_join, f"Expected to get an IGMP membership report for multicast group {MGROUP_1}"

@pytest.mark.skipif("SKIP_MANUAL")
def test_leave_on_config_change(user_input):
    """Verify that the device send IGMP leave and specific membership report when changing configuration
    This test is not applicable for devices that do not support configuration of the multicast addresses.
    In this test, it is verified that when the multicast address configuration of the DUT is modified, the DUT
    correctly 'leaves' the old multicast group and joins the new group.
    Modify the test configuration to configure MGROUP_1 and MGROUP_2 variables to match values that can be configured
    on the DUT.
    """
    pcap_file = "output/leave_on_config_change.pcap"

    print(f"Detect link up on interface {IFACE}")
    check_interface_up()

    print(f"Start capture on interface {IFACE} to file {pcap_file}")
    start_capture(IFACE, pcap_file)

    print('Send v2 Query in an attempt to force v2 operation of DUT')
    packet.send_igmp_v2_membership_query()

    sleep(1)

    with user_input:
        input(f'\nChange the configuration of the DUT to no longer accept {MGROUP_1}, '
              f'but receive {MGROUP_2} instead. Afterwards press enter')

    sleep(1)

    print("Stop capture")
    stop_capture(pcap_file)

    membership_reports = packet.get_v2_membership_reports(pcap_file)
    leaves = packet.get_v2_leaves(pcap_file)
    assert len(leaves) > 0, "Received no IGMP group leaves"
    assert len(membership_reports) > 0, "Received no IGMP membership reports"

    print(f"Validate that the DUT transmitted a leave for {MGROUP_1}")
    found_mgroup_1_leave = False
    for leave in leaves:
        assert leave["dst"] == "224.0.0.2", f"IGMP leaves are expected to be transmitted to " \
                                            f"224.0.0.2, but a leave with destination {leave['dst']} is discovered"
        assert leave["gaddr"] != "0.0.0.0", "IGMP leave discovered with IGMP multicast address set  " \
                                            "0.0.0.0, which is an unexpected value"
        if leave["gaddr"] == MGROUP_1:
            found_mgroup_1_leave = True
    assert found_mgroup_1_leave, f"Expected to get an IGMP leave for multicast group {MGROUP_1}"

    print(f"Validate that the DUT transmitted a membership report for {MGROUP_2}")
    found_mgroup_2_join = False
    for report in membership_reports:
        if report["gaddr"] == MGROUP_2:
            found_mgroup_2_join = True
            assert report["gaddr"] == report["dst"], "Membership reports should use the same multicast destination " \
                                                     "address as the address present in the IGMP payload"
    assert found_mgroup_2_join, f"Expected to get an IGMP membership report for multicast group {MGROUP_2}"

    assert True


@pytest.mark.skipif("SKIP_MANUAL")
def test_report_on_boot(user_input):
    """Verify that the device send IGMP membership report on boot up
    This test validates that the DUT transmits unsolicited membership reports after booting up.
    Although not required by the IGMP specification, it is a good idea to implement this behavior so
    that the DUT can immediately receive multicast data after booting up. It doesn't have to wait until
    the next query interval.
    """
    pcap_file = "output/report_on_boot.pcap"

    with user_input:
        input(f'\nConfigure the DUT to receive {MGROUP_1}, afterwards power down the DUT. '
              f'Press enter when this is done.')

    sleep(0.5)

    print(f"Start capture on interface {IFACE} to file {pcap_file}")
    start_capture(IFACE, pcap_file)

    with user_input:
        input('\nStartup the DUT. Press enter when the DUT is fully booted up.')

    print(f"Detect link up on interface {IFACE}")
    check_interface_up()

    sleep(1)

    print("Stop capture")
    stop_capture(pcap_file)

    v2_membership_reports = packet.get_v2_membership_reports(pcap_file)
    v3_membership_reports = packet.get_v3_membership_reports(pcap_file)

    assert len(v2_membership_reports) > 0 or len(v3_membership_reports) > 0, "Received no IGMP membership reports"

    found_mgroup_1_join = False
    for report in v2_membership_reports:
        if report["gaddr"] == MGROUP_1:
            found_mgroup_1_join = True
            assert report["gaddr"] == report["dst"], "Membership reports should use the same multicast destination " \
                                                     "address as the address present in the IGMP payload"
    for report in v3_membership_reports:
        assert report["dst"] == "224.0.0.22", "IGMPv3 packets should be addressed to 224.0.0.22"
        for record in report["records"]:
            if record.maddr == MGROUP_1:
                found_mgroup_1_join = True

    assert found_mgroup_1_join, f"Expected to get an IGMP membership report for multicast group {MGROUP_1}"
