"""IGMP Pcap Test suite
The tests in this test suite analyse data from a PCAP network capture instead
of 'live' connecting to the DUT.
"""
import pytest
from configuration import PCAP_FILE, IGMPV3_SUPPORT  # noqa: F401
import lib.utils as utils


@pytest.mark.skipif("not PCAP_FILE")
def test_pcap_v2():
    pcap_file = PCAP_FILE
    utils.validate_igmpv2_reports(pcap_file)
    utils.validate_igmpv2_packet_spacing(pcap_file)


@pytest.mark.skipif("not PCAP_FILE or not IGMPV3_SUPPORT")
def test_pcap_v3():
    pcap_file = PCAP_FILE
    utils.validate_igmpv3_reports(pcap_file)
    utils.validate_igmpv3_packet_spacing(pcap_file)
