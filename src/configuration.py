# Set IFACE to the network interface on which the Device Under Test (DUT)
# is connected
# - On Linux, this can be something like "enp0s31f6". Use `ip a` to get a list of the available network interfaces.
# - On MacOS, this will be something like "en0". Use `ifconfig` to get a list of the available network interfaces.
# - On Windows, this will be the name of your ethernet adapter.
#   Use `ipconfig` to get a list of the available network interfaces.
IFACE = "eth0"

# Set this to False if the DUT does not support IGMPv3
IGMPV3_SUPPORT = True

# Set this to True to skip the tests requiring manual actions
SKIP_MANUAL = False

# Set mgroup1 to the first multicast address which the DUT will receive
# If using sACN, universe 1 corresponds with multicast address 239.255.0.1
MGROUP_1 = "239.255.0.1"  # sACN universe 1
# MGROUP_1 = "239.255.255.255"  # Dante
# MGROUP_1 = "224.0.0.251"  # mDNS

# Set mgroup2 to the second multicast address which the DUT will receive.
# It should be possible to change the DUT configuration from receiving MGROUP_1
# to receiving MGROUP_2.
# If using sACN, universe 2 corresponds with multicast address 239.255.0.2
# MGROUP_2 is only used in manual tests
MGROUP_2 = "239.255.0.2"  # sACN universe 2

# When a single device transmits more than this amount of IGMP membership reports,
# The test will fail. Sending too many membership reports can overwhelm the networking
# equipment and most networking equipment has a (large) limit to the number of multicast
# registrations are handled. Therefore it is recommended that end devices stay well below
# such a limit with the number of multicast addresses they would like to register
IGMP_MEMBERSHIP_REPORT_THRESHOLD = 256

# It is possible to test the contents of a PCAP file instead of running 'live'
# against a device.
# To do this, filter 1 IGMP query interval from the capture. Meaning: the capture
# should only contain 1 IGMP query and the IGMP reports on this query.
# If it is IGMPv3, make sure to enable IGMPV3_SUPPORT above.
# Set the following parameter to the path to the pcap file
# Run the test by appending `src/test_pcap.py` to the run command
#PCAP_FILE = "output/my_capture.pcapng"
PCAP_FILE = False
