# Set IFACE to the network interface on which the Device Under Test (DUT)
# is connected
# - On Linux, this can be something like "enp0s31f6". Use `ip a` to get a list of the available network interfaces.
# - On MacOS, this will be something like "en0". Use `ifconfig` to get a list of the available network interfaces.
# - On Windows, this will be the name of your ethernet adapter.
#   Use `ipconfig` to get a list of the available network interfaces.
IFACE = ""

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
