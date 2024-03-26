<!-- PROJECT Header -->
<div align="center">
  <h3 align="center">IGMP Tester</h3>

  <p align="center">
    A testtool to validate IGMP behavior of end devices.
  </p>
</div>

<!-- TABLE OF CONTENTS -->
<details>
  <summary>Table of Contents</summary>
  <ol>
    <li>
      <a href="#about-the-project">About The Project</a>
    </li>
    <li>
      <a href="#getting-started">Getting Started</a>
      <ul>
        <li><a href="#prerequisites">Prerequisites</a></li>
        <li><a href="#installation">Installation</a></li>
      </ul>
    </li>
    <li><a href="#usage">Usage</a></li>
    <li><a href="#contributing">Contributing</a></li>
    <li><a href="#license">License</a></li>
  </ol>
</details>

<!-- ABOUT THE PROJECT -->
## About The Project

This is a tool to validate IGMP behavior of endpoints, more specific for devices receiving multicast data.

This is not a certification tool, the results of the tests do not warrant any claims on the quality or
robustness of a certain product. It is merely a testtool to validate the behavior with the sole purpose
of increasing the stability of multicast networks, in particular in the ProAV and entertainment industry.

The tests are based on known issues. Since the primary target audience are manufacturers of professional
lighting products using sACN (ANSI E1.31), the default test configuration is targetted for this audience.

<!-- GETTING STARTED -->
## Getting Started

### Prerequisites

This tool uses python. It has been developped using Python 3.10.12.

The required modules can be installed using:

```
python3 -m pip install -r requirements.txt
```

Please note that this uses the 'new' `pcapy-ng` package. If you are getting an issue
about `PY_SSIZE_T_CLEAN macro must be defined for '#' formats`, make sure you uninstall
`pcapy` (the old package without `-ng`).

### Installation

Clone this repository:

```
git clone <insert repository URL>
```

<!-- USAGE EXAMPLES -->
## Usage

Modify `configuration.py` to your needs. Especially change the network interface to the NIC you will be using.

This tool uses `pytest`. It can be executed using:

```
pytest -o log_cli=True
```

Elevated privileges (`sudo` or administrator rights) might be needed since this tool needs control over the network interface.

Captures created during the test will be stored in the `output/` folder and can be used for reviewing and debugging
the test results.

<details>
  <summary>As an example, here is the output of a test run:</summary>

```
sudo pytest -o log_cli=True .
==================================================================================== test session starts ====================================================================================
platform linux -- Python 3.10.12, pytest-7.4.4, pluggy-1.3.0
rootdir: ~/tools/igmptester
plugins: docs-0.1.0
collected 16 items

test_igmp.py::test_v2_general_query_response PASSED                                                                                                                                   [  6%]
test_igmp.py::test_v2_general_query_response_no_router_alert_option PASSED                                                                                                            [ 12%]
test_igmp.py::test_v2_general_query_response_other_querier_ip_same_net PASSED                                                                                                         [ 18%]
test_igmp.py::test_v2_general_query_response_other_querier_ip PASSED                                                                                                                  [ 25%]
test_igmp.py::test_v2_general_query_response_zeroes_querier_ip PASSED                                                                                                                 [ 31%]
test_igmp.py::test_v2_specific_query_response PASSED                                                                                                                                  [ 37%]
test_igmp.py::test_unsolicited_membership_reports PASSED                                                                                                                              [ 43%]
test_igmp.py::test_maximum_response_time PASSED                                                                                                                                       [ 50%]
test_igmp.py::test_report_on_link FAILED                                                                                                                                              [ 56%]
test_igmp_manual.py::test_leave_on_config_change
Change the configuration of the DUT to no longer accept 239.255.0.1, but receive 239.255.0.2 instead. Afterwards press enter
PASSED                                                                                                                                                                                [ 62%]
test_igmp_manual.py::test_report_on_boot
Configure the DUT to receive 239.255.0.1, afterwards power down the DUT. Press enter when this is done.

Startup the DUT. Press enter when the DUT is fully booted up.
PASSED                                                                                                                                                                                [ 68%]
test_igmp_v3.py::test_v3_general_query_response PASSED                                                                                                                                [ 75%]
test_igmp_v3.py::test_v3_general_query_response_no_router_alert_option PASSED                                                                                                         [ 81%]
test_igmp_v3.py::test_v3_general_query_response_other_querier_ip PASSED                                                                                                               [ 87%]
test_igmp_v3.py::test_v3_specific_query_response PASSED                                                                                                                               [ 93%]
test_igmp_v3.py::test_maximum_response_time PASSED                                                                                                                                    [100%]

========================================================================================== FAILURES ========================================================================================
____________________________________________________________________________________ test_report_on_link ___________________________________________________________________________________

    def test_report_on_link():
        """Verify that the device send IGMP membership report on link up
        Although not required by the specification, it can be a good idea to transmit unsolicited
        membership reports on a link up event. This will speed up multicast registrations since now
        the DUT doesn't have to wait on the next query interval.
        """
        pcap_file = "output/report_on_link.pcap"

        print(f"Start capture on interface {IFACE} to file {pcap_file}")
        start_capture(IFACE, pcap_file)

        print(f"Toggle link on interface {IFACE}")
        set_interface_link(up=False)
        sleep(10)
        check_interface_up(expected=False)
        set_interface_link(up=True)
        sleep(10)
        check_interface_up()

        print("Stop capture")
        stop_capture(pcap_file)

        v2_membership_reports = packet.get_v2_membership_reports(pcap_file)
        v3_membership_reports = packet.get_v3_membership_reports(pcap_file)

>       assert len(v2_membership_reports) > 0 or len(v3_membership_reports) > 0, "Received no IGMP membership reports"
E       AssertionError: Received no IGMP membership reports
E       assert (0 > 0 or 0 > 0)
E        +  where 0 = len([])
E        +  and   0 = len([])

test_igmp.py:250: AssertionError
---------------------------------------------------------------------------------- Captured stdout call ------------------------------------------------------------------------------------
Start capture on interface enx00249b2b23c9 to file output/report_on_link.pcap
Starting CapturingProcess on interface enx00249b2b23c9 with 'None' as bpf filter and dumping data to output/report_on_link.pcap
Toggle link on interface enx00249b2b23c9
Stop capture
=============================================================================== short test summary info ====================================================================================
FAILED test_igmp.py::test_report_on_link - AssertionError: Received no IGMP membership reports
===================================================================== 1 failed, 15 passed in 809.32s (0:13:29) =============================================================================
```
</details>

<!-- CONTRIBUTING -->
## Contributing

Contributions are what make the open source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**.

If you have a suggestion that would make this test tool better or if you would like to add a test case, please fork the repo and create a pull request.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

<!-- LICENSE -->
## License

Distributed under the GNU General Public License v3.0. See `LICENSE.txt` for more information.

