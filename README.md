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
    <li><a href="#getting-started">Getting Started</a></li>
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

We strongly recommend to implement IGMP according to the IETF standards:
- IGMPv2: RFC 2236 - https://datatracker.ietf.org/doc/html/rfc2236
- IGMPv3: RFC 3376 - https://datatracker.ietf.org/doc/html/rfc3376

The tests are based on known issues. Since the primary target audience are manufacturers of professional
lighting products using sACN (ANSI E1.31), the default test configuration is targetted for this audience.

<!-- GETTING STARTED -->
## Getting Started

The easiest way to get started with this tool is to use Docker. This is however only possible on Linux systems,
since other operating systems don't supported handing network interfaces directly to the docker container.

It can also be executed without docker, which should also work on Windows and MacOS, but in that case,
you will have to make sure to install all dependencies and python packages with the right versions.

### Git

Install git in order to clone this repository. Alternatively, use the 'Download ZIP' function on Github.

To clone this repository:

```
git clone https://github.com/luminex-lce/igmptester.git
```

Afterwards, go into the cloned repository:

```
cd igmptester
```

### Docker

Using the docker container only works when using a Linux operating system.

Make sure to install Docker for your operating system. Afterwards, run the `run_linux.sh` script to run the test tool
with the network interface you would like to use as parameter:

```
./run_linux.sh eth0
```

### Prerequisites

This tool uses python. It has been developed using Python 3.12. Make sure to install
this version of python from `https://www.python.org/downloads/` or using your operating
system package manager

#### Linux

When using a Linux based operating system, the preferred method is to use the docker file, as described earlier.

If you would like to use this tool without docker, make sure to install the pcap library and ip tools:

```
sudo apt-get install -y libpcap-dev iproute2
```

#### MacOS

Install the libpcap library

```
brew install libpcap
```

#### Windows

1. Install the Microsoft C++ Build tools from https:://visualstudio.microsoft.com/visual-cpp-build-tools.
   Make sure to select 'Desktop development with C++ and the MSVC package during the installation process.
2. Install the WinPcap developer pack from https://www.winpcap.org/devel.htm
   Extract the package on your C:\ drive. You should get a `C:\WpdPack` folder.

### Python packages and Virutal environment setup

Elevated privileges (`sudo` or administrator rights) might be needed since this tool needs control over the network interface.

On Linux and MacOS:
```
sudo su
```

Create a virtual environment. This gives the best isolation for python package management

```
python3 -m venv .venv
```

Activate the virtual environment:

For Linux / MacOS:
```
source .venv/bin/activate
```

For Windows:
```
.venv\Scripts\activate.bat
```

The required python modules can be installed using:

```
python -m pip install -r docker/requirements.txt
```

Please note that this uses the 'new' `pcapy-ng` package. If you are getting an issue
about `PY_SSIZE_T_CLEAN macro must be defined for '#' formats`, make sure you uninstall
`pcapy` (the old package without `-ng`).


<!-- USAGE EXAMPLES -->
## Usage

### Setup

To run this tool:
1. Make sure any program on your computer that might interact with IGMP (for example sACNViewer), is closed.
2. Connect the device under test directly to a network interface on your computer. There should be no switch
   in between the DUT and the test computer since that might filter IGMP packets or alter the test results.

### Run

Modify `src/configuration.py` to your needs. Especially change the network interface to the NIC you will be using.

This tool uses `pytest`. It can be executed using:

```
python -m pytest -o log_cli=True
```

A specific test file or test case can be added to the command to run only that file or test case:

```
python -m pytest -o log_cli=True src/test_igmp.py::test_v2_general_query_response
```

The test results can be stored in a JUnit file by adding the `--junit-xml` parameter followed by the path to the file:

```
python -m pytest -o log_cli=True --junit-xml=./output/result.junit
```

This file can be viewed in the browser, for example using junit2html:

```
pip install junit2xml
junit2xml ./output/result.junit
open ./output/result.junit.html
```


### Results

Captures created during the test will be stored in the `output/` folder and can be used for reviewing and debugging
the test results.

<details>
  <summary>As an example, here is the output of a test run:</summary>

```
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

### Leave virtual environment

To leave the python virtual environment when you are done testing, just run the `deactivate` command:
```
deactivate
```

If you used `sudo su` to activate admin privileges, you can exit this:
```
exit
```

<!-- ROADMAP -->
## Roadmap

- It would be nice if the network interface can be passed as an environment variable or command argument
instead of hardcoding it in `src/configuration.py`

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

