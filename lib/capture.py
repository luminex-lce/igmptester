from multiprocessing import Process, Event, Pipe
import signal
import traceback
import select
import sys
import pcapy


class CapturingProcess(Process):
    def __init__(self, interface, filename, bpf_filter=None, stop_cb=None):
        '''
        Create CapturingProcess, creating a process for packet captures

        Args:
            interface: interface to capture on
            filename: filename to capture to, this is also used as an identifier
            bpf_filter: filter to apply to captured packets (see tcpdump filtering)
            stop_cb: optional callback to be called for each captured packet.
                    This must be set if you want to wait for a packet with waitfor_capture
                    The cb expects a pkt argument and returns a Bool.
                    When the cb returns True, the capturing stops
        '''
        self.interface = interface
        self.filename = filename
        self.bpf_filter = bpf_filter
        self.stop_cb = stop_cb
        self.ready_event = Event()
        self._parent_conn, self._child_conn = Pipe()
        self._exception = None

        Process.__init__(self)

    @staticmethod
    def _handle_capture_term(signum, frame):
        if signum != signal.SIGTERM:
            return
        sys.exit(0)

    def start(self):
        Process.start(self)
        if not self.ready_event.wait(5):
            if self.exception:
                _, traceback = self.exception
                raise(Exception(traceback))

    def stop(self):
        self.ready_event.clear()
        if self.exception:
            _, traceback = self.exception
            raise(Exception(traceback))

    def run(self):
        print("Starting CapturingProcess on interface {} with '{}' as bpf filter and dumping data to {}"
              .format(self.interface, self.bpf_filter, self.filename))
        try:
            cap = pcapy.open_live(self.interface, 65536, True, 10)

            if self.bpf_filter:
                cap.setfilter(self.bpf_filter)
            cap.setnonblock(True)
            pcap_dumper = cap.dump_open(self.filename)
            signal.signal(signal.SIGTERM, self._handle_capture_term)

            self.ready_event.set()

            read_fds = [cap.getfd()]
            write_fds = []
            except_fds = []

            try:
                while self.ready_event.is_set():
                    # use select because while we're in a blocking cap.next() signals aren't delivered,
                    # and this process wouldn't terminate
                    readable, _, _ = select.select(read_fds, write_fds, except_fds, 0.1)

                    if cap.getfd() in readable:
                        hdr, pkt = cap.next()

                        if hdr is None:
                            continue

                        pcap_dumper.dump(hdr, pkt)

                        if self.stop_cb:
                            if self.stop_cb(pkt):
                                break

            finally:
                self.ready_event.clear()
                cap.close()
                pcap_dumper.close()
                del pcap_dumper
        except Exception as e:
            tb = traceback.format_exc()
            self._child_conn.send((e, tb))

    @property
    def exception(self):
        if self._parent_conn.poll():
            self._exception = self._parent_conn.recv()
        return self._exception


capture_procs = {}


def start_capture(interface, filename, **kwargs):
    '''
    start a capture

    This will start a new thread to capture packets.

    Args:
        interface: interface to capture on
        filename: filename to capture to, this is also used as an identifier
        **kwargs: options passed to CapturingProcess
    '''
    if filename is None:
        raise Exception('Filename for capturing cannot be None')
    if filename in capture_procs:
        raise Exception(f'Trying to start duplicate capture: {filename}')

    p = CapturingProcess(interface, filename, **kwargs)

    capture_procs[filename] = p
    p.start()


def stop_capture(filename):
    if filename is None:
        raise Exception('Filename for capturing cannot be None')
    if filename not in capture_procs:
        raise Exception('Capture \'{}\'was never started'.format(filename))

    t = capture_procs[filename]
    t.stop()
    t.join(1)
    if t.is_alive():
        print(f"Capturing process {filename} is still alive")
        t.terminate()
        t.join(8)  # wait for capture process to terminate

    if t.exitcode != 0:
        raise Exception('Capture \'{}\': process exited abnormally ({})'
                        .format(filename, t.exitcode))

    del capture_procs[filename]


def waitfor_capture(filename, timeout=0):
    '''
    This will wait for the packet capturing thread

    Args:
        filename: the same as passed to the start_capture call,
                  this is used to identify the capture thread
        timeout: time to wait for the capturing thread to finish

    Returns:
        bool: True if the capture process timedout
    '''
    timedout = False

    if filename not in capture_procs:
        raise Exception('Capture \'{}\'was never started'.format(filename))

    t = capture_procs[filename]

    t.join(timeout)

    if t.is_alive():
        timedout = True

    t.stop()
    t.join(1)

    if t.is_alive():
        t.terminate()
        t.join(8)  # wait for capture process to terminate

    if t.exitcode != 0:
        raise Exception('Capture \'{}\': process exited abnormally ({})'
                        .format(filename, t.exitcode))

    del capture_procs[filename]

    return timedout
