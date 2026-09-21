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
            # The capture did not come up. Give the child a moment to report why,
            # then fail regardless: returning here would leave the caller believing
            # packets are being captured while nothing is listening.
            reported = self.get_exception(timeout=1)
            if reported:
                _, tb = reported
                raise Exception(f"Capture '{self.filename}' failed to start on interface "
                                f"{self.interface}:\n{tb}")
            raise Exception(f"Capture '{self.filename}' did not start within 5 seconds on "
                            f"interface {self.interface}, and reported no error. Check that the "
                            f"interface exists, that the directory for the capture file exists "
                            f"and that this process has permission to capture.")

    def stop(self):
        self.ready_event.clear()
        if self.exception:
            _, tb = self.exception
            raise Exception(f"Capture '{self.filename}' failed on interface "
                            f"{self.interface}:\n{tb}")

    def run(self):  # noqa: C901
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

            if not sys.platform.startswith('win'):
                read_fds = [cap.getfd()]
                write_fds = []
                except_fds = []

            try:
                while self.ready_event.is_set():
                    if sys.platform.startswith('win'):
                        hdr, pkt = cap.next()

                        if hdr is None:
                            continue

                        pcap_dumper.dump(hdr, pkt)

                        if self.stop_cb:
                            if self.stop_cb(pkt):
                                break
                    else:
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
            # Exit non-zero so the parent notices the failure even if it does not
            # manage to read the traceback off the pipe. Without this the process
            # exits 0 after a fatal error and the exitcode checks below never fire,
            # which turns a capture that never started into an empty pcap and a
            # misleading 'expected at least 1 membership report' further on.
            sys.exit(1)

    @property
    def exception(self):
        return self.get_exception()

    def get_exception(self, timeout=0):
        '''
        Return the (exception, traceback) the capturing process reported, if any.

        Args:
            timeout: how long to wait for the child to report a failure. The default
                     of 0 only looks at what has already arrived. Use a short timeout
                     when a failure is suspected: the child sends the traceback over a
                     pipe just before it exits, so sampling the pipe at the wrong
                     instant reports no failure at all and the real diagnostic is lost.
        '''
        if self._exception is None and self._parent_conn.poll(timeout):
            self._exception = self._parent_conn.recv()
        return self._exception


capture_procs = {}


def _reported_failure(capture_proc):
    '''
    Return the traceback the capturing process reported, formatted for appending to
    an error message, or an empty string when it reported nothing. The child sends
    the traceback just before exiting, so allow a moment for it to arrive.
    '''
    reported = capture_proc.get_exception(timeout=1)
    if not reported:
        return ''
    _, tb = reported
    return f'. The capturing process reported:\n{tb}'


def _release_capture(filename, capture_proc):
    '''
    Remove a capture from the registry and make sure its process is gone.

    Both have to happen even when the teardown above raised, and they have to happen
    together: dropping the registry entry is what stops a failed capture from
    blocking later captures to the same file, but it also drops the last reference to
    the process, so anything still running at that point could never be stopped again.
    '''
    try:
        if capture_proc.is_alive():
            capture_proc.terminate()
            capture_proc.join(8)
    finally:
        del capture_procs[filename]


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
    try:
        p.start()
    except Exception:
        # A capture that never started must not stay registered, otherwise the next
        # attempt to capture to this file fails with 'duplicate capture' instead of
        # the real reason. Make sure the process is not left running either.
        _release_capture(filename, p)
        raise


def stop_capture(filename):
    if filename is None:
        raise Exception('Filename for capturing cannot be None')
    if filename not in capture_procs:
        raise Exception('Capture \'{}\'was never started'.format(filename))

    t = capture_procs[filename]
    # Release the capture whatever happens below. Leaving a failed capture registered
    # makes every later start_capture for the same file fail with 'Trying to start
    # duplicate capture', so a single genuine failure turns into a string of
    # unrelated ones in the tests that follow.
    try:
        t.stop()
        t.join(1)
        if t.is_alive():
            print(f"Capturing process {filename} is still alive")
            t.terminate()
            t.join(8)  # wait for capture process to terminate

        if t.exitcode != 0:
            raise Exception("Capture '{}': process exited abnormally ({}){}"
                            .format(filename, t.exitcode, _reported_failure(t)))
    finally:
        _release_capture(filename, t)


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

    # As in stop_capture, the capture has to be released even when the teardown fails.
    try:
        t.join(timeout)

        if t.is_alive():
            timedout = True

        t.stop()
        t.join(1)

        if t.is_alive():
            t.terminate()
            t.join(8)  # wait for capture process to terminate

        if t.exitcode != 0:
            raise Exception("Capture '{}': process exited abnormally ({}){}"
                            .format(filename, t.exitcode, _reported_failure(t)))
    finally:
        _release_capture(filename, t)

    return timedout
