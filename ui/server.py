"""IGMP Tester UI

A small local web interface around the pytest based IGMP test suite. Run it from the
project directory, with the same (elevated) privileges you would use for pytest:

    python ui/server.py [--port 8080] [--no-browser]

Only the Python standard library is needed on top of the test suite's own requirements.
The server listens on 127.0.0.1 only.
"""
import argparse
import json
import mimetypes
import os
import subprocess
import sys
import threading
import webbrowser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, unquote, parse_qs

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import config_editor  # noqa: E402
import runner  # noqa: E402

STATIC_DIR = os.path.join(runner.UI_DIR, "static")


class State:
    lock = threading.Lock()
    run_lock = threading.Lock()
    run = None
    tests = None
    tests_error = None


def is_admin():
    try:
        if sys.platform.startswith("win"):
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:
        return None


def list_interfaces():
    try:
        import psutil
    except ImportError:
        return None
    import socket
    stats = psutil.net_if_stats()
    addrs = psutil.net_if_addrs()
    result = []
    for name in sorted(stats):
        ipv4 = [a.address for a in addrs.get(name, []) if a.family == socket.AF_INET]
        mac = next((a.address for a in addrs.get(name, []) if a.family == psutil.AF_LINK), "")
        result.append({"name": name, "up": stats[name].isup, "ipv4": ipv4, "mac": mac,
                       "speed": stats[name].speed})
    return result


def get_tests(refresh=False):
    with State.lock:
        if State.tests is None or refresh:
            State.tests, State.tests_error = runner.collect_tests()
        return State.tests, State.tests_error


def safe_output_path(rel):
    """Resolve a path inside output/, refusing anything that escapes it."""
    base = os.path.realpath(runner.OUTPUT_DIR)
    path = os.path.realpath(os.path.join(base, rel or ""))
    if path != base and not path.startswith(base + os.sep):
        raise PermissionError(rel)
    return path


def open_with_os(path):
    if sys.platform.startswith("win"):
        os.startfile(path)  # noqa: S606 - local file chosen by the operator
    elif sys.platform == "darwin":
        subprocess.Popen(["open", path])
    else:
        subprocess.Popen(["xdg-open", path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


class Handler(BaseHTTPRequestHandler):
    server_version = "IGMPTesterUI/1.0"

    def log_message(self, fmt, *args):
        pass  # keep the terminal quiet; polling would flood it

    # ------------------------------------------------------------------ helpers
    def _send_json(self, data, status=HTTPStatus.OK):
        body = json.dumps(data, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _error(self, message, status=HTTPStatus.BAD_REQUEST, **extra):
        self._send_json({"error": message, **extra}, status)

    def _send_file(self, path, download=False):
        ctype = mimetypes.guess_type(path)[0] or "application/octet-stream"
        if path.lower().endswith((".pcap", ".pcapng", ".junit", ".jsonl", ".log")):
            ctype = "application/octet-stream" if download else "text/plain; charset=utf-8"
        with open(path, "rb") as f:
            body = f.read()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        if download:
            self.send_header("Content-Disposition",
                             f'attachment; filename="{os.path.basename(path)}"')
        self.end_headers()
        self.wfile.write(body)

    def _host_ok(self):
        # Guards against DNS rebinding: only answer requests addressed to localhost.
        host = (self.headers.get("Host") or "").rsplit(":", 1)[0].strip("[]")
        return host in ("127.0.0.1", "localhost", "::1")

    def _read_json(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length > 1_000_000:
            raise ValueError("request too large")
        raw = self.rfile.read(length) if length else b"{}"
        return json.loads(raw or b"{}")

    # ------------------------------------------------------------------ GET
    def do_GET(self):  # noqa: C901
        if not self._host_ok():
            return self._error("forbidden host", HTTPStatus.FORBIDDEN)
        url = urlparse(self.path)
        path = url.path
        query = parse_qs(url.query)

        if path == "/" or path.startswith("/static/"):
            name = "index.html" if path == "/" else path[len("/static/"):]
            file = os.path.realpath(os.path.join(STATIC_DIR, unquote(name)))
            if not file.startswith(os.path.realpath(STATIC_DIR) + os.sep) or not os.path.isfile(file):
                return self._error("not found", HTTPStatus.NOT_FOUND)
            return self._send_file(file)

        if path.startswith("/files/"):
            try:
                file = safe_output_path(unquote(path[len("/files/"):]))
            except PermissionError:
                return self._error("forbidden", HTTPStatus.FORBIDDEN)
            if not os.path.isfile(file):
                return self._error("not found", HTTPStatus.NOT_FOUND)
            return self._send_file(file, download="download" in query)

        if path == "/api/status":
            return self._send_json({
                "admin": is_admin(),
                "platform": sys.platform,
                "python": sys.version.split()[0],
                "project_dir": runner.PROJECT_DIR,
                "output_dir": runner.OUTPUT_DIR,
                "running": bool(State.run and State.run.active),
            })

        if path == "/api/tests":
            tests, error = get_tests(refresh="refresh" in query)
            return self._send_json({"tests": tests, "error": error})

        if path == "/api/run":
            run = State.run
            if not run:
                return self._send_json({"run": None})
            log_from = int(query.get("log_from", ["0"])[0])
            return self._send_json({"run": run.snapshot(log_from=log_from)})

        if path == "/api/runs":
            return self._send_json({"runs": runner.list_runs()})

        if path.startswith("/api/runs/"):
            run_id = path[len("/api/runs/"):]
            if State.run and State.run.id == run_id:
                return self._send_json({"run": State.run.snapshot(log_from=None)})
            try:
                return self._send_json({"run": runner.load_run(run_id)})
            except (OSError, json.JSONDecodeError):
                return self._error("run not found", HTTPStatus.NOT_FOUND)

        if path == "/api/config":
            try:
                return self._send_json({"settings": config_editor.load(runner.CONFIG_FILE),
                                        "path": runner.CONFIG_FILE})
            except (OSError, SyntaxError) as e:
                return self._error(f"Could not read {runner.CONFIG_FILE}: {e}")

        if path == "/api/interfaces":
            return self._send_json({"interfaces": list_interfaces()})

        if path == "/api/captures":
            # capture files that can be analysed offline (PCAP_FILE)
            found = []
            for root, _, files in os.walk(runner.OUTPUT_DIR):
                for name in files:
                    if name.lower().endswith(runner.CAPTURE_EXTENSIONS):
                        rel = os.path.relpath(os.path.join(root, name), runner.PROJECT_DIR)
                        found.append(rel.replace(os.sep, "/"))
            return self._send_json({"captures": sorted(found, reverse=True)[:500]})

        return self._error("not found", HTTPStatus.NOT_FOUND)

    # ------------------------------------------------------------------ POST
    def do_POST(self):  # noqa: C901
        if not self._host_ok():
            return self._error("forbidden host", HTTPStatus.FORBIDDEN)
        # A custom header cannot be sent cross-site without a CORS preflight, which this
        # server never approves, so other web pages cannot trigger these actions.
        if self.headers.get("X-IGMP-UI") != "1":
            return self._error("missing header", HTTPStatus.FORBIDDEN)
        try:
            body = self._read_json()
        except (ValueError, json.JSONDecodeError) as e:
            return self._error(f"invalid request: {e}")
        path = urlparse(self.path).path

        if path == "/api/run":
            selection = [str(t) for t in body.get("tests") or []]
            if not selection:
                return self._error("Select at least one test")
            tests, _ = get_tests()
            if tests:
                # pytest aborts the whole run when asked for a test that does not exist
                known = {t["nodeid"] for t in tests}
                selection = [t for t in selection if t in known]
                if not selection:
                    return self._error("None of the selected tests exist any more. "
                                       "Reload the test list.")
            with State.run_lock:
                if State.run and State.run.active:
                    return self._error("A test run is already in progress", HTTPStatus.CONFLICT)
                run = runner.TestRun(selection, tests or [])
                try:
                    run.start()
                except OSError as e:
                    return self._error(f"Could not start pytest: {e}")
                State.run = run
            return self._send_json({"run": run.snapshot()})

        if path == "/api/run/stop":
            if State.run:
                threading.Thread(target=State.run.stop, daemon=True).start()
            return self._send_json({"ok": True})

        if path == "/api/run/prompt":
            ok = bool(State.run and State.run.answer_prompt(body.get("id")))
            return self._send_json({"ok": ok})

        if path == "/api/config":
            try:
                settings = config_editor.save(runner.CONFIG_FILE, body.get("values") or {})
            except config_editor.ConfigError as e:
                return self._error("Some settings are not valid", errors=e.errors)
            except (OSError, SyntaxError) as e:
                return self._error(f"Could not save the configuration: {e}")
            with State.lock:
                State.tests = None  # skip markers and imports may depend on the settings
            return self._send_json({"settings": settings})

        if path == "/api/open":
            try:
                target = safe_output_path(body.get("path", ""))
            except PermissionError:
                return self._error("forbidden", HTTPStatus.FORBIDDEN)
            if not os.path.exists(target):
                return self._error("not found", HTTPStatus.NOT_FOUND)
            if body.get("reveal") and os.path.isfile(target):
                if sys.platform.startswith("win"):
                    subprocess.Popen(["explorer", "/select,", target])
                    return self._send_json({"ok": True, "path": target})
                target = os.path.dirname(target)
            try:
                open_with_os(target)
            except OSError as e:
                return self._error(f"Could not open {target}: {e}", path=target)
            return self._send_json({"ok": True, "path": target})

        return self._error("not found", HTTPStatus.NOT_FOUND)


def main():
    parser = argparse.ArgumentParser(description="IGMP Tester web interface")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--no-browser", action="store_true", help="do not open a browser")
    args = parser.parse_args()

    os.makedirs(runner.OUTPUT_DIR, exist_ok=True)
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    url = f"http://127.0.0.1:{args.port}/"
    print(f"IGMP Tester UI running at {url}  (Ctrl+C to quit)")
    if is_admin() is False:
        print("Note: not running with administrator/root privileges. "
              "Capturing and sending packets will probably fail.")
    if not args.no_browser:
        threading.Timer(0.5, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        if State.run and State.run.active:
            print("Stopping the running test...")
            State.run.stop()
        server.server_close()


if __name__ == "__main__":
    main()
