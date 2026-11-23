"""Runs the pytest suite in a subprocess and keeps track of its progress."""
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime

UI_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(UI_DIR)
SRC_DIR = os.path.join(PROJECT_DIR, "src")
OUTPUT_DIR = os.path.join(PROJECT_DIR, "output")
CONFIG_FILE = os.path.join(SRC_DIR, "configuration.py")
CAPTURE_EXTENSIONS = (".pcap", ".pcapng")
MAX_LOG_LINES = 20000


def _pytest_env(run_dir, events_file):
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(p for p in (UI_DIR, env.get("PYTHONPATH")) if p)
    env["PYTHONUNBUFFERED"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    env["IGMP_UI_EVENTS"] = events_file
    env["IGMP_UI_RUN_DIR"] = run_dir
    env["IGMP_UI_OUTPUT_DIR"] = OUTPUT_DIR
    return env


def _popen_kwargs():
    if sys.platform.startswith("win"):
        return {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
    return {"start_new_session": True}


def _read_events(path):
    events = []
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        events.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
    return events


def collect_tests():
    """Ask pytest which tests exist, with their docstrings. Returns (tests, error)."""
    with tempfile.TemporaryDirectory() as tmp:
        events_file = os.path.join(tmp, "events.jsonl")
        env = _pytest_env("", events_file)
        env.pop("IGMP_UI_RUN_DIR")
        proc = subprocess.run(
            [sys.executable, "-m", "pytest", "--collect-only", "-q", "--color=no",
             "-p", "igmp_ui_plugin", "-p", "no:cacheprovider", "src"],
            cwd=PROJECT_DIR, env=env, capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=120)
        events = _read_events(events_file)
    tests = next((e["tests"] for e in events if e["type"] == "collected"), [])
    errors = [e["longrepr"] for e in events if e["type"] == "collect_error"]
    error = None
    if errors or (proc.returncode not in (0, 5) and not tests):
        error = "\n\n".join(errors) or (proc.stdout + proc.stderr).strip()
    return tests, error


def list_runs():
    runs = []
    if not os.path.isdir(OUTPUT_DIR):
        return runs
    for name in sorted(os.listdir(OUTPUT_DIR), reverse=True):
        summary = os.path.join(OUTPUT_DIR, name, "summary.json")
        if os.path.isfile(summary):
            try:
                with open(summary, encoding="utf-8") as f:
                    data = json.load(f)
                runs.append({k: data.get(k) for k in
                             ("id", "status", "started", "ended", "counts", "exit_code")})
            except (OSError, json.JSONDecodeError):
                pass
    return runs


def load_run(run_id):
    path = os.path.join(OUTPUT_DIR, os.path.basename(run_id), "summary.json")
    with open(path, encoding="utf-8") as f:
        return json.load(f)


class TestRun:
    def __init__(self, selection, known_tests):
        self.id = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.dir = os.path.join(OUTPUT_DIR, self.id)
        suffix = 1
        while os.path.exists(self.dir):
            suffix += 1
            self.dir = os.path.join(OUTPUT_DIR, f"{self.id}_{suffix}")
        self.id = os.path.basename(self.dir)
        os.makedirs(self.dir)

        self.events_file = os.path.join(self.dir, "events.jsonl")
        self.log_file = os.path.join(self.dir, "console.log")
        self.junit_file = os.path.join(self.dir, "result.junit")
        self.selection = list(selection)
        self.status = "starting"
        self.started = time.time()
        self.ended = None
        self.exit_code = None
        self.prompt = None
        self.current = None
        self.collect_errors = []
        self.log = []
        self.log_dropped = 0
        self.lock = threading.Lock()
        self.stop_requested = False
        known = {t["nodeid"]: t for t in known_tests}
        self.tests = {}
        for nodeid in self.selection:
            self.tests[nodeid] = self._new_test(known.get(nodeid, {"nodeid": nodeid}))
        self.proc = None
        self._events_pos = 0

    @staticmethod
    def _new_test(info):
        test = {"nodeid": info["nodeid"], "name": info.get("name", info["nodeid"].split("::")[-1]),
                "file": info.get("file", info["nodeid"].split("::")[0]),
                "summary": info.get("summary", ""), "details": info.get("details", ""),
                "status": "pending", "duration": None, "message": "", "longrepr": "",
                "output": "", "warnings": [], "pcaps": [], "started": None, "progress": None}
        return test

    # ------------------------------------------------------------------ control
    def start(self):
        args = [sys.executable, "-m", "pytest", "-v", "--color=no", "-o", "log_cli=True",
                "-p", "igmp_ui_plugin", "-p", "no:cacheprovider",
                f"--junit-xml={self.junit_file}"] + self.selection
        self.log.append(f"$ {' '.join(args[1:])}")
        self.proc = subprocess.Popen(
            args, cwd=PROJECT_DIR, env=_pytest_env(self.dir, self.events_file),
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, encoding="utf-8", errors="replace", bufsize=1, **_popen_kwargs())
        self.status = "running"
        threading.Thread(target=self._read_output, daemon=True).start()
        threading.Thread(target=self._watch, daemon=True).start()

    def stop(self):
        self.stop_requested = True
        proc = self.proc
        if not proc or proc.poll() is not None:
            return
        self._append_log("[igmp-ui] Stopping test run...")
        if sys.platform.startswith("win"):
            # /T also ends the capture processes started by the tests
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                           capture_output=True)
        else:
            try:
                os.killpg(proc.pid, signal.SIGTERM)
                proc.wait(5)
            except (ProcessLookupError, subprocess.TimeoutExpired):
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass

    def answer_prompt(self, prompt_id):
        with self.lock:
            if not self.prompt or self.prompt["id"] != prompt_id:
                return False
        tmp = os.path.join(self.dir, f"prompt_{prompt_id}.tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            f.write("")
        os.replace(tmp, os.path.join(self.dir, f"prompt_{prompt_id}.answer"))
        return True

    # ------------------------------------------------------------------ monitoring
    def _append_log(self, line):
        with self.lock:
            self.log.append(line)
            if len(self.log) > MAX_LOG_LINES:
                drop = len(self.log) - MAX_LOG_LINES
                del self.log[:drop]
                self.log_dropped += drop

    def _read_output(self):
        with open(self.log_file, "w", encoding="utf-8") as log:
            for line in self.proc.stdout:
                line = line.rstrip("\n")
                log.write(line + "\n")
                log.flush()
                self._append_log(line)

    def _watch(self):
        while self.proc.poll() is None:
            self._process_events()
            time.sleep(0.3)
        time.sleep(0.5)  # let the output reader drain
        self._process_events()
        self._finish()

    def _process_events(self):
        if not os.path.exists(self.events_file):
            return
        with open(self.events_file, "rb") as f:
            f.seek(self._events_pos)
            chunk = f.read()
        # only consume complete lines
        end = chunk.rfind(b"\n")
        if end < 0:
            return
        self._events_pos += end + 1
        for line in chunk[:end + 1].decode("utf-8", errors="replace").splitlines():
            try:
                self._handle(json.loads(line))
            except (json.JSONDecodeError, KeyError):
                pass

    def _handle(self, ev):  # noqa: C901
        with self.lock:
            kind = ev["type"]
            if kind == "collected":
                # use pytest's order; keep the selected tests that were found
                ordered = {}
                for info in ev["tests"]:
                    old = self.tests.get(info["nodeid"])
                    test = old or self._new_test(info)
                    test.update({k: info[k] for k in ("name", "file", "summary", "details")})
                    ordered[info["nodeid"]] = test
                for nodeid, test in self.tests.items():
                    if nodeid not in ordered:
                        test["status"] = "not found"
                        ordered[nodeid] = test
                self.tests = ordered
            elif kind == "collect_error":
                self.collect_errors.append(ev["longrepr"])
            elif kind == "test_start":
                test = self.tests.setdefault(ev["nodeid"], self._new_test({"nodeid": ev["nodeid"]}))
                test["status"] = "running"
                test["started"] = ev["time"]
                self.current = ev["nodeid"]
            elif kind == "test_end":
                test = self.tests.setdefault(ev["nodeid"], self._new_test({"nodeid": ev["nodeid"]}))
                test.update({k: ev[k] for k in
                             ("duration", "message", "longrepr", "output", "pcaps")})
                test["status"] = ev["outcome"]
                test["progress"] = None
                self.current = None
            elif kind == "progress":
                test = self.tests.get(self.current)
                if test is not None:
                    test["progress"] = {k: ev[k] for k in
                                        ("index", "steps", "label", "step_seconds",
                                         "done_seconds", "total_seconds", "time")}
            elif kind == "test_warning":
                test = self.tests.get(ev["nodeid"])
                if test is not None and ev["message"] not in test["warnings"]:
                    test["warnings"].append(ev["message"])
            elif kind == "prompt":
                self.prompt = {"id": ev["id"], "text": ev["text"], "nodeid": ev.get("nodeid")}
            elif kind == "prompt_done":
                if self.prompt and self.prompt["id"] == ev["id"]:
                    self.prompt = None

    def _finish(self):  # noqa: C901
        self.exit_code = self.proc.returncode
        self.ended = time.time()
        # Pick up captures of a test that was interrupted before it could move them.
        leftovers = []
        if os.path.isdir(OUTPUT_DIR):
            for name in os.listdir(OUTPUT_DIR):
                src = os.path.join(OUTPUT_DIR, name)
                if os.path.isfile(src) and name.lower().endswith(CAPTURE_EXTENSIONS) \
                        and os.path.getmtime(src) >= self.started - 1:
                    try:
                        shutil.move(src, os.path.join(self.dir, name))
                        leftovers.append(name)
                    except OSError:
                        pass
        with self.lock:
            self.prompt = None
            for test in self.tests.values():
                if test["status"] == "running":
                    test["status"] = "stopped" if self.stop_requested else "error"
                    test["pcaps"] = sorted(set(test["pcaps"]) | set(leftovers))
                    if not self.stop_requested:
                        test["message"] = "pytest ended while this test was running"
                elif test["status"] == "pending":
                    test["status"] = "not run"
            self.current = None
            if self.stop_requested:
                self.status = "stopped"
            elif self.exit_code in (0, 1):
                self.status = "finished"
            else:
                self.status = "error"
                if not any(t["status"] in ("passed", "failed", "error", "skipped")
                           for t in self.tests.values()) and not self.collect_errors:
                    # pytest gave up before running anything; show why
                    self.collect_errors.append("pytest exited with code {} before running any "
                                               "test:\n\n{}".format(self.exit_code,
                                                                    "\n".join(self.log[-40:])))
        try:
            with open(os.path.join(self.dir, "summary.json"), "w", encoding="utf-8") as f:
                json.dump(self.snapshot(log_from=None), f, indent=2)
        except OSError as e:
            self._append_log(f"[igmp-ui] Could not write summary: {e}")

    # ------------------------------------------------------------------ reporting
    def counts(self):
        counts = {}
        for test in self.tests.values():
            counts[test["status"]] = counts.get(test["status"], 0) + 1
        return counts

    def snapshot(self, log_from=0):
        with self.lock:
            data = {
                "id": self.id,
                "dir": self.dir,
                "status": self.status,
                "started": self.started,
                "ended": self.ended,
                "exit_code": self.exit_code,
                "current": self.current,
                "prompt": self.prompt,
                "collect_errors": self.collect_errors,
                "tests": list(self.tests.values()),
                "counts": self.counts(),
                "has_junit": os.path.exists(self.junit_file),
            }
            if log_from is not None:
                start = max(0, min(log_from - self.log_dropped, len(self.log)))
                data["log"] = self.log[start:]
                data["log_next"] = self.log_dropped + len(self.log)
            return data

    @property
    def active(self):
        return self.status in ("starting", "running")
