"""pytest plugin used by the IGMP Tester UI.

It is loaded with `-p igmp_ui_plugin` by the UI server and does three things:

* it writes machine readable events (collection, test start, test result, prompts)
  as JSON lines to the file named by IGMP_UI_EVENTS, so the UI can show progress;
* it replaces `input()` so the manual tests ask the operator through the UI instead
  of the terminal. The answer is handed back through a file in the run directory;
* after each test it moves the capture files that test wrote to `output/` into the
  run directory, so every run keeps its own pcaps and each result links to them.

Nothing here changes how the tests themselves behave.
"""
import builtins
import json
import os
import shutil
import time

EVENTS_FILE = os.environ.get("IGMP_UI_EVENTS")
RUN_DIR = os.environ.get("IGMP_UI_RUN_DIR")
OUTPUT_DIR = os.environ.get("IGMP_UI_OUTPUT_DIR")

CAPTURE_EXTENSIONS = (".pcap", ".pcapng")

_state = {
    "current": None,
    "start": 0.0,
    "reports": {},
    "prompt_counter": 0,
}


def _emit(event_type, **data):
    if not EVENTS_FILE:
        return
    data["type"] = event_type
    data["time"] = time.time()
    with open(EVENTS_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(data, default=str) + "\n")
        f.flush()


def _ui_input(prompt=""):
    """Replacement for input(): ask the operator through the UI and wait for the answer."""
    _state["prompt_counter"] += 1
    prompt_id = _state["prompt_counter"]
    answer_file = os.path.join(RUN_DIR, f"prompt_{prompt_id}.answer")
    _emit("prompt", id=prompt_id, nodeid=_state["current"], text=str(prompt).strip())
    print(f"[waiting for operator] {str(prompt).strip()}")
    while not os.path.exists(answer_file):
        time.sleep(0.2)
    # The UI writes to a temporary name and renames, so the file is complete here.
    with open(answer_file, encoding="utf-8") as f:
        answer = f.read()
    _emit("prompt_done", id=prompt_id)
    print("[operator continued]")
    return answer


def _first_doc_line(item):
    doc = getattr(getattr(item, "obj", None), "__doc__", None) or ""
    lines = [line.strip() for line in doc.strip().splitlines()]
    return (lines[0] if lines else ""), "\n".join(lines[1:]).strip()


def _move_new_captures(since):
    """Move capture files written to output/ since `since` into the run directory."""
    moved = []
    if not (OUTPUT_DIR and RUN_DIR) or not os.path.isdir(OUTPUT_DIR):
        return moved
    for name in sorted(os.listdir(OUTPUT_DIR)):
        src = os.path.join(OUTPUT_DIR, name)
        if not (os.path.isfile(src) and name.lower().endswith(CAPTURE_EXTENSIONS)):
            continue
        try:
            if os.path.getmtime(src) < since - 1:
                continue  # an older file, e.g. a pcap configured as PCAP_FILE
            dst = os.path.join(RUN_DIR, name)
            if os.path.exists(dst):
                os.remove(dst)
            shutil.move(src, dst)
            moved.append(name)
        except OSError as e:
            print(f"[igmp-ui] could not move capture {src}: {e}")
    return moved


def pytest_configure(config):
    if RUN_DIR and EVENTS_FILE:
        builtins.input = _ui_input


def pytest_collection_finish(session):
    tests = []
    for item in session.items:
        summary, details = _first_doc_line(item)
        tests.append({
            "nodeid": item.nodeid,
            "name": item.name,
            "file": item.location[0],
            "summary": summary,
            "details": details,
        })
    _emit("collected", tests=tests)


def pytest_collectreport(report):
    if report.failed:
        _emit("collect_error", nodeid=report.nodeid, longrepr=str(report.longrepr))


def pytest_runtest_logstart(nodeid, location):
    _state["current"] = nodeid
    _state["start"] = time.time()
    _state["reports"][nodeid] = []
    _emit("test_start", nodeid=nodeid)


def pytest_runtest_logreport(report):
    _state["reports"].setdefault(report.nodeid, []).append(report)


def pytest_warning_recorded(warning_message, when, nodeid, location):
    # pytest reports a test's warnings after pytest_runtest_logfinish, so they are sent
    # as a separate event that the UI attaches to the test.
    if nodeid:
        _emit("test_warning", nodeid=nodeid, message=str(warning_message.message))


def _skip_reason(report):
    longrepr = report.longrepr
    if isinstance(longrepr, tuple) and len(longrepr) == 3:
        return str(longrepr[2]).replace("Skipped: ", "")
    return str(longrepr)


def _short_message(report):
    crash = getattr(report.longrepr, "reprcrash", None)
    if crash is not None:
        return crash.message
    text = str(report.longrepr).strip().splitlines()
    return text[-1] if text else ""


def pytest_runtest_logfinish(nodeid, location):
    reports = _state["reports"].pop(nodeid, [])
    outcome, message, longrepr = "passed", "", ""
    duration = 0.0
    output = []
    for rep in reports:
        duration += rep.duration
        for title, content in rep.sections:
            if content.strip():
                output.append(f"----- {title} -----\n{content.rstrip()}")
        if rep.skipped and outcome == "passed":
            outcome, message = "skipped", _skip_reason(rep)
        elif rep.failed:
            if outcome in ("passed", "skipped"):
                outcome = "failed" if rep.when == "call" else "error"
                message = _short_message(rep)
                longrepr = str(rep.longrepr)

    pcaps = _move_new_captures(_state["start"])
    _emit("test_end",
          nodeid=nodeid,
          outcome=outcome,
          duration=round(duration, 2),
          message=message,
          longrepr=longrepr,
          output="\n".join(output),
          pcaps=pcaps)
    _state["current"] = None


def pytest_sessionfinish(session, exitstatus):
    _emit("session_end", exitstatus=int(exitstatus))
