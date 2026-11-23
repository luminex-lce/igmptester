"""Progress reporting for long running tests.

A test announces each of its steps and how long that step is expected to take.
When the suite runs from the UI (ui/server.py), this is shown as a progress bar
with the remaining time. Anywhere else, e.g. plain `python -m pytest`, it does
nothing.

    progress = Progress([12, 7, 7])        # expected duration of each step, in seconds
    for ...:
        progress.step("Query with max response time 10 s")
        ...
"""
import json
import os
import time


class Progress:
    def __init__(self, step_seconds):
        self.step_seconds = [float(s) for s in step_seconds]
        self.total_seconds = sum(self.step_seconds)
        self.index = 0

    def step(self, label):
        """Report that the next step starts now."""
        self.index += 1
        i = min(self.index, len(self.step_seconds)) - 1
        _emit(index=self.index,
              steps=len(self.step_seconds),
              label=label,
              step_seconds=self.step_seconds[i] if self.step_seconds else 0,
              done_seconds=sum(self.step_seconds[:i]),
              total_seconds=self.total_seconds)


def _emit(**data):
    events_file = os.environ.get("IGMP_UI_EVENTS")
    if not events_file:
        return
    data.update(type="progress", time=time.time())
    try:
        with open(events_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(data) + "\n")
    except OSError:
        pass  # progress reporting must never make a test fail
