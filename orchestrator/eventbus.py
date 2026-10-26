"""A tiny in-process event bus for the dashboard's live feed (Phase 6).

The monitor is the only producer: it publishes verdict transitions
(and monitor errors) as they happen. The dashboard's SSE endpoint is
the only consumer: it replays missed events from the ring buffer on
reconnect (EventSource sends Last-Event-ID) and then streams new ones.

Bounded by construction: the buffer holds the newest 200 events, and
waiters wake at most every 25 s (the SSE heartbeat cadence), so a
dead client costs one thread and no memory growth. No persistence:
a dashboard restart replays nothing, and the Health Center history
(the durable record) is what the operator reads back.
"""

import collections
import threading
import time

MAX_EVENTS = 200
HEARTBEAT_SECONDS = 25.0


class EventBus:
    def __init__(self, max_events=MAX_EVENTS):
        self._events = collections.deque(maxlen=max_events)
        self._cond = threading.Condition()
        self._next_id = 1

    def publish(self, event_type, pair_id, verdict, detail=""):
        """Append one event and wake waiters. Returns the event id."""
        with self._cond:
            event = {"id": self._next_id, "ts": time.time(),
                     "type": event_type, "pair_id": pair_id,
                     "verdict": verdict, "detail": detail}
            self._next_id += 1
            self._events.append(event)
            self._cond.notify_all()
            return event["id"]

    def since(self, last_id):
        """Events with an id greater than last_id, oldest first."""
        with self._cond:
            return [e for e in self._events if e["id"] > last_id]

    def wait_since(self, last_id, timeout=HEARTBEAT_SECONDS):
        """Events since last_id, waiting up to `timeout` seconds for at
        least one. Returns [] on timeout (the caller's heartbeat)."""
        deadline = time.time() + timeout
        with self._cond:
            while True:
                found = [e for e in self._events if e["id"] > last_id]
                if found:
                    return found
                remaining = deadline - time.time()
                if remaining <= 0:
                    return []
                self._cond.wait(timeout=remaining)
