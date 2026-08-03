# server/events.py
"""In-process event hub: engines (worker threads) publish, WebSockets fan out.

The UI is "live" because every job progress tick and every data mutation is
pushed here; the frontend invalidates its queries on receipt instead of
polling. publish() is safe to call from any thread.
"""
import asyncio
import threading


class EventHub:
    def __init__(self):
        self._loop = None
        self._queues = set()
        self._lock = threading.Lock()

    def attach_loop(self, loop):
        self._loop = loop

    def subscribe(self):
        q = asyncio.Queue(maxsize=500)
        with self._lock:
            self._queues.add(q)
        return q

    def unsubscribe(self, q):
        with self._lock:
            self._queues.discard(q)

    def publish(self, event: dict):
        loop = self._loop
        if loop is None or loop.is_closed():
            return
        loop.call_soon_threadsafe(self._fanout, event)

    def _fanout(self, event):
        with self._lock:
            queues = list(self._queues)
        for q in queues:
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                pass       # a stalled socket must not block the workers


hub = EventHub()
