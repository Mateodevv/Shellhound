"""Bounded event counts, sharing the full timeline's evidence and decisions."""
import math

from server.chain import case_chain


SERIES = ("filesystem_confirmed", "filesystem_pending", "log_confirmed", "log_pending")
INTERVALS = (1, 5, 10, 30, 60, 300, 900, 1800, 3600, 10800, 21600,
             43200, 86400, 259200, 604800, 1209600, 2592000, 7776000, 31536000)


def absolute_time(event):
    value = event.get("epoch")
    return (isinstance(value, (int, float)) and not isinstance(value, bool)
            and math.isfinite(value))


def filter_events(events, *, scope="confirmed", event_source="",
                  from_epoch=None, to_epoch=None):
    """The exact same set a chart segment opens, before any list limit."""
    result = []
    for event in events:
        state = event.get("review_state", "confirmed")
        if scope != "all" and state != scope and not (scope == "confirmed" and state == "context"):
            continue
        if event_source and event["source"] != event_source:
            continue
        if from_epoch is not None or to_epoch is not None:
            # Chart links describe current, absolutely dated evidence only.
            if not absolute_time(event) or not event.get("fresh", True):
                continue
            if from_epoch is not None and event["epoch"] < from_epoch:
                continue
            if to_epoch is not None and event["epoch"] >= to_epoch:
                continue
        result.append(event)
    return sorted(result, key=lambda e: (not absolute_time(e),
                                         e["epoch"] if absolute_time(e) else e["at"], e.get("id", "")))


def aggregate(result, bins=24):
    totals = dict.fromkeys(SERIES, 0)
    output = {"buckets": [], "totals": totals, "span": {"first": None, "last": None},
              "interval": 0, "undated": len(result.get("undated", [])),
              "unavailable": 0, "zone": "UTC"}
    events = {}
    for event in result["events"]:
        if event["source"] not in ("filesystem", "log"):
            if not absolute_time(event):
                output["undated"] += 1
            continue
        if not event.get("fresh", True):
            output["unavailable"] += 1
        elif not absolute_time(event):
            output["undated"] += 1
        else:
            events[event["id"]] = event
    if not events:
        return output
    first = min(e["epoch"] for e in events.values())
    last = max(e["epoch"] for e in events.values())
    if bins == 1:
        # One zero-aligned bucket cannot contain both sides of epoch zero.
        start = math.floor(first)
        step = max(1, math.floor(last) - start + 1)
    else:
        step = INTERVALS[-1]
        for candidate in INTERVALS:
            if math.floor(last / candidate) - math.floor(first / candidate) + 1 <= bins:
                step = candidate
                break
        else:
            while math.floor(last / step) - math.floor(first / step) + 1 > bins:
                step *= 2
        start = math.floor(first / step) * step
    count = math.floor((last - start) / step) + 1
    buckets = [{"start": start + i * step, "end": start + (i + 1) * step,
                **dict.fromkeys(SERIES, 0)} for i in range(count)]
    for event in events.values():
        key = event["source"] + "_" + event["review_state"]
        buckets[int((event["epoch"] - start) // step)][key] += 1
        totals[key] += 1
    output.update(buckets=buckets, interval=step, span={"first": first, "last": last})
    return output


def summarize(case_dir, *, bins=24, muted=()):
    return aggregate(case_chain(case_dir, "en", "utc", event_cap=None,
                                scope="all", muted=muted), bins)
