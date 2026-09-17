"""Source clock choices; filesystem epochs are never reinterpreted as wall time."""
from datetime import datetime, timezone
from zoneinfo import available_timezones

from server import log_parsers


def validate(value):
    value = str(value or '').strip()
    if value in ('auto', 'unknown'):
        return value
    log_parsers.zone(value)
    return value or 'auto'


def fallback(value):
    return '' if value in ('', 'auto', 'unknown', None) else value


def catalogue():
    return {'zones': sorted(available_timezones()), 'default': 'auto'}


def example(raw, selected='auto', recorded_epoch=None):
    epoch = recorded_epoch if recorded_epoch is not None else log_parsers.timestamp(raw, fallback(selected))
    return {'original': raw, 'epoch': epoch,
            'utc': datetime.fromtimestamp(epoch, timezone.utc).isoformat() if epoch is not None else '',
            'basis': 'recorded' if recorded_epoch is not None else 'selected' if fallback(selected) else 'unknown'}
