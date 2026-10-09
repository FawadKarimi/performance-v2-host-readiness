"""Offline UTC serialization/check; never enables approvals or dispatches."""
import datetime as dt
import hashlib
import json
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
import external_review as reviewed

def validate_window(record, now):
    issued = reviewed.utc(record['issued_utc'])
    expires = reviewed.utc(record['expires_utc'])
    if now.tzinfo is None or not issued <= now < expires:
        raise ValueError('inactive_window')
    if not dt.timedelta(0) < expires-issued <= dt.timedelta(minutes=15):
        raise ValueError('window_bound')
    return record

def stamp(record, now, minutes=15):
    if now.tzinfo is None or type(minutes) is not int or not 1 <= minutes <= 15:
        raise ValueError('timestamp_parameters')
    issued = now.astimezone(dt.timezone.utc).replace(microsecond=0)
    result = dict(record)
    result['issued_utc'] = issued.strftime('%Y-%m-%dT%H:%M:%SZ')
    result['expires_utc'] = (issued+dt.timedelta(minutes=minutes)).strftime('%Y-%m-%dT%H:%M:%SZ')
    return validate_window(result, now)

def main():
    mode, source, argument = sys.argv[1:]
    raw = Path(source).read_bytes()
    record = reviewed.decode(raw)
    now = dt.datetime.now(dt.timezone.utc)
    if mode == 'generate':
        # Caller supplies separately reviewed bindings/flags; none are changed here.
        result = stamp(record, now)
        encoded = json.dumps(result, sort_keys=True, separators=(',', ':')).encode()
        validate_window(reviewed.decode(encoded), now)
        with Path(argument).open('xb') as output:
            output.write(encoded)
        print(hashlib.sha256(encoded).hexdigest())
    elif mode == 'check':
        if hashlib.sha256(raw).hexdigest() != argument:
            raise ValueError('activation_hash')
        validate_window(record, now)
        print('exact UTC Z format, current bounded window and digest verified')
    else:
        raise ValueError('mode')

if __name__ == '__main__':
    main()
