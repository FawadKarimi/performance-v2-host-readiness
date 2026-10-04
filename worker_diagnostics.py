"""Bounded diagnostic channel. Never persist raw stderr, argv, env or traceback."""
import json
import threading

MAX_BYTES=16384
MAX_LINE=1024
CODES=frozenset(('parser_missing','parser_layout_rejected','runtime_record_oversized',
 'runtime_record_hash_mismatch','runtime_record_duplicate_key','runtime_record_schema',
 'runtime_scope_rejected','runtime_not_accepted','runtime_review_missing',
 'python_identity_mismatch','parser_identity_mismatch','authorization_hash_mismatch',
 'authorization_rejected','runtime_binding_missing','output_rejected',
 'worker_failure','timeout','process_failure'))

def error_record(exc):
    from runtime_acceptance import RuntimeRejected
    code=exc.code if isinstance(exc,RuntimeRejected) and exc.code in CODES else 'worker_failure'
    # Exact static messages only. Never interpolate exception text.
    safe={'authorization byte hash mismatch':'authorization_hash_mismatch',
          'runtime acceptance binding missing':'runtime_binding_missing',
          'explicit owner/review approval missing':'authorization_rejected',
          'run/attempt/commit/runner identity mismatch':'authorization_rejected',
          'implementation binding mismatch':'authorization_rejected',
          'output exists/replayed run':'output_rejected'}
    if code=='worker_failure':code=safe.get(str(exc),'worker_failure')
    return {'schema':'worker_error_v1','code':code}

class Capture:
    """Drain pipes concurrently; retain only a bounded allowlisted projection.

    Arbitrary output, even valid-looking messages with extra fields, is dropped.
    Overflow is counted; memory stays bounded while the parent enforces timeout.
    """
    def __init__(self,stream):
        self.stream=stream;self.total=0;self.rejected=0;self.records=[];self.complete=False
        self.thread=threading.Thread(target=self._read,daemon=True)
        self.thread.start()
    def _line(self,line):
        try:
            d=json.loads(line)
            if set(d)!={'schema','code'} or d['schema']!='worker_error_v1' or d['code'] not in CODES:raise ValueError()
            if len(self.records)<16:self.records.append(d)
        except Exception:self.rejected+=1
    def _read(self):
        pending=b''
        try:
            while True:
                chunk=self.stream.read(1024)
                if not chunk:break
                previous=self.total;self.total=min(self.total+len(chunk),2**63-1)
                accepted=chunk[:max(0,MAX_BYTES-previous)]
                pending+=accepted
                while b'\n' in pending:
                    line,pending=pending.split(b'\n',1)
                    if len(line)<=MAX_LINE:self._line(line)
                    else:self.rejected+=1
                if len(pending)>MAX_LINE:pending=b'';self.rejected+=1
            if pending:self._line(pending)
            self.complete=True
        except Exception:self.rejected+=1
    def finish(self):
        self.thread.join(timeout=1)
        return {'records':list(self.records),'bytes_observed':self.total,
                'capture_limit_bytes':MAX_BYTES,'overflow':self.total>MAX_BYTES,
                'unrecognized_records':self.rejected,'drain_complete':self.complete,
                'raw_output_retained':False}
