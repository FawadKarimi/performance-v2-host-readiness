"""Separately reviewed, fail-closed transport for seven literal metadata GETs.

No index, artifact client, proxy, redirect, retry or address fallback exists here.
Construction and each open require an independent sidecar admission grant.  The
proposal's authorization flags remain false.  Parent-process termination is
required to bound blocking platform DNS, TLS and cancellation behavior.
"""
from __future__ import annotations

import copy
import re
import socket
import ssl
import threading
import time
from urllib.parse import urlsplit

HOST = 'files.pythonhosted.org'
HEADER_BYTE_CAP = 16384  # Additional conservative transport review bound.
PER_BODY_CAP = 262144
TOTAL_BODY_CAP = 1835008
URLS = (
    'https://files.pythonhosted.org/packages/5b/2a/4b1ea3f2180be251a5cff1e70c8a5b7994ffa5c8eab8937901f8a9db58fe/filelock-4.0.10-py3-none-any.whl.metadata',
    'https://files.pythonhosted.org/packages/fd/3c/6a2bf344106328fd04963664a60b9bb6496fc25df8e962fcdc1367285fb9/fsspec-2026.7.0-py3-none-any.whl.metadata',
    'https://files.pythonhosted.org/packages/62/a1/3d680cbfd5f4b8f15abc1d571870c5fc3e594bb582bc3b64ea099db13e56/jinja2-3.1.6-py3-none-any.whl.metadata',
    'https://files.pythonhosted.org/packages/7e/cd/fe58041e9011f307c490e3e17dd48cc516448f7c698a3f2d9d9d65d7e6a8/networkx-3.7-py3-none-any.whl.metadata',
    'https://files.pythonhosted.org/packages/95/9c/c510029fc6ef33a6275cd2c5d3cecd6613dfd6aa401d57c54f1c18852ccf/setuptools-84.0.0-py3-none-any.whl.metadata',
    'https://files.pythonhosted.org/packages/a2/09/77d55d46fd61b4a135c444fc97158ef34a095e5681d0a6c10b75bf356191/sympy-1.14.0-py3-none-any.whl.metadata',
    'https://files.pythonhosted.org/packages/49/d3/b8441a820a491ddfc024b0b0cf0393375b75ea13866d9c66727e54c2fc80/typing_extensions-4.16.0-py3-none-any.whl.metadata',
)
EXPECTED_HEADERS = {'Accept': 'text/plain', 'Accept-Encoding': 'identity'}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def _validate(proposal):
    # Lazy import permits offline, injected-transport tests without admission.
    from sidecar_contract import validate_proposal
    validate_proposal(proposal)


def _authorize(proposal, grant):
    from sidecar_admission import authorize_network
    authorize_network(proposal, grant)


def _resolve(budget):
    """One DNS lookup; the caller's 20-second request deadline bounds waiting.

    A stuck OS resolver cannot be cancelled portably.  Its daemon may continue
    until worker exit but cannot connect or issue GETs.  There is no retry or
    address fallback, and parent termination remains an aggregate backstop.
    """
    done = threading.Event()
    result = {}
    def lookup():
        try:
            result['addresses'] = socket.getaddrinfo(HOST, 443, type=socket.SOCK_STREAM,
                                                     proto=socket.IPPROTO_TCP)
        except BaseException as exc:
            result['error'] = exc
        finally:
            done.set()
    thread = threading.Thread(target=lookup, daemon=True)
    thread.start()
    if not done.wait(timeout=budget.remaining()):
        raise TimeoutError('DNS per-request deadline exceeded')
    budget.remaining()
    if 'error' in result:
        raise result['error']
    return result['addresses']


class Budget:
    """One aggregate deadline and a fresh, non-extensible deadline per attempt."""

    def __init__(self, proposal, clock=time.monotonic):
        b = proposal['bounded_transport']
        require(b['per_response_byte_cap'] == PER_BODY_CAP and
                b['aggregate_response_byte_cap'] == TOTAL_BODY_CAP and
                b['per_request_timeout_seconds'] == 20 and
                b['aggregate_deadline_seconds'] == 120 and
                b['exact_get_count'] == b['max_attempts'] == 7,
                'sidecar budget differs from frozen bounds')
        self.clock = clock
        self.bounds = copy.deepcopy(b)
        self.end = clock() + 120
        self.request_end = None
        self.total = 0
        self.calls = 0

    def start(self):
        # Previous request's deadline does not prevent a later request, but the
        # collector must stop on any previous error; no automatic retry exists.
        now = self.clock()
        if now >= self.end:
            raise TimeoutError('aggregate deadline exceeded')
        require(self.calls < 7, 'request count exceeded')
        self.calls += 1
        self.request_end = min(now + 20, self.end)
        return self.remaining()

    def remaining(self):
        now = self.clock()
        if now >= self.end:
            raise TimeoutError('aggregate deadline exceeded')
        if self.request_end is not None and now >= self.request_end:
            raise TimeoutError('per-request deadline exceeded')
        return min(20, self.end - now,
                   self.request_end - now if self.request_end is not None else 20)

    def account(self, n):
        # Deliberately no clock check: caller first persists bytes already read,
        # then checks remaining(), so a timeout cannot discard that last chunk.
        require(type(n) is int and n >= 0, 'invalid byte accounting')
        require(self.total + n <= TOTAL_BODY_CAP, 'aggregate body limit exceeded')
        self.total += n

    def remaining_body_capacity(self, current_body_bytes):
        require(type(current_body_bytes) is int and
                0 <= current_body_bytes <= PER_BODY_CAP,
                'invalid response byte count')
        return min(PER_BODY_CAP - current_body_bytes, TOTAL_BODY_CAP - self.total)


class WireResponse:
    """Unbuffered HTTP/1.x framing retaining raw, bounded header evidence."""

    def __init__(self, sock, url, budget):
        self.sock = sock
        self.final_url = url
        self.budget = budget
        self.body_bytes = 0
        raw = bytearray()
        try:
            while not raw.endswith(b'\r\n\r\n'):
                require(len(raw) < HEADER_BYTE_CAP, 'header limit exceeded')
                sock.settimeout(budget.remaining())
                chunk = sock.recv(1)
                require(len(chunk) <= 1, 'socket returned excess header bytes')
                raw.extend(chunk)
                budget.remaining()
                require(chunk, 'truncated HTTP headers')
            self.raw_headers = bytes(raw)
            lines = self.raw_headers.decode('iso-8859-1').split('\r\n')
            match = re.fullmatch(r'HTTP/1\.[01] ([0-9]{3})(?: [^\r\n]*)?', lines[0])
            require(match is not None, 'malformed HTTP status')
            require(all(32 <= ord(c) < 127 for c in lines[0]), 'invalid HTTP status text')
            self.status = int(match[1])
            self.headers = []
            for line in lines[1:-2]:
                require(':' in line and not line.startswith((' ', '\t')),
                        'malformed/folded header')
                name, value = line.split(':', 1)
                require(re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name) is not None,
                        'invalid header name')
                require(all((ord(c) >= 32 and ord(c) != 127) or c == '\t' for c in value),
                        'invalid header value')
                self.headers.append((name, value.strip()))
        except BaseException as exc:
            # Includes timeout/cancellation: outer collector can persist the
            # received prefix even when a usable response object was not made.
            exc.partial_response_header_bytes = bytes(raw)
            exc.response_url = url
            raise

    def read(self, n):
        require(type(n) is int and n > 0, 'positive bounded read required')
        require(n <= self.budget.remaining_body_capacity(self.body_bytes),
                'read exceeds remaining body cap')
        self.sock.settimeout(self.budget.remaining())
        chunk = self.sock.recv(n)
        require(isinstance(chunk, bytes) and len(chunk) <= n, 'invalid socket read')
        self.body_bytes += len(chunk)
        # No deadline exception after recv: persist these bytes before checking
        # the clock.  The next IO still checks the deadline before touching wire.
        return chunk

    def close(self):
        self.sock.close()


class TLSMetadataTransport:
    def __init__(self, proposal, grant=None):
        _validate(proposal)
        _authorize(proposal, grant)
        self.proposal = copy.deepcopy(proposal)
        self.grant = grant
        self.attempted = set()
        self.failed = False

    def open(self, method, url, headers, budget):
        _validate(self.proposal)
        _authorize(self.proposal, self.grant)
        require(not self.failed, 'transport stopped after failure')
        require(method == 'GET' and url in URLS, 'unapproved URL/method')
        request = next((r for r in self.proposal['requests'] if r['url'] == url), None)
        require(request is not None and request['method'] == method and
                request['headers'] == headers == EXPECTED_HEADERS,
                'unapproved request headers')
        require(url not in self.attempted and len(self.attempted) < 7,
                'duplicate request/retry or request limit exceeded')
        require(budget.request_end is not None and budget.calls == len(self.attempted) + 1,
                'collector must start exactly one budget attempt before open')
        self.attempted.add(url)
        plain = sock = None
        try:
            budget.remaining()
            context = ssl.create_default_context()
            require(context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED,
                    'TLS verification disabled')
            budget.remaining()
            # Deliberately no create_connection() address iteration/fallback.
            # Only waiting for the one daemon DNS lookup is deadline-bounded;
            # a timed-out resolver thread can never initiate a connection.
            addresses = _resolve(budget)
            budget.remaining()
            require(addresses, 'DNS returned no address')
            family, kind, proto, _, address = addresses[0]
            require(family in (socket.AF_INET, socket.AF_INET6) and
                    kind == socket.SOCK_STREAM and proto == socket.IPPROTO_TCP,
                    'unsupported DNS address family/type')
            plain = socket.socket(family, kind, proto)
            plain.settimeout(budget.remaining())
            plain.connect(address)
            budget.remaining()
            plain.settimeout(budget.remaining())
            sock = context.wrap_socket(plain, server_hostname=HOST)
            budget.remaining()
            sock.settimeout(budget.remaining())
            path = urlsplit(url).path
            wire = (f'GET {path} HTTP/1.1\r\nHost: {HOST}\r\n'
                    'Accept: text/plain\r\nAccept-Encoding: identity\r\n'
                    'Connection: close\r\n\r\n').encode('ascii')
            sock.sendall(wire)
            budget.remaining()
            return WireResponse(sock, url, budget)
        except BaseException:
            self.failed = True
            if sock is not None:
                sock.close()
            elif plain is not None:
                plain.close()
            raise


def validate_headers(response, url, proposal):
    """Conservative compatibility: no chunking, duplicate headers or redirects.

    Content-Type may be absent, text/plain or application/octet-stream with an
    optional utf-8/us-ascii charset.  The pinned body SHA, checked before parsing,
    remains authoritative.  Unexpected MIME/framing is a failure, never fallback.
    """
    require(url in URLS and response.final_url == url, 'final URL mismatch')
    require(response.status == 200, 'unexpected HTTP status; redirects forbidden')
    headers = {}
    total = 0
    for key, value in response.headers:
        require(isinstance(key, str) and isinstance(value, str), 'invalid HTTP header type')
        require(re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", key) is not None,
                'invalid header name')
        require(all((ord(c) >= 32 and ord(c) != 127) or c == '\t' for c in value),
                'invalid header value')
        total += len(key.encode('utf-8')) + len(value.encode('utf-8')) + 4
        require(total <= HEADER_BYTE_CAP, 'header limit exceeded')
        key = key.lower()
        require(key not in headers, 'duplicate HTTP header')
        headers[key] = value.strip()
    content_type = headers.get('content-type')
    if content_type is not None:
        require(re.fullmatch(r'(?:text/plain|application/octet-stream)(?:\s*;\s*charset=(?:utf-8|us-ascii))?',
                             content_type, re.I) is not None,
                'unsupported metadata content type')
    require(headers.get('content-encoding', 'identity').lower() == 'identity',
            'content encoding refused')
    require('transfer-encoding' not in headers, 'transfer encoding unsupported; no fallback')
    size = None
    if 'content-length' in headers:
        require(re.fullmatch(r'[0-9]+', headers['content-length']) is not None,
                'invalid Content-Length')
        size = int(headers['content-length'])
        require(size <= proposal['bounded_transport']['per_response_byte_cap'] == PER_BODY_CAP,
                'oversized Content-Length')
    return size
