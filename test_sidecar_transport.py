"""Offline transport tests: socket creation, DNS and TLS are always mocked."""
import hashlib
import json
from pathlib import Path
import socket
import ssl
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

import sidecar_transport as st


def proposal():
    from sidecar_contract import load_proposal
    return load_proposal(Path(__file__).with_name('sidecar-request-PROPOSED.json'))


class Clock:
    def __init__(self):
        self.now = 0

    def __call__(self):
        return self.now


class FakeSocket:
    def __init__(self, raw=b'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 3\r\n\r\nabc'):
        self.raw = raw
        self.sent = []
        self.timeouts = []
        self.connections = []
        self.closed = False
        self.recv_hook = None
        self.connect_error = None
        self.send_error = None

    def recv(self, n):
        if self.recv_hook:
            self.recv_hook()
        value, self.raw = self.raw[:n], self.raw[n:]
        return value

    def settimeout(self, value):
        self.timeouts.append(value)

    def connect(self, address):
        self.connections.append(address)
        if self.connect_error:
            raise self.connect_error

    def sendall(self, value):
        if self.send_error:
            raise self.send_error
        self.sent.append(value)

    def close(self):
        self.closed = True


class OfflineCase(unittest.TestCase):
    def setUp(self):
        self.p = proposal()
        self.clock = Clock()
        self.b = st.Budget(self.p, self.clock)
        self.sock = FakeSocket()
        self.context = SimpleNamespace(check_hostname=True, verify_mode=ssl.CERT_REQUIRED,
                                       wrap_socket=Mock(return_value=self.sock))
        patches = {
            'dns': patch.object(st.socket, 'getaddrinfo', return_value=[
                (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, '', ('192.0.2.1', 443)),
                (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, '', ('192.0.2.2', 443))]),
            'socket': patch.object(st.socket, 'socket', return_value=self.sock),
            'context': patch.object(st.ssl, 'create_default_context', return_value=self.context),
            'validate': patch.object(st, '_validate'),
            'authorize': patch.object(st, '_authorize'),
            # A regression reverting to this API would fail, never open wire.
            'create_connection': patch.object(st.socket, 'create_connection', side_effect=AssertionError('network forbidden')),
        }
        for name, item in patches.items():
            setattr(self, name + '_mock', item.start())
            self.addCleanup(item.stop)

    def transport(self):
        return st.TLSMetadataTransport(self.p, {'test_only': True})

    def open(self, transport=None, method='GET', url=None, headers=None):
        transport = transport or self.transport()
        self.b.start()
        return transport.open(method, url or st.URLS[0],
                              st.EXPECTED_HEADERS if headers is None else headers, self.b)


class BudgetTests(OfflineCase):
    def test_frozen_bounds_and_exact_attempt_count(self):
        for key, value in [('per_response_byte_cap', 262145), ('aggregate_response_byte_cap', 1835009),
                           ('per_request_timeout_seconds', 21), ('aggregate_deadline_seconds', 121),
                           ('exact_get_count', 8), ('max_attempts', 8)]:
            with self.subTest(key=key):
                p = proposal()
                p['bounded_transport'][key] = value
                with self.assertRaises(ValueError):
                    st.Budget(p, self.clock)
        for _ in range(4):
            self.b.start()
        with self.assertRaisesRegex(ValueError, 'request count'):
            self.b.start()
        self.assertEqual(self.b.calls, 4)

    def test_per_request_deadline_not_renewed_by_io(self):
        self.b.start()
        self.clock.now = 19.5
        self.assertEqual(self.b.remaining(), .5)
        self.clock.now = 20
        with self.assertRaisesRegex(TimeoutError, 'per-request'):
            self.b.remaining()

    def test_aggregate_deadline_truncates_last_attempt(self):
        self.clock.now = 75
        self.assertEqual(self.b.start(), 5)
        self.clock.now = 80
        with self.assertRaisesRegex(TimeoutError, 'aggregate'):
            self.b.remaining()
        with self.assertRaisesRegex(TimeoutError, 'aggregate'):
            self.b.start()

    def test_byte_accounting_never_exceeds_cap(self):
        self.b.account(st.TOTAL_BODY_CAP - 1)
        self.assertEqual(self.b.remaining_body_capacity(0), 1)
        self.b.account(1)
        self.assertEqual(self.b.remaining_body_capacity(0), 0)
        for n in (1, -1, 1.5, True):
            with self.subTest(n=n), self.assertRaises(ValueError):
                self.b.account(n)
        self.assertEqual(self.b.total, st.TOTAL_BODY_CAP)
        for n in (-1, st.PER_BODY_CAP + 1, True):
            with self.subTest(n=n), self.assertRaises(ValueError):
                self.b.remaining_body_capacity(n)

    def test_accounting_keeps_received_bytes_when_clock_has_expired(self):
        self.b.start()
        self.clock.now = 21
        self.b.account(3)
        self.assertEqual(self.b.total, 3)
        with self.assertRaises(TimeoutError):
            self.b.remaining()


class TransportTests(OfflineCase):
    def test_literal_get_wire_tls_and_no_proxy(self):
        t = self.transport()
        with patch.dict('os.environ', {'HTTPS_PROXY': 'https://wrong.invalid:443',
                                       'HTTP_PROXY': 'https://wrong.invalid:443'}):
            response = self.open(t)
        self.validate_mock.assert_any_call(self.p)
        self.assertEqual(self.authorize_mock.call_count, 2)
        self.dns_mock.assert_called_once_with(st.HOST, 443, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
        self.assertEqual(self.sock.connections, [('192.0.2.1', 443)])
        self.context.wrap_socket.assert_called_once_with(self.sock, server_hostname=st.HOST)
        self.assertEqual(self.sock.sent, [(
            'GET ' + st.URLS[0].split(st.HOST)[1] + ' HTTP/1.1\r\n'
            'Host: files.pythonhosted.org\r\nAccept: text/plain\r\n'
            'Accept-Encoding: identity\r\nConnection: close\r\n\r\n').encode('ascii')])
        self.assertEqual(st.validate_headers(response, st.URLS[0], self.p), 3)
        self.assertEqual(response.read(3), b'abc')
        self.b.account(3)
        self.assertEqual(response.body_bytes, 3)
        response.close()
        self.assertTrue(self.sock.closed)
        self.create_connection_mock.assert_not_called()

    def test_each_exact_url_is_permitted_once(self):
        t = self.transport()
        for url in st.URLS:
            self.sock.raw = b'HTTP/1.1 200 OK\r\n\r\n'
            self.open(t, url=url).close()
        self.assertEqual(self.b.calls, 4)
        self.assertEqual(t.attempted, set(st.URLS))
        self.assertEqual(self.dns_mock.call_count, 4)

    def test_constructor_authorization_rejected_before_dns(self):
        self.authorize_mock.side_effect = ValueError('network access disabled')
        with self.assertRaisesRegex(ValueError, 'network access disabled'):
            self.transport()
        self.dns_mock.assert_not_called()
        self.socket_mock.assert_not_called()

    def test_open_reauthorizes_before_dns(self):
        t = self.transport()
        self.authorize_mock.side_effect = ValueError('expired run grant')
        with self.assertRaisesRegex(ValueError, 'expired run grant'):
            self.open(t)
        self.dns_mock.assert_not_called()

    def test_proposal_revalidated_before_open(self):
        t = self.transport()
        self.validate_mock.side_effect = ValueError('proposal changed')
        with self.assertRaisesRegex(ValueError, 'proposal changed'):
            self.open(t)
        self.dns_mock.assert_not_called()

    def test_methods_wheels_indexes_and_url_variations_refused(self):
        bad = [('HEAD', st.URLS[0]), ('POST', st.URLS[0]),
               ('GET', st.URLS[0].removesuffix('.metadata')),
               ('GET', 'https://pypi.org/simple/filelock/'),
               ('GET', st.URLS[0] + '?q=1'), ('GET', st.URLS[0] + '#x'),
               ('GET', st.URLS[0].replace('https:', 'http:')),
               ('GET', st.URLS[0].replace(st.HOST, st.HOST + ':443')),
               ('GET', st.URLS[0].replace(st.HOST, 'user:pass@' + st.HOST)),
               ('GET', st.URLS[0].replace('filelock', 'unknown'))]
        for method, url in bad:
            with self.subTest(method=method, url=url), self.assertRaises(ValueError):
                self.transport().open(method, url, st.EXPECTED_HEADERS, self.b)
        self.dns_mock.assert_not_called()

    def test_extra_changed_or_missing_headers_refused(self):
        for headers in ({}, {'Accept': 'application/json'},
                        dict(st.EXPECTED_HEADERS, Authorization='secret'),
                        dict(st.EXPECTED_HEADERS, Cookie='secret'),
                        dict(st.EXPECTED_HEADERS, Host='wrong.invalid'),
                        dict(st.EXPECTED_HEADERS, **{'Accept-Encoding': 'gzip'})):
            with self.subTest(headers=headers), self.assertRaisesRegex(ValueError, 'headers'):
                self.transport().open('GET', st.URLS[0], headers, self.b)
        self.dns_mock.assert_not_called()

    def test_missing_start_and_repeated_start_refused(self):
        t = self.transport()
        with self.assertRaisesRegex(ValueError, 'budget attempt'):
            t.open('GET', st.URLS[0], st.EXPECTED_HEADERS, self.b)
        self.b.start()
        self.b.start()
        with self.assertRaisesRegex(ValueError, 'budget attempt'):
            t.open('GET', st.URLS[0], st.EXPECTED_HEADERS, self.b)
        self.dns_mock.assert_not_called()

    def test_retry_refused_without_second_dns(self):
        t = self.transport()
        self.open(t)
        with self.assertRaisesRegex(ValueError, 'duplicate request/retry'):
            self.open(t)
        self.assertEqual(self.dns_mock.call_count, 1)

    def test_tls_verification_cannot_be_disabled(self):
        for attribute, value in [('check_hostname', False), ('verify_mode', ssl.CERT_NONE)]:
            with self.subTest(attribute=attribute):
                self.context.check_hostname = True
                self.context.verify_mode = ssl.CERT_REQUIRED
                setattr(self.context, attribute, value)
                self.b = st.Budget(self.p, self.clock)
                with self.assertRaisesRegex(ValueError, 'TLS verification disabled'):
                    self.open()
        self.dns_mock.assert_not_called()

    def test_no_address_fallback_and_failure_stops_transport(self):
        self.sock.connect_error = OSError('connect failed')
        t = self.transport()
        with self.assertRaisesRegex(OSError, 'connect failed'):
            self.open(t)
        self.assertTrue(self.sock.closed)
        self.assertEqual(self.sock.connections, [('192.0.2.1', 443)])
        with self.assertRaisesRegex(ValueError, 'stopped after failure'):
            self.open(t, url=st.URLS[1])
        self.assertEqual(self.socket_mock.call_count, 1)

    def test_tls_wrap_failure_closes_plain_socket(self):
        self.context.wrap_socket.side_effect = ssl.SSLError('certificate failure')
        with self.assertRaises(ssl.SSLError):
            self.open()
        self.assertTrue(self.sock.closed)

    def test_send_failure_closes_tls_socket(self):
        self.sock.send_error = OSError('send failed')
        with self.assertRaises(OSError):
            self.open()
        self.assertTrue(self.sock.closed)

    def test_late_dns_result_does_not_connect(self):
        def delayed_dns(*args, **kwargs):
            self.clock.now = 21
            return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, '', ('192.0.2.1', 443))]
        self.dns_mock.side_effect = delayed_dns
        with self.assertRaisesRegex(TimeoutError, 'per-request'):
            self.open()
        self.socket_mock.assert_not_called()

    def test_never_finishing_dns_wait_is_bounded_without_network_or_real_wait(self):
        event = Mock()
        event.wait.return_value = False
        thread = Mock()
        with patch.object(st.threading, 'Event', return_value=event), \
                patch.object(st.threading, 'Thread', return_value=thread) as constructor:
            with self.assertRaisesRegex(TimeoutError, 'DNS per-request'):
                self.open()
        event.wait.assert_called_once_with(timeout=20)
        thread.start.assert_called_once_with()
        self.assertTrue(constructor.call_args.kwargs['daemon'])
        self.dns_mock.assert_not_called()
        self.socket_mock.assert_not_called()

    def test_dns_error_is_not_retried(self):
        self.dns_mock.side_effect = socket.gaierror('offline resolution failure')
        with self.assertRaises(socket.gaierror):
            self.open()
        self.dns_mock.assert_called_once()
        self.socket_mock.assert_not_called()

    def test_empty_or_unsupported_dns_result_rejected(self):
        for value in ([], [(socket.AF_UNSPEC, socket.SOCK_STREAM, socket.IPPROTO_TCP, '', '/tmp/none')]):
            with self.subTest(value=value):
                self.b = st.Budget(self.p, self.clock)
                self.dns_mock.return_value = value
                with self.assertRaises(ValueError):
                    self.open()
        self.socket_mock.assert_not_called()


class ResponseTests(OfflineCase):
    def response(self, headers=(), status=200, url=None):
        return SimpleNamespace(status=status, headers=list(headers), final_url=url or st.URLS[0])

    def test_permitted_mime_or_absent_and_exact_bound(self):
        for mime in (None, 'text/plain', 'text/plain; charset=utf-8',
                     'application/octet-stream', 'APPLICATION/OCTET-STREAM; charset=us-ascii'):
            headers = [] if mime is None else [('Content-Type', mime)]
            headers.append(('Content-Length', str(st.PER_BODY_CAP)))
            with self.subTest(mime=mime):
                self.assertEqual(st.validate_headers(self.response(headers), st.URLS[0], self.p), st.PER_BODY_CAP)
        self.assertIsNone(st.validate_headers(self.response(), st.URLS[0], self.p))

    def test_redirects_missing_sidecar_and_server_error_rejected(self):
        for status in (100, 201, 301, 302, 303, 307, 308, 404, 410, 429, 500, 503):
            with self.subTest(status=status), self.assertRaisesRegex(ValueError, 'status'):
                st.validate_headers(self.response(status=status), st.URLS[0], self.p)
        self.dns_mock.assert_not_called()


    def test_exact_binary_octet_stream_and_existing_charset_policy(self):
        for value in ('binary/octet-stream', 'BINARY/OCTET-STREAM',
                      'binary/octet-stream; charset=utf-8',
                      'binary/octet-stream; charset=us-ascii'):
            with self.subTest(value=value):
                self.assertEqual(st.validate_headers(self.response([
                    ('Content-Type', value), ('Content-Length', '2028')]),
                    st.URLS[0], self.p), 2028)

    def test_binary_mime_does_not_expand_type_or_parameter_policy(self):
        for value in ('binary/*', 'binary/zip', 'binary/octet-streamx',
                      'binary/octet-stream; charset=latin-1',
                      'binary/octet-stream; charset="utf-8"',
                      'binary/octet-stream; charset=utf-8; charset=utf-8',
                      'binary/octet-stream; name=file',
                      'binary/octet-stream, text/plain'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                st.validate_headers(self.response([('Content-Type', value)]),
                                    st.URLS[0], self.p)

    def test_final_url_must_match_exact_literal(self):
        with self.assertRaisesRegex(ValueError, 'final URL'):
            st.validate_headers(self.response(url=st.URLS[1]), st.URLS[0], self.p)

    def test_encoding_chunking_duplicates_malformed_and_oversized_headers(self):
        cases = [[('Content-Encoding', 'gzip')], [('Content-Encoding', 'br')],
                 [('Transfer-Encoding', 'chunked')], [('Transfer-Encoding', 'identity')],
                 [('Content-Length', '3'), ('content-length', '3')],
                 [('Content-Type', 'text/plain'), ('Content-Type', 'text/plain')],
                 [('Set-Cookie', 'a=1'), ('Set-Cookie', 'b=1')],
                 [('Content-Length', '-1')], [('Content-Length', '1, 1')],
                 [('Content-Length', str(st.PER_BODY_CAP + 1))],
                 [('Content-Type', 'application/json')], [('Content-Type', 'text/html')],
                 [('Content-Type', 'text/plain; charset=latin-1')],
                 [('X', 'x' * st.HEADER_BYTE_CAP)], [('Bad Name', 'x')],
                 [('X', 'value\r\nInjected: x')], [('X', 'value\x7f')]]
        for headers in cases:
            with self.subTest(headers=str(headers)[:80]), self.assertRaises(ValueError):
                st.validate_headers(self.response(headers), st.URLS[0], self.p)

    def test_malformed_raw_headers_preserve_prefix_and_close_socket(self):
        cases = [b'HTTP/2 200 OK\r\n\r\n', b'HTTP/1.1 200 OK\r\n folded: x\r\n\r\n',
                 b'HTTP/1.1 200 OK\r\nBad Name: x\r\n\r\n',
                 b'HTTP/1.1 200 OK\r\nX: a\x01\r\n\r\n',
                 b'HTTP/1.1 200 OK\r\nX: incomplete']
        for raw in cases:
            with self.subTest(raw=raw):
                self.b = st.Budget(self.p, self.clock)
                self.sock.raw = raw
                with self.assertRaises(ValueError) as caught:
                    self.open()
                self.assertEqual(caught.exception.partial_response_header_bytes, raw)
                self.assertEqual(caught.exception.response_url, st.URLS[0])
                self.assertTrue(self.sock.closed)

    def test_raw_header_cap_never_overshoots(self):
        self.sock.raw = b'HTTP/1.1 200 OK\r\nX: ' + b'x' * st.HEADER_BYTE_CAP
        with self.assertRaisesRegex(ValueError, 'header limit') as caught:
            self.open()
        self.assertEqual(len(caught.exception.partial_response_header_bytes), st.HEADER_BYTE_CAP)
        self.assertTrue(self.sock.closed)

    def test_header_timeout_keeps_received_byte(self):
        def expire():
            self.clock.now = 21
        self.sock.recv_hook = expire
        with self.assertRaises(TimeoutError) as caught:
            self.open()
        self.assertEqual(caught.exception.partial_response_header_bytes, b'H')
        self.assertTrue(self.sock.closed)

    def test_cancellation_keeps_header_prefix(self):
        calls = 0
        def cancel():
            nonlocal calls
            calls += 1
            if calls == 5:
                raise KeyboardInterrupt()
        self.sock.recv_hook = cancel
        with self.assertRaises(KeyboardInterrupt) as caught:
            self.open()
        self.assertEqual(caught.exception.partial_response_header_bytes, b'HTTP')
        self.assertTrue(self.sock.closed)

    def test_body_read_preserves_late_chunk_before_clock_exception(self):
        response = self.open()
        self.sock.recv_hook = lambda: setattr(self.clock, 'now', 21)
        self.assertEqual(response.read(3), b'abc')
        self.b.account(3)
        with self.assertRaises(TimeoutError):
            self.b.remaining()
        self.assertEqual(response.body_bytes, 3)

    def test_body_read_cap_is_enforced_before_socket(self):
        response = self.open()
        response.body_bytes = st.PER_BODY_CAP
        with self.assertRaisesRegex(ValueError, 'remaining body cap'):
            response.read(1)
        for n in (0, -1, True, 1.5):
            with self.subTest(n=n), self.assertRaises(ValueError):
                response.read(n)
        self.assertEqual(self.sock.raw, b'abc')


if __name__ == '__main__':
    unittest.main()
