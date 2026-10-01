#!/usr/bin/env python3
"""Linux systemd stress probe with a private neutral Unix backend, never PHP.

Run as root with a readable enforcement runtime and candidate executable.
This is bounded adversarial resource evidence, not paired performance acceptance.
"""
import argparse
import concurrent.futures
import hashlib
import http.client
import http.server
import json
import os
from pathlib import Path
import pwd
import grp
import socket
import socketserver
import subprocess
import tempfile
import threading
import time
import uuid


def command(*args, check=True):
    return subprocess.run(args, check=check, capture_output=True, text=True, timeout=15)


def properties(unit):
    result = command('systemctl', 'show', unit, '--property=ActiveState,SubState,ControlGroup,MemoryCurrent,MemoryPeak,MemoryMax,NRestarts').stdout
    values = dict(line.split('=', 1) for line in result.splitlines() if '=' in line)
    for key in ('MemoryCurrent', 'MemoryPeak', 'MemoryMax', 'NRestarts'):
        values[key] = int(values[key])
    control_group = values.pop('ControlGroup')
    if not control_group:
        raise RuntimeError('candidate cgroup is unavailable')
    cgroup = Path('/sys/fs/cgroup') / control_group.lstrip('/')
    values['memory_events'] = dict((key, int(value)) for key, value in
                                 (line.split() for line in (cgroup / 'memory.events').read_text().splitlines()))
    return values


def fixtures(size):
    yield 'opaque-text', 'text/plain', b'a' * size, 200
    yield 'opaque-binary', 'application/octet-stream', b'\xff' * size, 200
    yield 'form', 'application/x-www-form-urlencoded', b'a' * size, 200
    yield 'json-string', 'application/json', b'"' + b'a' * (size - 2) + b'"', 200
    count = (size - 2) // 3
    yield 'json-nodes', 'application/json', b'[' + b'[],' * (count - 1) + b'[]]', 200
    for case in ('json-empty-strings', 'json-unique-strings', 'json-object-keys'):
        obj = case == 'json-object-keys'
        body = bytearray(b'{' if obj else b'[')
        number = 0
        while True:
            value = (f'"k{number:06}":0' if obj else '""' if case == 'json-empty-strings'
                     else f'"v{number:06}"').encode()
            if len(body) + len(value) + bool(number) + 1 > size:
                break
            if number:
                body.extend(b',')
            body.extend(value)
            number += 1
        body.extend(b'}' if obj else b']')
        body.extend(b' ' * (size - len(body)))
        yield case, 'application/json', bytes(body), 200
    head = b'--fixture\r\nContent-Disposition: form-data; name="file"; filename="example.bin"\r\n\r\n'
    tail = b'\r\n--fixture--\r\n'
    yield 'multipart-binary', 'multipart/form-data; boundary=fixture', head + b'\xff' * (size-len(head)-len(tail)) + tail, 200
    # Full-body negative controls, including an invalid suffix after a rule hit.
    tail = b'<script>fixture()</script>'
    yield 'binary-tail-detection', 'application/octet-stream', b'\xff' * (size-len(tail)) + tail, 403
    yield 'json-invalid-tail', 'application/json', b'{"x":"<script>fixture()</script>"} trailing', 400
    yield 'json-escaped-duplicate', 'application/json', br'{"nested":{"a":0,"\u0061":1}}', 400


class Connection(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__('localhost', timeout=90)
        self.path = str(path)

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)


class Backend(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True, type=Path)
    parser.add_argument('--runtime', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--service-user', default='root')
    parser.add_argument('--service-group', default='root')
    parser.add_argument('--size', type=int, default=8 * 1024 * 1024)
    args = parser.parse_args()
    if os.geteuid() != 0 or not 1024 <= args.size <= 8 * 1024 * 1024:
        parser.error('root and a synthetic body size from 1 KiB through 8 MiB are required')
    config = json.loads(args.runtime.read_text())
    if config['mode'] != 'enforce' or config['max_concurrent'] != 8 or config['response_bytes'] < args.size:
        parser.error('runtime must enforce, allow eight tasks and allow the tested response size')
    uid = pwd.getpwnam(args.service_user).pw_uid
    gid = grp.getgrnam(args.service_group).gr_gid
    report = {'schema_version': 1, 'kind': 'neutral_backend_adversarial_resource_probe',
              'binary_sha256': hashlib.sha256(args.binary.read_bytes()).hexdigest(),
              'memory_max_bytes': 512 * 1024 * 1024, 'workers': 4,
              'request_size_bytes': args.size, 'repetitions': 3, 'concurrency': 8,
              'backend': 'neutral-unix-http-no-php', 'batches': [], 'passed': False}
    receipts, receipt_lock = {}, threading.Lock()
    chunk = b'R' * 65536
    response_digest = hashlib.sha256(b'R' * args.size).hexdigest()

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'
        def log_message(self, *_):
            pass
        def do_POST(self):
            length = int(self.headers['Content-Length'])
            remaining, digest = length, hashlib.sha256()
            while remaining:
                data = self.rfile.read(min(65536, remaining))
                if not data:
                    return
                digest.update(data)
                remaining -= len(data)
            with receipt_lock:
                receipts[self.headers['X-Request-ID']] = {'bytes': length, 'sha256': digest.hexdigest()}
            self.send_response(200)
            self.send_header('Content-Length', str(args.size))
            self.end_headers()
            remaining = args.size
            while remaining:
                data = chunk[:min(remaining, len(chunk))]
                self.wfile.write(data)
                remaining -= len(data)

    unit = 'waf-resource-' + uuid.uuid4().hex
    service_started = False
    server = None
    try:
        with tempfile.TemporaryDirectory(prefix='waf-resource-') as directory:
            folder = Path(directory)
            os.chown(folder, uid, gid)
            folder.chmod(0o750)
            server = Backend(str(folder/'backend.sock'), Handler)
            os.chown(folder/'backend.sock', uid, gid)
            (folder/'backend.sock').chmod(0o660)
            threading.Thread(target=server.serve_forever, daemon=True).start()
            config.update(listen_socket=str(folder/'frontend.sock'), backend_socket=str(folder/'backend.sock'))
            config.pop('ban_lookup_socket', None)
            runtime = folder/'runtime.json'
            runtime.write_text(json.dumps(config))
            os.chown(runtime, 0, gid)
            runtime.chmod(0o640)
            command('systemd-run', '--quiet', '--unit='+unit, '--service-type=exec',
                    '--property=MemoryMax=536870912', '--property=TasksMax=32',
                    '--property=User='+args.service_user, '--property=Group='+args.service_group,
                    '--property=RestrictAddressFamilies=AF_UNIX', '--setenv=TOKIO_WORKER_THREADS=4',
                    str(args.binary.resolve()), str(runtime))
            service_started = True
            for _ in range(100):
                if (folder/'frontend.sock').exists():
                    break
                if command('systemctl', 'is-active', unit, check=False).returncode:
                    raise RuntimeError('candidate service failed startup')
                time.sleep(.05)
            else:
                raise RuntimeError('candidate socket startup deadline')
            report['initial'] = properties(unit)
            for case, content_type, body, expected in fixtures(args.size):
                digest = hashlib.sha256(body).hexdigest()
                for repetition in range(1, 4):
                    barrier = threading.Barrier(8)
                    response_barrier = threading.Barrier(8)
                    def request(_):
                        connection = Connection(folder/'frontend.sock')
                        try:
                            barrier.wait(timeout=10)
                            start = time.monotonic()
                            connection.request('POST', '/resource-fixture/', body,
                                {'Content-Type': content_type, 'X-Waf-Client-IP': '198.51.100.25',
                                 'X-Waf-Admin-Friend': '0', 'Connection': 'close'})
                            response = connection.getresponse()
                            # Hold all responses until every gateway request has
                            # finished inspection/backend buffering. This exposes
                            # concurrent response retention rather than allowing
                            # a fast client to drain each response immediately.
                            response_barrier.wait(timeout=90)
                            ids = response.headers.get_all('x-request-id', [])
                            response_hash, received = hashlib.sha256(), 0
                            while data := response.read(65536):
                                response_hash.update(data)
                                received += len(data)
                            return {'status': response.status, 'request_ids': ids,
                                    'response_bytes': received, 'response_sha256': response_hash.hexdigest(),
                                    'duration_ms': round((time.monotonic()-start)*1000, 3)}
                        finally:
                            connection.close()
                    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                        responses = list(pool.map(request, range(8)))
                    events = [json.loads(line) for line in command('journalctl', '-u', unit, '-o', 'cat', '--no-pager').stdout.splitlines() if line.startswith('{')]
                    by_id = {event['request_id']: event for event in events}
                    deadline = time.monotonic() + 2
                    while any(len(r['request_ids']) == 1 and r['request_ids'][0] not in by_id for r in responses) and time.monotonic() < deadline:
                        time.sleep(.05)
                        events = [json.loads(line) for line in command('journalctl', '-u', unit, '-o', 'cat', '--no-pager').stdout.splitlines() if line.startswith('{')]
                        by_id = {event['request_id']: event for event in events}
                    checks = []
                    for response in responses:
                        ids = response['request_ids']
                        event = by_id.get(ids[0]) if len(ids) == 1 else None
                        with receipt_lock:
                            receipt = receipts.get(ids[0]) if len(ids) == 1 else None
                        valid = response['status'] == expected and event is not None
                        if expected == 200:
                            valid = valid and receipt == {'bytes': len(body), 'sha256': digest} and event['backend_attempted']
                            valid = valid and response['response_bytes'] == args.size and response['response_sha256'] == response_digest
                        else:
                            valid = valid and receipt is None and not event['backend_attempted']
                        checks.append(bool(valid))
                    state = properties(unit)
                    batch = {'case': case, 'repetition': repetition, 'request_bytes': len(body),
                             'expected_status': expected, 'passed_requests': sum(checks), 'total_requests': 8,
                             'durations_ms': [r['duration_ms'] for r in responses],
                             'statuses': [r['status'] for r in responses], 'service': state}
                    report['batches'].append(batch)
                    args.output.write_text(json.dumps(report, indent=2)+'\n')
                    print(json.dumps({'case': case, 'repetition': repetition, 'passed': sum(checks),
                                      'memory_peak_bytes': state['MemoryPeak']}), flush=True)
                    if not all(checks) or state['ActiveState'] != 'active' or state['NRestarts'] or state['memory_events']['oom'] or state['memory_events']['oom_kill']:
                        raise RuntimeError('resource or correlated forwarding check failed')
            report['final'] = properties(unit)
            report['passed'] = report['final']['MemoryPeak'] <= report['memory_max_bytes']
    except Exception as error:
        # Report error class only; commands/configs never enter output artifacts.
        report['error_type'] = type(error).__name__
        if service_started:
            try:
                report['failure_state'] = properties(unit)
            except Exception:
                report['failure_state_unavailable'] = True
    finally:
        if service_started:
            command('systemctl', 'stop', unit, check=False)
            command('systemctl', 'reset-failed', unit, check=False)
        if server:
            server.shutdown()
            server.server_close()
        args.output.write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps({'passed': report['passed'], 'batches': len(report['batches'])}), flush=True)
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
