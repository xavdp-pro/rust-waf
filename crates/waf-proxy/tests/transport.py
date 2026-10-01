"""Exercise the compiled proxy against an independently recording Unix HTTP backend."""
import hashlib
import http.client
import http.server
import json
import pathlib
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import unittest

BINARY = sys.argv.pop(1)
ROOT = pathlib.Path(__file__).resolve().parents[3]

class UnixServer(socketserver.UnixStreamServer):
    pass

class Connection(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__('localhost', timeout=3)
        self.path = str(path)
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)

class Transport(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix='waf-protocol-')
        cls.tmp = pathlib.Path(cls.directory.name)
        cls.received = []
        class Backend(http.server.BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'
            def log_message(self, *args):
                pass
            def respond(self):
                body = self.rfile.read(int(self.headers.get('Content-Length', 0)))
                cls.received.append({'id':self.headers.get('X-Request-ID'), 'sha256':hashlib.sha256(body).hexdigest(), 'path':self.path, 'method':self.command, 'headers':dict(self.headers)})
                self.send_response(200)
                self.send_header('Content-Length', str(len(body)))
                self.send_header('Set-Cookie','member=fixture; HttpOnly')
                self.end_headers()
                self.wfile.write(body)
            do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = respond
        cls.backend = UnixServer(str(cls.tmp/'backend.sock'), Backend)
        cls.thread = threading.Thread(target=cls.backend.serve_forever, daemon=True)
        cls.thread.start()
        core = json.loads((ROOT/'profiles/core/base.json').read_text())
        core['rules'] = [{'id':'fixture.sentinel','targets':['body','query','headers'],'pattern':'forbidden-sentinel','high_confidence':False}]
        limits = {'body_bytes':32768,'uri_bytes':8192,'header_bytes':65536,'header_count':128,'decode_passes':3,'multipart_parts':4}
        core['limits'] = limits
        (cls.tmp/'core.json').write_text(json.dumps(core))
        cls.config = {'listen_socket':str(cls.tmp/'proxy.sock'),'backend_socket':str(cls.tmp/'backend.sock'),'profiles':[str(cls.tmp/'core.json'),str(ROOT/'profiles/wordpress/base.json'),str(ROOT/'profiles/sites/example.json')],'site_id':'example-site','mode':'enforce','max_concurrent':2,'request_timeout_seconds':1,'backend_timeout_seconds':1,'response_bytes':65536}
        cls.events = open(cls.tmp/'events.txt','w')
        (cls.tmp/'config.json').write_text(json.dumps(cls.config))
        cls.process = subprocess.Popen([BINARY,str(cls.tmp/'config.json')],stdout=cls.events,stderr=subprocess.PIPE)
        for _ in range(300):
            if (cls.tmp/'proxy.sock').exists():
                break
            if cls.process.poll() is not None:
                raise RuntimeError(cls.process.stderr.read().decode())
            time.sleep(.01)
        else:
            raise RuntimeError('Proxy listener did not become ready')
    @classmethod
    def tearDownClass(cls):
        cls.process.terminate()
        try:
            cls.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            cls.process.kill(); cls.process.wait()
        cls.process.stderr.close()
        cls.events.close()
        cls.backend.shutdown(); cls.backend.server_close()
        cls.thread.join(timeout=3)
        cls.directory.cleanup()
    def request(self, method='POST', path='/form/?keep=original', body=b'benign', headers=None):
        connection = Connection(self.tmp/'proxy.sock')
        values = {'X-Waf-Client-IP':'198.51.100.25','X-Waf-Admin-Friend':'0','Content-Type':'text/plain'}
        if headers:
            values.update(headers)
        connection.request(method,path,body,values)
        response=connection.getresponse()
        result=(response.status,dict(response.getheaders()),response.read())
        connection.close()
        return result
    def assert_denied_before_backend(self, **kwargs):
        before=len(self.received)
        status,headers,_=self.request(**kwargs)
        self.assertGreaterEqual(status,400)
        self.assertEqual(len(self.received),before)
        events=[json.loads(line) for line in (self.tmp/'events.txt').read_text().splitlines()]
        event=next(e for e in events if e['request_id']==headers['x-request-id'])
        self.assertFalse(event['backend_attempted'])
        self.assertEqual(event['decision'],'block')
        return status
    def test_01_complete_bytes_methods_cookie_and_correlation(self):
        for method in ['POST','PUT','PATCH','DELETE','OPTIONS']:
            body=b'unchanged+bytes=%2526&items[]=a&items[]=b'
            status,headers,reply=self.request(method=method,body=body,headers={'X-Request-ID':'forged-public-id','X-Forwarded-For':'127.0.0.1'})
            self.assertEqual(status,200)
            self.assertEqual(reply,body)
            record=self.received[-1]
            self.assertEqual(record['sha256'],hashlib.sha256(body).hexdigest())
            self.assertEqual(record['path'],'/form/?keep=original')
            self.assertEqual(record['method'],method)
            self.assertEqual(record['id'],headers['x-request-id'])
            self.assertNotEqual(record['id'],'forged-public-id')
            self.assertNotIn('X-Forwarded-For',record['headers'])
            self.assertEqual(headers['set-cookie'],'member=fixture; HttpOnly')
    def test_02_tail_encoding_json_multipart_and_query_denials(self):
        cases=[{'body':b'a'*16000+b'forbidden-sentinel'},
               {'body':b'x=%2566orbidden-sentinel','headers':{'Content-Type':'application/x-www-form-urlencoded'}},
               {'body':br'{"x":"\u0066orbidden-sentinel"}','headers':{'Content-Type':'application/json'}},
               {'path':'/form/?x=%2566orbidden-sentinel'},
               {'headers':{'Cookie':'comment=%2566orbidden-sentinel'}},
               {'body':b'--bound\r\nContent-Disposition: form-data; name="x"\r\n\r\nforbidden-sentinel\r\n--bound--\r\n','headers':{'Content-Type':'multipart/form-data; boundary=bound'}}]
        for case in cases:
            self.assertEqual(self.assert_denied_before_backend(**case),403)
    def test_03_body_limits_and_parse_ambiguity(self):
        cases=[{'body':b'a'*32769}, {'body':b'{"x":1,"x":2}','headers':{'Content-Type':'application/json'}},
               {'body':b'broken','headers':{'Content-Type':'multipart/form-data; boundary=bound'}},
               {'path':'/a/%252e%252e/b'}, {'headers':{'Content-Encoding':'gzip'}},
               {'headers':{'X-Waf-Client-IP':'invalid'}}, {'method':'TRACE'}]
        for case in cases:
            self.assert_denied_before_backend(**case)
    def test_04_hop_headers_cannot_remove_trusted_identity(self):
        # Connection-nominated trusted headers must never disappear downstream.
        status,_,_=self.request(headers={'Connection':'x-waf-client-ip, x-waf-admin-friend'})
        self.assertGreaterEqual(status,400)
    def test_05_body_timeout_does_not_forward_partial_payload(self):
        before=len(self.received)
        sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);sock.settimeout(3);sock.connect(str(self.tmp/'proxy.sock'))
        sock.sendall(b'POST /form/ HTTP/1.1\r\nHost: localhost\r\nX-Waf-Client-IP: 198.51.100.25\r\nX-Waf-Admin-Friend: 0\r\nContent-Length: 10\r\n\r\na')
        data=sock.recv(8192);sock.close()
        self.assertIn(b'408',data.split(b'\r\n')[0]);self.assertEqual(len(self.received),before)
    def test_99_backend_outage_fails_closed(self):
        self.backend.shutdown();self.backend.server_close()
        status,_,_=self.request()
        self.assertEqual(status,502)

if __name__=='__main__':
    unittest.main(verbosity=2)
