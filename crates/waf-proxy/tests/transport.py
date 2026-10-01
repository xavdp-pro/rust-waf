"""Exercise the compiled proxy against an independently recording Unix HTTP backend."""
import contextlib
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
                if self.path.startswith('/representation/'):
                    representation=b'representation-bytes'
                    status=304 if '/cached' in self.path else 204 if self.path.endswith(('/empty','/empty-invalid')) else 200
                    self.send_response(status)
                    if status!=204 and not self.path.endswith('/unknown'):
                        self.send_header('Content-Length',str(1000000 if self.path.endswith('/large') else len(representation)))
                    if self.path.endswith('/empty-invalid'):
                        self.send_header('Content-Length','20')
                    if self.path.endswith('/cached-duplicate'):
                        self.send_header('Content-Length','21')
                    if self.path.endswith('/cached-invalid'):
                        self.send_header('Content-Length','+20')
                    self.send_header('ETag','"fixture-version"')
                    self.send_header('Connection','close')
                    self.end_headers()
                    if self.command!='HEAD' and status==200:
                        self.wfile.write(representation[:3] if self.path.endswith('/truncated') else representation)
                    return
                self.send_response(200)
                self.send_header('Content-Length', str(len(body)))
                self.send_header('Set-Cookie','member=fixture; HttpOnly')
                self.end_headers()
                self.wfile.write(body)
            do_GET = do_HEAD = do_POST = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = respond
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
    def request(self, method='POST', path='/form/?keep=original', body=b'benign', headers=None, socket_path=None):
        connection = Connection(socket_path or self.tmp/'proxy.sock')
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
        # The declared limit is rejected before the body is read. Announce it
        # without sending bytes: sending the entire oversized body can race the
        # server's early close and fail in the client's sendall instead.
        cases=[{'body':b'','headers':{'Content-Length':'32769'}}, {'body':b'{"x":1,"x":2}','headers':{'Content-Type':'application/json'}},
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
    @contextlib.contextmanager
    def alternate_proxy(self, name, mode='enforce', reliable=False, exception=False, common=False, wordpress=False, gate=False, field=False, login=False):
        config=dict(self.config)
        config['listen_socket']=str(self.tmp/(name+'.sock'))
        if gate:config['ban_lookup_socket']=str(self.tmp/(name+'-lookup.sock'))
        config['mode']=mode
        config['bans']={'threshold':2,'window_seconds':10,'duration_seconds':1,'max_entries':16}
        core=json.loads((ROOT/'profiles/core/base.json' if common else self.tmp/'core.json').read_text())
        if not common:core['rules'][0]['high_confidence']=reliable
        core_path=self.tmp/(name+'-core.json');core_path.write_text(json.dumps(core))
        config['profiles']=list(config['profiles']);config['profiles'][0]=str(core_path)
        if exception or wordpress:
            site=json.loads((ROOT/'profiles/sites/example.json').read_text())
            if exception:
                site['exceptions']=[{'rule_id':'fixture.sentinel','path_pattern':'^/feedback/$','methods':['POST'],'reason':'Synthetic feedback compatibility fixture','evidence':'protocol-test-scoped-exception'}]
                if field:site['exceptions'][0]['form_field']='pwd' if login else field if isinstance(field,str) else 'secret'
            if wordpress:
                site['modules']=[{'name':'wordpress-site','settings':{'schema_version':1,'method_rules':[
                    {'id':'fixture.rest-read','scope':'rest','pattern':'^/fixture/v1/read-only$','methods':['GET'],'evidence':'fictional-rest-read-workflow'},
                    {'id':'fixture.cart','scope':'rest','pattern':'^/fixture/v1/cart/items/[0-9]+$','methods':['GET','DELETE'],'evidence':'fictional-cart-method-workflow'},
                    {'id':'fixture.ajax-read','scope':'ajax','pattern':'^fixture_lookup$','methods':['GET'],'evidence':'fictional-ajax-method-workflow'},
                ]}}]
            if login:
                site['modules']=[{'name':'wordpress-site','settings':{'schema_version':1,'login_consumers':[
                    {'path':'/feedback','request_order':'GP','evidence':'fictional-wp-signon-field-consumer'}]}}]
            site_path=self.tmp/(name+'-site.json');site_path.write_text(json.dumps(site))
            config['profiles'][2]=str(site_path)
        config_path=self.tmp/(name+'-config.json');config_path.write_text(json.dumps(config))
        event_path=self.tmp/(name+'-events.txt')
        with open(event_path,'w') as out:
            process=subprocess.Popen([BINARY,str(config_path)],stdout=out,stderr=subprocess.PIPE)
            try:
                for _ in range(300):
                    if pathlib.Path(config['listen_socket']).exists() and (not gate or pathlib.Path(config['ban_lookup_socket']).exists()):break
                    if process.poll() is not None:raise RuntimeError(process.stderr.read().decode())
                    time.sleep(.01)
                else:raise RuntimeError('Alternate listener not ready')
                yield config['listen_socket'],event_path
            finally:
                process.terminate();process.wait(timeout=5);process.stderr.close()
    def test_06_reliable_bans_are_early_temporary_and_exempt_trusted_access(self):
        with self.alternate_proxy('reliable-ban',reliable=True) as (path,events):
            before=len(self.received)
            for _ in range(2):
                self.assertEqual(self.request(body=b'forbidden-sentinel',socket_path=path)[0],403)
            status,headers,_=self.request(socket_path=path)
            self.assertEqual(status,429);self.assertIn('retry-after',headers)
            self.assertEqual(len(self.received),before)
            self.assertEqual(self.request(socket_path=path,headers={'X-Waf-Admin-Friend':'1'})[0],200)
            # Trusted access avoids bans but still undergoes ordinary inspection.
            self.assertEqual(self.request(socket_path=path,body=b'forbidden-sentinel',headers={'X-Waf-Admin-Friend':'1'})[0],403)
            time.sleep(1.1)
            self.assertEqual(self.request(socket_path=path)[0],200)
            records=[json.loads(line) for line in events.read_text().splitlines()]
            self.assertEqual(sum(bool(r['ban_started']) for r in records),1)
            banned=next(r for r in records if r['status']==429)
            self.assertFalse(banned['backend_attempted'])
    def test_07_unreliable_and_observe_matches_do_not_ban(self):
        for name,mode in [('uncertain','enforce'),('observation','observe')]:
            with self.alternate_proxy(name,mode=mode,reliable=mode=='observe') as (path,events):
                for _ in range(3):
                    status,_,_=self.request(body=b'forbidden-sentinel',socket_path=path)
                    self.assertEqual(status,200 if mode=='observe' else 403)
                self.assertEqual(self.request(socket_path=path)[0],200)
                records=[json.loads(line) for line in events.read_text().splitlines()]
                self.assertFalse(any(r['ban_started'] for r in records))
                if mode=='observe':self.assertTrue(all(r['backend_attempted'] for r in records))
    def test_08_exceptions_are_method_scoped_and_do_not_trigger_bans(self):
        with self.alternate_proxy('excepted',reliable=True,exception=True) as (path,events):
            for _ in range(3):
                self.assertEqual(self.request(path='/feedback/',body=b'forbidden-sentinel',socket_path=path)[0],200)
            self.assertEqual(self.request(path='/other/',body=b'forbidden-sentinel',socket_path=path)[0],403)
            self.assertEqual(self.request(method='GET',path='/feedback/',body=b'forbidden-sentinel',socket_path=path)[0],403)
            records=[json.loads(line) for line in events.read_text().splitlines()]
            self.assertEqual(records[0]['matches'][0]['exception_profile'],'example-site')
            self.assertFalse(records[0]['ban_started'])
    def test_09_ambiguous_wire_framing_does_not_reach_backend(self):
        before=len(self.received)
        requests=[
            b'POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n',
            b'POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\nContent-Length: 5\r\n',
            b'POST / HTTP/1.1\r\nHost: localhost\r\nHost: other.test\r\nContent-Length: 0\r\n',
        ]
        for request in requests:
            sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);sock.settimeout(3);sock.connect(str(self.tmp/'proxy.sock'))
            sock.sendall(request+b'X-Waf-Client-IP: 198.51.100.25\r\nX-Waf-Admin-Friend: 0\r\nConnection: close\r\n\r\n0\r\n\r\n')
            line=sock.recv(8192).split(b'\r\n')[0];sock.close()
            self.assertGreaterEqual(int(line.split()[1]),400)
        self.assertEqual(len(self.received),before)
    def test_10_single_request_connections_prevent_pipeline_bypass(self):
        before=len(self.received)
        sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);sock.settimeout(3);sock.connect(str(self.tmp/'proxy.sock'))
        base=b'HTTP/1.1\r\nHost: localhost\r\nX-Waf-Client-IP: 198.51.100.25\r\nX-Waf-Admin-Friend: 0\r\nContent-Length: '
        sock.sendall(b'POST /first/ '+base+b'6\r\n\r\nbenign'+b'POST /second/ '+base+b'18\r\n\r\nforbidden-sentinel')
        data=b''
        while True:
            chunk=sock.recv(8192)
            if not chunk:break
            data+=chunk
        sock.close()
        self.assertIn(b'200',data.split(b'\r\n')[0]);self.assertEqual(len(self.received),before+1)
        self.assertEqual(self.received[-1]['path'],'/first/')
    def test_11_header_timeout_never_reaches_backend(self):
        before=len(self.received)
        sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);sock.settimeout(3);sock.connect(str(self.tmp/'proxy.sock'))
        sock.sendall(b'POST / HTTP/1.1\r\nHost: ')
        data=sock.recv(8192);sock.close()
        self.assertIn(b'408',data.split(b'\r\n')[0]);self.assertEqual(len(self.received),before)
    def test_12_common_development_decisions_have_backend_receipt_proof(self):
        fixture=json.loads((ROOT/'fixtures/common-development.json').read_text())
        sys.path.insert(0,str(ROOT/'observability'))
        from evaluate_waf import evaluate
        results=[]
        with self.alternate_proxy('common-corpus',common=True) as (path,event_path):
            for case in fixture['cases']:
                before=len(self.received)
                headers={'Content-Type':case['content_type'],**case['headers']}
                uri=case['path']+('?' + case['query'] if case['query'] else '')
                status,response_headers,_=self.request(method=case['method'],path=uri,body=case['body'].encode(),headers=headers,socket_path=path)
                event=next(r for r in [json.loads(line) for line in event_path.read_text().splitlines()] if r['request_id']==response_headers['x-request-id'])
                reached=any(r['id']==event['request_id'] for r in self.received[before:])
                results.append({'label':case['label'],'decision':event['decision'],'backend_reached':reached})
                if event['decision']=='block':self.assertFalse(reached,case['id'])
            report=evaluate(results)
            self.assertEqual(report['fp'],0);self.assertEqual(report['fn'],0)
            self.assertEqual(report['backend_proof_coverage'],1)
            print('COMMON_DEVELOPMENT_CORPUS '+json.dumps(report,sort_keys=True))
    def test_13_wordpress_effective_methods_admin_and_backend_proof(self):
        with self.alternate_proxy('wordpress-methods',wordpress=True) as (socket_path,event_path):
            denied=[
                {'path':'/wp-json/fixture/v1/read-only','method':'POST'},
                {'path':'/wp-json/fixture/v1/read-only?_method=DELETE','method':'POST'},
                {'path':'/index.php?rest.route=/fixture/v1/read-only','method':'POST','headers':{'X-HTTP-Method-Override':'DELETE'}},
                {'path':'/wp-json/fixture/v1/cart/items/42?_method=PUT','method':'POST'},
                {'path':'/wp-admin/users.php','method':'GET'},
                {'path':'/%77p-admin/plugins.php','method':'GET'},
                {'path':'/wp-admin/admin-ajax.php?action=fixture_lookup','method':'POST'},
                {'path':'/wp-admin/admin-ajax.php?action%00suffix=fixture_lookup','method':'POST'},
                {'path':'/index.php?rest_route%00suffix=/fixture/v1/read-only','method':'POST'},
                {'path':'/wp-json/fixture/v1/read-only?_method%00suffix=DELETE','method':'POST'},
                {'path':'/','body':b'rest_route=/fixture/v1/read-only','headers':{'Content-Type':'application/x-www-form-urlencoded'}},
                {'path':'/','body':b'rest_route%00suffix=/fixture/v1/read-only','headers':{'Content-Type':'application/x-www-form-urlencoded'}},
            ]
            for case in denied:
                before=len(self.received)
                status,headers,_=self.request(socket_path=socket_path,**case)
                self.assertIn(status,[403,405])
                event=next(r for r in [json.loads(line) for line in event_path.read_text().splitlines()] if r['request_id']==headers['x-request-id'])
                self.assertFalse(event['backend_attempted']);self.assertEqual(len(self.received),before)
                self.assertFalse(event['ban_started'])
            allowed=[
                {'path':'/wp-json/fixture/v1/cart/items/42?_method=delete','method':'POST','headers':{'X-HTTP-Method-Override':'PUT'}},
                {'path':'/wp-json/fixture/v1/read-only','method':'OPTIONS'},
                {'path':'/wp-admin/users.php','method':'GET','headers':{'X-Waf-Admin-Friend':'1'}},
                {'path':'/wp-login.php','method':'POST'},
                {'path':'/wp-admin/admin-ajax.php?action=fixture_lookup','method':'GET'},
                {'path':'/wp-json/unknown/v1/custom','method':'PATCH'},
            ]
            for case in allowed:
                status,headers,_=self.request(socket_path=socket_path,**case);self.assertEqual(status,200)
                self.assertEqual(self.received[-1]['id'],headers['x-request-id'])
            records=[json.loads(line) for line in event_path.read_text().splitlines()]
            override=next(r for r in records if r['application'] and r['application']['method_source']=='query' and r['decision']=='allow')
            self.assertEqual(override['application']['effective_method'],'DELETE')
            method_denial=next(r for r in records if r['reason']=='wordpress_method_policy')
            self.assertEqual(method_denial['matches'][0]['profile_id'],'example-site')
    def test_14_rest_override_cannot_reuse_wire_post_exception(self):
        with self.alternate_proxy('wordpress-exception',exception=True) as (socket_path,events):
            # This URL is outside REST, so the POST exception still works.
            self.assertEqual(self.request(path='/feedback/?_method=DELETE',body=b'forbidden-sentinel',socket_path=socket_path)[0],200)
            # A query-selected REST dispatch has DELETE semantics and cannot use that POST exception.
            before=len(self.received)
            status,headers,_=self.request(path='/feedback/?rest_route=/fixture/v1/x&_method=DELETE',body=b'forbidden-sentinel',socket_path=socket_path)
            self.assertEqual(status,403);self.assertEqual(len(self.received),before)
            event=next(r for r in [json.loads(line) for line in events.read_text().splitlines()] if r['request_id']==headers['x-request-id'])
            self.assertEqual(event['application']['effective_method'],'DELETE')
            self.assertIsNone(event['matches'][0]['exception_profile'])
    def test_15_read_only_ban_gate_shares_state_and_expiry(self):
        with self.alternate_proxy('early-gate',reliable=True,gate=True) as (path,events):
            gate=self.tmp/'early-gate-lookup.sock'
            before=len(self.received)
            lookup=lambda **kw:self.request(method='GET',path='/',body=b'',socket_path=gate,**kw)
            self.assertEqual(lookup()[0],204)
            self.assertEqual(events.read_text(),'')
            for _ in range(2):self.assertEqual(self.request(body=b'forbidden-sentinel',socket_path=path)[0],403)
            status,headers,body=lookup()
            self.assertEqual(status,403);self.assertEqual(body,b'');self.assertIn('retry-after',headers)
            self.assertEqual(len(self.received),before)
            records=[json.loads(line) for line in events.read_text().splitlines()]
            blocked=next(r for r in records if r['request_id']==headers['x-request-id'])
            self.assertEqual(blocked['reason'],'temporary_local_ban_early')
            self.assertFalse(blocked['backend_attempted']);self.assertFalse(blocked['ban_started'])
            self.assertEqual(lookup(headers={'X-Waf-Admin-Friend':'1'})[0],204)
            self.assertEqual(lookup(headers={'X-Waf-Client-IP':'198.51.100.26'})[0],204)
            self.assertEqual(self.request(socket_path=path)[0],429)
            time.sleep(1.1)
            self.assertEqual(lookup()[0],204)
            self.assertEqual(self.request(socket_path=path)[0],200)
    def test_16_ban_gate_has_no_forward_or_mutation_endpoint(self):
        with self.alternate_proxy('gate-boundaries',gate=True) as (_,events):
            gate=self.tmp/'gate-boundaries-lookup.sock'
            before=len(self.received)
            for case in [{'method':'POST','path':'/'},{'method':'GET','path':'/forward'},
                         {'method':'GET','path':'/','headers':{'X-Waf-Client-IP':'invalid'}},
                         {'method':'GET','path':'/','body':b'declared-body'}]:
                values={'method':'GET','path':'/','body':b'','socket_path':gate};values.update(case)
                self.assertEqual(self.request(**values)[0],400)
            self.assertEqual(len(self.received),before)
            self.assertEqual(self.request(method='GET',path='/',body=b'',socket_path=gate)[0],204)
            # The declared original body must not be awaited at this lookup socket.
            sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);sock.settimeout(.8);sock.connect(str(gate))
            sock.sendall(b'GET / HTTP/1.1\r\nHost: localhost\r\nX-Waf-Client-IP: 198.51.100.25\r\nX-Waf-Admin-Friend: 0\r\nContent-Length: 1000000\r\n\r\n')
            self.assertIn(b'400',sock.recv(8192).split(b'\r\n')[0]);sock.close()
            self.assertEqual(len(self.received),before)
    def test_17_json_detection_cannot_skip_invalid_tail_or_duplicate_key(self):
        for body in [br'{"x":"forbidden-sentinel"} trailing',
                     br'{"x":"forbidden-sentinel","tail":[1,]}',
                     br'{"nested":{"a":0,"\u0061":1}}']:
            self.assertEqual(self.assert_denied_before_backend(body=body,
                headers={'Content-Type':'application/json'}),400)
        # Distinct nested objects may use the same key. Verify original bytes reach
        # the backend after full validation, including all otherwise empty nodes.
        body=b'['+b'{"same":0},'*1200+b'{"same":1}]'
        status,headers,reply=self.request(body=body,headers={'Content-Type':'application/json'})
        self.assertEqual(status,200);self.assertEqual(reply,body)
        self.assertEqual(self.received[-1]['sha256'],hashlib.sha256(body).hexdigest())
        self.assertEqual(self.received[-1]['id'],headers['x-request-id'])
    def test_18_head_and_bodyless_response_representation_metadata(self):
        def raw_response(method,path):
            # Inspect actual wire bytes; HTTP clients hide content on HEAD/304.
            with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as sock:
                sock.settimeout(3);sock.connect(str(self.tmp/'proxy.sock'))
                sock.sendall((method+' '+path+' HTTP/1.1\r\nHost: localhost\r\nX-Waf-Client-IP: 198.51.100.25\r\nX-Waf-Admin-Friend: 0\r\nContent-Length: 0\r\nConnection: close\r\n\r\n').encode())
                wire=b''
                while chunk:=sock.recv(8192):wire+=chunk
            head,body=wire.split(b'\r\n\r\n',1)
            lines=head.decode().split('\r\n')
            headers={name.lower():value.strip() for name,value in (line.split(':',1) for line in lines[1:])}
            return int(lines[0].split()[1]),headers,body
        cases=[('GET','/representation/normal',200,'20',b'representation-bytes'),
               ('HEAD','/representation/normal',200,'20',b''),
               ('HEAD','/representation/large',200,'1000000',b''),
               ('HEAD','/representation/unknown',200,None,b''),
               ('GET','/representation/cached',304,'20',b''),
               ('HEAD','/representation/cached',304,'20',b''),
               ('GET','/representation/empty',204,None,b''),
               ('GET','/representation/empty-invalid',204,None,b'')]
        for method,path,expected,length,payload in cases:
            with self.subTest(method=method,path=path):
                before=len(self.received)
                status,headers,body=raw_response(method,path)
                self.assertEqual(status,expected)
                self.assertEqual(headers.get('content-length'),length)
                self.assertEqual(body,payload)
                self.assertEqual(headers['etag'],'"fixture-version"')
                self.assertEqual(len(self.received),before+1)
                self.assertEqual(self.received[-1]['id'],headers['x-request-id'])
                event=next(r for r in [json.loads(line) for line in (self.tmp/'events.txt').read_text().splitlines()] if r['request_id']==headers['x-request-id'])
                self.assertTrue(event['backend_attempted'])
                self.assertEqual(event['decision'],'allow')
        # A normal response's declared length remains a framing requirement.
        for path in ['/representation/truncated','/representation/cached-duplicate','/representation/cached-invalid']:
            status,headers,_=self.request(method='GET',path=path,body=b'')
            self.assertEqual(status,502)
            event=next(r for r in [json.loads(line) for line in (self.tmp/'events.txt').read_text().splitlines()] if r['request_id']==headers['x-request-id'])
            self.assertEqual(event['reason'],'backend_unavailable_or_response_limit')
            self.assertTrue(event['backend_attempted'])
        self.assertEqual(self.assert_denied_before_backend(method='HEAD',path='/representation/normal?x=forbidden-sentinel',body=b''),403)
    def test_19_field_configuration_and_forged_confirmation_cannot_bypass_inspection(self):
        with self.alternate_proxy('unconfirmed-field',exception=True,field=True) as (socket_path,events):
            cases=[{'body':b'secret=forbidden-sentinel','headers':{'Content-Type':'application/x-www-form-urlencoded'}},
                   {'body':b'secret=forbidden-sentinel','headers':{'Content-Type':'application/x-www-form-urlencoded','X-Waf-Confirmed-Field':'secret'}},
                   {'body':b'{"secret":"forbidden-sentinel"}','headers':{'Content-Type':'application/json'}}]
            for case in cases:
                before=len(self.received)
                status,headers,_=self.request(path='/feedback/',socket_path=socket_path,**case)
                self.assertEqual(status,403)
                self.assertEqual(len(self.received),before)
                event=next(r for r in [json.loads(line) for line in events.read_text().splitlines()] if r['request_id']==headers['x-request-id'])
                self.assertFalse(event['backend_attempted'])
                self.assertIsNone(event['matches'][0]['exception_profile'])
                self.assertFalse(event['ban_started'])
    def test_20_wordpress_confirmed_password_preserves_bytes_and_other_boundaries(self):
        with self.alternate_proxy('qualified-login',exception=True,field=True,login=True,reliable=True) as (socket_path,events):
            for body in [b'pwd=forbidden-sentinel',b'%70wd=forbidden-sentinel',b'pwd=%2566orbidden-sentinel&action=login']:
                status,headers,reply=self.request(path='/feedback/',body=body,socket_path=socket_path,
                    headers={'Content-Type':'application/x-www-form-urlencoded'})
                self.assertEqual(status,200);self.assertEqual(reply,body)
                self.assertEqual(self.received[-1]['sha256'],hashlib.sha256(body).hexdigest())
                event=next(r for r in [json.loads(line) for line in events.read_text().splitlines()] if r['request_id']==headers['x-request-id'])
                self.assertEqual(event['matches'][0]['exception_profile'],'example-site')
                self.assertEqual(event['application']['consumer_profile'],'example-site')
                self.assertTrue(event['backend_attempted']);self.assertFalse(event['ban_started'])
            denied=[{'body':b'pwd=forbidden-sentinel&other=forbidden-sentinel'},
                    {'path':'/feedback/?q=forbidden-sentinel'}, {'path':'/feedback/?key='},
                    {'path':'/feedback/?checkemail=0'}, {'path':'/feedback/?action=logout'},
                    {'body':b'pwd=forbidden-sentinel&action=logout'},
                    {'body':b'pwd=forbidden-sentinel&rest_route=/fixture/v1/x'},
                    {'path':'/feedback/?rest_route=/fixture/v1/x&_method=DELETE'},
                    {'method':'GET'}, {'body':b'pwd=forbidden-sentinel&pwd%00suffix=benign'},
                    {'body':b'pwd[]=forbidden-sentinel'}, {'body':b'pwd=forbidden-sentinel&pwd=benign'}]
            for case in denied:
                before=len(self.received)
                values={'path':'/feedback/','body':b'pwd=forbidden-sentinel','socket_path':socket_path,
                    'headers':{'Content-Type':'application/x-www-form-urlencoded','X-Waf-Admin-Friend':'1'}}
                values.update(case)
                status,headers,_=self.request(**values)
                self.assertIn(status,[400,403]);self.assertEqual(len(self.received),before)
                event=next(r for r in [json.loads(line) for line in events.read_text().splitlines()] if r['request_id']==headers['x-request-id'])
                self.assertFalse(event['backend_attempted']);self.assertFalse(event['ban_started'])
                if case.get('body')==b'pwd=forbidden-sentinel&other=forbidden-sentinel' or case.get('path')=='/feedback/?q=forbidden-sentinel':
                    self.assertIsNone(event['matches'][0]['exception_profile'])
                    self.assertEqual(event['matches'][0]['unapplied_field_profiles'],['example-site'])
    def test_21_unapplied_candidates_do_not_suppress_bans_or_change_observation(self):
        body=b'pwd=forbidden-sentinel&other=forbidden-sentinel'
        with self.alternate_proxy('partial-ban',exception=True,field=True,login=True,reliable=True) as (path,events):
            before=len(self.received)
            for _ in range(2):
                self.assertEqual(self.request(path='/feedback/',body=body,socket_path=path,
                    headers={'Content-Type':'application/x-www-form-urlencoded'})[0],403)
            self.assertEqual(self.request(path='/feedback/',socket_path=path)[0],429)
            self.assertEqual(len(self.received),before)
            records=[json.loads(line) for line in events.read_text().splitlines()]
            matched=[r for r in records if r['matches']]
            self.assertEqual(sum(r['ban_started'] for r in matched),1)
            self.assertTrue(all(r['matches'][0]['exception_profile'] is None and
                r['matches'][0]['unapplied_field_profiles']==['example-site'] for r in matched))
        with self.alternate_proxy('partial-observe',mode='observe',exception=True,field=True,login=True,reliable=True) as (path,events):
            status,_,reply=self.request(path='/feedback/',body=body,socket_path=path,
                headers={'Content-Type':'application/x-www-form-urlencoded'})
            self.assertEqual(status,200);self.assertEqual(reply,body)
            record=json.loads(events.read_text().splitlines()[-1])
            self.assertEqual(record['decision'],'observe');self.assertFalse(record['ban_started'])
            self.assertEqual(record['matches'][0]['unapplied_field_profiles'],['example-site'])
    def test_22_nested_field_configuration_never_invents_confirmation(self):
        with self.alternate_proxy('nested-unconfirmed',exception=True,field='form[fields][1]') as (path,events):
            for body in [b'form[fields][1]=forbidden-sentinel',
                         b'%66orm%5Bfields%5D%5B1%5D=forbidden-sentinel',
                         b'form[fields][1]=forbidden-sentinel&form[fields][2][]=benign',
                         b'form=benign&form[fields][1]=forbidden-sentinel']:
                before=len(self.received)
                status,headers,_=self.request(path='/feedback/',body=body,socket_path=path,
                    headers={'Content-Type':'application/x-www-form-urlencoded','X-Waf-Confirmed-Field':'form[fields][1]'})
                self.assertEqual(status,403)
                self.assertEqual(len(self.received),before)
                event=next(r for r in [json.loads(line) for line in events.read_text().splitlines()] if r['request_id']==headers['x-request-id'])
                self.assertFalse(event['backend_attempted'])
                self.assertIsNone(event['matches'][0]['exception_profile'])
                self.assertNotIn('unapplied_field_profiles',event['matches'][0])

    def test_99_backend_outage_fails_closed(self):
        self.backend.shutdown();self.backend.server_close()
        status,_,_=self.request()
        self.assertEqual(status,502)

if __name__=='__main__':
    unittest.main(verbosity=2)
