#!/usr/bin/env python3
"""Aggregate origin observations; never infer WAF effectiveness from HTTP status."""
import argparse,collections,datetime,html,json,math,os,statistics
from pathlib import Path

def percentile(values,p):
 if not values:return None
 v=sorted(values);return round(v[max(0,math.ceil(len(v)*p)-1)],2)

MAX_INPUT_BYTES = 64 * 1024 * 1024
MAX_LINE_BYTES = 65536
MAX_RECORDS = 25000

def read_origin(log):
 events=collections.deque(maxlen=MAX_RECORDS);malformed=0;oversized=0;dropped=0
 with Path(log).open('rb') as source:
  size=os.fstat(source.fileno()).st_size
  offset=max(0,size-MAX_INPUT_BYTES+1) if size>MAX_INPUT_BYTES else 0
  scanned=0;prefix=False
  if offset:
   source.seek(offset-1);prefix=source.read(1)!=b'\n';scanned=1
  source.seek(offset);remaining=size-offset;discarding=prefix
  while remaining:
   line=source.readline(min(MAX_LINE_BYTES+1,remaining));remaining-=len(line);scanned+=len(line)
   if not line:break
   if discarding:
    discarding=not line.endswith(b'\n');continue
   if len(line)>MAX_LINE_BYTES:
    oversized+=1;malformed+=1;discarding=not line.endswith(b'\n');continue
   try:
    e=json.loads(line)
    if not isinstance(e,dict):raise ValueError('Invalid origin record')
    if not isinstance(e.get('method'),str) or not 1<=len(e['method'])<=32:raise ValueError('Invalid method')
    if not isinstance(e.get('path'),str) or not 1<=len(e['path'])<=8192:raise ValueError('Invalid path')
    if not isinstance(e.get('ts'),str) or not 1<=len(e['ts'])<=128:raise ValueError('Invalid timestamp')
    if type(e.get('status')) is not int or not 100<=e['status']<=599:raise ValueError('Invalid status')
    if type(e.get('seconds')) not in (int,float) or not math.isfinite(e['seconds']) or e['seconds']<0:raise ValueError('Invalid duration')
    if any(type(e.get(k,0)) is not int or e.get(k,0) not in (0,1) for k in ['admin_denied','method_denied']):raise ValueError('Invalid denial counter')
    # Discard unknown fields rather than retaining arbitrary input metadata.
    row={k:e[k] for k in ['ts','method','path','status','seconds']}
    row.update({k:e.get(k,0) for k in ['admin_denied','method_denied']})
    dropped+=len(events)==MAX_RECORDS;events.append(row)
   except (ValueError,TypeError,RecursionError,OverflowError):malformed+=1
 window={'file_size_bytes':size,'offset_bytes':offset,'bytes_scanned':scanned,
  'max_input_bytes':MAX_INPUT_BYTES,'max_line_bytes':MAX_LINE_BYTES,'max_retained_records':MAX_RECORDS,
  'discarded_prefix_fragment':prefix,'oversized_lines':oversized,'retention_dropped':dropped,
  'complete_file_scanned':offset==0 and remaining==0}
 return list(events),malformed,window

def aggregate(log):
 events,malformed,window=read_origin(log)
 routes=collections.defaultdict(lambda:{'requests':0,'errors_5xx':0,'admin_denied':0,'method_denied':0,'latency_ms':[]})
 for e in events:
  row=routes[(e['method'],e['path'])];row['requests']+=1;row['errors_5xx']+=e['status']>=500;row['admin_denied']+=e.get('admin_denied',0);row['method_denied']+=e.get('method_denied',0);row['latency_ms'].append(e['seconds']*1000)
 rows=[]
 for (method,path),v in routes.items():
  times=v.pop('latency_ms');rows.append({'method':method,'path':path,**v,'p50_ms':percentile(times,.5),'p95_ms':percentile(times,.95)})
 rows.sort(key=lambda r:(-r['requests'],r['path']))
 total=len(events)
 return {'generated_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'scope':'Bounded recent origin window; at most 25,000 valid records from the final 64 MiB; synthetic verification is included','input_window':window,'first_event':events[0]['ts'] if events else None,'last_event':events[-1]['ts'] if events else None,'requests':total,'status_counts':dict(collections.Counter(str(e['status']) for e in events)),'admin_denied':sum(e.get('admin_denied',0) for e in events),'method_denied':sum(e.get('method_denied',0) for e in events),'errors_5xx':sum(e['status']>=500 for e in events),'p50_ms':percentile([e['seconds']*1000 for e in events],.5),'p95_ms':percentile([e['seconds']*1000 for e in events],.95),'malformed_lines':malformed,'waf':{'deployed':False,'detection_rate':None,'false_positive_rate':None,'overhead_p95_ms':None,'reason':'Requires Rust decision events and labeled attack/legitimate corpus, followed by matched baseline/protected runs'},'routes':rows}

def render(d):
 rows=''.join('<tr>'+''.join('<td>'+html.escape(str(r[k]))+'</td>' for k in ['method','path','requests','admin_denied','method_denied','errors_5xx','p50_ms','p95_ms'])+'</tr>' for r in d['routes'])
 return '''<!doctype html><html lang="en"><meta charset="utf-8"><title>WAF measurements</title><meta name="viewport" content="width=device-width,initial-scale=1"><style>body{font:16px system-ui;max-width:1200px;margin:32px auto;padding:0 20px;color:#17212a;background:#fafafa}h1{font-size:24px}table{border-collapse:collapse;width:100%;font-size:14px}td,th{padding:10px;text-align:left;border-bottom:1px solid #ddd}code{word-break:break-all}small{color:#566}</style><h1>Origin measurements</h1>'''+f'<p><strong>{d["requests"]} requests</strong> · {d["admin_denied"]} administration network denials · {d["method_denied"]} method denials · {d["errors_5xx"]} server errors</p><p>Total origin latency : median {d["p50_ms"]} ms · p95 {d["p95_ms"]} ms.</p><p>The Rust WAF is not deployed. Detection rate, false positives, and overhead are not yet measured. An HTTP denial does not prove that an attack was blocked.</p><small>Source: {html.escape(d["scope"])}. Scanned {d["input_window"]["bytes_scanned"]} bytes; complete file: {d["input_window"]["complete_file_scanned"]}; dropped by record retention: {d["input_window"]["retention_dropped"]}; rejected records: {d["malformed_lines"]}. Refresh depends on the deployment scheduler. Generated {html.escape(d["generated_at"])}.</small><h2>Observed routes</h2><table><thead><tr><th>Method</th><th>Path</th><th>Requests</th><th>Admin denials</th><th>Method denials</th><th>5xx errors</th><th>p50 (ms)</th><th>p95 (ms)</th></tr></thead><tbody>'+rows+'</tbody></table><p><a href="metrics.json">JSON data</a></p></html>'

if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--log',default='/var/log/nginx/waf-metrics.jsonl');p.add_argument('--output',default='/var/lib/waf-observability/report');a=p.parse_args();d=aggregate(a.log);out=Path(a.output);out.mkdir(parents=True,exist_ok=True)
 for name,content in [('metrics.json',json.dumps(d,ensure_ascii=False,indent=2)),('index.html',render(d))]:
  temporary=out/(name+'.tmp');temporary.write_text(content);temporary.chmod(0o644);temporary.replace(out/name)
