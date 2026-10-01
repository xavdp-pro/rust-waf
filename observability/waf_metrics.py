#!/usr/bin/env python3
"""Bounded event aggregation, with no payload, identity or control interface."""
import argparse
import collections
import datetime
import html
import json
from pathlib import Path
from origin_metrics import aggregate, percentile, render

MAX_RECORDS = 25000
MAX_LINE = 65536
MAX_BYTES = 64 * 1024 * 1024

def read_events(path):
    rows = collections.deque(maxlen=MAX_RECORDS)
    rejected = 0
    total = 0
    with Path(path).open('rb') as source:
        while True:
            line = source.readline(MAX_LINE + 1)
            if not line:
                break
            total += len(line)
            if total > MAX_BYTES:
                raise ValueError('Event input exceeds 64 MiB; rotate or select a bounded window')
            if len(line) > MAX_LINE:
                raise ValueError('Event line exceeds 64 KiB')
            try:
                event = json.loads(line)
                if event.get('schema_version') != 1 or event.get('decision') not in ['allow', 'observe', 'block', 'error']:
                    raise ValueError('Unsupported decision event')
                if not isinstance(event.get('elapsed_us'), int) or event['elapsed_us'] < 0:
                    raise ValueError('Invalid duration')
                if not isinstance(event.get('matches'), list):
                    raise ValueError('Invalid matches')
                rows.append(event)
            except (ValueError, AttributeError):
                rejected += 1
    return list(rows), rejected

def summarize(path, active=False):
    events, rejected = read_events(path)
    rules = collections.Counter()
    profiles = collections.Counter()
    policies = collections.Counter()
    exceptions = collections.Counter()
    for event in events:
        for match in event['matches']:
            if not isinstance(match, dict):
                continue
            if isinstance(match.get('rule_id'), str):
                rules[match['rule_id']] += 1
            if isinstance(match.get('policy_id'), str):
                policies[match['policy_id']] += 1
            if isinstance(match.get('profile_id'), str):
                profiles[match['profile_id']] += 1
            if isinstance(match.get('exception_profile'), str):
                exceptions[match['exception_profile']] += 1
    return {'deployed': bool(active and events), 'service_active': active,
        'events_available': bool(events), 'events': len(events), 'max_retained_events': MAX_RECORDS,
        'rejected_lines': rejected, 'decisions': dict(collections.Counter(e['decision'] for e in events)),
        'reasons': dict(collections.Counter(e.get('reason', 'unknown') for e in events)),
        'fingerprints': dict(collections.Counter(e.get('fingerprint', 'unknown') for e in events)),
        'rule_matches': dict(rules), 'policy_matches': dict(policies), 'profile_matches': dict(profiles), 'exceptions': dict(exceptions),
        'ban_starts': sum(e.get('ban_started') is True for e in events),
        'ban_denials': sum(e.get('reason') == 'temporary_local_ban' for e in events),
        'backend_attempts': sum(e.get('backend_attempted') is True for e in events),
        'gateway_total_p50_ms': percentile([e['elapsed_us']/1000 for e in events], .5),
        'gateway_total_p95_ms': percentile([e['elapsed_us']/1000 for e in events], .95),
        'detection_rate': None, 'false_positive_rate': None, 'overhead_p95_ms': None,
        'reason': 'Decision counts are not attack labels. Gateway total duration includes backend work. Independent labeled acceptance and matched baseline/protected measurements remain required.'}

def block(waf):
    status = 'active, with decision events' if waf['deployed'] else 'unverified or inactive'
    groups = '<h3>Currently configured profiles</h3><table><tbody>' + ''.join('<tr>'+''.join('<td>'+html.escape(str(row[key]))+'</td>' for key in ['profile_id','version','layer'])+'</tr>' for row in waf.get('configured_profiles',[])) + '</tbody></table><p>Configured versions do not retroactively identify older event fingerprints.</p>'
    for key, label in [('decisions','Decisions'),('reasons','Reasons'),('rule_matches','Rule matches'),('policy_matches','Policy matches'),('profile_matches','Profile matches'),('exceptions','Exceptions'),('fingerprints','Policy fingerprints')]:
        rows = ''.join('<tr><td>'+html.escape(str(k))+'</td><td>'+str(v)+'</td></tr>' for k,v in sorted(waf[key].items()))
        groups += '<h3>'+label+'</h3><table><tbody>'+rows+'</tbody></table>'
    return '<h2>Rust gateway</h2><p>Engine: '+status+'. Retained events: '+str(waf['events'])+'. Rejected event lines: '+str(waf['rejected_lines'])+'.</p><p>Gateway total duration: median '+str(waf['gateway_total_p50_ms'])+' ms; p95 '+str(waf['gateway_total_p95_ms'])+' ms. This includes backend time.</p><p>Ban starts: '+str(waf['ban_starts'])+'; ban denials: '+str(waf['ban_denials'])+'.</p><p>'+html.escape(waf['reason'])+'</p>'+groups

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--log',required=True)
    parser.add_argument('--waf-log',required=True)
    parser.add_argument('--engine-active',action='store_true')
    parser.add_argument('--output',required=True)
    parser.add_argument('--profile',action='append',default=[])
    args = parser.parse_args()
    data = aggregate(args.log)
    data['waf'] = summarize(args.waf_log,args.engine_active)
    data['waf']['configured_profiles'] = []
    for path in args.profile:
        profile_path = Path(path)
        if profile_path.stat().st_size > 1024*1024:
            raise ValueError('Configured profile exceeds 1 MiB')
        profile = json.loads(profile_path.read_text())
        data['waf']['configured_profiles'].append({key:profile[key] for key in ['profile_id','version','layer']})
    page = render(data)
    old = '<p>The Rust WAF is not deployed. Detection rate, false positives, and overhead are not yet measured. An HTTP denial does not prove that an attack was blocked.</p>'
    page = page.replace(old,block(data['waf']))
    output = Path(args.output)
    output.mkdir(parents=True,exist_ok=True)
    for name,content in [('metrics.json',json.dumps(data,indent=2)),('index.html',page)]:
        temporary = output/(name+'.tmp')
        temporary.write_text(content)
        temporary.chmod(0o644)
        temporary.replace(output/name)
