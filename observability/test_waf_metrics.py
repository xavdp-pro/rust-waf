#!/usr/bin/env python3
"""Verify body-free aggregation and honest unavailable effectiveness metrics."""
import json
import tempfile
from pathlib import Path
from waf_metrics import summarize, block
with tempfile.TemporaryDirectory() as directory:
    source=Path(directory)/'events'
    event={'schema_version':1,'decision':'block','reason':'rule_match','elapsed_us':2500,
        'fingerprint':'synthetic','backend_attempted':False,'ban_started':True,
        'matches':[{'rule_id':'fictional.rule','profile_id':'fictional-core','exception_profile':None}],
        'body':'PRIVATE_SENTINEL','cookie':'PRIVATE_SENTINEL','client_ip':'PRIVATE_SENTINEL'}
    source.write_text('not json\n'+json.dumps(event)+'\n')
    result=summarize(source,True)
    assert result['deployed'] and result['rejected_lines']==1 and result['decisions']=={'block':1}
    assert result['backend_attempts']==0 and result['gateway_total_p95_ms']==2.5
    assert result['detection_rate'] is None and result['false_positive_rate'] is None and result['overhead_p95_ms'] is None
    assert 'PRIVATE_SENTINEL' not in json.dumps(result)+block(result)
    assert not summarize(source,False)['deployed']
    event['reason']='temporary_local_ban'
    source.write_text(json.dumps(event)+'\n')
    assert summarize(source,True)['ban_denials']==1
    event['matches']=[{'policy_id':'fictional.method-policy','profile_id':'fictional-site'}]
    event['ban_started']=False
    source.write_text(json.dumps(event)+'\n')
    result=summarize(source,True)
    assert result['policy_matches']=={'fictional.method-policy':1} and result['rule_matches']=={}
    assert 'fictional.method-policy' in block(result)
    source.write_bytes(b'x'*65537)
    try:summarize(source)
    except ValueError:pass
    else:raise AssertionError('Oversized record accepted')
print('WAF_METRICS_TEST_PASSED (synthetic aggregation proof, not effectiveness)')
