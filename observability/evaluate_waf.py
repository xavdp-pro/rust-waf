#!/usr/bin/env python3
"""Score labeled Rust-WAF decisions, separately from origin HTTP status codes."""
import argparse,json

def evaluate(records):
 counts={'tp':0,'fp':0,'tn':0,'fn':0};bypasses=0;proofs=0;blocked=0
 for r in records:
  if r.get('bypass',False):bypasses+=1;continue
  if r['label'] not in ('malicious','legitimate') or r['decision'] not in ('block','allow'):raise ValueError('Invalid label or WAF decision')
  malicious=r['label']=='malicious';block=r['decision']=='block'
  counts['tp' if malicious and block else 'fn' if malicious else 'fp' if block else 'tn']+=1
  if block:
   blocked+=1
   if r.get('backend_reached') is False:proofs+=1
 def ratio(n,d):return n/d if d else None
 return {**counts,'labeled_cases':sum(counts.values()),'bypass_cases_excluded':bypasses,'detection_rate':ratio(counts['tp'],counts['tp']+counts['fn']),'false_positive_rate':ratio(counts['fp'],counts['fp']+counts['tn']),'precision':ratio(counts['tp'],counts['tp']+counts['fp']),'backend_non_execution_proven':proofs,'blocked_cases':blocked,'backend_proof_coverage':ratio(proofs,blocked),'note':'Scores require actual Rust decisions and independently labeled cases; HTTP status alone is insufficient.'}

if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('results',nargs='?');p.add_argument('--self-test',action='store_true');a=p.parse_args()
 if a.self_test:
  rows=[{'label':label,'decision':decision,'backend_reached':False} for label in ['malicious','legitimate'] for decision in ['block','allow']]
  r=evaluate(rows);assert r['tp']==r['fp']==r['tn']==r['fn']==1 and r['detection_rate']==r['false_positive_rate']==.5
  assert evaluate([])['detection_rate'] is None
  assert evaluate([{'bypass':True}])['labeled_cases']==0
  print('SCORER_SELF_TEST_PASSED (synthetic unit fixture; not WAF effectiveness)')
 else:
  if not a.results:p.error('results JSON file is required')
  print(json.dumps(evaluate(json.load(open(a.results))),indent=2))
