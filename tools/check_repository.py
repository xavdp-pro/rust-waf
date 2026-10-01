#!/usr/bin/env python3
"""Offline check of the repository foundation; this does not validate a WAF engine."""
import json,re
from pathlib import Path
root=Path(__file__).resolve().parents[1]
required=['README.md','AGENTS.md','CONTRIBUTING.md','docs/architecture.md','docs/status.md','docs/roadmap.md','observability/evaluate_waf.py']
for path in required:
 if not (root/path).is_file():raise SystemExit('Missing required file: '+path)
profiles=[json.loads(p.read_text()) for p in (root/'profiles').rglob('*.json')]
registry={p['profile_id']:p for p in profiles}
if len(registry)!=len(profiles):raise SystemExit('Duplicate profile identifiers')
for profile in profiles:
 if profile['status']!='design-only':raise SystemExit('Example must state its design-only status')
 seen=set();node=profile
 while node is not None:
  name=node['profile_id']
  if name in seen:raise SystemExit('Cyclic inheritance: '+name)
  seen.add(name);parent=node['extends']
  if parent is not None and parent not in registry:raise SystemExit('Missing parent: '+parent)
  node=registry[parent] if parent else None
core=registry['core-base']
if core['ui']!={'mode':'statistics-only','read_only':True,'controls':False}:raise SystemExit('Stats-only UI contract changed')
if core['cloudflare']['per_request_api_calls'] or core['cloudflare']['per_detection_api_calls']:raise SystemExit('Cloudflare API budget contract changed')
if registry['wordpress-base']['extends']!='core-base' or registry['example-site']['extends']!='wordpress-base':raise SystemExit('Layer structure changed')
patterns=[re.compile(r'gh[pousr]_[A-Za-z0-9]{30,}'),re.compile(r'github_pat_[A-Za-z0-9_]{50,}'),re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----')]
for file in root.rglob('*'):
 if not file.is_file() or '.git' in file.parts or '__pycache__' in file.parts:continue
 if file.name.startswith('.env') or file.suffix in {'.pem','.key','.p12','.pfx','.sql','.dump','.db','.token'}:raise SystemExit('Private artifact found: '+str(file.relative_to(root)))
 text=file.read_text(errors='replace')
 if any(pattern.search(text) for pattern in patterns):raise SystemExit('Possible credential material: '+str(file.relative_to(root)))
 if file.suffix=='.md':
  for target in re.findall(r'\[[^]]*\]\(([^)]+)\)',text):
   if '://' in target or target.startswith('#'):continue
   if not (file.parent/target.split('#')[0]).exists():raise SystemExit('Broken local link: '+str(file.relative_to(root))+' -> '+target)
print('Repository foundation passed: three design profiles, valid inheritance, stats-only contract, offline API budget, local links, basic private-material check. No Rust engine was tested.')
