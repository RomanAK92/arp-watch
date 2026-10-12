"""Create a private starter configuration; review it before deploying."""
import json,os,pathlib,secrets
p=pathlib.Path('config.json')
if p.exists():raise SystemExit('config.json already exists; leaving it unchanged')
cfg=json.loads(pathlib.Path('config.example.json').read_text());cfg['dashboard_password']=secrets.token_urlsafe(24);cfg['csrf']=secrets.token_urlsafe(32)
cfg.update(interface='',targets=[],core='',switches={},links=[],network='',setup_complete=False)
fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
with os.fdopen(fd,'w') as f:json.dump(cfg,f,indent=2)
print('Created config.json with a unique dashboard password and CSRF secret.')
print('Read credentials locally from config.json, start Docker Compose, and sign in to complete the setup wizard.')
