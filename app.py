"""ARP Watch: bounded active probes, durable incidents, read-only MAC tracing."""
import copy,base64,hashlib,hmac,http.server,ipaddress,json,os,pathlib,queue,re,secrets,socket,sqlite3,struct,threading,time
from http.cookies import SimpleCookie
from urllib.parse import urlsplit,urlencode
from urllib.request import build_opener,ProxyHandler
from datetime import datetime,timezone,timedelta
CONFIG=os.environ.get('ARP_CONFIG','/config/config.json')
DATA=pathlib.Path(os.environ.get('ARP_DATA','/data'))
UI_DIR=pathlib.Path(__file__).resolve().parent
from setup_config import KEYS as SETUP_KEYS,public_setup,validate as validate_setup,interfaces,discovery_hosts
def now():return datetime.now(timezone.utc).isoformat()

def password_hash(password):
 salt=secrets.token_bytes(16)
 return {'salt':salt.hex(),'digest':hashlib.pbkdf2_hmac('sha256',password.encode(),salt,300000).hex(),'iterations':300000}

def password_matches(cfg,password):
 record=cfg.get('account_password_hash')
 if record:
  digest=hashlib.pbkdf2_hmac('sha256',password.encode(),bytes.fromhex(record['salt']),record['iterations']).hex()
  return hmac.compare_digest(digest,record['digest'])
 return hmac.compare_digest(password.encode(),cfg['dashboard_password'].encode())

def load_settings(cfg):
 path=pathlib.Path(cfg.get('_settings_path',DATA/'settings.json'))
 if path.exists():
  saved=json.loads(path.read_text())
  for key in ['dashboard_user','account_password_hash','resolved_retention_days']+SETUP_KEYS:
   if key in saved:cfg[key]=saved[key]
 cfg.setdefault('resolved_retention_days',30)

def save_settings(cfg,changes):
 path=pathlib.Path(cfg.get('_settings_path',DATA/'settings.json'));saved={k:cfg[k] for k in ['dashboard_user','account_password_hash','resolved_retention_days']+SETUP_KEYS if k in cfg};saved.update(changes)
 # Separate writable settings retain the read-only switch/notification config.
 tmp=path.with_suffix('.tmp');fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
 try:
  with os.fdopen(fd,'w') as f:json.dump(saved,f);f.flush();os.fsync(f.fileno())
  os.replace(tmp,path)
 finally:
  if tmp.exists():tmp.unlink()
 cfg.update(changes)
def macnorm(m):
 h=re.sub('[^0-9a-f]','',m.lower())
 if len(h)!=12:raise ValueError('Invalid MAC')
 return ':'.join(h[i:i+2] for i in range(0,12,2))
def portnorm(p):
 return p.lower().replace('tengigabitethernet','xge').replace('gigabitethernet','ge').replace('bridge-aggregation','bagg')

def kuma_message(cfg,state,rows):
 parts=[]
 if not state['healthy']:parts.append('ARP Watch monitoring unavailable. Detection cannot be confirmed.')
 for row in rows:
  if row['resolved_at']:continue
  target=next((t for t in cfg['targets'] if t['ip']==row['ip']),{})
  stamp=datetime.fromisoformat(row['first_seen']).astimezone(timezone(timedelta(hours=3))).strftime('%d %B %Y, %H:%M:%S Moscow')
  lines=['ARP conflict: '+row['ip'] if row['kind']=='Duplicate IP replies' else 'ARP identity changed: '+row['ip'],'Incident #'+str(row['id']),'Source: independent ARP probe','', 'Approved device: '+target.get('name','Unknown'),'Approved MAC: '+', '.join(m.upper() for m in row['approved'])]
  for mac in row['macs']:
   if mac in row['approved']:continue
   name=cfg.get('device_labels',{}).get(mac,'Unknown device (identify from MAC)')
   lines+=['','Unexpected device: '+name,'MAC to investigate: '+mac.upper()]
   trace=row['trace'].get(mac,{});path=trace.get('path',[])
   if path:
    last=path[-1];lines+=['','Last confirmed switch: '+last['switch_name'],'Switch IP: '+last['switch_ip'],'Port: '+last['port'],'VLAN: '+str(last['vlan']),'','Verified path:']
    lines += [p['switch_name']+' '+p['switch_ip']+' — '+portnorm(p['port']).upper() if '/' in p['port'] else p['switch_name']+' '+p['switch_ip']+' — port '+p['port'] for p in path]
    if trace.get('status')!='access_port':
     lines.append('Trace incomplete; last confirmed managed hop shown.')
     lines += ['Trace limitation: '+e for e in trace.get('errors',[])]
   else:lines+=['Port trace: pending or unavailable; check the dashboard for updates.']
  present=state.get('targets',{}).get(row['ip'],{}).get('conflict_present')
  lines+=['','First detected: '+stamp,'Current observation: '+('conflict still detected' if present else 'conflict not seen in latest probe; incident remains unresolved'),'Alert remains open after disconnection until Resolve is selected. Saved evidence remains available.']
  parts.append('\n'.join(lines))
 if not parts:parts.append('No unresolved conflicts detected. Monitoring is healthy.')
 text='\n\n'.join(parts)
 if len(text)>3200:text=text[:3200]+'\nFurther incident details are in the dashboard.'
 return text+'\n\nDashboard: '+cfg.get('dashboard_url','http://localhost:8096/')

def kuma_report(cfg,store,sensor):
 opener=build_opener(ProxyHandler({}))
 while True:
  try:
   # Avoid sending an intermediate first-hop snapshot while a quick trace is
   # running. Detection alerts are delayed by at most ten seconds, never hidden.
   deadline=time.monotonic()+10
   while sensor.traces_pending() and time.monotonic()<deadline:time.sleep(.25)
   if not cfg.get('kuma_push_url'):time.sleep(5);continue
   st=sensor.snapshot();message=kuma_message(cfg,st,store.rows())
   url=cfg['kuma_push_url']+'?'+urlencode({'status':'up' if st['state']=='clear' else 'down','msg':message})
   with opener.open(url,timeout=8) as response:
    if not json.load(response).get('ok'):raise RuntimeError('Kuma rejected heartbeat')
   with sensor.lock:sensor.status['notification_error']=None;sensor.status['notification_last_sent']=now()
  except Exception as e:
   # Never include the secret push URL in errors or logs.
   with sensor.lock:sensor.status['notification_error']=type(e).__name__
  time.sleep(60)
def parse_mac_table(text,mac,family):
 rows=[]
 targeted=family=='procurve' and macnorm(mac).replace(':','') in re.sub('[^0-9a-f]','',text.lower()) and 'Address Table -' in text
 for line in text.replace('---- More ----','').splitlines():
  t=line.split()
  if not t:continue
  if targeted and len(t)==2 and re.fullmatch(r'[A-Za-z0-9/]+',t[0]) and t[1].isdigit():
   rows.append({'port':t[0],'vlan':int(t[1]),'raw':mac+' '+line.strip()});continue
  try:match=macnorm(t[0])==macnorm(mac)
  except ValueError:continue
  if not match:continue
  if family=='comware' and len(t)>=4:port,vlan=t[3],t[1]
  elif family=='procurve' and len(t)>=3:port,vlan=t[1],t[2]
  elif family=='cx' and len(t)>=4:port,vlan=t[-1],t[1]
  else:continue
  if not vlan.isdigit():continue
  rows.append({'port':port,'vlan':int(vlan),'raw':line.strip()})
 return rows
class Store:
 def __init__(self,path):
  self.lock=threading.RLock();self.db=sqlite3.connect(path,check_same_thread=False);self.db.row_factory=sqlite3.Row
  self.db.executescript('PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; CREATE TABLE IF NOT EXISTS incidents(id INTEGER PRIMARY KEY,signature TEXT,ip TEXT,kind TEXT,macs TEXT,approved TEXT,first_seen TEXT,last_seen TEXT,hits INTEGER DEFAULT 1,resolved_at TEXT,trace TEXT DEFAULT "{}"); CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY,incident INTEGER,time TEXT,kind TEXT,data TEXT);')
 def event(self,i,kind,data):self.db.execute('INSERT INTO events(incident,time,kind,data) VALUES(?,?,?,?)',(i,now(),kind,json.dumps(data)))
 def detect(self,ip,macs,approved,evidence):
  unexpected=sorted(set(macs)-set(approved));bad=bool(unexpected) if approved else len(macs)>1
  if not bad:return None,False
  sig=ip+'|'+','.join(unexpected or sorted(macs));kind='Duplicate IP replies' if len(macs)>1 else 'Approved MAC changed'
  with self.lock:
   r=self.db.execute('SELECT * FROM incidents WHERE signature=? AND resolved_at IS NULL',(sig,)).fetchone();new=r is None
   if new:
    cur=self.db.execute('INSERT INTO incidents(signature,ip,kind,macs,approved,first_seen,last_seen) VALUES(?,?,?,?,?,?,?)',(sig,ip,kind,json.dumps(sorted(macs)),json.dumps(approved),now(),now()));i=cur.lastrowid;self.event(i,'detected',evidence)
   else:
    i=r['id'];union=sorted(set(json.loads(r['macs']))|set(macs));self.db.execute('UPDATE incidents SET last_seen=?,hits=hits+1,macs=?,kind=? WHERE id=?',(now(),json.dumps(union),kind if len(macs)>1 else r['kind'],i))
   self.db.commit();return i,new
 def rows(self):
  with self.lock:
   out=[]
   for r in self.db.execute('SELECT * FROM incidents ORDER BY id DESC LIMIT 500'):
    d=dict(r)
    for k in ['macs','approved','trace']:d[k]=json.loads(d[k])
    out.append(d)
   return out
 def trace_update(self,i,mac,result):
  with self.lock:
   row=self.db.execute('SELECT trace FROM incidents WHERE id=?',(i,)).fetchone();d=json.loads(row[0]);d[mac]=result
   self.db.execute('UPDATE incidents SET trace=? WHERE id=?',(json.dumps(d),i));self.event(i,'trace',{'mac':mac,'result':result});self.db.commit()
 def resolve(self,i):
  with self.lock:
   r=self.db.execute('SELECT * FROM incidents WHERE id=? AND resolved_at IS NULL',(i,)).fetchone()
   if not r:return False
   self.db.execute('UPDATE incidents SET resolved_at=? WHERE id=?',(now(),i));self.event(i,'resolved',{});self.db.commit();return True
 def open_count(self):
  with self.lock:return self.db.execute('SELECT count(*) FROM incidents WHERE resolved_at IS NULL').fetchone()[0]
 def history(self,i):
  with self.lock:return [dict(r) for r in self.db.execute('SELECT * FROM events WHERE incident=? ORDER BY id',(i,))]
 def prune_resolved(self,days):
  if not days:return 0
  cutoff=(datetime.now(timezone.utc)-timedelta(days=days)).isoformat()
  with self.lock:
   ids=[r[0] for r in self.db.execute('SELECT id FROM incidents WHERE resolved_at IS NOT NULL AND resolved_at<?',(cutoff,))]
   with self.db:
    for i in ids:
     self.db.execute('DELETE FROM events WHERE incident=?',(i,));self.db.execute('DELETE FROM incidents WHERE id=?',(i,))
   return len(ids)

def retention_worker(cfg,store,sensor):
 while True:
  try:
   count=store.prune_resolved(cfg.get('resolved_retention_days',30))
   with sensor.lock:sensor.status.update(retention_checked_at=now(),retention_deleted=count,retention_error=None)
  except Exception as e:
   with sensor.lock:sensor.status['retention_error']=type(e).__name__
  time.sleep(3600)
class Sensor:
 def __init__(self,cfg,store):
  self.cfg=cfg;self.store=store;self.lock=threading.RLock();self.status={'last_cycle':0,'error':'Starting','targets':{},'trace_error':None};self.jobs=queue.Queue();self.pending=set()
 def frame(self,ip):
  return b'\xff'*6+self.mac+b'\x08\x06'+struct.pack('!HHBBH',1,0x0800,6,4,1)+self.mac+b'\0'*4+b'\0'*6+socket.inet_aton(ip)
 def probe(self,ip):
  replies={}
  for attempt in range(2):
   self.sock.send(self.frame(ip));end=time.monotonic()+.6
   while time.monotonic()<end:
    try:f=self.sock.recv(2048)
    except socket.timeout:continue
    offset=14
    if len(f)>46 and f[12:14]==b'\x81\x00':offset=18
    if len(f)<offset+28 or f[offset:offset+8]!=struct.pack('!HHBBH',1,0x0800,6,4,2):continue
    if socket.inet_ntoa(f[offset+14:offset+18])!=ip:continue
    mac=macnorm(f[offset+8:offset+14].hex())
    if f[offset+8:offset+14]==self.mac:continue
    replies[mac]={'mac':mac,'seen':now(),'ethernet_destination':macnorm(f[:6].hex()),'arp_hex':f[:offset+28].hex()}
  return replies
 def queue_trace(self,i,mac):
  with self.lock:
   if (i,mac) not in self.pending:self.pending.add((i,mac));self.jobs.put((i,mac))
 def traces_pending(self):
  with self.lock:return bool(self.pending)
 def cycle(self):
  with self.lock:cfg=copy.deepcopy(self.cfg);revision=cfg.get('_revision',0);targets={ip:t for ip,t in self.status['targets'].items() if t.get('discovery')}
  trusted={t['ip'] for t in cfg['targets']};network=cfg.get('discovery_network','')
  all_candidates=discovery_hosts(network,trusted|{getattr(self,'local_ip','')})
  followups=list(dict.fromkeys(r['ip'] for r in self.store.rows() if not r['resolved_at'] and r['ip'] in all_candidates))[:64]
  candidates=all_candidates
  if getattr(self,'scan_network',None)!=network:self.scan_network=network;self.scan_index=0;self.discovery_seen=set()
  if candidates:
   count=min(2,max(1,int(cfg.get('discovery_batch',2))),len(candidates));batch=[]
   for _ in range(len(candidates)):
    ip=candidates[self.scan_index%len(candidates)];self.scan_index=(self.scan_index+1)%len(candidates)
    if ip not in followups:batch.append(ip)
    if len(batch)>=count:break
   self.discovery_seen.update(batch)
  else:batch=[]
  self.discovery_seen.update(followups)
  selections=cfg['targets']+[{'ip':ip,'name':'Subnet discovery','approved_macs':[],'vlan':1,'discovery':True} for ip in followups+batch]
  for target in selections:
   ip=target['ip'];replies=self.probe(ip);approved=target['approved_macs'];macs=sorted(replies)
   i,new=self.store.detect(ip,macs,approved,{'source':'ARP probe','interface':cfg['interface'],'sender_ip':'0.0.0.0','replies':list(replies.values())})
   targets[ip]={'name':target['name'],'vlan':target.get('vlan',1),'approved_macs':approved,'observed_macs':macs,'checked_at':now(),'conflict_present':bool(set(macs)-set(approved)) if approved else len(macs)>1,'responded':bool(macs),'discovery':target.get('discovery',False)}
   # Publish this observation immediately so a simultaneous notification does
   # not describe the preceding clean cycle after detecting a new conflict.
   with self.lock:
    if self.cfg.get('_revision',0)==revision:self.status['targets'][ip]=targets[ip]
   if i and cfg.get('core') and cfg.get('switches'):
    # Unexpected MACs first, then approved peers. Retry unresolved traces every five minutes.
    row=next(r for r in self.store.rows() if r['id']==i)
    for mac in sorted(macs,key=lambda m:m in approved):
     old=row['trace'].get(mac,{})
     retry_seconds=30 if any(e.startswith('MAC absent or ambiguous') for e in old.get('errors',[])) else 300
     if new or not old or (old.get('status')!='access_port' and time.time()-old.get('epoch',0)>retry_seconds):self.queue_trace(i,mac)
  with self.lock:
   if self.cfg.get('_revision',0)==revision:self.status.update(last_cycle=time.time(),error=None,targets=targets,discovery_checked=len(self.discovery_seen),discovery_total=len(all_candidates),discovery_cursor=getattr(self,'scan_index',0),cycle_seconds=len(selections)*1.2)

 def run(self):
  while True:
   started=time.monotonic()
   try:
    iface=self.cfg['interface']
    if not iface or (not self.cfg.get('targets') and not self.cfg.get('discovery_network')):raise ValueError('Complete the setup wizard before monitoring')
    self.local_ip=next((i['ip'] for i in interfaces() if i['name']==iface),'')
    self.mac=bytes.fromhex(pathlib.Path('/sys/class/net/'+iface+'/address').read_text().strip().replace(':',''))
    self.sock=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(0x0806));self.sock.bind((iface,0));self.sock.settimeout(.1)
    self.cycle()
   except Exception as e:
    with self.lock:self.status['error']=type(e).__name__+': '+str(e)[:160]
   finally:
    if hasattr(self,'sock'):self.sock.close()
   time.sleep(max(1,self.cfg['interval']-(time.monotonic()-started)))
 def snapshot(self):
  with self.lock:st=json.loads(json.dumps(self.status))
  expected=[t['ip'] for t in self.cfg['targets']];freshness=max(self.cfg['interval']*3,st.get('cycle_seconds',0)+self.cfg['interval']+15)
  healthy=not st['error'] and time.time()-st['last_cycle']<freshness and all(st['targets'].get(ip,{}).get('responded') for ip in expected) and bool(expected or self.cfg.get('discovery_network'))
  n=self.store.open_count();st.update(healthy=healthy,open_count=n,state='unavailable' if not healthy else 'incident' if n else 'clear',message='Monitoring unavailable' if not healthy else str(n)+' unresolved incident(s)' if n else 'No unresolved conflicts detected',checked_scope=self.cfg.get('scope_label','Configured addresses / VLAN 1'),trace_jobs=self.jobs.qsize(),probe_interval=self.cfg['interval'],interface=self.cfg.get('interface',''),segments=self.cfg.get('segments',[{'id':1,'name':'Main LAN','network':self.cfg.get('network','Configured LAN'),'status':'active','note':'Selected addresses only.'}]))
  return st
 def tracer(self):
  from cli_runtime import CLI
  while True:
   i,mac=self.jobs.get();path=[];result={'epoch':time.time(),'observed_at':now(),'status':'unresolved','path':path,'topology_source':'Audited LLDP mapping; each MAC location queried live','errors':[]};visited=set();host=self.cfg.get('core','');uplink=None
   try:
    for hop in range(12):
     if host in visited:result['errors'].append('Cycle in path; stopped');break
     visited.add(host);dev=self.cfg['switches'].get(host)
     if not dev:result['status']='last_managed_port';result['errors'].append('Downstream '+host+' lacks a supported tracing adapter; its final port is unverified');break
     cli=None
     try:
      family=dev['family']
      if family=='officeconnect':
       from officeconnect import OfficeConnect
       cli=OfficeConnect(host,dev['username'],dev['password'])
      else:cli=CLI(host,dev['transport'],dev['username'],dev['password'])
      h=mac.replace(':','');cmd='display mac-address '+h[:4]+'-'+h[4:8]+'-'+h[8:] if family=='comware' else 'show mac-address-table address '+mac if family=='cx' else 'show mac-address '+h[:6]+'-'+h[6:]
      # A just-connected device can answer before the first FDB lookup sees it.
      # Retry within the same authenticated session; never repeat a failed login.
      for attempt in range(3):
       if family=='officeconnect':found=cli.lookup(mac)
       else:found=parse_mac_table(cli.command(cmd,10),mac,family)
       rows=[r for r in found if r['vlan']==1 and portnorm(r['port'])!=portnorm(uplink or '')]
       if len(rows)==1:break
       if attempt<2:time.sleep(2)
      if len(rows)!=1:
       result['errors'].append('MAC absent or ambiguous at '+host);result['status']='last_managed_port' if path else 'unresolved';break
      r=rows[0];step={'switch_ip':host,'switch_name':dev['name'],'port':r['port'],'vlan':r['vlan'],'observed_at':now(),'evidence':r['raw']};path.append(step)
      # Persist every hop before continuing, so a disconnect cannot erase the evidence.
      self.store.trace_update(i,mac,result)
      edge=next((e for e in self.cfg['links'] if e['a']==host and portnorm(e['a_port'])==portnorm(r['port'])),None)
      if family=='officeconnect' and r['port'].upper().startswith('TRK') and not edge:
       result['status']='last_managed_port';result['errors'].append('MAC learned on aggregate '+r['port']+'; physical member and downstream path are unverified');break
      if not edge:result['status']='access_port';result['note']='Last managed port. Unmanaged downstream sockets cannot be identified.';break
      host,uplink=edge['b'],edge['b_port'];result['status']='last_managed_port'
     except Exception as e:
      result['errors'].append(host+': '+type(e).__name__);result['status']='last_managed_port' if path else 'unresolved';break
     finally:
      if cli:cli.close()
   finally:
    result['epoch']=time.time();self.store.trace_update(i,mac,result)
    with self.lock:self.pending.discard((i,mac))
    self.jobs.task_done()
 def can_resolve(self,row):
  st=self.snapshot();target=st['targets'].get(row['ip'])
  recent=not target or not target.get('discovery') or time.time()-datetime.fromisoformat(target['checked_at']).timestamp()<max(90,st.get('cycle_seconds',0)+self.cfg['interval']+15)
  return st['healthy'] and target and recent and not target['conflict_present']
def serve(cfg,store,sensor):
 sessions={};session_lock=threading.RLock();attempts={}
 def credentials_match(username,password):
  with session_lock:return hmac.compare_digest(username.encode(),cfg['dashboard_user'].encode()) and password_matches(cfg,password)
 class Handler(http.server.BaseHTTPRequestHandler):
  def log_message(self,*args):pass
  def respond(self,code,data,content='application/json',headers=None):
   body=data if isinstance(data,bytes) else json.dumps(data).encode();self.send_response(code);self.send_header('Content-Type',content);self.send_header('Cache-Control','no-store');self.send_header('X-Content-Type-Options','nosniff');self.send_header('X-Frame-Options','DENY')
   for key,value in (headers or {}).items():self.send_header(key,value)
   self.end_headers();self.wfile.write(body)
  def redirect(self,path):self.respond(303,b'',headers={'Location':path})
  def session_token(self):
   try:
    cookies=SimpleCookie();cookies.load(self.headers.get('Cookie',''));return cookies['arp_session'].value if 'arp_session' in cookies else ''
   except Exception:return ''
  def authenticated(self):
   token=self.session_token()
   with session_lock:
    if sessions.get(token,0)>time.time():return True
   # Retain HTTP Basic for existing API tools only; browser pages use sessions.
   if not self.path.startswith('/api/'):return False
   try:
    user,password=base64.b64decode(self.headers.get('Authorization','').split(' ',1)[1]).decode().split(':',1)
    return credentials_match(user,password)
   except Exception:return False
  def authorized(self):
   ok=self.authenticated()
   if not ok:self.respond(401,{'error':'Sign in required'})
   return ok
  def do_GET(self):
   if self.path=='/live':self.respond(200,{'running':True});return
   if self.path=='/health':
    st=sensor.snapshot();self.respond(200 if st['state']=='clear' else 503,{'state':st['state'],'message':st['message'],'open_count':st['open_count']});return
   if self.path=='/login':
    if self.authenticated():self.redirect('/')
    else:self.respond(200,(UI_DIR/'login.html').read_bytes(),'text/html; charset=utf-8')
    return
   if self.path in ['/','/settings','/setup'] and not self.authenticated():self.redirect('/login');return
   if not self.authorized():return
   if self.path=='/' and not cfg.get('targets') and not cfg.get('discovery_network'):self.redirect('/setup');return
   if self.path=='/':self.respond(200,(UI_DIR/'dashboard.html').read_bytes(),'text/html; charset=utf-8')
   elif self.path=='/setup':self.respond(200,(UI_DIR/'wizard.html').read_bytes(),'text/html; charset=utf-8')
   elif self.path=='/api/setup':
    value=public_setup(cfg);value['csrf']=cfg['csrf'];self.respond(200,value)
   elif self.path=='/settings':self.respond(200,(UI_DIR/'settings.html').read_bytes(),'text/html; charset=utf-8')
   elif self.path=='/api/settings':self.respond(200,{'username':cfg['dashboard_user'],'resolved_retention_days':cfg.get('resolved_retention_days',30),'csrf':cfg['csrf']})
   elif self.path=='/api/state':
    rows=store.rows()
    for r in rows:r['can_resolve']=sensor.can_resolve(r)
    self.respond(200,{'sensor':sensor.snapshot(),'incidents':rows,'csrf':cfg['csrf']})
   elif re.fullmatch(r'/api/incident/\d+',self.path):self.respond(200,{'events':store.history(int(self.path.rsplit('/',1)[1]))})
   else:self.respond(404,{'error':'Not found'})
  def do_POST(self):
   if self.path=='/api/login':
    origin=self.headers.get('Origin')
    if origin and urlsplit(origin).netloc!=self.headers.get('Host'):self.respond(403,{'error':'Invalid request origin'});return
    try:
     size=int(self.headers.get('Content-Length',0))
     if size<1 or size>4096:raise ValueError()
     body=json.loads(self.rfile.read(size));username=str(body.get('username',''));password=str(body.get('password',''))
    except Exception:self.respond(400,{'error':'Invalid login request'});return
    ip=self.client_address[0]
    with session_lock:
     recent=[t for t in attempts.get(ip,[]) if t>time.time()-60]
     if len(recent)>=10:self.respond(429,{'error':'Too many attempts. Try again in one minute.'});return
     if not credentials_match(username,password):attempts[ip]=recent+[time.time()];self.respond(401,{'error':'Incorrect username or password'});return
     attempts.pop(ip,None)
     for t in list(sessions):
      if sessions[t]<=time.time():sessions.pop(t,None)
     if len(sessions)>=1000:self.respond(503,{'error':'Session limit reached'});return
     token=secrets.token_urlsafe(32);sessions[token]=time.time()+28800
    cookie='arp_session='+token+'; Path=/; HttpOnly; SameSite=Strict; Max-Age=28800'+('; Secure' if cfg.get('cookie_secure',False) else '')
    self.respond(200,{'signed_in':True},headers={'Set-Cookie':cookie});return
   if not self.authorized():return
   if self.headers.get('X-CSRF-Token')!=cfg['csrf']:self.respond(403,{'error':'CSRF check failed'});return
   if self.path=='/api/setup':
    try:
     size=int(self.headers.get('Content-Length',0))
     if size<1 or size>65536:raise ValueError('Invalid setup request size')
     body=json.loads(self.rfile.read(size))
     if not body.get('review_confirmed'):raise ValueError('Review and confirm the monitoring scope before saving')
     with session_lock:
      recent=[t for t in attempts.get(self.client_address[0],[]) if t>time.time()-60]
      if len(recent)>=10:self.respond(429,{'error':'Too many attempts. Try again in one minute.'});return
      if not password_matches(cfg,str(body.get('current_password',''))):attempts[self.client_address[0]]=recent+[time.time()];self.respond(401,{'error':'Current password is incorrect'});return
      attempts.pop(self.client_address[0],None)
      changes=validate_setup(body,cfg,interfaces());trusted={t['ip'] for t in changes['targets']};network=ipaddress.ip_network(changes['discovery_network']) if changes['discovery_network'] else None
      for row in store.rows():
       if not row['resolved_at'] and row['ip'] not in trusted and (not network or ipaddress.ip_address(row['ip']) not in network):raise ValueError('Resolve existing incidents before removing their IP from monitoring')
      with sensor.lock:
       save_settings(cfg,changes);cfg['_revision']=cfg.get('_revision',0)+1;sensor.status.update(last_cycle=0,error='Configuration saved; waiting for first check',targets={});sensor.scan_network=None
     self.respond(200,{'saved':True,'message':'Monitoring will apply the saved setup on the next cycle. Existing incident evidence is retained.'})
    except (ValueError,KeyError,TypeError) as e:self.respond(400,{'error':str(e)})
    except Exception:self.respond(500,{'error':'Setup could not be saved'})
    return
   if self.path=='/api/settings':
    try:
     size=int(self.headers.get('Content-Length',0))
     if size<1 or size>4096:raise ValueError('Invalid request size')
     body=json.loads(self.rfile.read(size));username=body.get('username',cfg['dashboard_user']);password=body.get('new_password','');days=body.get('resolved_retention_days',cfg.get('resolved_retention_days',30))
     if not isinstance(username,str) or not re.fullmatch(r'[A-Za-z0-9_.@-]{1,64}',username):raise ValueError('Username must be 1–64 letters, digits, or _ . @ -')
     if not isinstance(password,str) or (password and not 12<=len(password)<=256):raise ValueError('New password must contain 12–256 characters')
     if isinstance(days,bool) or not isinstance(days,int) or not 0<=days<=3650:raise ValueError('Retention must be 0–3650 days; 0 keeps resolved incidents indefinitely')
     ip=self.client_address[0]
     with session_lock:
      recent=[t for t in attempts.get(ip,[]) if t>time.time()-60]
      if len(recent)>=10:self.respond(429,{'error':'Too many attempts. Try again in one minute.'});return
      if not password_matches(cfg,str(body.get('current_password',''))):attempts[ip]=recent+[time.time()];self.respond(401,{'error':'Current password is incorrect'});return
      attempts.pop(ip,None)
     with session_lock:
      changes={'dashboard_user':username,'resolved_retention_days':days};changed=username!=cfg['dashboard_user'] or bool(password)
      if password:changes['account_password_hash']=password_hash(password)
      save_settings(cfg,changes)
      if changed:sessions.clear();cfg['csrf']=secrets.token_urlsafe(32)
     deleted=store.prune_resolved(days)
     self.respond(200,{'saved':True,'sign_in_required':changed,'deleted_resolved_incidents':deleted},headers={'Set-Cookie':'arp_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0'} if changed else None)
    except ValueError as e:self.respond(400,{'error':str(e)})
    except Exception:self.respond(500,{'error':'Settings could not be saved; check service storage'})
    return
   if self.path=='/api/logout':
    with session_lock:sessions.pop(self.session_token(),None)
    self.respond(200,{'signed_out':True},headers={'Set-Cookie':'arp_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0'});return
   if self.path=='/api/retrace':
    try:
     size=int(self.headers.get('Content-Length',0))
     if size<1 or size>1024:raise ValueError()
     i=int(json.loads(self.rfile.read(size))['id']);row=next(r for r in store.rows() if r['id']==i)
     for mac in sorted(row['macs'],key=lambda m:m in row['approved']):sensor.queue_trace(i,mac)
     with store.lock:store.event(i,'trace_retry_requested',{});store.db.commit()
     self.respond(200,{'queued':True,'incident_id':i})
    except Exception:self.respond(400,{'error':'Invalid incident'})
    return
   if self.path!='/api/resolve':self.respond(404,{'error':'Not found'});return
   try:
    size=int(self.headers.get('Content-Length',0))
    if size>1024:raise ValueError()
    i=int(json.loads(self.rfile.read(size))['id']);row=next(r for r in store.rows() if r['id']==i)
    if not sensor.can_resolve(row):self.respond(409,{'error':'Conflict still observed or monitoring unavailable. Recheck after removing the device.'});return
    self.respond(200,{'resolved':store.resolve(i)})
   except Exception:self.respond(400,{'error':'Invalid request'})
 http.server.ThreadingHTTPServer((cfg['bind'],cfg['port']),Handler).serve_forever()
if __name__=='__main__':
 cfg=json.loads(pathlib.Path(CONFIG).read_text());DATA.mkdir(exist_ok=True);load_settings(cfg);store=Store(DATA/'incidents.sqlite3');sensor=Sensor(cfg,store)
 threading.Thread(target=retention_worker,args=(cfg,store,sensor),daemon=True).start()
 threading.Thread(target=sensor.run,daemon=True).start();threading.Thread(target=sensor.tracer,daemon=True).start()
 if True:
  # Allow the first probe cycle to finish before sending the startup heartbeat.
  def start_report():time.sleep(18);kuma_report(cfg,store,sensor)
  threading.Thread(target=start_report,daemon=True).start()
 serve(cfg,store,sensor)
