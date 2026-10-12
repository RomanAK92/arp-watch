"""Isolated HTTP lifecycle test. No ARP packets, switch logins, or notifications."""
import base64,json,pathlib,secrets,tempfile,threading,time,urllib.request,urllib.error
from app import Store,Sensor,serve
temp=tempfile.TemporaryDirectory();store=Store(pathlib.Path(temp.name)/'test.sqlite3');password=secrets.token_urlsafe(12)
cfg={'targets':[{'ip':'192.0.2.1'}],'interval':15,'bind':'127.0.0.1','port':8097,'dashboard_user':'test','dashboard_password':password,'csrf':secrets.token_urlsafe(20),'_settings_path':str(pathlib.Path(temp.name)/'settings.json')}
sensor=Sensor(cfg,store);good='aa:bb:cc:dd:ee:01';bad='aa:bb:cc:dd:ee:02'
sensor.status={'last_cycle':time.time(),'error':None,'targets':{'192.0.2.1':{'responded':True,'conflict_present':False}}}
threading.Thread(target=serve,args=(cfg,store,sensor),daemon=True).start();time.sleep(.3)
auth='Basic '+base64.b64encode(('test:'+password).encode()).decode()
def req(path,body=None,authorized=True,csrf=True):
 headers={'Authorization':auth} if authorized else {}
 if csrf:headers['X-CSRF-Token']=cfg['csrf']
 data=json.dumps(body).encode() if body is not None else None
 r=urllib.request.Request('http://127.0.0.1:8097'+path,data=data,headers=headers)
 try:
  with urllib.request.urlopen(r,timeout=3) as response:return response.status,response.read()
 except urllib.error.HTTPError as e:return e.code,e.read()
assert req('/health')[0]==200
assert req('/api/state',authorized=False)[0]==401
assert req('/login',authorized=False)[0]==200
assert req('/api/login',{'username':'test','password':'incorrect'},authorized=False)[0]==401
login=urllib.request.Request('http://127.0.0.1:8097/api/login',data=json.dumps({'username':'test','password':password}).encode(),headers={'Content-Type':'application/json'})
with urllib.request.urlopen(login,timeout=3) as response:
 cookie=response.headers['Set-Cookie'];assert 'HttpOnly' in cookie and 'SameSite=Strict' in cookie
cookie=cookie.split(';',1)[0]
with urllib.request.urlopen(urllib.request.Request('http://127.0.0.1:8097/api/state',headers={'Cookie':cookie}),timeout=3) as response:assert response.status==200
logout=urllib.request.Request('http://127.0.0.1:8097/api/logout',data=b'{}',headers={'Cookie':cookie,'X-CSRF-Token':cfg['csrf']})
with urllib.request.urlopen(logout,timeout=3) as response:assert response.status==200
try:
 urllib.request.urlopen(urllib.request.Request('http://127.0.0.1:8097/api/state',headers={'Cookie':cookie}),timeout=3);raise AssertionError('Logged-out session still valid')
except urllib.error.HTTPError as error:assert error.code==401
i,_=store.detect('192.0.2.1',[good,bad],[good],{'source':'isolated test; no network packets'})
sensor.status['targets']['192.0.2.1']['conflict_present']=True
assert req('/health')[0]==503
assert req('/api/settings',authorized=False)[0]==401
assert req('/api/settings',{'current_password':password,'resolved_retention_days':30},csrf=False)[0]==403
assert req('/api/settings',{'current_password':'wrong','resolved_retention_days':30})[0]==401
assert req('/api/settings',{'current_password':password,'resolved_retention_days':-1})[0]==400
assert req('/api/settings',{'current_password':password,'new_password':'short'})[0]==400
assert req('/api/settings',{'current_password':password,'resolved_retention_days':60})[0]==200
assert store.open_count()==1  # Retention cannot delete the active incident.
assert req('/api/retrace',{'id':i})[0]==200
assert store.open_count()==1 and sensor.jobs.qsize()==2
assert req('/api/resolve',{'id':i})[0]==409
sensor.status['targets']['192.0.2.1']['conflict_present']=False
assert req('/health')[0]==503  # Disconnection alone does not clear the latch.
assert req('/api/resolve',{'id':i},csrf=False)[0]==403
assert req('/api/resolve',{'id':i})[0]==200
assert req('/health')[0]==200
assert [e['kind'] for e in store.history(i)]==['detected','trace_retry_requested','resolved']
sensor.status['error']='Isolated unavailable test'
assert req('/health')[0]==503
# Credential changes invalidate existing browser sessions and old API credentials.
with urllib.request.urlopen(login,timeout=3) as response:active_cookie=response.headers['Set-Cookie'].split(';',1)[0]
new_password=secrets.token_urlsafe(18)
assert req('/api/settings',{'current_password':password,'username':'changed','new_password':new_password,'resolved_retention_days':30})[0]==200
assert req('/api/state')[0]==401
try:
 urllib.request.urlopen(urllib.request.Request('http://127.0.0.1:8097/api/state',headers={'Cookie':active_cookie}),timeout=3);raise AssertionError('Old session remained valid after account change')
except urllib.error.HTTPError as error:assert error.code==401
assert req('/api/login',{'username':'changed','password':new_password},authorized=False)[0]==200
saved=json.loads(pathlib.Path(cfg['_settings_path']).read_text());assert saved['dashboard_user']=='changed' and 'account_password_hash' in saved and new_password not in json.dumps(saved)
print(json.dumps({'test':'isolated HTTP lifecycle','passed':True,'production_incidents_touched':False,'arp_packets_sent':0,'notifications_sent':0}))

store.db.close()
temp.cleanup()
