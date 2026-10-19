"""Availability diagnostics: bounded durable logs and secret-safe alert details."""
import copy,datetime,json,logging,logging.handlers,os,pathlib,re,threading,time

def safe_error(error,cfg):
 if isinstance(error,OSError) and error.errno is not None:
  text=type(error).__name__+' (errno '+str(error.errno)+'): '+os.strerror(error.errno)
 else:text=type(error).__name__+': '+str(error)
 def redact(value):
  nonlocal text
  if isinstance(value,dict):
   for key,item in value.items():
    if any(word in key.lower() for word in ['password','secret','token','csrf','push_url']) and isinstance(item,str) and item:text=text.replace(item,'[redacted]')
    else:redact(item)
  elif isinstance(value,list):
   for item in value:redact(item)
 redact(cfg)
 return re.sub(r'https?://\S+','[URL omitted]',text).replace('\r',' ').replace('\n',' ')[:240]

def details(state,targets,interval,epoch):
 age=max(0,epoch-state['last_cycle']) if state.get('last_cycle') else None
 threshold=max(interval*3,state.get('cycle_seconds',0)+interval+15)
 failed=[]
 for target in targets:
  observed=state.get('targets',{}).get(target['ip'],{})
  if not observed.get('responded'):
   failed.append({'ip':target['ip'],'name':target.get('name','Monitored device'),'reason':'No ARP reply observed' if observed.get('checked_at') else 'Not checked in a completed observation yet','last_check_at':observed.get('checked_at'),'last_reply_at':observed.get('last_reply_at')})
 reasons=[]
 if state.get('error'):reasons.append('Probe error: '+state['error'])
 if failed:reasons.append('Missing replies: '+', '.join(item['ip'] for item in failed))
 stale=age is not None and age>=threshold
 if age is None:reasons.append('No completed probe cycle yet')
 elif stale:reasons.append('Probe results are stale')
 return {'interface':state.get('interface'),'failed_targets':failed,'probe_error':state.get('error'),'failed_probe_ip':state.get('failed_probe_ip'),'cycle_age_seconds':round(age,1) if age is not None else None,'freshness_threshold_seconds':threshold,'last_complete_cycle_at':datetime.datetime.fromtimestamp(state['last_cycle'],datetime.timezone.utc).isoformat() if state.get('last_cycle') else None,'stale':stale,'reasons':reasons}

def summary_lines(info):
 lines=['Interface: '+str(info.get('interface') or 'not selected')]
 for item in info.get('failed_targets',[])[:12]:
  lines.append(item['ip']+' ('+item['name']+'): '+item['reason'])
  if item.get('last_reply_at'):lines.append('Last reply: '+item['last_reply_at'])
 if len(info.get('failed_targets',[]))>12:lines.append('Additional failed addresses: '+str(len(info['failed_targets'])-12)+'; see availability log')
 if info.get('probe_error'):lines.append('Probe error: '+info['probe_error'])
 if info.get('failed_probe_ip'):lines.append('Probe target when error occurred: '+info['failed_probe_ip'])
 if info.get('cycle_age_seconds') is None:lines.append('No completed probe cycle yet')
 elif info.get('stale'):lines.append('Stale probe results: '+str(info['cycle_age_seconds'])+' seconds old; threshold '+str(info['freshness_threshold_seconds'])+' seconds')
 return lines

class Availability:
 def __init__(self,path):
  self.path=pathlib.Path(path);self.lock=threading.RLock();self.failure=None;self.last_outage=None;self.fingerprint=None;self.last_log=0;self.ever_healthy=False
 def log(self,event,data):
  with self.lock:self._log(event,data)
 def _log(self,event,data):
  row={'time_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'event':event,**data};line=json.dumps(row,ensure_ascii=False)
  # stdout uses the existing Docker rotation; the private file survives recreation.
  print(line,flush=True)
  handler=None
  try:
   self.path.parent.mkdir(parents=True,exist_ok=True)
   handler=logging.handlers.RotatingFileHandler(self.path,maxBytes=2*1024*1024,backupCount=3,encoding='utf-8',delay=True)
   handler.setFormatter(logging.Formatter('%(message)s'))
   handler.emit(logging.LogRecord('arp-watch.availability',logging.INFO,'',0,line,(),None))
   if self.path.exists():self.path.chmod(0o600)
  except OSError as error:print(json.dumps({'time_utc':row['time_utc'],'event':'availability_log_write_failed','error':type(error).__name__}),flush=True)
  finally:
   if handler:handler.close()
 def observe(self,healthy,info,epoch=None):
  epoch=time.time() if epoch is None else epoch
  stamp=datetime.datetime.fromtimestamp(epoch,datetime.timezone.utc).isoformat()
  with self.lock:
   if not healthy:
    # Ordinary initialization is not reported as a recovered outage.
    if not self.ever_healthy and info.get('probe_error')=='Starting' and info.get('cycle_age_seconds') is None:return None
    fingerprint=json.dumps({'failed':[x['ip'] for x in info['failed_targets']],'error':info['probe_error'],'probe_ip':info['failed_probe_ip'],'stale':info['stale']},sort_keys=True)
    if self.failure is None:self.failure={'started_at':stamp,'started_epoch':epoch,'first_details':copy.deepcopy(info),'failed_ips':[]}
    self.failure['failed_ips']=sorted(set(self.failure['failed_ips'])|{x['ip'] for x in info['failed_targets']})
    self.failure.update(last_observed_at=stamp,last_details=copy.deepcopy(info))
    if fingerprint!=self.fingerprint or epoch-self.last_log>=300:
     self.log('monitoring_unavailable',{'unavailable_since':self.failure['started_at'],**info});self.last_log=epoch;self.fingerprint=fingerprint
   else:
    if not self.ever_healthy and self.failure is None:self.log('monitoring_started',{'interface':info.get('interface'),'last_complete_cycle_at':info.get('last_complete_cycle_at')})
    if self.failure is not None:
     self.last_outage={**copy.deepcopy(self.failure),'recovered_at':stamp,'recovered_epoch':epoch,'duration_seconds':round(epoch-self.failure['started_epoch'],1)}
     self.log('monitoring_recovered',self.last_outage);self.failure=None;self.fingerprint=None
    self.ever_healthy=True
   return copy.deepcopy(self.last_outage) if self.last_outage and epoch-self.last_outage['recovered_epoch']<=900 else None
