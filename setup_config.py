"""Setup validation and bounded subnet discovery. No network writes."""
import copy,ipaddress,re,socket,struct
from urllib.parse import urlsplit
KEYS=['interface','network','scope_label','targets','discovery_network','discovery_batch','core','switches','links','kuma_push_url','dashboard_url','setup_complete','segments']
def interfaces():
 rows=[]
 try:import fcntl
 except ImportError:return rows
 with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
  for _,name in socket.if_nameindex():
   if name=='lo':continue
   try:
    req=struct.pack('256s',name.encode()[:15]);ip=socket.inet_ntoa(fcntl.ioctl(s.fileno(),0x8915,req)[20:24]);mask=socket.inet_ntoa(fcntl.ioctl(s.fileno(),0x891b,req)[20:24]);network=str(ipaddress.ip_network(ip+'/'+mask,strict=False));rows.append({'name':name,'ip':ip,'network':network})
   except OSError:continue
 return rows

def normalize_mac(value):
 if not isinstance(value,str) or not re.fullmatch(r'(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}',value):raise ValueError('Use a MAC address such as 02:00:00:00:00:01')
 return value.lower().replace('-',':')
def ipv4(value):
 address=ipaddress.ip_address(value)
 if address.version!=4 or address.is_multicast or address.is_unspecified or address.is_loopback:raise ValueError('Use a unicast IPv4 address')
 return str(address)
def validate(body,current,available):
 iface=next((i for i in available if i['name']==body.get('interface')),None)
 if not iface:raise ValueError('Choose an available Linux interface with an IPv4 address')
 net=ipaddress.ip_network(body['network'],strict=True);local=ipaddress.ip_network(iface['network'])
 if net.version!=4 or net.prefixlen>30 or not net.subnet_of(local):raise ValueError('Network must be an IPv4 subnet on the selected interface (prefix /30 or larger)')
 targets=[];seen=set()
 for t in body.get('targets',[]):
  ip=ipv4(t['ip']);name=str(t.get('name','Trusted device')).strip()[:80];macs=sorted({normalize_mac(m) for m in t.get('approved_macs',[])})
  if ipaddress.ip_address(ip) not in net or ip in [str(net.network_address),str(net.broadcast_address)] or ip==iface['ip']:raise ValueError('Trusted IP must be a host in the selected network, other than the sensor itself')
  if ip in seen:raise ValueError('Each trusted IP can appear only once')
  if not macs:raise ValueError('Each trusted device requires an explicitly approved MAC')
  seen.add(ip);targets.append({'ip':ip,'name':name or 'Trusted device','approved_macs':macs,'vlan':1})
 if len(targets)>64:raise ValueError('Maximum 64 frequently checked trusted addresses')
 discovery=bool(body.get('discovery_enabled'))
 if discovery and net.num_addresses-2>4094:raise ValueError('Subnet discovery is limited to 4094 hosts; use /20 or a smaller subnet')
 if not targets and not discovery:raise ValueError('Add at least one trusted device or enable subnet discovery')
 switches={};links=[];core=''
 if body.get('tracing_enabled'):
  for t in body.get('switches',[]):
   ip=ipv4(t['ip']);old=current.get('switches',{}).get(ip,{})
   family=t['family'];transport=t.get('transport','http' if family=='officeconnect' else 'ssh')
   if family not in ['comware','procurve','cx','officeconnect'] or transport not in (['http'] if family=='officeconnect' else ['ssh','telnet']):raise ValueError('Unsupported switch family or transport')
   password=t.get('password') or old.get('password','');user=str(t.get('username','')).strip();name=str(t.get('name',ip)).strip()[:80]
   if not password or not user:raise ValueError('Each switch needs a username/password (blank password keeps its existing secret)')
   if ip in switches:raise ValueError('Duplicate switch address')
   switches[ip]={'name':name or ip,'family':family,'transport':transport,'username':user,'password':password}
  if len(switches)>64:raise ValueError('Maximum 64 tracing switches')
  core=ipv4(body['core'])
  if core not in switches:raise ValueError('Select a configured starting switch')
  for edge in body.get('links',[]):
   if edge['a'] not in switches or edge['b'] not in switches or edge['a']==edge['b']:raise ValueError('Each link must join two different configured switches')
   for key in ['a_port','b_port']:
    if not re.fullmatch(r'[A-Za-z0-9/_.-]{1,64}',str(edge[key])):raise ValueError('Invalid link port name')
   links.append({k:edge[k] for k in ['a','a_port','b','b_port']})
  if len(links)>256:raise ValueError('Maximum 256 directed links')
 push=''
 if body.get('kuma_enabled'):
  push=body.get('kuma_push_url') or current.get('kuma_push_url','');u=urlsplit(push)
  if u.scheme not in ['http','https'] or not u.hostname or u.username or u.password or u.query or u.fragment or not re.fullmatch(r'/api/push/[A-Za-z0-9_-]+',u.path):raise ValueError('Enter the secret Push URL from your separate Uptime Kuma instance')
 url=body.get('dashboard_url','');u=urlsplit(url)
 if u.scheme not in ['http','https'] or not u.hostname or u.username or u.password:raise ValueError('Enter the dashboard URL operators can reach')
 return {'interface':iface['name'],'network':str(net),'scope_label':str(net)+' / trusted devices'+(' + paced discovery' if discovery else ''),'targets':targets,'discovery_network':str(net) if discovery else '', 'discovery_batch':2,'core':core,'switches':switches,'links':links,'kuma_push_url':push,'dashboard_url':url,'setup_complete':True,'segments':[{'id':1,'name':'Configured LAN','network':str(net),'status':'active','note':'Trusted IP/MAC checks'+(' and paced subnet discovery; a full sweep takes time.' if discovery else ' only.')}]}

def public_setup(cfg):
 rows=[]
 for ip,d in cfg.get('switches',{}).items():rows.append({'ip':ip,**{k:v for k,v in d.items() if k!='password'},'password_set':bool(d.get('password'))})
 return {'interfaces':interfaces(),'interface':cfg.get('interface',''),'network':cfg.get('network',''),'targets':copy.deepcopy(cfg.get('targets',[])),'discovery_enabled':bool(cfg.get('discovery_network')),'tracing_enabled':bool(cfg.get('core') and cfg.get('switches')),'switches':rows,'core':cfg.get('core',''),'links':copy.deepcopy([e for e in cfg.get('links',[]) if e.get('a') in cfg.get('switches',{}) and e.get('b') in cfg.get('switches',{})]),'kuma_enabled':bool(cfg.get('kuma_push_url')),'kuma_secret_set':bool(cfg.get('kuma_push_url')),'dashboard_url':cfg.get('dashboard_url',''),'setup_complete':cfg.get('setup_complete',bool(cfg.get('targets')))}

def discovery_hosts(network,exclude):
 if not network:return []
 net=ipaddress.ip_network(network)
 if net.version!=4 or net.num_addresses-2>4094:raise ValueError('Discovery subnet exceeds supported size')
 return [str(ip) for ip in net.hosts() if str(ip) not in exclude]
