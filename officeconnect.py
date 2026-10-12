"""Read-only HPE OfficeConnect 1820 web MAC table adapter."""
import ast,http.cookiejar,ipaddress,json,re
from urllib.parse import urlencode
from urllib.request import build_opener,ProxyHandler,HTTPCookieProcessor

def parse_table(text,mac=None):
 if '<title>MAC Table</title>' not in text:raise ValueError('MAC table page unavailable or session expired')
 match=re.search(r'var\s+aDataSet\s*=\s*(\[.*?\])\s*;',text,re.S)
 if not match:raise ValueError('Unsupported OfficeConnect MAC table format')
 # Parse literals only; never execute device-provided JavaScript.
 data=ast.literal_eval(match.group(1))
 if not isinstance(data,list) or len(data)>10000:raise ValueError('Invalid MAC table size')
 result=[];wanted=re.sub('[^0-9a-f]','',mac.lower()) if mac else None
 for row in data:
  if not isinstance(row,list) or len(row)!=5 or not all(isinstance(x,str) for x in row):raise ValueError('Invalid MAC table row')
  vlan,address,port,internal,kind=row
  if not vlan.isdigit() or not re.fullmatch(r'(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}',address):raise ValueError('Invalid MAC table address')
  if wanted and address.replace(':','').lower()!=wanted:continue
  if kind!='Learned' or not re.fullmatch(r'(?:\d+|TRK\d+)',port,re.I):continue
  result.append({'mac':address.lower(),'port':port,'vlan':int(vlan),'raw':'OfficeConnect web MAC table: VLAN '+vlan+' MAC '+address+' port '+port+' type '+kind})
 return result

class OfficeConnect:
 def __init__(self,host,username,password):
  self.base='http://'+str(ipaddress.ip_address(host));self.opener=build_opener(ProxyHandler({}),HTTPCookieProcessor(http.cookiejar.CookieJar()))
  self.read('/')
  body=urlencode({'username':username,'password':password}).encode()
  with self.opener.open(self.base+'/htdocs/login/login.lua',body,timeout=10) as response:
   result=json.loads(response.read(65536))
  if result.get('error') or result.get('redirect')!='/htdocs/pages/main/main.lsp':raise PermissionError('OfficeConnect login rejected')
 def read(self,path):
  # Fixed read allowlist prevents accidental configuration requests.
  if path not in ['/','/htdocs/pages/base/mac_address_table.lsp','/htdocs/pages/main/logout.lsp']:raise ValueError('Read endpoint not allowed')
  with self.opener.open(self.base+path,timeout=10) as response:
   body=response.read(2*1024*1024+1)
   if len(body)>2*1024*1024:raise ValueError('OfficeConnect response exceeds bound')
   return body.decode('utf-8')
 def lookup(self,mac):return parse_table(self.read('/htdocs/pages/base/mac_address_table.lsp'),mac)
 def close(self):
  try:self.read('/htdocs/pages/main/logout.lsp')
  except Exception:pass
