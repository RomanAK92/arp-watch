import warnings
warnings.filterwarnings('ignore',category=DeprecationWarning)
import json,getpass,telnetlib,paramiko,re,time,socket,concurrent.futures,threading,datetime,ipaddress
from pathlib import Path

PROMPT=re.compile(rb'(?m)^[ \t]*(?:<[^\r\n<>]{1,80}>|[A-Za-z0-9][^\r\n]{0,79}[#>] ?)[ \t]*$')

def clean(text):
    text=re.sub(r'\x1b\][\s\S]*?(?:\x07|\x1b\\)','',text)
    text=re.sub(r'\x1b\[[0-9;?]*[A-Za-z]','',text)
    return text.replace('\r','').replace('\x08','')

def safe_config(text):
    result=[]
    allowed=re.compile(r'^(?:#|!|return|version |sysname |hostname |interface |vlan |name |description |tagged |untagged |port |ip (?:address|route|routing|default-gateway)|ipv6 (?:address|enable)|shutdown|no shutdown|speed |duplex |stp|spanning-tree|loop-protect|lldp|irf|link-aggregation|trunk |arp rate-limit|dhcp-snooping|dhcp relay|dhcp select|exit$|qos (?:apply|trust)|flow-control|no (?:ip routing|spanning-tree|lldp)|management-vlan)')
    secret=re.compile(r'password|secret|community|pre-shared|preshared|wpa-psk|private-key|auth.*key|access-token|credential',re.I)
    for line in clean(text).splitlines():
        if not secret.search(line) and allowed.search(line.strip()): result.append(line)
    return '\n'.join(result)

class CLI:
    def __init__(self,host,transport,user,password):
        self.transport=transport; self.tn=None; self.client=None; self.ch=None
        if transport=='telnet':
            self.tn=telnetlib.Telnet(host,23,timeout=5)
            idx,_,pre=self.tn.expect([rb'Username:',rb'Login:',rb'login:',rb'Password:'],timeout=10)
            if idx<0: raise RuntimeError('No supported login prompt')
            if idx!=3:
                self.tn.write(user.encode()+b'\r\n')
                idx,_,pw=self.tn.expect([rb'Password:',rb'password:'],timeout=6)
                if idx<0: raise RuntimeError('No password prompt')
            self.tn.write(password.encode()+b'\r\n')
        else:
            self.client=paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.client.connect(host,port=22,username=user,password=password,look_for_keys=False,allow_agent=False,timeout=5,auth_timeout=8,banner_timeout=8)
            self.ch=self.client.invoke_shell(width=240,height=1000)
        self.banner=self.read(12)
        if 'Enter switch number to connect to or <CR>:' in self.banner:
            self.send('')
            self.banner+=self.read(12)
        if re.search(r'authentication failed|invalid password|login incorrect|incorrect login/password|access denied',self.banner,re.I):
            self.close()
            raise RuntimeError('Authentication rejected')
        if not PROMPT.search(self.banner.encode()): raise RuntimeError('No command prompt after login')

    def send(self,s):
        data=(s+'\r\n').encode()
        if self.tn: self.tn.write(data)
        else: self.ch.sendall(data)
    def read(self,timeout):
        end=time.monotonic()+timeout; data=b''; sent_return=False; last=time.monotonic()
        while time.monotonic()<end:
            try:
                if self.tn:
                    part=self.tn.read_very_eager()
                else:
                    part=self.ch.recv(65536) if self.ch.recv_ready() else b''
            except EOFError: break
            if part:
                data+=part; last=time.monotonic()
                if len(data)>4000000: raise RuntimeError('Response too large')
                text=clean(data.decode(errors='replace'))
                if re.search(r'Press (?:Return|any key)|press (?:ENTER|Enter)',text) and not sent_return:
                    self.send(''); sent_return=True
                if '-- MORE --' in text[-160:] or '---- More ----' in text[-160:]:
                    if self.tn:self.tn.write(b' ')
                    else:self.ch.send(b' ')
                if 'CTRL+C ESC q Quit SPACE n Next Page' in text[-180:]:
                    if self.tn:self.tn.write(b'a')
                    else:self.ch.send(b'a')
                if PROMPT.search(text.encode()) and time.monotonic()-last<.2:
                    time.sleep(.12)
                    if self.tn:
                        extra=self.tn.read_very_eager()
                        if not extra:return text
                        data+=extra
                    if not self.tn and not self.ch.recv_ready(): return text
            else: time.sleep(.04)
        return clean(data.decode(errors='replace'))
    def command(self,s,timeout=16):
        if not (s.startswith(('show ','display ','dir ')) or s in ('no page','screen-length disable','switchshow','fabricshow','firmwareshow','nsshow','nsallshow','islshow','trunkshow','version')):
            raise ValueError('Read-only command rejected')
        self.send(s); return self.read(timeout)
    def close(self):
        if self.tn:self.tn.close()
        if self.client:self.client.close()
