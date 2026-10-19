import tempfile,unittest,pathlib,time,socket,struct
from app import Store,Sensor,parse_mac_table,kuma_message,save_settings,load_settings,password_hash,password_matches
from officeconnect import parse_table
class Tests(unittest.TestCase):
 def setUp(self):self.tmp=tempfile.TemporaryDirectory();self.path=pathlib.Path(self.tmp.name)/'test.sqlite';self.s=Store(self.path)
 def tearDown(self):self.s.db.close();self.tmp.cleanup()
 def test_monitor_requests_do_not_compete_with_windows_dad(self):
  sensor=Sensor({},self.s);sensor.local_ip='192.0.2.100';sensor.mac=bytes.fromhex('020000000100')
  frame=sensor.frame('192.0.2.10')
  self.assertEqual(len(frame),42)
  self.assertEqual(frame[:6],b'\xff'*6)
  self.assertEqual(frame[6:12],sensor.mac)
  self.assertEqual(struct.unpack('!HHBBH',frame[14:22]),(1,0x0800,6,4,1))
  self.assertEqual(frame[22:28],sensor.mac)
  self.assertEqual(socket.inet_ntoa(frame[28:32]),'192.0.2.100')
  self.assertEqual(socket.inet_ntoa(frame[38:42]),'192.0.2.10')
 def test_monitor_does_not_fall_back_to_an_unassigned_source(self):
  sensor=Sensor({},self.s);sensor.mac=bytes.fromhex('020000000100')
  for source in ['', '0.0.0.0','169.254.1.2','127.0.0.1','224.0.0.1','255.255.255.255','::1']:
   sensor.local_ip=source
   with self.subTest(source=source),self.assertRaises(ValueError):sensor.frame('192.0.2.10')
 def test_latch_resolve_restart_and_recurrence(self):
  good='02:00:00:00:00:01';bad='02:00:00:00:00:02';i,new=self.s.detect('192.0.2.1',[good,bad],[good],{'test':'isolated'})
  self.assertTrue(new);self.s.trace_update(i,bad,{'path':[{'switch_ip':'192.0.2.189','port':'18'}]})
  self.s.detect('192.0.2.1',[good],[good],{});self.assertEqual(self.s.open_count(),1)
  self.s.db.close();self.s=Store(self.path);self.assertEqual(self.s.open_count(),1);self.assertEqual(self.s.rows()[0]['trace'][bad]['path'][0]['port'],'18')
  self.assertTrue(self.s.resolve(i));self.assertEqual(self.s.open_count(),0);self.assertIsNotNone(self.s.rows()[0]['resolved_at']);self.assertEqual(len(self.s.history(i)),3)
  j,new=self.s.detect('192.0.2.1',[good,bad],[good],{});self.assertTrue(new);self.assertNotEqual(i,j)
 def test_change_is_not_claimed_as_simultaneous_duplicate(self):
  i,_=self.s.detect('192.0.2.1',['02:00:00:00:00:02'],['02:00:00:00:00:01'],{});self.assertEqual(self.s.rows()[0]['kind'],'Approved MAC changed')
 def test_approved_multiple_macs_allowed(self):
  self.assertEqual(self.s.detect('192.0.2.1',['aa:bb:cc:dd:ee:01','aa:bb:cc:dd:ee:02'],['aa:bb:cc:dd:ee:01','aa:bb:cc:dd:ee:02'],{}),(None,False))
 def test_unavailable_cannot_be_green_or_resolve(self):
  cfg={'targets':[{'ip':'192.0.2.1'}],'interval':15};sensor=Sensor(cfg,self.s);self.assertEqual(sensor.snapshot()['state'],'unavailable')
  sensor.status={'error':None,'last_cycle':time.time(),'targets':{'192.0.2.1':{'responded':False,'conflict_present':False}}};self.assertEqual(sensor.snapshot()['state'],'unavailable');self.assertFalse(sensor.can_resolve({'ip':'192.0.2.1'}))
 def test_mac_parsers(self):
  m='02:00:00:00:00:02'
  for txt,family,port in [('0200-0000-0002 1 Learned GigabitEthernet2/0/6 AGING','comware','GigabitEthernet2/0/6'),('020000-000002 18 1','procurve','18'),('02:00:00:00:00:02 1 dynamic 1/1/45','cx','1/1/45')]:self.assertEqual(parse_mac_table(txt,m,family)[0]['port'],port)
  self.assertEqual(parse_mac_table('Status and Counters - Address Table - 020000-000002\n Port VLAN\n 18 1\n','02:00:00:00:00:02','procurve')[0]['port'],'18')
 def test_notification_details_and_latch(self):
  good='02:00:00:00:00:01';bad='02:00:00:00:00:02'
  i,_=self.s.detect('192.0.2.1',[good,bad],[good],{})
  cfg={'targets':[{'ip':'192.0.2.1','name':'Main MikroTik'}],'device_labels':{bad:'ASUS RT-N1'}}
  state={'healthy':True,'targets':{'192.0.2.1':{'conflict_present':True}}}
  self.assertIn('pending or unavailable',kuma_message(cfg,state,self.s.rows()))
  self.s.trace_update(i,bad,{'status':'access_port','path':[{'switch_name':'Example access switch','switch_ip':'192.0.2.189','port':'18','vlan':1}]})
  msg=kuma_message(cfg,state,self.s.rows())
  for value in ['192.0.2.1','ASUS RT-N1','02:00:00:00:00:02','02:00:00:00:00:01','Port: 18','VLAN: 1','Moscow','Verified path:']:self.assertIn(value,msg)
  state['targets']['192.0.2.1']['conflict_present']=False
  self.assertIn('remains unresolved',kuma_message(cfg,state,self.s.rows()))
  self.s.resolve(i);self.assertIn('No unresolved conflicts detected',kuma_message(cfg,state,self.s.rows()))
  state['healthy']=False;self.assertIn('monitoring unavailable',kuma_message(cfg,state,self.s.rows()))
 def test_officeconnect_table_and_reject_login_or_executable_content(self):
  page="<title>MAC Table</title><script>var aDataSet = [['1','02:00:00:00:00:02','4','4','Learned'],['1','02:00:00:00:00:01','TRK1','54','Learned'],['1','02:00:00:00:00:03','CPU','53','Management']];</script>"
  self.assertEqual(parse_table(page,'02:00:00:00:00:02')[0]['port'],'4')
  self.assertEqual(parse_table(page,'02:00:00:00:00:01')[0]['port'],'TRK1')
  self.assertEqual(len(parse_table(page)),2)
  with self.assertRaises(ValueError):parse_table('<title>Log In</title>')
  with self.assertRaises(ValueError):parse_table('<title>MAC Table</title>var aDataSet = [__import__("os").system("false")];')
 def test_retention_only_deletes_expired_resolved_evidence(self):
  ids=[]
  for ip in ['192.0.2.1','192.0.2.2','192.0.2.3']:
   i,_=self.s.detect(ip,['aa:bb:cc:dd:ee:02'],['aa:bb:cc:dd:ee:01'],{});ids.append(i)
  self.s.resolve(ids[0]);self.s.resolve(ids[1])
  self.s.db.execute('UPDATE incidents SET resolved_at=? WHERE id=?',('2000-01-01T00:00:00+00:00',ids[0]));self.s.db.commit()
  self.assertEqual(self.s.prune_resolved(0),0);self.assertEqual(self.s.prune_resolved(30),1)
  self.assertEqual(self.s.history(ids[0]),[]);self.assertEqual({r['id'] for r in self.s.rows()},set(ids[1:]));self.assertEqual(self.s.open_count(),1)
 def test_account_settings_persist_hash_without_plaintext(self):
  cfg={'dashboard_user':'old','dashboard_password':'old-secret','_settings_path':str(pathlib.Path(self.tmp.name)/'settings.json')}
  load_settings(cfg);self.assertEqual(cfg['resolved_retention_days'],30)
  save_settings(cfg,{'dashboard_user':'new','account_password_hash':password_hash('new-password-12345'),'resolved_retention_days':60})
  restored={'dashboard_user':'old','dashboard_password':'old-secret','_settings_path':cfg['_settings_path']};load_settings(restored)
  self.assertEqual(restored['dashboard_user'],'new');self.assertTrue(password_matches(restored,'new-password-12345'));self.assertFalse(password_matches(restored,'old-secret'));self.assertNotIn('new-password-12345',pathlib.Path(cfg['_settings_path']).read_text())
if __name__=='__main__':unittest.main()
