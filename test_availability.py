import contextlib,errno,io,json,pathlib,tempfile,time,unittest
from app import Sensor,Store,kuma_message
from availability import Availability,details,safe_error

class AvailabilityTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.path=pathlib.Path(self.tmp.name);self.store=Store(self.path/'test.sqlite3')
  self.cfg={'targets':[{'ip':'192.0.2.10','name':'Lab server','approved_macs':['02:00:00:00:00:10']}],'interval':15,'interface':'lab0','core':'','switches':{}}
  self.sensor=Sensor(self.cfg,self.store);self.sensor.local_ip='192.0.2.100'
 def tearDown(self):self.store.db.close();self.tmp.cleanup()
 def test_missing_ip_and_last_success_are_logged_and_sent_to_kuma(self):
  self.sensor.probe=lambda ip:{'02:00:00:00:00:10':{'mac':'02:00:00:00:00:10'}}
  self.sensor.cycle();good=self.sensor.snapshot();last=good['targets']['192.0.2.10']['last_reply_at']
  self.sensor.probe=lambda ip:{};self.sensor.cycle();bad=self.sensor.snapshot()
  self.assertFalse(bad['healthy']);self.assertEqual(bad['availability']['failed_targets'][0]['last_reply_at'],last)
  msg=kuma_message(self.cfg,bad,[])
  for text in ['192.0.2.10','Lab server','No ARP reply observed','lab0',last]:self.assertIn(text,msg)
  rows=[json.loads(line) for line in (self.path/'availability.jsonl').read_text().splitlines()]
  self.assertEqual(rows[-1]['event'],'monitoring_unavailable');self.assertEqual(rows[-1]['failed_targets'][0]['ip'],'192.0.2.10')
 def test_recovery_retains_the_reason_in_log_and_kuma(self):
  self.sensor.probe=lambda ip:{};self.sensor.cycle();self.sensor.snapshot()
  self.sensor.probe=lambda ip:{'02:00:00:00:00:10':{'mac':'02:00:00:00:00:10'}};self.sensor.cycle();state=self.sensor.snapshot()
  self.assertTrue(state['healthy']);self.assertIn('Monitoring recovered',kuma_message(self.cfg,state,[]));self.assertIn('192.0.2.10',kuma_message(self.cfg,state,[]))
  rows=[json.loads(line) for line in (self.path/'availability.jsonl').read_text().splitlines()]
  self.assertEqual(rows[-1]['event'],'monitoring_recovered');self.assertEqual(rows[-1]['failed_ips'],['192.0.2.10'])
 def test_probe_exception_identifies_target_and_redacts_secrets(self):
  def fail(ip):raise PermissionError(errno.EPERM,'private-password')
  self.sensor.probe=fail
  with self.assertRaises(PermissionError):self.sensor.cycle()
  self.assertEqual(self.sensor.current_probe_ip,'192.0.2.10')
  self.sensor.status.update(error=safe_error(PermissionError(errno.EPERM,'private-password'),self.cfg),failed_probe_ip=self.sensor.current_probe_ip)
  state=self.sensor.snapshot();msg=kuma_message(self.cfg,state,[])
  self.assertIn('PermissionError',msg);self.assertIn('192.0.2.10',msg);self.assertNotIn('private-password',msg)
 def test_credentials_and_push_url_are_not_exposed(self):
  cfg={'dashboard_password':'unique-secret','csrf':'csrf-value','kuma_push_url':'http://kuma.invalid/api/push/hidden-token','switches':{'lab':{'password':'switch-password'}}}
  text=safe_error(RuntimeError('unique-secret csrf-value switch-password http://kuma.invalid/api/push/hidden-token?down=1'),cfg)
  for secret in ['unique-secret','csrf-value','switch-password','hidden-token','http://']:self.assertNotIn(secret,text)
 def test_stale_cycle_is_not_misreported_as_a_missing_ip(self):
  self.sensor.status.update(error=None,last_cycle=time.time()-120,targets={'192.0.2.10':{'responded':True,'conflict_present':False}})
  state=self.sensor.snapshot();self.assertTrue(state['availability']['stale']);self.assertEqual(state['availability']['failed_targets'],[])
  self.assertIn('Stale probe results',kuma_message(self.cfg,state,[]))
 def test_unchanged_failure_is_not_logged_on_every_health_request(self):
  self.sensor.probe=lambda ip:{};self.sensor.cycle();self.sensor.snapshot();self.sensor.snapshot();self.sensor.snapshot()
  rows=(self.path/'availability.jsonl').read_text().splitlines();self.assertEqual(len(rows),1)
 def test_healthy_conflict_does_not_become_an_availability_failure(self):
  self.sensor.probe=lambda ip:{'02:00:00:00:00:10':{'mac':'02:00:00:00:00:10'},'02:00:00:00:00:11':{'mac':'02:00:00:00:00:11'}}
  self.sensor.cycle();state=self.sensor.snapshot();self.assertTrue(state['healthy']);self.assertEqual(state['state'],'incident');self.assertEqual(state['availability']['failed_targets'],[])

if __name__=='__main__':unittest.main()
