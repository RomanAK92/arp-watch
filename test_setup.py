import copy,json,pathlib,tempfile,time,unittest
from app import Store,Sensor
from setup_config import validate,public_setup,discovery_hosts
class SetupTests(unittest.TestCase):
 def setUp(self):
  self.ifaces=[{'name':'eth0','ip':'192.0.2.6','network':'192.0.2.0/29'}]
  self.body={'interface':'eth0','network':'192.0.2.0/29','dashboard_url':'http://192.0.2.6:8096/','targets':[{'ip':'192.0.2.1','name':'Router','approved_macs':['02:00:00:00:00:01']}],'discovery_enabled':False,'tracing_enabled':False,'kuma_enabled':False}
 def test_explicit_trust_and_local_network_required(self):
  c=validate(self.body,{},self.ifaces);self.assertEqual(c['targets'][0]['approved_macs'],['02:00:00:00:00:01'])
  for changes in [{'network':'198.51.100.0/24'},{'interface':'missing'},{'targets':[]},{'targets':[{'ip':'192.0.2.2','approved_macs':[]}]}]:
   with self.assertRaises(ValueError):validate({**self.body,**changes},{},self.ifaces)
 def test_secret_preservation_and_redaction(self):
  old={'switches':{'192.0.2.3':{'family':'officeconnect','transport':'http','name':'Switch','username':'admin','password':'switch-secret'}},'kuma_push_url':'http://kuma:3001/api/push/privateToken'}
  b={**self.body,'tracing_enabled':True,'core':'192.0.2.3','switches':[{'ip':'192.0.2.3','family':'officeconnect','transport':'http','username':'admin','password':''}],'links':[],'kuma_enabled':True,'kuma_push_url':''}
  c=validate(b,old,self.ifaces);self.assertEqual(c['switches']['192.0.2.3']['password'],'switch-secret')
  safe=json.dumps(public_setup(c));self.assertNotIn('switch-secret',safe);self.assertNotIn('privateToken',safe)
 def test_subnet_scan_is_bounded_and_unknown_single_mac_is_not_rogue(self):
  cfg=validate({**self.body,'discovery_enabled':True},{},self.ifaces);cfg.update(interval=15,core='',switches={})
  with tempfile.TemporaryDirectory() as d:
   store=Store(pathlib.Path(d)/'db');sensor=Sensor(cfg,store);sensor.local_ip='192.0.2.6'
   answers={'192.0.2.1':['02:00:00:00:00:01'],'192.0.2.2':['02:00:00:00:00:02','02:00:00:00:00:03'],'192.0.2.4':['02:00:00:00:00:04']};called=[]
   def probe(ip):called.append(ip);return {m:{'mac':m} for m in answers.get(ip,[])}
   sensor.probe=probe;sensor.cycle();self.assertEqual(called,['192.0.2.1','192.0.2.2','192.0.2.3']);self.assertTrue(sensor.snapshot()['healthy']);self.assertEqual(store.open_count(),1);self.assertEqual(sensor.jobs.qsize(),0)
   called.clear();sensor.cycle();self.assertEqual(called,['192.0.2.1','192.0.2.2','192.0.2.4','192.0.2.5']);self.assertEqual(store.open_count(),1);self.assertTrue(sensor.snapshot()['healthy']);self.assertEqual(sensor.snapshot()['discovery_checked'],4)
   answers['192.0.2.2']=['02:00:00:00:00:02'];sensor.cycle();self.assertTrue(sensor.can_resolve(store.rows()[0]))
   store.db.close()
 def test_discovery_size_and_sensitive_urls_rejected(self):
  with self.assertRaises(ValueError):discovery_hosts('192.0.0.0/16',set())
  with self.assertRaises(ValueError):validate({**self.body,'kuma_enabled':True,'kuma_push_url':'http://kuma/api/push/token?status=up'},{},self.ifaces)
if __name__=='__main__':unittest.main()
