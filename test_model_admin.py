"""Model administration contract with isolated files and no provider calls."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from flask import Flask
import model_admin as models


class ModelAdminTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'model_settings.json'
        p = patch.object(models, 'SETTINGS_PATH', self.path);p.start();self.addCleanup(p.stop)
        self.base = [{'name':'first', 'readable_name':'First', 'enabled':True, 'provider':'openrouter', 'params':{'model':'publisher/first','reasoning_effort':'none','api_key':'synthetic-secret'}},
                     {'name':'second', 'readable_name':'Second', 'enabled':True, 'provider':'openrouter', 'params':{'model':'publisher/second'}}]
        app = Flask(__name__)
        models.install(app, lambda:models.snapshot(self.base, 'first'), lambda f:f, lambda f:f)
        self.client = app.test_client()

    def payload(self): return self.client.get('/api/admin/models').json

    def test_add_disable_default_and_persistence(self):
        p = self.payload();p['models'][0]['enabled']=False
        p['models'].append({'name':'publisher/new','model_id':'publisher/new','label':'New model','enabled':True})
        p['default']='publisher/new'
        response=self.client.put('/api/admin/models',json=p)
        self.assertEqual(response.status_code,200,response.json)
        name=response.json['default'];self.assertTrue(name.startswith('openrouter_custom_'))
        data=models.snapshot([],None)
        self.assertEqual(models.resolve(data,'first'),name)
        self.assertEqual(models.resolve(data,'second'),'second')
        self.assertEqual(data['models'][0]['params'],self.base[0]['params'])
        self.assertEqual(data['models'][-1]['params'],{'model':'publisher/new'})
        self.assertEqual(self.path.stat().st_mode & 0o777,0o600)
        self.assertNotIn('synthetic-secret',response.get_data(as_text=True))
        self.assertEqual(len(self.client.get('/api/models').json['models']),2)

    def test_invalid_edits_leave_file_unchanged(self):
        p=self.payload();self.assertEqual(self.client.put('/api/admin/models',json=p).status_code,200)
        original=self.path.read_bytes()
        for change in ['all_disabled','default_disabled','endpoint','duplicate','delete','change_id','bad_id']:
            p=self.payload()
            if change=='all_disabled':
                for row in p['models']:row['enabled']=False
            elif change=='default_disabled':p['models'][0]['enabled']=False
            elif change=='endpoint':p['models'][0]['base_url']='https://example.com'
            elif change=='duplicate':p['models'].append(copy.deepcopy(p['models'][0]))
            elif change=='delete':p['models'].pop()
            elif change=='change_id':p['models'][0]['model_id']='publisher/different'
            else:p['models'].append({'name':'new','model_id':'not-a-model-id','label':'New','enabled':True})
            with self.subTest(change=change):
                self.assertEqual(self.client.put('/api/admin/models',json=p).status_code,400)
                self.assertEqual(self.path.read_bytes(),original)

    def test_stale_admin_cannot_overwrite_newer_settings(self):
        old=self.payload();new=copy.deepcopy(old);new['default']='second'
        self.assertEqual(self.client.put('/api/admin/models',json=new).status_code,200)
        self.assertEqual(self.client.put('/api/admin/models',json=old).status_code,409)
        self.assertEqual(self.payload()['default'],'second')

    def test_replace_failure_keeps_saved_catalogue(self):
        p=self.payload();self.client.put('/api/admin/models',json=p);original=self.path.read_bytes()
        with patch.object(models.os,'replace',side_effect=OSError('fixture failure')):
            with self.assertRaises(OSError):models.save({'models':[],'default':None})
        self.assertEqual(self.path.read_bytes(),original)
        self.assertEqual(list(self.path.parent.iterdir()),[self.path])

    def test_release_catalogue_changes_preserve_runtime_choices(self):
        p=self.payload();p['default']='second';self.client.put('/api/admin/models',json=p)
        self.assertEqual(models.snapshot([], 'unrelated')['default'],'second')

if __name__=='__main__':unittest.main()
