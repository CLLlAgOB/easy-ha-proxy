"""Authenticated, per-site downloads; bounded disk uploads and no admin bypass."""
from __future__ import annotations
import hashlib
import importlib
import copy
from contextlib import nullcontext
import io
import json
import os
import re
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
import yaml

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'docker/app'))
if sys.platform != 'win32':
    from haproxy_admin import create_app, access_portal as store
    from haproxy_admin import routes_access_portal as routes
else:
    store=None


@unittest.skipUnless(store, 'Linux file locking')
class PortalTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.env=patch.dict(os.environ,{'HAPROXY_ADMIN_PORTAL_DIR':str(self.root/'portals'),
            'HAPROXY_ADMIN_PROXY_SECRET':'portal-test-proxy','HAPROXY_ADMIN_SECRET_KEY':'portal-test-session',
            'AUDIT_DATABASE':str(self.root/'audit.db')})
        self.env.start();self.addCleanup(self.env.stop)
        with patch('haproxy_admin.ensure_whitelist_file'):
            self.app=create_app()
        self.app.config.update(TESTING=True,WTF_CSRF_ENABLED=False)
        self.client=self.app.test_client()
        self.site={'name':'support','domain':'support.example.test','access_gate':True}
        p=patch.object(routes,'get_site_raw_and_effective',return_value=({},self.site,self.site));p.start();self.addCleanup(p.stop)
        p=patch.object(routes,'set_routing',return_value=False);p.start();self.addCleanup(p.stop)
        self.admin={'X-Easy-HA-Proxy-Secret':'portal-test-proxy','Remote-User':'admin','Remote-Groups':'superadmin'}
        self.user={**self.admin,'Remote-User':'person','Remote-Groups':'users','X-Easy-HA-Proxy-Portal-Host':'support.example.test'}
        def host(hostname):
            if hostname=='support.example.test':return self.site
            if hostname=='other.example.test':return {**self.site,'name':'other'}
            raise FileNotFoundError()
        p=patch.object(store,'site_by_host',side_effect=host);p.start();self.addCleanup(p.stop)

    def enable(self,value,**changes):
        return store.configure('support',{'enabled':True,'text':'Help <script>alert(1)</script>',
            'files':[{k:f[k] for k in ('id','title','description')} for f in value['files']],
            'revision':value['revision'],**changes})

    def test_upload_download_and_deletion_preserve_bytes_and_digest(self):
        content=b'synthetic executable download bytes'
        response=self.client.post('/haproxy/sites/support/portal/files?filename=helper.exe',data=content,content_type='application/octet-stream',headers=self.admin)
        self.assertEqual(response.status_code,200)
        value=response.json['settings'];file=value['files'][0]
        self.assertEqual(file['sha256'],hashlib.sha256(content).hexdigest())
        url='/access-portal/downloads/'+file['id']
        self.assertEqual(self.client.get(url,headers=self.user).status_code,404)
        self.enable(value)
        response=self.client.get(url,headers=self.user,buffered=False)
        self.assertTrue(response.is_streamed)
        self.assertEqual(response.data,content)
        self.assertIn('attachment;',response.headers['Content-Disposition'])
        self.assertEqual(response.mimetype,'application/octet-stream')
        self.assertEqual(response.headers['X-Content-Type-Options'],'nosniff')
        response.close()
        self.assertEqual(self.client.get(url,headers={**self.user,'X-Easy-HA-Proxy-Portal-Host':'other.example.test'}).status_code,404)
        store.delete('support',file['id'])
        self.assertEqual(self.client.get(url,headers=self.user).status_code,404)

    def test_guests_forged_proxy_and_allowlist_only_users_cannot_download(self):
        value=store.upload('support','helper.exe',io.BytesIO(b'fixture'));self.enable(value)
        url='/access-portal/downloads/'+value['files'][0]['id']
        for headers in ({},{**self.user,'X-Easy-HA-Proxy-Secret':'wrong'},
                        {**self.user,'Remote-User':''},{**self.user,'X-Easy-HA-Proxy-Portal-Host':''},
                        {**self.user,'Remote-User':'easy-ha-proxy-healthcheck','Remote-Groups':'healthcheck'}):
            self.assertEqual(self.client.get(url,headers=headers).status_code,403)

    def test_a_portal_user_cannot_enter_admin_routes_or_upload(self):
        self.assertEqual(self.client.get('/system/updates/',headers=self.user).status_code,403)
        self.assertEqual(self.client.get('/haproxy/sites/support/portal/settings',headers=self.user).status_code,403)
        self.assertEqual(self.client.post('/haproxy/sites/support/portal/files?filename=x.exe',data=b'x',headers=self.user,content_type='application/octet-stream').status_code,403)

    def test_generic_site_api_cannot_change_a_service_into_a_proxy(self):
        from haproxy_admin import routes_haproxy_sites as proxy_api
        with patch.object(proxy_api,'source_lock',side_effect=lambda _:nullcontext()),patch.object(proxy_api,'get_site_raw_and_effective',return_value=({},self.site,self.site)),patch.object(proxy_api,'save_site_from_json') as write:
            response=self.client.post('/haproxy/sites/save',headers=self.admin,
                json={'original_name':'support','site':{**self.site,'access_gate':False,'backend_ip':'192.0.2.50'}})
            self.assertEqual(response.status_code,400);write.assert_not_called()

    def test_settings_require_csrf_in_the_real_application(self):
        self.app.config['WTF_CSRF_ENABLED']=True
        response=self.client.post('/haproxy/sites/support/portal/files?filename=x.exe',data=b'x',headers=self.admin,content_type='application/octet-stream')
        self.assertEqual(response.status_code,400)
        self.assertFalse(list((self.root/'portals').glob('*/*.bin')))

    def test_raw_stream_upload_also_works_with_real_csrf_validation(self):
        self.app.config['WTF_CSRF_ENABLED']=True
        response=self.client.get('/haproxy/sites/support/portal',headers=self.admin,base_url='https://localhost')
        token=re.search(rb'name="csrf-token" content="([^"]+)"',response.data).group(1).decode()
        response=self.client.post('/haproxy/sites/support/portal/files?filename=x.exe',data=b'fixture',
            headers={**self.admin,'X-CSRFToken':token,'Referer':'https://localhost/haproxy/sites/support/portal'},
            content_type='application/octet-stream',base_url='https://localhost')
        self.assertEqual(response.status_code,200)

    def test_capability_probe_is_read_only_and_scoped_to_its_health_identity(self):
        headers={**self.admin,'Remote-User':'easy-ha-proxy-healthcheck','Remote-Groups':'healthcheck'}
        self.assertEqual(self.client.get('/api/access-portal-health',headers=headers).status_code,200)
        self.assertEqual(self.client.get('/haproxy/sites/support/portal/settings',headers=headers).status_code,403)

    def test_interrupted_uploads_are_pruned_without_removing_registered_files(self):
        value=store.upload('support','helper.exe',io.BytesIO(b'fixture'))
        directory=store._directory('support');abandoned=directory/('0'*32+'.bin');abandoned.write_bytes(b'abandoned')
        store.upload('support','second.exe',io.BytesIO(b'second'))
        self.assertFalse(abandoned.exists())
        self.assertTrue((directory/(value['files'][0]['id']+'.bin')).is_file())

    def test_user_text_is_escaped_and_disabled_blocks_are_hidden(self):
        value=store.upload('support','helper.exe',io.BytesIO(b'fixture'));self.enable(value)
        response=self.client.get('/access-portal/',headers=self.user)
        self.assertEqual(response.status_code,200)
        self.assertIn(b'&lt;script&gt;',response.data)
        self.assertNotIn(b'<script>alert(1)</script>',response.data)
        value=store.settings('support');self.enable(value,enabled=False)
        response=self.client.get('/access-portal/',headers=self.user)
        self.assertNotIn(b'helper.exe',response.data)

    def test_saved_language_overrides_browser_and_translates_the_whole_page(self):
        value=store.upload('support','helper.exe',io.BytesIO(b'fixture'))
        for language, browser, heading, lead, meta, instructions, downloads, button, opposite in (
            ('ru','en','Доступ разрешён','Вы успешно прошли аутентификацию через Authelia.',
             'Теперь это устройство считается доверенным.', 'Инструкция','Файлы для скачивания','Скачать','Access granted'),
            ('en','ru','Access granted','You have successfully authenticated with Authelia.',
             'This device is now trusted.', 'Instructions','Downloads','Download','Доступ разрешён'),
        ):
            with self.subTest(language=language):
                value=self.enable(value,language=language)
                response=self.client.get('/access-portal/',headers={**self.user,'Accept-Language':browser})
                html=response.get_data(as_text=True)
                self.assertEqual(response.status_code,200)
                self.assertEqual(response.headers['Content-Language'],language)
                for text in (f'lang="{language}"',heading,lead,meta,instructions,downloads,button,'Help &lt;script&gt;'):
                    self.assertIn(text,html)
                self.assertNotIn(opposite,html)
                self.assertIn('7 Б' if language=='ru' else '7 B',html)
                self.assertEqual(store.settings('other')['language'],'auto')

    def test_browser_language_is_used_in_auto_mode(self):
        self.enable(store.settings('support'),language='auto')
        for language, heading in (('ru','Доступ разрешён'),('en','Access granted')):
            with self.subTest(language=language):
                response=self.client.get('/access-portal/',headers={**self.user,'Accept-Language':language})
                self.assertEqual(response.headers['Content-Language'],language)
                self.assertIn(heading,response.get_data(as_text=True))

    def test_language_saves_via_admin_api_and_survives_attachment_changes(self):
        value=store.settings('support')
        response=self.client.post('/haproxy/sites/support/portal/settings',headers=self.admin,
            json={'enabled':True,'language':'ru','text':'Помощь','files':[],'revision':value['revision']})
        self.assertEqual(response.status_code,200)
        self.assertEqual(response.json['settings']['language'],'ru')
        value=store.upload('support','helper.exe',io.BytesIO(b'fixture'))
        self.assertEqual(value['language'],'ru')
        value=store.delete('support',value['files'][0]['id'])
        self.assertEqual(value['language'],'ru')
        # Old clients that do not send the new field must retain the selection.
        self.assertEqual(self.enable(value)['language'],'ru')
        self.assertIn(b'id="portal-language"',self.client.get('/haproxy/sites/support/portal',headers=self.admin).data)

    def test_existing_metadata_defaults_to_auto_and_invalid_languages_are_rejected(self):
        directory=store._directory('support')
        (directory/'settings.json').write_text(json.dumps({'enabled':True,'text':'Existing instructions','files':[]}))
        value=store.settings('support')
        self.assertEqual(value['language'],'auto')
        for language in ('de','RU','',None,[],{}):
            with self.subTest(language=language):
                with self.assertRaisesRegex(ValueError,'Unsupported access-page language'):
                    self.enable(value,language=language)
                self.assertEqual(store.settings('support'),value)

    def test_busy_download_message_uses_the_saved_page_language(self):
        value=store.upload('support','helper.exe',io.BytesIO(b'fixture'));self.enable(value,language='ru')
        with patch.object(routes,'_DOWNLOAD_SLOTS',threading.BoundedSemaphore(0)):
            response=self.client.get('/access-portal/downloads/'+value['files'][0]['id'],
                headers={**self.user,'Accept-Language':'en'})
        self.assertEqual(response.status_code,429)
        self.assertIn('Все каналы скачивания заняты.',response.get_data(as_text=True))

    def test_stale_settings_cannot_overwrite_another_upload(self):
        old=store.settings('support')
        store.upload('support','helper.exe',io.BytesIO(b'fixture'))
        with self.assertRaises(FileExistsError):self.enable(old)

    def test_a_failed_routing_change_does_not_publish_attachments(self):
        value=store.upload('support','helper.exe',io.BytesIO(b'fixture'))
        payload={'enabled':True,'text':'help','files':[{k:f[k] for k in ('id','title','description')} for f in value['files']],'revision':value['revision']}
        def refused(_enabled):raise ValueError('Configuration confirmation is pending')
        with self.assertRaises(ValueError):store.configure('support',payload,before_save=refused)
        self.assertFalse(store.settings('support')['enabled'])

    def test_download_admission_keeps_health_available_and_releases_canceled_streams(self):
        value=store.upload('support','helper.exe',io.BytesIO(b'fixture'));self.enable(value)
        url='/access-portal/downloads/'+value['files'][0]['id']
        with patch.object(routes,'_DOWNLOAD_SLOTS',threading.BoundedSemaphore(1)):
            first=self.client.get(url,headers=self.user,buffered=False)
            try:
                busy=self.client.get(url,headers=self.user)
                self.assertEqual(busy.status_code,429)
                self.assertEqual(busy.headers['Retry-After'],'10')
                self.assertEqual(self.client.get('/api/access-portal-health',headers=self.admin).status_code,200)
            finally:first.close()
            again=self.client.get(url,headers=self.user)
            self.assertEqual(again.status_code,200);again.close()

    def test_a_gate_with_a_configured_upstream_can_edit_its_page(self):
        self.site.update(backend_ip='192.0.2.80',backend_port=8080)
        self.assertEqual(self.client.get('/haproxy/sites/support/portal',headers=self.admin).status_code,200)

    def test_service_sites_have_a_separate_list_and_compact_editor(self):
        from haproxy_admin import routes_haproxy_config as proxy_routes
        normal={'name':'shop','domain':'shop.example.test','backend_ip':'192.0.2.10','backend_port':80}
        items=[{'raw':site,'effective':site,'cert':{'short':'valid'}} for site in (self.site,normal)]
        with patch.object(routes,'get_sites_and_defaults_for_ui',return_value=({},items)):
            response=self.client.get('/haproxy/access-sites',headers=self.admin)
            self.assertEqual(response.status_code,200)
            self.assertIn(b'support.example.test',response.data)
            self.assertNotIn(b'shop.example.test',response.data)
        with patch.object(proxy_routes,'get_sites_and_defaults_for_ui',return_value=({},items)),patch.object(proxy_routes,'_load_yaml',return_value={}):
            response=self.client.get('/haproxy/sites',headers=self.admin)
            self.assertEqual(response.status_code,200)
            self.assertIn(b'shop.example.test',response.data)
            self.assertNotIn(b'support.example.test',response.data)
        with patch.object(proxy_routes,'get_site_raw_and_effective',return_value=({},self.site,self.site)):
            response=self.client.get('/haproxy/sites/support/edit',headers=self.admin)
            self.assertEqual(response.status_code,302)
            self.assertTrue(response.location.endswith('/haproxy/sites/support/portal'))
        response=self.client.get('/haproxy/sites/support/portal',headers=self.admin)
        for control in (b'id="service-domain"',b'id="service-paused"',b'id="portal-language"',b'id="portal-text"',b'id="portal-upload"'):
            self.assertIn(control,response.data)
        for control in (b'name="backend_ip"',b'name="tcp_passthrough"',b'name="zero_trust"',b'name="authelia_enabled"',b'id="portal-enabled"'):
            self.assertNotIn(control,response.data)

    def test_normal_sites_and_regular_users_cannot_use_the_service_editor(self):
        self.assertEqual(self.client.get('/haproxy/access-sites',headers=self.user).status_code,403)
        self.site['access_gate']=False
        for path in ('/haproxy/sites/support/portal','/haproxy/sites/support/portal/settings'):
            self.assertEqual(self.client.get(path,headers=self.admin).status_code,404)

    def test_short_form_rejects_proxy_fields_and_creates_a_backendless_service(self):
        with patch.object(routes,'save_access_site_identity') as save:
            response=self.client.post('/haproxy/sites/support/portal',headers=self.admin,
                data={'action':'save_identity','domain':'changed.example.test','revision':'x','backend_ip':'192.0.2.9'})
            self.assertEqual(response.status_code,400);save.assert_not_called()
        with patch.object(routes,'add_site_minimal',return_value=(True,'saved')) as create:
            response=self.client.post('/haproxy/access-sites',headers=self.admin,data={'domain':'new.example.test'})
            self.assertEqual(response.status_code,302)
            create.assert_called_once_with('new.example.test','new.example.test','','')
        from haproxy_admin import routes_haproxy_config as proxy_routes
        with patch.object(proxy_routes,'add_site_minimal') as create,patch.object(proxy_routes,'get_sites_and_defaults_for_ui',return_value=({},[])),patch.object(proxy_routes,'_load_yaml',return_value={}):
            self.client.post('/haproxy/sites',headers=self.admin,data={'action':'add','domain':'empty.example.test'})
            create.assert_not_called()

    def test_upload_limits_cleanup_and_path_safety(self):
        for name in ('../file.exe','x/y.exe','x\\y.exe','x\r\nY.exe','x\tY.exe',''):
            with self.assertRaises(ValueError):store.upload('support',name,io.BytesIO(b'fixture'))
        with patch.object(store,'MAX_FILE_BYTES',3):
            with self.assertRaises(ValueError):store.upload('support','helper.exe',io.BytesIO(b'four'))
        self.assertEqual(store.settings('support')['files'],[])
        self.assertFalse(list((self.root/'portals').glob('*/*.bin')))

    def test_symlinks_cannot_redirect_downloads_to_other_files(self):
        value=store.upload('support','helper.exe',io.BytesIO(b'fixture'));self.enable(value)
        file=value['files'][0]
        target=store._directory('support')/(file['id']+'.bin');target.unlink()
        outside=self.root/'outside';outside.write_text('PRIVATE')
        target.symlink_to(outside)
        with self.assertRaises(OSError):store.open_download('support',file['id'])

    def test_reads_remain_available_while_an_upload_holds_the_write_lock(self):
        with store._locked('support'):
            self.assertFalse(store.settings('support')['enabled'])


@unittest.skipUnless(store, 'Linux application imports')
class PortalHostTests(unittest.TestCase):
    def test_host_lookup_accepts_only_enabled_gate_sites_and_their_aliases(self):
        config=importlib.import_module('haproxy_admin.services_haproxy_config')
        sites={'sites':[{'name':'support','domain':'support.example.test','alt_names':['alias.example.test'],'access_gate':True,'backend_ip':'192.0.2.80'},
            {'name':'normal','domain':'normal.example.test','backend_ip':'192.0.2.1'}]}
        # Exercise real source versions: mocking only the YAML loader leaves
        # stat-based caches and the applied snapshot from other tests in play.
        with tempfile.TemporaryDirectory() as directory:
            folder=Path(directory)
            websites=folder/'websites.yml'
            websites.write_text(yaml.safe_dump(sites),encoding='utf-8')
            with patch.object(config,'WEBSITES_YAML',websites),patch.object(config,'CONFIG_YAML',folder/'vars.yml'),patch.object(config,'HAPROXY_STATE_WEBSITES',folder/'applied.yml'),patch.object(config,'HAPROXY_STATE_VARS',folder/'applied-vars.yml'):
                self.assertEqual(store.site_by_host('ALIAS.EXAMPLE.TEST')['name'],'support')
                for host in ('normal.example.test','missing.example.test'):
                    with self.assertRaises(FileNotFoundError):store.site_by_host(host)
                sites['sites'][0]['enabled']=False
                replacement=folder/'replacement.yml'
                replacement.write_text(yaml.safe_dump(sites),encoding='utf-8')
                replacement.replace(websites)
                with self.assertRaises(FileNotFoundError):store.site_by_host('support.example.test')

    def test_the_generated_proxy_sanitizes_markers_and_checks_panel_capability(self):
        source=(ROOT/'ansible/roles/haproxy/templates/haproxy.cfg.j2').read_text()
        self.assertLess(source.index('http-request del-header X-Easy-HA-Proxy-Portal-Host'),source.index('http-request set-header X-Easy-HA-Proxy-Portal-Host'))
        self.assertIn('http-request set-path /access-portal%[path]',source)
        self.assertIn('uri /api/access-portal-health',source)
        self.assertIn('use_backend be_access_granted if host_{{ id }} { path -i / } !{ nbsrv(be_access_portal) gt 0 }',source)


@unittest.skipUnless(store, 'Linux application imports')
class PortalRoutingTests(unittest.TestCase):
    def test_new_services_override_proxy_defaults_without_an_upstream(self):
        from haproxy_admin import services_haproxy_sites as sites
        data={'sites':[]}
        def write(_kind,text):
            data.update(yaml.safe_load(text));return True,'saved'
        with patch.object(sites,'source_lock',side_effect=lambda _:nullcontext()),patch.object(sites,'_load_yaml',side_effect=lambda _:copy.deepcopy(data)),patch.object(sites,'update_yaml_file',side_effect=write),patch.object(sites,'_ensure_access_gate_authelia_rule',return_value=(True,'already present')):
            for domain in ('first.example.test','second.example.test'):
                self.assertTrue(sites.add_site_minimal(domain,domain,'','')[0])
        self.assertEqual(len(data['sites']),2)
        for site in data['sites']:
            for key in ('access_gate','authelia_enabled','redirect_to_https','access_portal_enabled'):
                self.assertIs(site[key],True)
            self.assertIs(site['tcp_passthrough'],False)
            self.assertIs(site['zero_trust'],False)
            self.assertEqual(site['allow_ips'],[])
            self.assertNotIn('backend_ip',site)
            self.assertNotIn('servers',site)

    def test_new_service_requires_authelia_before_writing_any_configuration(self):
        from haproxy_admin import services_haproxy_sites as sites
        with patch.object(sites,'source_lock',side_effect=lambda _:nullcontext()),patch.object(sites,'_load_yaml',return_value={'authelia_enabled':False}),patch.object(sites,'update_yaml_file') as write:
            ok,message=sites.add_site_minimal('support','support.example.test','','')
            self.assertFalse(ok)
            self.assertIn('Enable Authelia',message)
            write.assert_not_called()

    def test_identity_edits_preserve_legacy_settings_and_refuse_stale_or_conflicting_names(self):
        from haproxy_admin import services_haproxy_sites as sites
        original={'name':'support','domain':'old.example.test','access_gate':True,'backend_ip':'192.0.2.80','backend_port':8080,'certificate_source':'external','external_ca_id':'corp'}
        other={'name':'other','domain':'occupied.example.test'}
        revision=routes.config.entry_revision(original)
        with patch.object(sites,'source_lock',side_effect=lambda _:nullcontext()),patch.object(sites,'get_site_raw_and_effective',return_value=({},original,original)),patch.object(sites,'get_websites_list',return_value=[original,other]),patch.object(sites,'_save_site_raw',return_value=(True,'saved')) as write,patch.object(sites,'_ensure_access_gate_authelia_rule',return_value=(True,'already present')) as rule:
            self.assertTrue(sites.save_access_site_identity('support','new.example.test',True,revision)[0])
            self.assertEqual(write.call_args.args[1],{**original,'domain':'new.example.test','paused':True})
            rule.assert_called_once_with(['new.example.test'])
            write.reset_mock()
            with self.assertRaises(routes.config.StaleEntry):
                sites.save_access_site_identity('support','new.example.test',False,'stale')
            self.assertFalse(sites.save_access_site_identity('support','occupied.example.test',False,revision)[0])
            self.assertFalse(sites.save_access_site_identity('support','new.example.test',False,None)[0])
            write.assert_not_called()

    def test_opt_in_preserves_the_existing_upstream_and_other_sites(self):
        data={'sites':[{'name':'support','access_gate':True,'backend_ip':'192.0.2.80','backend_port':8080},{'name':'other','domain':'other.example.test'}]}
        original=copy.deepcopy(data)
        with patch.object(routes.config,'source_lock',side_effect=lambda _:nullcontext()),patch.object(routes.config,'_load_yaml',side_effect=lambda _:copy.deepcopy(data)),patch.object(routes.config,'update_yaml_file',return_value=(True,'saved')) as write:
            self.assertTrue(routes.set_routing('support',True))
            saved=yaml.safe_load(write.call_args.args[1])
            self.assertEqual(saved['sites'][0],{**original['sites'][0],'access_portal_enabled':True})
            self.assertEqual(saved['sites'][1],original['sites'][1])
            data=saved;write.reset_mock()
            self.assertFalse(routes.set_routing('support',True));write.assert_not_called()

    def test_rendering_leaves_a_gate_unchanged_until_it_opts_in(self):
        from test_security_boundaries import GeneratedConfigurationPassesItsOwnPolicyTests
        renderer=GeneratedConfigurationPassesItsOwnPolicyTests()
        site={'name':'support','domain':'support.example.test','access_gate':True,'backend_ip':'192.0.2.80','backend_port':8080}
        before=renderer.render(authelia_enabled=True,admin_authelia_enabled=True,sites=[site]).decode()
        self.assertNotIn('backend be_access_portal',before)
        after=renderer.render(authelia_enabled=True,admin_authelia_enabled=True,sites=[{**site,'access_portal_enabled':True}]).decode()
        self.assertIn('use_backend be_access_portal if host_support { path -i / }',after)
        self.assertIn('use_backend be_access_portal if host_support { path_beg /downloads/ }',after)
        self.assertIn('backend be_support',after)
