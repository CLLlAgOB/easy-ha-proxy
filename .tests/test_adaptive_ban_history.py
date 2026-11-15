"""A retained ban, rather than today's decayed score, explains a strike."""
import unittest
from unittest import mock

import test_guardd as base
from test_live_memory_budget import Handler


class BanHistory(base.EngineTestCase):
    def record(self, ip, ts, **extra):
        return self.database.record_decision(ip, ts, 'applied', 'adaptive', 'applied',
                                             reason={'categories': {'secrets': 60},
                                                     'evidence': [{'ts': ts-5, 'detail': '/.env', 'points': 60}]}, **extra)

    def test_filters_and_sort_apply_to_the_whole_history_before_pagination(self):
        for number in range(65):
            self.record('203.0.113.1', 1000+number, score=number)
        first = self.database.adaptive_ban_history(sort='score', direction='asc', limit=10)
        self.assertEqual([row['score'] for row in first['bans']], list(range(10)))
        self.record('203.0.113.2', 2000, score=0)
        second = self.database.adaptive_ban_history(sort='score', direction='asc', offset=10,
                                                    snapshot=first['snapshot'], limit=10)
        self.assertEqual(second['total'], 65)
        self.assertEqual([row['score'] for row in second['bans']], list(range(10, 20)))
        found = self.database.adaptive_ban_history(query='secrets', since=1060)
        self.assertEqual(found['total'], 6)
        self.assertEqual(self.database.adaptive_ban_history(query="' OR 1=1 --")['total'], 0)
        self.assertEqual(self.database.adaptive_ban_history(query='секрет', terms=('secrets',))['total'], 66)
        self.assertEqual(self.database.adaptive_ban_history(query='absent', terms=("' OR 1=1 --",))['total'], 0)

    def test_only_applied_adaptive_decisions_appear(self):
        self.record('203.0.113.1', 1000)
        for source, action, outcome in [('operator', 'applied', 'applied'), ('adaptive', 'applied', 'failed'),
                                         ('adaptive', 'lifted', 'applied'), ('adaptive', 'applied', 'pending')]:
            self.database.record_decision('203.0.113.2', 1001, action, source, outcome)
        self.assertEqual(self.database.adaptive_ban_history()['total'], 1)

    def test_detail_is_the_exact_selected_strike_even_after_another_ban(self):
        self.record('203.0.113.1', 1000, score=60, strike=1)
        first = self.database.adaptive_ban_history()['bans'][0]
        self.record('203.0.113.1', 2000, score=95, strike=2)
        detail = self.database.adaptive_ban_detail(decision_id=first['id'])
        self.assertEqual((detail['ts'], detail['score'], detail['strike']), (1000, 60, 1))
        self.assertEqual(detail['reason']['evidence'][0]['detail'], '/.env')
        self.assertEqual(self.database.adaptive_ban_detail(ip=first['ip'], at=1000), detail)
        self.assertIsNone(self.database.adaptive_ban_detail(ip=first['ip'], at=999))

    def test_active_ban_uses_recorded_strike_even_if_the_current_chain_resets(self):
        now = 10000
        self.database.observe_ip('203.0.113.1', now, base.guardd.Verdict(False, ''))
        self.database.set_ban('203.0.113.1', now+86400, 40, now)
        self.record('203.0.113.1', now, score=95, strike=2, until=now+86400)
        with mock.patch.object(self.engine, 'strike_level', return_value=0), \
                mock.patch.object(self.database, 'last_ban_ts', return_value=now):
            active = self.engine.current_bans(now+1)[0]
        detail = self.database.adaptive_ban_detail(decision_id=active['id'])
        self.assertEqual(active['strikes'], 2)
        self.assertEqual(active['strikes'], detail['strike'])
        self.assertEqual(active['score'], detail['score'])

    def test_long_ban_keeps_its_step_and_timestamp_after_scoring_events_are_pruned(self):
        now = 10000
        self.database.observe_ip('203.0.113.1', now, base.guardd.Verdict(False, ''))
        self.database.set_ban('203.0.113.1', now+86400, 40, now)
        self.record('203.0.113.1', now, score=95, strike=3, until=now+86400)
        with mock.patch.object(self.database, 'last_ban_ts', return_value=0):
            active = self.engine.current_bans(now+10)[0]
        self.assertEqual((active['banned_at'], active['strikes']), (now, 3))

    def test_unknown_legacy_strike_is_not_replaced_with_todays_count(self):
        now = 10000
        self.database.observe_ip('203.0.113.1', now, base.guardd.Verdict(False, ''))
        self.database.set_ban('203.0.113.1', now+86400, 40, now)
        with mock.patch.object(self.engine, 'strike_level', return_value=4):
            active = self.engine.current_bans(now+1)[0]
        self.assertIsNone(active['strikes'])

    def test_api_refuses_bad_filters_and_reports_missing_records(self):
        for query in ('sort=reason', 'direction=drop', 'since=oops', 'offset=NaN'):
            self.assertEqual(Handler(self.engine, 'GET', '/api/v1/guard/adaptive/bans?'+query).sent[0], 400)
        self.assertEqual(Handler(self.engine, 'GET', '/api/v1/guard/adaptive/ban?id=100').sent[0], 404)
        self.assertEqual(Handler(self.engine, 'GET', '/api/v1/guard/adaptive/ban?ip=invalid').sent[0], 400)
        self.record('203.0.113.1', 1000)
        code, payload = Handler(self.engine, 'GET', '/api/v1/guard/adaptive/bans').sent
        self.assertEqual(code, 200)
        self.assertEqual(payload['total'], 1)
        code, detail = Handler(self.engine, 'GET', '/api/v1/guard/adaptive/ban?ip=203.0.113.1&at=1000').sent
        self.assertEqual(code, 200)
        self.assertEqual(detail['ban']['ts'], 1000)


class PanelRoutes(unittest.TestCase):
    def setUp(self):
        from test_authelia_acl_roundtrip import ACLRoundTripTests
        self.fixture = ACLRoundTripTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)

    def test_overview_list_and_decision_have_separate_pages(self):
        client, headers = self.fixture.client, self.fixture.headers
        overview = client.get('/security/adaptive', headers=headers)
        self.assertEqual(overview.status_code, 200)
        self.assertNotIn(b'id="ap-bans"', overview.data)
        self.assertIn(b'id="ap-show-normal"', overview.data)
        self.assertIn(b'id="ap-settings"', overview.data)
        listing = client.get('/security/adaptive/bans?mode=history&page=3', headers=headers)
        self.assertEqual(listing.status_code, 200)
        self.assertIn(b'id="ap-bans"', listing.data)
        self.assertNotIn(b'id="ab-evidence"', listing.data)
        detail = client.get('/security/adaptive/ban?id=12&ip=203.0.113.1&at=1000', headers=headers)
        self.assertEqual(detail.status_code, 200)
        self.assertIn(b'id="ab-evidence"', detail.data)
        self.assertIn(b'id="ab-back"', detail.data)
        self.assertNotIn(b'id="ap-bans"', detail.data)
        self.assertEqual(client.get('/security/adaptive/ban?ip=203.0.113.1', headers=headers).status_code, 200)
        for query in ('', '?id=bad', '?id=-1', '?ip=bad&at=1000'):
            self.assertEqual(client.get('/security/adaptive/ban'+query, headers=headers).status_code, 400)
        self.assertEqual(client.get('/security/adaptive/bans').status_code, 403)

    def test_routes_pass_only_supported_filters_and_handle_unavailability(self):
        from haproxy_admin import guardd_client
        fixture = self.fixture
        with mock.patch.object(guardd_client, 'guardd_adaptive_bans', return_value={'ok': True, 'bans': []}) as rpc:
            response = fixture.client.get('/api/security/adaptive/bans?sort=score&shell=bad', headers=fixture.headers)
            self.assertEqual(response.status_code, 200)
            rpc.assert_called_once_with({'sort': 'score'}, detail=False)
            response = fixture.client.get('/api/security/adaptive/ban?id=42', headers=fixture.headers)
            self.assertEqual(response.status_code, 200)
            rpc.assert_called_with({'id': '42'}, detail=True)
            rpc.side_effect = guardd_client.GuarddUnavailable('offline')
            self.assertEqual(fixture.client.get('/api/security/adaptive/bans', headers=fixture.headers).status_code, 503)
        self.assertEqual(fixture.client.get('/api/security/adaptive/bans').status_code, 403)
