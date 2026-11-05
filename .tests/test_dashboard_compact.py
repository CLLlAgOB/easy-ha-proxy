"""The dashboard fetches only bans without changing the legacy table API."""
from datetime import datetime
from pathlib import Path
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'docker/app'))

if sys.platform != 'win32':
    from flask import Flask
    from haproxy_admin import routes, services


@unittest.skipIf(sys.platform == 'win32', 'the admin package needs fcntl')
class CompactDashboardTables(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.multiple(services, cache_time=datetime.min,
                                      ban_cache_time=datetime.min, ban_table_cache={'ban': None})
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_the_dashboard_does_not_read_error_tables_and_keeps_adaptive_expiry(self):
        ban = {'rows': [['203.0.113.24', 'Blocked', '40', '3600']]}
        def schedule(table):
            table['rows'][0][3] = '120'
        with mock.patch.object(services, 'haproxy_runtime_command', return_value='raw') as runtime, \
                mock.patch.object(services, 'parse_table_output', return_value=ban), \
                mock.patch.object(services, '_apply_adaptive_expiry', side_effect=schedule), \
                mock.patch.object(services, '_list_err_tables') as errors:
            result = services.get_tables(include_errors=False)
            self.assertEqual(services.get_tables(include_errors=False), result)
        runtime.assert_called_once_with('show table tbl_ban', services.SOCKET, timeout=2)
        errors.assert_not_called()
        self.assertEqual(result, {'ban': {'rows': [['203.0.113.24', 'Blocked', '40', '120']]}})

    def test_a_fresh_full_response_can_be_reused_without_reading_the_socket(self):
        with mock.patch.object(services, 'cache_time', datetime.now()), \
                mock.patch.object(services, 'table_cache', {'ban': {'rows': []}, 'err': {'rows': []}}), \
                mock.patch.object(services, 'haproxy_runtime_command') as runtime:
            self.assertEqual(services.get_tables(include_errors=False), {'ban': {'rows': []}})
        runtime.assert_not_called()

    def test_a_ban_change_invalidates_the_compact_view_too(self):
        with mock.patch.object(services, 'haproxy_runtime_command', return_value='raw') as runtime, \
                mock.patch.object(services, 'parse_table_output', return_value={'rows': []}), \
                mock.patch.object(services, '_apply_adaptive_expiry'):
            services.get_tables(include_errors=False)
            services.invalidate_table_cache()
            services.get_tables(include_errors=False)
        self.assertEqual(runtime.call_count, 2)

    def test_both_api_views_remain_read_only(self):
        app = Flask('compact-dashboard')
        app.register_blueprint(routes.bp)
        with app.test_client() as client, mock.patch.object(routes, 'get_tables', return_value={'ban': None}) as tables:
            self.assertEqual(client.get('/api/tables?view=bans').status_code, 200)
            tables.assert_called_once_with(include_errors=False)
            tables.reset_mock()
            self.assertEqual(client.get('/api/tables').status_code, 200)
            tables.assert_called_once_with()
            self.assertEqual(client.post('/api/tables?view=bans').status_code, 405)


if __name__ == '__main__':
    unittest.main()
