import datetime
import json
import os
import subprocess
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest.mock import patch
from http.server import ThreadingHTTPServer
from monitor import state
from monitor.scanner import Scanner, parse_packages, osv_query, scan, CheckError
from monitor.server import Handler

class StateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.patch = patch.object(state, 'ROOT', Path(self.temp.name) / 'state')
        self.patch.start()
    def tearDown(self):
        self.patch.stop(); self.temp.cleanup()
    def test_calendar_crosses_month_and_missed_day_is_not_due(self):
        cfg = {'anchor_date': '2026-01-31'}
        for day, expected in [('2026-01-30', False), ('2026-01-31', True), ('2026-02-01', False), ('2026-02-02', True), ('2026-02-04', True)]:
            self.assertEqual(state.due(cfg, datetime.date.fromisoformat(day)), expected)
    def test_state_private_and_lock_exclusive(self):
        state.config()
        self.assertEqual(state.ROOT.stat().st_mode & 0o777, 0o700)
        self.assertEqual((state.ROOT / 'config.json').stat().st_mode & 0o777, 0o600)
        with state.lock():
            self.assertTrue(state.scanning())
            with self.assertRaises(RuntimeError):
                state.lock()
        self.assertFalse(state.scanning())
    def test_findings_disappearance_not_resolved_when_coverage_incomplete(self):
        a = {'id': '20260101', 'findings': [{'id': 'f1'}], 'checks': [{'status': 'checked'}]}
        b = {'id': '20260102', 'findings': [], 'checks': [{'status': 'incomplete'}]}
        with patch.object(Scanner, 'run', return_value=a):
            scan()
        with patch.object(Scanner, 'run', return_value=b):
            self.assertEqual(scan()['resolved_ids'], [])

class ScannerTests(unittest.TestCase):
    def cfg(self):
        return {'projects': [], 'external_lookup': True, 'excluded_packages': []}
    def test_secret_evidence_never_contains_value_or_line(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            sentinel = 'ghp_' + 'A' * 36
            (root / 'app.py').write_text('TOKEN="' + sentinel + '"\n')
            scanner = Scanner(self.cfg())
            scanner.project(root)
            payload = json.dumps(scanner.findings, ensure_ascii=False)
            self.assertNotIn(sentinel, payload)
            self.assertNotIn('TOKEN=', payload)
            self.assertIn('1행', payload)
    def test_untracked_env_does_not_abort_scan(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            subprocess.run(['git', 'init', '-q', str(root)], check=True)
            (root / '.env').write_text('NOT_A_SECRET=true')
            scanner = Scanner(self.cfg())
            scanner.project(root)
            self.assertFalse(scanner.findings)
            subprocess.run(['git', '-C', str(root), 'add', '.env'], check=True)
            scanner.project(root)
            self.assertTrue(any(f['title'] == '환경 파일이 Git에 추적됨' for f in scanner.findings))
    def test_unquoted_env_secret_is_redacted(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            value = 'a-real-looking-value-123456789'
            (root / '.env').write_text('AWS_SECRET_ACCESS_KEY=' + value)
            scanner = Scanner(self.cfg()); scanner.project(root)
            self.assertEqual(len(scanner.findings), 1)
            self.assertNotIn(value, json.dumps(scanner.findings))
    def test_no_symlink_escape(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / 'project'; root.mkdir()
            outside = Path(folder) / 'outside'; outside.mkdir()
            (outside / 'secret').write_text('ghp_' + 'A' * 36)
            (root / 'linked').symlink_to(outside, target_is_directory=True)
            (root / 'linked-file').symlink_to(outside / 'secret')
            scanner = Scanner(self.cfg()); scanner.project(root)
            self.assertFalse(scanner.findings)
    def test_scoped_transitive_packages_and_no_urls(self):
        raw = {'packages': {'': {'name': 'private-root', 'version': '1.0.0'},
                            'node_modules/@scope/pkg': {'version': '2.3.4', 'resolved': 'https://user:secret@example.org/pkg'},
                            'node_modules/x/node_modules/y': {'version': '1.2.3'}}}
        result = parse_packages('package-lock.json', json.dumps(raw))
        self.assertEqual(result, {('npm', '@scope/pkg', '2.3.4'), ('npm', 'y', '1.2.3')})
    def test_only_fixed_python_requirements(self):
        text = 'jinja2==2.4.1\nrequests>=2\nprivate @ https://token@example.org\n-r other.txt\n'
        self.assertEqual(parse_packages('requirements.txt', text), {('PyPI', 'jinja2', '2.4.1')})
    def test_lookup_payload_exclusions_and_offline(self):
        scanner = Scanner(self.cfg())
        text = 'jinja2==2.4.1\nprivate-lib==1.0\n'
        scanner.cfg['excluded_packages'] = ['private-lib']
        with patch('monitor.scanner.osv_query', return_value={}) as request:
            scanner.dependencies(Path('/private/path/requirements.txt'), text)
            request.assert_called_once_with({'package': {'ecosystem': 'PyPI', 'name': 'jinja2'}, 'version': '2.4.1'})
        scanner.cfg['external_lookup'] = False
        with patch('monitor.scanner.osv_query') as request:
            with self.assertRaises(CheckError):
                scanner.dependencies(Path('requirements.txt'), text)
            request.assert_not_called()
    def test_osv_request_has_only_allowed_fields_no_proxy_or_redirect(self):
        class Reply:
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def read(self, length): return b'{}'
        class Opener:
            def open(self, request, timeout):
                self.request = request
                return Reply()
        opener = Opener()
        query = {'package': {'name': 'jinja2', 'ecosystem': 'PyPI'}, 'version': '2.4.1'}
        with patch('urllib.request.build_opener', return_value=opener) as build:
            osv_query(query)
            handlers = build.call_args.args
            self.assertEqual(handlers[0].proxies, {})
            self.assertIsNone(handlers[1].redirect_request(None, None, None, None, None, None))
        self.assertEqual(opener.request.full_url, 'https://api.osv.dev/v1/query')
        self.assertEqual(json.loads(opener.request.data), query)
    def test_command_failures_are_incomplete_not_passed(self):
        scanner = Scanner(self.cfg())
        with patch('monitor.scanner.command', side_effect=CheckError('SECRET_STDERR')):
            scanner.check('포트', scanner.ports)
        self.assertEqual(scanner.checks[0]['status'], 'incomplete')
        self.assertNotIn('SECRET_STDERR', json.dumps(scanner.checks))
    def test_wildcard_ports_only(self):
        scanner = Scanner(self.cfg())
        data = 'tcp LISTEN 0 10 0.0.0.0:8000 0.0.0.0:*\ntcp LISTEN 0 10 127.0.0.1:8001 0.0.0.0:*\nudp UNCONN 0 0 [::]:123 [::]:*\n'
        with patch('monitor.scanner.command', return_value=data):
            scanner.ports()
        self.assertEqual(len(scanner.findings), 2)
    def test_docker_privilege_and_socket_without_environment(self):
        scanner = Scanner(self.cfg())
        raw = {'name': '/test', 'privileged': True, 'network': 'bridge', 'capadd': [], 'ports': {},
               'mounts': [{'Source': '/var/run/docker.sock', 'RW': True}]}
        with patch('monitor.scanner.command', side_effect=['abc\n', json.dumps(raw)]) as cmd:
            scanner.docker()
        self.assertEqual(scanner.findings[0]['severity'], 'high')
        self.assertNotIn('.Config.Env', str(cmd.call_args_list))

class HttpTests(StateTests):
    def setUp(self):
        super().setUp()
        state.config()
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.port = self.server.server_port
        self.server.allowed_hosts = {f'127.0.0.1:{self.port}', f'localhost:{self.port}'}
        self.server.csrf = 'test-token'; self.server.guard = threading.Lock()
        self.server.scanning = threading.Event(); self.server.scan_error = None
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True); self.thread.start()
    def tearDown(self):
        self.server.shutdown(); self.server.server_close(); self.thread.join()
        super().tearDown()
    def request(self, path, data=None, headers=None):
        req = urllib.request.Request(f'http://127.0.0.1:{self.port}{path}', data=None if data is None else json.dumps(data).encode(), headers=headers or {})
        try:
            with urllib.request.urlopen(req) as r:
                return r.status, r.read(), dict(r.headers)
        except urllib.error.HTTPError as e:
            with e:
                return e.code, e.read(), dict(e.headers)
    def headers(self):
        return {'Origin': f'http://127.0.0.1:{self.port}', 'X-CSRF-Token': 'test-token', 'Content-Type': 'application/json'}
    def test_static_csp_no_cache_and_unknown_file(self):
        code, body, headers = self.request('/')
        self.assertEqual(code, 200); self.assertIn(b'<!doctype html>', body)
        self.assertIn("frame-ancestors 'none'", headers['Content-Security-Policy'])
        self.assertEqual(headers['Cache-Control'], 'no-store')
        self.assertEqual(self.request('/../../monitor/state.py')[0], 404)
    def test_dns_rebinding_and_cross_origin_blocked(self):
        self.assertEqual(self.request('/api/status', headers={'Host': 'evil.example'})[0], 403)
        self.assertEqual(self.request('/api/status', headers={'Origin': 'https://evil.example'})[0], 403)
        self.assertEqual(self.request('/api/scan', {}, {'Content-Type': 'application/json'})[0], 403)
        headers = self.headers(); headers['Origin'] = 'https://evil.example'
        self.assertEqual(self.request('/api/scan', {}, headers)[0], 403)
    def test_config_rejects_home_and_credentials(self):
        data = {'projects': [str(Path.home())], 'excluded_packages': [], 'external_lookup': True}
        self.assertEqual(self.request('/api/config', data, self.headers())[0], 400)
        data['projects'] = [str(Path.home() / '.ssh')]
        self.assertEqual(self.request('/api/config', data, self.headers())[0], 400)
        data['projects'] = []
        self.assertEqual(self.request('/api/config', data, self.headers())[0], 200)
    def test_report_id_traversal_rejected(self):
        self.assertEqual(self.request('/api/reports/..')[0], 400)
    def test_scan_returns_immediately_and_saves_report(self):
        with patch('monitor.server.scan', return_value={}) as mocked:
            self.assertEqual(self.request('/api/scan', {}, self.headers())[0], 202)
            for _ in range(20):
                if not self.server.scanning.wait(.01): break
            mocked.assert_called_once()

if __name__ == '__main__':
    unittest.main()
