import json
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse
from . import state
from .scanner import scan

STATIC = Path(__file__).resolve().parent.parent / 'static'

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def allowed(self):
        return self.headers.get('Host') in self.server.allowed_hosts

    def send(self, code, data, kind='application/json; charset=utf-8'):
        raw = json.dumps(data, ensure_ascii=False).encode() if not isinstance(data, bytes) else data
        self.send_response(code)
        self.send_header('Content-Type', kind)
        self.send_header('Content-Length', str(len(raw)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        if not self.allowed():
            return self.send(403, {'error': '허용하지 않는 Host입니다.'})
        origin = self.headers.get('Origin')
        if origin and origin != 'http://' + self.headers['Host']:
            return self.send(403, {'error': '다른 출처의 접근을 거부합니다.'})
        path = urlparse(self.path).path
        if path == '/api/status':
            cfg = state.config()
            return self.send(200, {'config': cfg, 'next_run': state.next_run(cfg), 'csrf': self.server.csrf,
                                   'running': self.server.scanning.is_set() or state.scanning(), 'error': self.server.scan_error,
                                   'latest_id': state.history()[0].stem if state.history() else None})
        if path == '/api/reports':
            reports = []
            for file in state.history():
                report = state.read('reports/' + file.name)
                reports.append({k: report[k] for k in ('id', 'finished_at', 'duration_seconds')})
                reports[-1]['findings_count'] = len(report['findings'])
            return self.send(200, reports)
        if path.startswith('/api/reports/'):
            report_id = path.rsplit('/', 1)[1]
            if not report_id.isalnum() or len(report_id) > 40:
                return self.send(400, {'error': '잘못된 점검 ID'})
            report = state.read('reports/' + report_id + '.json')
            return self.send(200, report) if report else self.send(404, {'error': '점검 결과가 없습니다.'})
        assets = {'/': ('index.html', 'text/html; charset=utf-8'), '/app.js': ('app.js', 'text/javascript; charset=utf-8'), '/style.css': ('style.css', 'text/css; charset=utf-8')}
        if path in assets:
            filename, kind = assets[path]
            return self.send(200, (STATIC / filename).read_bytes(), kind)
        self.send(404, {'error': '찾을 수 없습니다.'})

    def do_POST(self):
        if not self.allowed() or self.headers.get('Origin') != 'http://' + self.headers.get('Host', '') or not secrets.compare_digest(self.headers.get('X-CSRF-Token', '').encode(), self.server.csrf.encode()):
            return self.send(403, {'error': '출처 또는 요청 토큰을 확인할 수 없습니다.'})
        if self.headers.get('Content-Type') != 'application/json':
            return self.send(415, {'error': 'JSON 요청만 지원합니다.'})
        try:
            length = int(self.headers.get('Content-Length', '0'))
            if not 0 < length <= 16384:
                raise ValueError()
            data = json.loads(self.rfile.read(length))
            if not isinstance(data, dict):
                raise ValueError()
        except (ValueError, UnicodeError):
            return self.send(400, {'error': '잘못된 요청입니다.'})
        path = urlparse(self.path).path
        if path == '/api/scan':
            with self.server.guard:
                if self.server.scanning.is_set():
                    return self.send(409, {'error': '점검 중입니다.'})
                self.server.scanning.set()
                self.server.scan_error = None
                threading.Thread(target=self.run_scan, daemon=True).start()
            return self.send(202, {'ok': True})
        if path == '/api/config':
            try:
                projects = data['projects']
                exclusions = data['excluded_packages']
                external = data['external_lookup']
                if not isinstance(projects, list) or len(projects) > 20 or not all(isinstance(p, str) for p in projects):
                    raise ValueError()
                resolved = []
                home = Path.home().resolve()
                for item in projects:
                    path = Path(item).expanduser()
                    if path.is_symlink():
                        raise ValueError()
                    path = path.resolve(strict=True)
                    if not path.is_dir() or not path.is_relative_to(home) or path == home or any(part in ('.ssh', '.aws', '.codex', '.claude', '.config') for part in path.relative_to(home).parts):
                        raise ValueError()
                    resolved.append(str(path))
                if not isinstance(exclusions, list) or not all(isinstance(x, str) and len(x) < 250 for x in exclusions) or len(exclusions) > 500 or not isinstance(external, bool):
                    raise ValueError()
                with self.server.guard:
                    if self.server.scanning.is_set():
                        return self.send(409, {'error': '점검 완료 후 설정을 저장하세요.'})
                    cfg = state.config()
                    cfg.update(projects=list(dict.fromkeys(resolved)), excluded_packages=exclusions, external_lookup=external)
                    state.write('config.json', cfg)
            except (KeyError, ValueError, OSError):
                return self.send(400, {'error': '홈 내부의 프로젝트 폴더를 지정하세요. 홈 전체·자격증명 폴더·심볼릭 링크는 제외합니다.'})
            return self.send(200, {'ok': True})
        return self.send(404, {'error': '찾을 수 없습니다.'})

    def run_scan(self):
        try:
            scan()
        except Exception:
            self.server.scan_error = '점검에 실패했습니다. 다른 점검이 실행 중인지와 로컬 상태 디렉터리 권한을 확인하세요.'
        finally:
            self.server.scanning.clear()


def serve(port=8765):
    state.config()
    server = ThreadingHTTPServer(('127.0.0.1', port), Handler)
    server.allowed_hosts = {f'localhost:{port}', f'127.0.0.1:{port}'}
    server.csrf = secrets.token_urlsafe(32)
    server.guard = threading.Lock()
    server.scanning = threading.Event()
    server.scan_error = None
    print(f'http://localhost:{port}', flush=True)
    server.serve_forever()
