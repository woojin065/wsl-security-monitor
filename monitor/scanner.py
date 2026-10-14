"""Read-only checks. No shell, installs, remediation, or source uploads."""
import hashlib
import json
import os
import platform
import re
import stat
import subprocess
import time
import urllib.request
from pathlib import Path
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from . import state

SKIP_DIRS = {'.git', 'node_modules', '.venv', 'venv', '__pycache__', 'dist', 'build', '.cache', '.ssh', '.aws', '.codex', '.claude'}
MAX_FILE = 1024 * 1024
MAX_FILES = 10000
SECRETS = [
    ('개인 키', re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----')),
    ('GitHub 토큰', re.compile(r'\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})\b')),
    ('AWS 접근 키 식별자', re.compile(r'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b')),
    ('비밀값 할당 의심', re.compile(r'''(?i)\b[A-Za-z0-9_]*(?:api[_-]?key|secret|password|access[_-]?token|auth[_-]?token)[A-Za-z0-9_]*\s*[:=]\s*["']?([A-Za-z0-9_./+=:-]{12,})''')),
]

class CheckError(Exception):
    pass

def command(args, timeout=20):
    try:
        run = subprocess.run(args, capture_output=True, text=True, timeout=timeout,
                             env={**os.environ, 'LC_ALL': 'C', 'GIT_TERMINAL_PROMPT': '0'})
    except (OSError, subprocess.TimeoutExpired):
        raise CheckError('명령을 실행할 수 없거나 제한 시간을 초과했습니다.') from None
    if run.returncode:
        # stderr may contain sensitive data. Never persist it.
        raise CheckError('권한·설치·서비스 상태 때문에 명령 실행에 실패했습니다.')
    return run.stdout

class Scanner:
    def __init__(self, cfg):
        self.cfg = cfg
        self.findings = []
        self.checks = []
        self.started = time.monotonic()

    def finding(self, category, severity, title, target, evidence, fix, verify):
        if len(self.findings) >= 2000:
            raise CheckError('발견 항목 수 제한 초과')
        identity = f'{category}|{title}|{target}|{evidence}'
        self.findings.append({'id': hashlib.sha256(identity.encode()).hexdigest()[:16],
                              'category': category, 'severity': severity, 'title': title,
                              'target': str(target), 'evidence': evidence, 'fix': fix, 'verify': verify})

    def check(self, name, fn):
        before = len(self.findings)
        try:
            note = fn()
            self.checks.append({'name': name, 'status': 'findings' if len(self.findings) > before else 'checked', 'note': note or ''})
        except (CheckError, OSError, ValueError, KeyError, TypeError):
            self.checks.append({'name': name, 'status': 'incomplete', 'note': '권한, 입력 형식 또는 명령 상태로 점검을 완료하지 못했습니다. 미점검은 안전을 의미하지 않습니다.'})

    def ports(self):
        output = command(['ss', '-H', '-lntu'])
        for line in output.splitlines():
            fields = line.split()
            if len(fields) < 5:
                continue
            address = fields[4]
            host = address.rsplit(':', 1)[0].strip('[]')
            if host in ('*', '0.0.0.0', '::'):
                self.finding('WSL', 'medium', '전체 인터페이스에서 수신하는 포트', address,
                             f'{fields[0]} {address}에서 수신 중. 실제 외부 접근 가능 여부는 Windows 방화벽·WSL 네트워크에 따라 달라집니다.',
                             '개발 서비스라면 127.0.0.1에 바인딩하고 필요한 접근 범위를 확인하세요.', 'ss -lntu로 바인딩 주소를 다시 확인하세요.')
        return 'TCP·UDP 수신 주소 검사. Windows 방화벽과 실제 원격 도달성은 검사하지 않습니다.'

    def services(self):
        names = command(['systemctl', 'list-units', '--type=service', '--state=running', '--no-legend', '--plain'])
        risky = {'telnet.service', 'vsftpd.service', 'proftpd.service', 'rsh.service', 'rpcbind.service'}
        for line in names.splitlines():
            name = line.split()[0] if line.split() else ''
            if name in risky:
                self.finding('WSL', 'medium', '접근 범위를 검토할 서비스', name, '해당 서비스가 실행 중입니다.',
                             '필요성을 확인하고 불필요하면 중지·비활성화하세요. 필요한 경우 인증과 접근 제한을 확인하세요.', 'systemctl is-active로 서비스 상태를 확인하세요.')
        return '실행 중인 서비스의 제한된 위험 목록 검사. 모든 프로세스의 악성 여부를 판정하지 않습니다.'

    def permissions(self):
        paths = [Path.home() / '.ssh', Path.home() / '.aws', Path.home() / '.config/gh/hosts.yml']
        ssh = Path.home() / '.ssh'
        if ssh.exists():
            paths.extend(p for p in ssh.iterdir() if not p.is_symlink() and p.is_file())
        for path in paths:
            if not path.exists() or path.is_symlink():
                continue
            mode = stat.S_IMODE(path.stat().st_mode)
            public = path.name.endswith('.pub') or path.name in ('known_hosts', 'known_hosts.old')
            unsafe = mode & 0o022 if public else mode & 0o077
            if unsafe:
                self.finding('WSL', 'medium', '민감한 경로의 권한 검토 필요', path,
                             f'파일 내용은 읽지 않았습니다. 현재 권한: {mode:03o}.',
                             ('호스트 공개 키 목록·공개 키 파일은 다른 사용자의 쓰기 권한을 제거하세요. 읽기 권한만으로 개인 키 노출로 판단하지 마세요.' if public else
                              '소유자와 공유 필요성을 확인한 뒤 개인 디렉터리는 700, 개인 파일은 600 권한을 검토하세요.'), 'stat으로 소유자와 권한을 다시 확인하세요.')

    def ssh(self):
        active = subprocess.run(['systemctl', 'is-active', 'ssh.service'], capture_output=True, text=True)
        if active.returncode:
            return 'ssh.service가 실행 중이지 않습니다. 다른 방식으로 실행한 SSH 서버는 별도 확인이 필요합니다.'
        binary = '/usr/sbin/sshd'
        settings = dict(line.split(' ', 1) for line in command([binary, '-T']).splitlines() if ' ' in line)
        for key, safe in [('permitrootlogin', {'no'}), ('passwordauthentication', {'no'})]:
            if settings.get(key) not in safe:
                self.finding('WSL', 'medium', 'SSH 인증 설정 검토 필요', '/etc/ssh/sshd_config',
                             f'{key}={settings.get(key, "unknown")}',
                             '접속 유지 수단과 공개 키 인증을 먼저 검증하고 root 로그인·비밀번호 인증 제한을 검토하세요. Match 블록도 확인하세요.',
                             'sshd -t 및 접속 조건별 sshd -T -C 검사 후 기존 접속을 유지한 채 새 연결을 검증하세요.')
        return '기본 유효 설정 검사. 사용자·주소별 Match 설정은 별도 검증이 필요합니다.'

    def updates(self):
        entries = list(Path('/var/lib/apt/lists').glob('*InRelease'))
        if not entries:
            raise CheckError('APT 메타데이터 없음')
        current = time.time()
        codename = platform.freedesktop_os_release().get('VERSION_CODENAME')
        ages = []
        for entry in entries:
            fields = {}
            for line in entry.read_text().splitlines():
                if line.startswith(('Origin:', 'Suite:', 'Date:', 'Valid-Until:')):
                    key, value = line.split(':', 1)
                    fields[key] = value.strip()
            # Ubuntu's base release is static. Its publication date is not a
            # record of the last apt update, and can remain old after refresh.
            static_base = fields.get('Origin') == 'Ubuntu' and codename and fields.get('Suite') == codename
            expired = 'Valid-Until' in fields and parsedate_to_datetime(fields['Valid-Until']).timestamp() <= current
            if static_base and not expired:
                continue
            published = parsedate_to_datetime(fields['Date'])
            if published.tzinfo is None or published.timestamp() > current + 86400:
                raise CheckError('저장소 발행 시각을 확인할 수 없습니다.')
            age = max(0, int((current - published.timestamp()) / 86400))
            if not static_base:
                ages.append(age)
            if expired or age > 2:
                evidence = f'{entry.name}: ' + ('Valid-Until 유효기간 만료.' if expired else f'메타데이터 발행 후 약 {age}일 경과.')
                self.finding('WSL', 'low', 'APT 저장소 메타데이터 확인 필요', '/var/lib/apt/lists',
                             evidence + ' 발행 시각은 마지막 apt update 실행 시각이 아닙니다.',
                             '승인 후 apt update를 실행하고 저장소별 오류·서명·유효기간을 확인하세요. 저장소에서 새 메타데이터를 발행하지 않은 경우도 구분하세요.',
                             'apt update의 성공 여부와 InRelease의 Date·Valid-Until을 확인하고 재점검하세요.')
        if not ages:
            raise CheckError('변경되는 저장소의 메타데이터가 없습니다.')
        stamp = Path('/var/lib/apt/periodic/update-success-stamp')
        refresh_note = '마지막 apt update 전체 성공 시각은 확인할 수 없습니다(성공 기록 없음).'
        if stamp.exists():
            updated = stamp.stat().st_mtime
            refresh_note = 'APT 자동 갱신 성공 기록: ' + datetime.fromtimestamp(updated, timezone.utc).isoformat() + '. 수동 갱신 여부·전체 저장소 성공을 보증하지 않습니다.'
            if current - updated > 3 * 86400:
                self.finding('WSL', 'low', 'APT 갱신 성공 기록 확인 필요', stamp,
                             f'자동 갱신 성공 기록이 약 {int((current - updated) / 86400)}일 전입니다. 이후 수동 갱신 여부는 확인할 수 없습니다.',
                             '최근 수동 갱신 여부와 자동 갱신 설정을 확인하고 필요하면 승인 후 apt update를 실행하세요.',
                             '갱신 결과와 자동 갱신 성공 기록을 확인하세요.')
        upgrades = command(['apt', 'list', '--upgradable'])
        security = [line.split()[0] for line in upgrades.splitlines() if '-security' in line]
        if security:
            self.finding('WSL', 'high', '캐시에서 보안 업데이트 후보 발견', 'APT', '\n'.join(security[:50]),
                         '최신 패키지 메타데이터와 변경 영향을 확인하고 보안 업데이트를 적용하세요. 서비스 재시작 필요성을 확인하세요.', '업데이트 후 apt list --upgradable 및 필요 시 재부팅 필요 여부를 확인하세요.')
        return f'변경되는 저장소의 발행 시각 기준 최대 {max(ages)}일 경과. Ubuntu 정적 기본 저장소의 오래된 발행 시각은 갱신 실패로 판정하지 않습니다. {refresh_note} 패키지 설치·apt update는 실행하지 않습니다. 전체 CVE 판정이 아닙니다.'

    def docker(self):
        ids = command(['docker', 'ps', '-q']).split()
        for cid in ids:
            fmt = '{"name":{{json .Name}},"privileged":{{json .HostConfig.Privileged}},"network":{{json .HostConfig.NetworkMode}},"mounts":{{json .Mounts}},"ports":{{json .NetworkSettings.Ports}},"capadd":{{json .HostConfig.CapAdd}}}'
            data = json.loads(command(['docker', 'inspect', '--format', fmt, cid]))
            name = data['name']
            risks = []
            if data['privileged']:
                risks.append('privileged 모드')
            if data['network'] == 'host':
                risks.append('호스트 네트워크 공유')
            if data.get('capadd'):
                risks.append('추가 Linux capability: ' + ', '.join(data['capadd']))
            for mount in data['mounts']:
                src = mount.get('Source', '')
                if src in ('/', '/etc', '/home', str(Path.home())) or src.endswith('/docker.sock'):
                    risks.append(f'민감한 호스트 경로 마운트: {src} (쓰기={mount.get("RW")})')
            for port, mappings in (data['ports'] or {}).items():
                for mapping in mappings or []:
                    if mapping.get('HostIp') in ('', '0.0.0.0', '::'):
                        risks.append(f'전체 인터페이스 포트 공개: {port} → {mapping.get("HostPort")}')
            if risks:
                self.finding('Docker', 'high', '컨테이너 권한·노출 검토 필요', name, '\n'.join(risks),
                             '실행 정의를 확인하고 필요한 권한·마운트만 남기며 개발 포트는 127.0.0.1에 공개하세요. 중단 영향을 검토하세요.',
                             'docker inspect의 권한·마운트·포트 설정과 애플리케이션 동작을 다시 확인하세요.')
        return f'실행 중 컨테이너 {len(ids)}개 검사. 환경 변수·로그·파일 내용은 읽지 않습니다. 이미지 CVE와 중지된 컨테이너는 미검사입니다.'

    def project(self, root):
        root = Path(root)
        if not root.is_dir() or root.is_symlink():
            raise CheckError('프로젝트 경로 접근 불가')
        count = 0
        skipped = 0
        manifests = []
        for directory, dirs, files in os.walk(root, followlinks=False):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not (Path(directory) / d).is_symlink()]
            for name in files:
                if time.monotonic() - self.started > 600:
                    raise CheckError('점검 시간 제한 초과')
                path = Path(directory) / name
                count += 1
                if count > MAX_FILES:
                    raise CheckError('파일 수 제한 초과')
                if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_FILE:
                    skipped += 1
                    continue
                raw = path.read_bytes()
                if b'\x00' in raw:
                    skipped += 1
                    continue
                text = raw.decode('utf-8', errors='replace')
                for number, line in enumerate(text.splitlines(), 1):
                    for label, regex in SECRETS:
                        match = regex.search(line)
                        if not match:
                            continue
                        if label == '비밀값 할당 의심' and any(x in match.group(1).lower() for x in ('example', 'placeholder', '${', 'changeme', 'your_', '<', 'test', 'dummy')):
                            continue
                        self.finding('프로젝트', 'high' if label != '비밀값 할당 의심' else 'medium', '비밀정보 노출 흔적', path,
                                     f'{number}행에서 {label} 패턴 발견. 원문과 비밀값은 저장하지 않았습니다. 실제 사용 값인지 로컬에서 확인하세요.',
                                     '실제 자격증명이면 폐기·재발급하고 환경 변수나 비밀 저장소로 옮기세요. Git 추적·과거 커밋 노출 여부를 확인하세요. 예제·테스트 값이면 오탐일 수 있습니다.',
                                     '재점검과 Git 추적 상태를 확인하고 이전 자격증명이 거부되는지 검증하세요.')
                        break
                if name in ('package-lock.json', 'requirements.txt', 'uv.lock', 'poetry.lock'):
                    manifests.append((path, text))
                if name == '.env' or name.startswith('.env.') and name not in ('.env.example', '.env.sample', '.env.template'):
                    tracked = command(['git', '-C', str(root), 'ls-files', '--', str(path)]) if (root / '.git').exists() else ''
                    if tracked:
                        self.finding('프로젝트', 'high', '환경 파일이 Git에 추적됨', path, '파일 내용은 결과에 포함하지 않습니다. git ls-files에서 추적 확인.',
                                     '실제 비밀 포함 여부를 로컬에서 확인하고 비밀이면 재발급 및 Git 추적 제거·ignore를 검토하세요.', 'git ls-files 및 재점검으로 확인하세요.')
        if not manifests:
            self.checks.append({'name': f'의존성 · {root.name}', 'status': 'skipped', 'note': '지원하는 잠금 파일 또는 requirements.txt가 없습니다.'})
        for path, text in manifests:
            self.check(f'의존성 · {path.relative_to(root)} ({root.name})', lambda p=path, t=text: self.dependencies(p, t))
        return f'텍스트 파일 검사. 후보 {count}개, 바이너리·대용량·심볼릭 링크 제외 {skipped}개. 미지원 비밀 형식·무시한 폴더·Git 이력은 검사하지 않습니다.'

    def dependencies(self, path, text):
        if not self.cfg['external_lookup']:
            raise CheckError('외부 조회 비활성화')
        packages = parse_packages(path.name, text)
        excluded = set(self.cfg.get('excluded_packages', []))
        queried = 0
        for ecosystem, name, version in sorted(packages):
            if name in excluded or f'{ecosystem}:{name}' in excluded:
                continue
            if queried >= 500 or time.monotonic() - self.started > 240:
                raise CheckError('조회 시간·개수 한도 초과')
            # Construct fields explicitly. No lockfile URLs, source snippets, paths or tokens.
            query = {'package': {'ecosystem': ecosystem, 'name': name}, 'version': version}
            result = osv_query(query)
            queried += 1
            for vuln in result.get('vulns', []):
                if vuln.get('withdrawn'):
                    continue
                vid = vuln.get('id', '')
                if not re.fullmatch(r'[A-Za-z0-9_.-]{1,100}', vid):
                    raise CheckError('잘못된 취약점 응답')
                fixes = sorted({e['fixed'] for a in vuln.get('affected', [])
                                if a.get('package', {}).get('name') == name
                                for r in a.get('ranges', []) for e in r.get('events', []) if 'fixed' in e})
                self.finding('의존성', 'high', '알려진 의존성 취약점', path,
                             f'{ecosystem} {name}@{version}: {vid}',
                             '공식 보안 공지와 호환성을 확인해 취약점이 해결된 버전으로 업데이트하세요. 수정 버전 후보: ' + (', '.join(fixes) or '공식 공지 확인 필요'),
                             f'잠금 파일과 기능 테스트를 검증하고 재점검하세요. 공지: https://osv.dev/vulnerability/{vid}')
        if not packages:
            raise CheckError('고정 버전 없음')
        return f'{queried}개 공개 패키지 이름·버전만 OSV로 조회. 제외 {len(packages) - queried}개. 지원 형식 내 고정 버전만 검사합니다.'

    def run(self):
        for name, fn in [('수신 포트', self.ports), ('실행 서비스', self.services), ('민감한 경로 권한', self.permissions),
                         ('SSH 인증', self.ssh), ('보안 업데이트 후보', self.updates), ('Docker 설정', self.docker)]:
            self.check(name, fn)
        if not self.cfg['projects']:
            self.checks.append({'name': '프로젝트 검사', 'status': 'skipped', 'note': '설정에서 검사할 프로젝트 경로를 지정하세요.'})
        for root in self.cfg['projects']:
            self.check(f'프로젝트 · {root}', lambda r=root: self.project(r))
        return {'id': state.now().strftime('%Y%m%dT%H%M%S%f'), 'finished_at': state.now().isoformat(),
                'duration_seconds': round(time.monotonic() - self.started, 1), 'findings': self.findings, 'checks': self.checks}


def parse_packages(filename, text):
    packages = set()
    if filename == 'package-lock.json':
        data = json.loads(text)
        for location, package in data.get('packages', {}).items():
            if 'node_modules/' in location:
                name = package.get('name') or location.rsplit('node_modules/', 1)[1]
                if not package.get('link'):
                    packages.add(('npm', name, package.get('version', '')))
        def legacy(items):
            for name, item in items.items():
                packages.add(('npm', name, item.get('version', '')))
                legacy(item.get('dependencies', {}))
        if not data.get('packages'):
            legacy(data.get('dependencies', {}))
    elif filename in ('uv.lock', 'poetry.lock'):
        import tomllib
        for package in tomllib.loads(text).get('package', []):
            source = package.get('source', {})
            if source and source.get('registry') != 'https://pypi.org/simple' and source.get('type') != 'legacy':
                continue
            packages.add(('PyPI', package['name'], package.get('version', '')))
    else:
        for line in text.splitlines():
            match = re.match(r'^\s*([A-Za-z0-9][A-Za-z0-9_.-]*)==([A-Za-z0-9][A-Za-z0-9_.+!-]*)\s*(?:;|#|$)', line)
            if match:
                packages.add(('PyPI', match[1], match[2]))
    return {(e, n, v) for e, n, v in packages if re.fullmatch(r'(?:@[A-Za-z0-9_.-]+/)?[A-Za-z0-9][A-Za-z0-9_.-]{0,200}', n)
            and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.+!-]{0,100}', v)}


def osv_query(query):
    request = urllib.request.Request('https://api.osv.dev/v1/query', data=json.dumps(query).encode(),
                                     headers={'Content-Type': 'application/json', 'User-Agent': 'wsl-security-monitor/1'})
    # Disable ambient proxy variables and redirects: queries must go only to this endpoint.
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            return None
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    try:
        with opener.open(request, timeout=10) as response:
            raw = response.read(4 * 1024 * 1024 + 1)
            if len(raw) > 4 * 1024 * 1024:
                raise CheckError('응답 크기 제한')
            return json.loads(raw)
    except (OSError, ValueError):
        raise CheckError('OSV 조회 실패') from None


def scan():
    with state.lock():
        report = Scanner(state.config()).run()
        previous = state.read('reports/' + state.history()[0].name) if state.history() else None
        old = {f['id'] for f in previous['findings']} if previous else set()
        current = {f['id'] for f in report['findings']}
        report['new_ids'] = sorted(current - old)
        report['resolved_ids'] = sorted(old - current) if previous and all(c['status'] == 'checked' or c['status'] == 'findings' for c in report['checks']) else []
        state.write(f'reports/{report["id"]}.json', report)
        for path in state.history()[100:]:
            path.unlink()
        return report
