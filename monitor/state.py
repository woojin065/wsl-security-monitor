"""Private local state; never stored inside the source repository."""
import fcntl
import json
import os
import tempfile
from pathlib import Path
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

ROOT = Path(os.environ.get('WSM_STATE_DIR', str(Path.home() / '.local/share/wsl-security-monitor')))
SEOUL = ZoneInfo('Asia/Seoul')

def now():
    return datetime.now(SEOUL)

def setup():
    ROOT.mkdir(parents=True, exist_ok=True, mode=0o700)
    ROOT.chmod(0o700)
    (ROOT / 'reports').mkdir(exist_ok=True, mode=0o700)

def read(name, default=None):
    try:
        return json.loads((ROOT / name).read_text())
    except FileNotFoundError:
        return default

def write(name, value):
    setup()
    target = ROOT / name
    fd, tmp = tempfile.mkstemp(dir=target.parent)
    try:
        with os.fdopen(fd, 'w') as out:
            json.dump(value, out, ensure_ascii=False, indent=2)
        os.replace(tmp, target)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)

def config():
    setup()
    cfg = read('config.json')
    if cfg is None:
        cfg = {'projects': [], 'external_lookup': True, 'excluded_packages': [],
               'anchor_date': now().date().isoformat()}
        write('config.json', cfg)
    return cfg

def due(cfg, date):
    anchor = datetime.fromisoformat(cfg['anchor_date']).date()
    return (date - anchor).days >= 0 and (date - anchor).days % 2 == 0

def next_run(cfg):
    current = now()
    for offset in range(4):
        date = current.date() + timedelta(days=offset)
        candidate = datetime.combine(date, datetime.min.time(), SEOUL).replace(hour=9)
        if candidate > current and due(cfg, date):
            return candidate.isoformat()

def history():
    setup()
    return sorted((ROOT / 'reports').glob('*.json'), reverse=True)

def lock():
    setup()
    fd = os.open(ROOT / 'scan.lock', os.O_CREAT | os.O_RDWR, 0o600)
    file = os.fdopen(fd, 'w')
    try:
        fcntl.flock(file, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        file.close()
        raise RuntimeError('점검이 이미 실행 중입니다.') from None
    return file

def scanning():
    try:
        with lock():
            return False
    except RuntimeError:
        return True
