#!/usr/bin/env python3
"""Install unprivileged user services. No dependencies or sudo."""
import subprocess
import sys
from pathlib import Path
from monitor import state

root = Path(__file__).resolve().parent
units = Path.home() / '.config/systemd/user'
units.mkdir(parents=True, exist_ok=True)
state.config()
# ExecStart uses shell-like quoting; WorkingDirectory does not.
def quoted(path):
    return '"' + str(path).replace('%', '%%').replace('\\', '\\\\').replace('"', '\\"') + '"'
common = f'''[Service]
WorkingDirectory={str(root).replace('%', '%%')}
ExecStart={quoted(sys.executable)} -m monitor {{action}}
UMask=0077
NoNewPrivileges=true
'''
(units / 'wsl-security-monitor.service').write_text('[Unit]\nDescription=Local WSL security dashboard\n\n' + common.format(action='serve') + 'Restart=on-failure\nRestartSec=5\n\n[Install]\nWantedBy=default.target\n')
(units / 'wsl-security-scan.service').write_text('[Unit]\nDescription=Read-only WSL security scan\n\n' + common.format(action='scheduled') + 'Type=oneshot\nTimeoutStartSec=15min\n')
(units / 'wsl-security-scan.timer').write_text('''[Unit]
Description=Check every second day at 09:00 Asia/Seoul

[Timer]
OnCalendar=*-*-* 09:00:00 Asia/Seoul
Persistent=false
AccuracySec=1min
Unit=wsl-security-scan.service

[Install]
WantedBy=timers.target
''')
subprocess.run(['systemd-analyze', '--user', 'verify', str(units / 'wsl-security-monitor.service'), str(units / 'wsl-security-scan.service'), str(units / 'wsl-security-scan.timer')], check=True)
subprocess.run(['systemctl', '--user', 'daemon-reload'], check=True)
subprocess.run(['systemctl', '--user', 'enable', '--now', 'wsl-security-monitor.service', 'wsl-security-scan.timer'], check=True)
print('http://localhost:8765')
